"""SMB connection and UBR retrieval.

* Auth mirrors impacket's ``smbclient.py`` exactly: same target syntax
  ``[[domain/]username[:password]@]<target>``, same ``-hashes / -no-pass / -k /
  -aesKey / -dc-ip / -target-ip / -port`` options.
* UBR (Update Build Revision) is read from
  ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion!UBR`` over the
  ``\\winreg`` pipe after nudging RemoteRegistry awake (unauthenticated nudge,
  same trick NetExec uses).
"""

from __future__ import annotations

import contextlib
import socket
from dataclasses import dataclass
from time import sleep

from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SessionError, SMBConnection

_REMOTE_REGISTRY_WAKEUP_SECONDS = 1


class CveDetectError(Exception):
    """Raised for unrecoverable connection / detection errors."""


@dataclass
class AuthArgs:
    username: str
    password: str
    domain: str
    lmhash: str
    nthash: str
    aes_key: str
    kerberos: bool
    dc_ip: str | None
    target_ip: str
    port: int
    smb_timeout: int = 5


@dataclass
class OsVersion:
    os_string: str
    major: int
    minor: int
    build: int
    signing_required: bool
    is_dc: bool = False


def connect(address: str, auth: AuthArgs) -> SMBConnection:
    """Open an authenticated SMBConnection (Kerberos or NTLM)."""
    try:
        conn = SMBConnection(address, auth.target_ip, sess_port=auth.port, timeout=auth.smb_timeout)
        # Windows Server 2025+ rate-limits NTLM auth to one attempt per ~2s.
        # Bump the timeout by 1s during login to ride it out, then restore.
        # Mirrors nxc's increase_auth_timeout context manager.
        conn.setTimeout(auth.smb_timeout + 1)
        try:
            if auth.kerberos:
                conn.kerberosLogin(
                    auth.username,
                    auth.password,
                    auth.domain,
                    auth.lmhash,
                    auth.nthash,
                    auth.aes_key,
                    auth.dc_ip,
                )
            else:
                conn.login(auth.username, auth.password, auth.domain, auth.lmhash, auth.nthash)
        finally:
            with contextlib.suppress(Exception):
                conn.setTimeout(auth.smb_timeout)
    except Exception as e:  # noqa: BLE001 - bubble up as a single typed error
        raise CveDetectError(f"SMB login failed: {e}") from e
    return conn


def get_os_version(conn: SMBConnection) -> OsVersion:
    return OsVersion(
        os_string=conn.getServerOS() or "",
        major=conn.getServerOSMajor(),
        minor=conn.getServerOSMinor(),
        build=conn.getServerOSBuild(),
        signing_required=_safe_signing_required(conn),
        is_dc=detect_dc(conn),
    )


def detect_dc(conn: SMBConnection) -> bool:
    """Best-effort DC detection over SMB: only DCs publish the SYSVOL share.

    A successful TREE_CONNECT, or STATUS_ACCESS_DENIED (share exists but we lack
    rights), both prove the share exists -> DC. STATUS_BAD_NETWORK_NAME -> not a
    DC. Same Tier-1 probe NetExec uses.
    """
    try:
        tid = conn.connectTree("SYSVOL")
        with contextlib.suppress(Exception):
            conn.disconnectTree(tid)
        return True
    except SessionError as e:
        msg = str(e)
        if "STATUS_ACCESS_DENIED" in msg:
            return True
        if "STATUS_BAD_NETWORK_NAME" in msg:
            return False
        return False
    except Exception:  # noqa: BLE001
        return False


def _safe_signing_required(conn: SMBConnection) -> bool:
    try:
        return bool(conn.isSigningRequired())
    except Exception:  # noqa: BLE001
        return False


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP reachability probe used to pick \\winreg over ncacn_ip_tcp fallback."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def trigger_remote_registry(conn: SMBConnection) -> None:
    """Nudge RemoteRegistry awake by opening \\winreg without admin privs.

    Opening the pipe (and swallowing STATUS_PIPE_NOT_AVAILABLE) is enough to make
    the service manager start RemoteRegistry on modern Windows. Same trick used by
    NetExec (credit: splinter_code).
    """
    try:
        tid = conn.connectTree("IPC$")
    except (SessionError, BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
        raise CveDetectError(f"Could not connect to IPC$: {e}") from e

    try:
        conn.openFile(tid, r"\winreg", 0x12019F, creationOption=0x40, fileAttributes=0x80)
    except SessionError as e:
        # STATUS_PIPE_NOT_AVAILABLE is the expected (and useful) error here.
        if "STATUS_PIPE_NOT_AVAILABLE" not in str(e):
            raise
    except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError):
        # Best effort; the bind attempt below will surface a real failure.
        pass
    sleep(_REMOTE_REGISTRY_WAKEUP_SECONDS)


def read_ubr(conn: SMBConnection, auth: AuthArgs) -> int:
    """Connect to \\winreg, bind RRP, and return the UBR REG_DWORD value.

    Tries the SMB \\winreg pipe first (reusing the existing session). If the pipe
    is unreachable (e.g. RemoteRegistry disabled and the nudge failed, or SMB pipe
    access blocked), falls back to ncacn_ip_tcp on the DCE/RPC endpoint mapper.
    Raises CveDetectError if UBR cannot be determined.
    """
    try:
        dce = _open_winreg_smb(conn)
    except CveDetectError:
        dce = _open_winreg_tcp(auth)  # may raise CveDetectError
    try:
        ubr = _query_ubr(dce)
    finally:
        with contextlib.suppress(Exception):
            dce.disconnect()
    return ubr


def _open_winreg_smb(conn: SMBConnection):
    try:
        rpctransport = transport.SMBTransport(conn.getRemoteName(), filename=r"\winreg", smb_connection=conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        return dce
    except Exception as e:  # noqa: BLE001
        raise CveDetectError(f"\\winreg pipe bind failed: {e}") from e


def _open_winreg_tcp(auth: AuthArgs):
    host = auth.target_ip
    if not _port_open(host, 135):
        raise CveDetectError("RemoteRegistry unavailable: \\winreg pipe failed and the RPC EPM (135) is closed")
    string_binding = rf"ncacn_ip_tcp:{host}[135]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.setRemoteHost(host)
    rpctransport.set_credentials(
        auth.username, auth.password or "", auth.domain, auth.lmhash, auth.nthash, auth.aes_key
    )
    if auth.kerberos:
        rpctransport.set_kerberos(True, auth.dc_ip)
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        return dce
    except Exception as e:  # noqa: BLE001
        raise CveDetectError(f"winreg over ncacn_ip_tcp failed: {e}") from e


def _query_ubr(dce) -> int:
    try:
        h_root = rrp.hOpenLocalMachine(dce)["phKey"]
        h_key = rrp.hBaseRegOpenKey(dce, h_root, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]
        ubr = rrp.hBaseRegQueryValue(dce, h_key, "UBR")[1]
    except SessionError as e:
        if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
            raise CveDetectError("RemoteRegistry is probably deactivated (UBR value not found)") from e
        raise CveDetectError(f"winreg query failed: {e}") from e
    except DCERPCException as e:
        raise CveDetectError(f"DCERPC error while reading UBR: {e}") from e
    except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
        raise CveDetectError(f"DCERPC transport error while reading UBR: {e.__class__.__name__}: {e}") from e

    if not ubr:
        raise CveDetectError("Could not determine UBR from registry (empty value)")
    return int(ubr)
