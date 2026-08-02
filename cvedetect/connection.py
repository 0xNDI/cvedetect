"""SMB connection and UBR retrieval.

* Auth mirrors impacket's ``smbclient.py`` exactly: same target syntax
  ``[[domain/]username[:password]@]<target>``, same ``-hashes / -no-pass / -k /
  -aesKey / -dc-ip / -target-ip / -port`` options.
* UBR (Update Build Revision) is read from
  ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion!UBR`` over the
  ``\\winreg`` pipe. Opening that pipe trigger-starts RemoteRegistry, so the bind
  itself is the nudge; a retry loop waits out cold starts instead of a fixed
  sleep (faster on warm hosts, more robust on slow ones).
"""

from __future__ import annotations

import contextlib
import socket
import time
from dataclasses import dataclass

from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SessionError, SMBConnection

# RemoteRegistry is trigger-started: opening the \winreg pipe asks the SCM to
# launch it, returning STATUS_PIPE_NOT_AVAILABLE until an instance is ready.
# We retry the bind within a generous budget so cold/slow starts are handled
# (the bind's pipe-open is itself the trigger), instead of a fixed sleep.
_WINREG_BIND_BUDGET = 4.0  # seconds to wait for RemoteRegistry to come up
_WINREG_BIND_BACKOFF = 0.2  # seconds between bind attempts
_RETRYABLE_MARKERS = (
    "STATUS_PIPE_NOT_AVAILABLE",  # service trigger-started, not ready yet
    "STATUS_PIPE_BUSY",
    "STATUS_PIPE_NOT_FOUND",
)


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


def get_os_version(conn: SMBConnection, detect_dc_flag: bool = True) -> OsVersion:
    return OsVersion(
        os_string=conn.getServerOS() or "",
        major=conn.getServerOSMajor(),
        minor=conn.getServerOSMinor(),
        build=conn.getServerOSBuild(),
        signing_required=_safe_signing_required(conn),
        is_dc=detect_dc(conn) if detect_dc_flag else False,
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


def _is_service_starting(err: Exception) -> bool:
    """True if the error means RemoteRegistry is still coming up (worth retrying)."""
    msg = str(err)
    return any(m in msg for m in _RETRYABLE_MARKERS)


def read_ubr(conn: SMBConnection, auth: AuthArgs) -> int:
    """Connect to \\winreg, bind RRP, and return the UBR REG_DWORD value.

    The bind opens the \\winreg pipe, which trigger-starts RemoteRegistry and
    returns STATUS_PIPE_NOT_AVAILABLE until an instance is ready. We retry within
    a budget so warm hosts resolve on the first attempt and cold starts are waited
    out — both faster and more robust than a fixed sleep (the previous code gave
    up after a single 1s sleep and fell through to a TCP path that also needs the
    service running). If SMB pipe access stays blocked, fall back to ncacn_ip_tcp
    on the RPC endpoint mapper (135). Raises CveDetectError if UBR cannot be read.
    """
    deadline = time.monotonic() + _WINREG_BIND_BUDGET
    while True:
        try:
            dce = _open_winreg_smb(conn)
            break
        except CveDetectError as e:
            # Only retry the transient "service starting" states; fail fast on
            # access-denied / disabled-service / real transport errors.
            if not _is_service_starting(e) or time.monotonic() >= deadline:
                dce = _open_winreg_tcp(auth)  # may raise CveDetectError
                break
            time.sleep(_WINREG_BIND_BACKOFF)

    # Skip an explicit dce.disconnect() round-trip: conn.logoff() tears down the
    # underlying SMB transport (and thus the named pipe / RPC context).
    return _query_ubr(dce)


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
