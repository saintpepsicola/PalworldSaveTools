r"""
PalworldSaveTools — Authenticode signing helper.

Self-signs a Windows .exe with an in-memory (CurrentUser\My store) code-
signing certificate and RFC 3161 timestamp. Designed to be called by
build/nuitka/build_nuitka.py after a successful build, but also runnable
standalone:

    python build/sign/sign_exe.py dist/PalworldSaveTools-V2.0.5-win.exe
    python build/sign/sign_exe.py <exe> --subject "CN=Pylar Self-Signed"

═══════════════════════════════════════════════════════════════════════════
WHAT THIS BUYS YOU — AND WHAT IT DOESN'T
═══════════════════════════════════════════════════════════════════════════

A self-signed Authenticode signature:
  ✓ Gives the binary a stable identity (same cert thumbprint across
    builds) so AV reputation can accrue to *your* binary rather than
    treating each build as a fresh unknown.
  ✓ Satisfies "is this binary signed at all?" checks (some heuristics
    and some enterprise app-allow-list policies treat unsigned as
    inherently riskier).
  ✗ Does NOT clear Windows SmartScreen / Edge download warnings.
     SmartScreen reputation is tied to the cert *chain* (a Microsoft-
     trusted root) plus download volume. A self-signed cert has no
     trusted root, so SmartScreen keeps warning until enough users
     click "Run anyway".
  ✗ Does NOT establish trust with any third-party AV by itself.

To actually clear SmartScreen, you need one of:
  • OV (Organization Validation) code-signing cert — reputation builds
    organically as users run your signed binary over time.
  • EV (Extended Validation) cert — instant SmartScreen trust; requires
    a hardware token or qualified HSM.
  • Azure Trusted Signing (formerly Azure Code Signing) — cloud-signed
    with a Microsoft-managed cert; builds reputation faster than OV.

  ── Upgrading from self-signed to a real cert ───────────────────────
  This script's --pfx / --subject / --thumbprint flags are the upgrade
  path. With a real OV/EV cert (exported to .pfx):
      python build/sign/sign_exe.py <exe> --pfx mycert.pfx --pfx-pass ...
  signtool then signs against your real cert and the same timestamp
  server, with no other code changes. For EV certs on a USB token,
  signtool will prompt for the token PIN automatically — just drop the
  --pfx args and pass --subject to pick the token's cert by subject.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

# RFC 3161 timestamp servers (tried in order). Timestamping proves the
# signature was made while the cert was valid, so it stays trustworthy
# after cert expiry. DigiCert/Sectigo are widely-reliable free public
# RFC3161 endpoints.
_TIMESTAMP_URLS = [
    'http://timestamp.digicert.com',
    'http://timestamp.sectigo.com',
    'http://ts.ssl.com',
]

# Default self-signed cert subject. Keep it clearly labeled "Self-Signed"
# so anyone inspecting the binary's signature chain sees the intent.
DEFAULT_SUBJECT = 'CN=Pylar Self-Signed PalworldSaveTools'


def is_windows() -> bool:
    return sys.platform == 'win32'


def find_signtool() -> str | None:
    """Locate signtool.exe.

    Prefers a copy on PATH; otherwise scans the Windows SDK install dirs
    (signtool ships with the Windows SDK, not with Windows itself).
    """
    on_path = shutil.which('signtool') or shutil.which('signtool.exe')
    if on_path:
        return on_path

    if not is_windows():
        return None

    program_files = os.environ.get('ProgramFiles(x86)') or r'C:\Program Files (x86)'
    sdk_root = os.path.join(program_files, 'Windows Kits', '10', 'bin')
    if not os.path.isdir(sdk_root):
        return None

    # SDK installs are versioned dirs (10.0.19041.0, 10.0.22621.0, ...).
    # Pick the newest one that has an x64 signtool.exe.
    candidates = sorted(
        (d for d in os.listdir(sdk_root) if d.startswith('10.')),
        reverse=True,
    )
    for d in candidates:
        exe = os.path.join(sdk_root, d, 'x64', 'signtool.exe')
        if os.path.exists(exe):
            return exe
    return None


def ensure_self_signed_cert(subject: str) -> str | None:
    r"""Create (or reuse) a self-signed code-signing cert in CurrentUser\My.

    Returns the certificate's thumbprint, or None on failure.

    Uses PowerShell New-SelfSignedCertificate with:
      -Type CodeSigningCert        — marks it for code signing
      -CertStoreLocation ...CurrentUser\My — current-user store (no admin)
      -TextExtension "2.5.29.37..." — EKU = Code Signing OID
      -KeyAlgorithm RSA -KeyLength 4096 — strong key (SHA-256 era)
    """
    # Reuse if an existing cert with the same subject is present.
    existing = _find_cert_thumbprint(subject)
    if existing:
        print(f'sign: reusing existing self-signed cert ({subject}).')
        return existing

    ps = (
        f'$cert = New-SelfSignedCertificate '
        f'-Type CodeSigningCert '
        f'-Subject "{subject}" '
        f'-KeyAlgorithm RSA -KeyLength 4096 -HashAlgorithm SHA256 '
        f'-CertStoreLocation Cert:\\CurrentUser\\My '
        f'-TextExtension @("2.5.29.37={{text}}1.3.6.1.5.5.7.3.3","2.5.29.19={{text}}") ; '
        f'Write-Output $cert.Thumbprint'
    )
    print(f'sign: creating self-signed cert ({subject})...')
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps],
            capture_output=True, text=True, check=True,
        )
        thumbprint = result.stdout.strip()
        if thumbprint and all(c in '0123456789ABCDEFabcdef' for c in thumbprint):
            print(f'sign: created cert, thumbprint {thumbprint}.')
            # Self-signed certs land in CurrentUser\My but are NOT trusted
            # for code signing by default. Copy to Root so the local
            # machine treats it as trusted (local-dev convenience only —
            # this has NO effect on other users' machines).
            _trust_locally(thumbprint)
            return thumbprint
        print(f'sign: unexpected PowerShell output: {result.stdout!r}')
        return None
    except subprocess.CalledProcessError as exc:
        print(f'sign: cert creation failed: {exc.stderr}')
        return None


def _find_cert_thumbprint(subject: str) -> str | None:
    r"""Look up an existing cert by subject in CurrentUser\My."""
    ps = (
        f'$c = Get-ChildItem Cert:\\CurrentUser\\My '
        f'-CodeSigningCert -ErrorAction SilentlyContinue '
        f'| Where-Object {{ $_.Subject -eq "{subject}" }} '
        f'| Select-Object -First 1 ; '
        f'if ($c) {{ Write-Output $c.Thumbprint }}'
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps],
            capture_output=True, text=True, check=True,
        )
        thumbprint = result.stdout.strip()
        if thumbprint and all(c in '0123456789ABCDEFabcdef' for c in thumbprint):
            return thumbprint
    except subprocess.CalledProcessError:
        pass
    return None


def _trust_locally(thumbprint: str) -> None:
    r"""Copy the cert into CurrentUser\Root for local trust.

    Best-effort: failures here are non-fatal (signing still works; only
    the local machine's trust UI is affected).
    """
    ps = (
        f'$src = Get-ChildItem Cert:\\CurrentUser\\My | '
        f'Where-Object {{ $_.Thumbprint -eq "{thumbprint}" }} ; '
        f'if ($src) {{ '
        f'  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store '
        f'    -ArgumentList "Root","CurrentUser" ; '
        f'  $store.Open("ReadWrite") ; '
        f'  $store.Add($src) ; '
        f'  $store.Close() '
        f'}}'
    )
    try:
        subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError:
        pass  # non-fatal


def sign_with_pfx(signtool: str, exe: str, pfx: str,
                  pfx_pass: str | None) -> bool:
    """Sign using a .pfx file (real OV/EV cert path)."""
    cmd = [signtool, 'sign', '/fd', 'SHA256', '/f', pfx]
    if pfx_pass:
        cmd += ['/p', pfx_pass]
    # RFC 3161 timestamp.
    cmd += ['/tr', _TIMESTAMP_URLS[0], '/td', 'SHA256']
    cmd.append(exe)
    return _run_signtool(cmd, exe)


def sign_with_store(signtool: str, exe: str, subject_or_thumb: str) -> bool:
    """Sign using a cert in the CurrentUser store (self-signed path).

    Accepts either a subject (CN=...) via /sha1 lookup or a raw thumbprint.
    """
    thumbprint = subject_or_thumb
    if thumbprint.startswith('CN='):
        found = _find_cert_thumbprint(thumbprint)
        if not found:
            print(f'sign: no cert matching {thumbprint!r} in store.')
            return False
        thumbprint = found

    cmd = [
        signtool, 'sign',
        '/fd', 'SHA256',
        '/sha1', thumbprint,
        '/tr', _TIMESTAMP_URLS[0],
        '/td', 'SHA256',
        exe,
    ]
    return _run_signtool(cmd, exe)


def _run_signtool(cmd: list[str], exe: str) -> bool:
    """Invoke signtool, retrying once on timestamp failure with a backup TS."""
    print(f'sign: {" ".join(cmd[:3])} ... {os.path.basename(exe)}')

    # Try each timestamp server until one works (network blips happen).
    ts_idx = 0
    base_cmd = [c for c in cmd if c not in _TIMESTAMP_URLS]
    # Reconstruct with the current timestamp server at the /tr slot.
    while ts_idx < len(_TIMESTAMP_URLS):
        ts_cmd = base_cmd.copy()
        # Insert the timestamp URL right after /tr.
        if '/tr' in ts_cmd:
            i = ts_cmd.index('/tr') + 1
            ts_cmd.insert(i, _TIMESTAMP_URLS[ts_idx])
        else:
            # PFX-less path: append timestamp block.
            ts_cmd += ['/tr', _TIMESTAMP_URLS[ts_idx], '/td', 'SHA256']
            # dedupe duplicate /td if base already had it
        try:
            result = subprocess.run(ts_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f'sign: signed {os.path.basename(exe)} '
                      f'(timestamp: {_TIMESTAMP_URLS[ts_idx]}).')
                return True
            # If timestamp failed specifically, try the next server.
            if 'timestamp' in (result.stdout + result.stderr).lower():
                print(f'sign: timestamp server {_TIMESTAMP_URLS[ts_idx]} '
                      f'failed, trying next...')
                ts_idx += 1
                continue
            print(f'sign: signtool failed:\n{result.stdout}{result.stderr}')
            return False
        except FileNotFoundError:
            print('sign: signtool binary not found.')
            return False
    print('sign: all timestamp servers failed; signed WITHOUT timestamp.')
    # Last resort: sign without timestamp (signature won't outlive cert).
    no_ts = [c for c in base_cmd]
    try:
        result = subprocess.run(no_ts, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'sign: signed {os.path.basename(exe)} (NO timestamp).')
            return True
        print(f'sign: signtool failed:\n{result.stdout}{result.stderr}')
    except FileNotFoundError:
        pass
    return False


def verify_signature(signtool: str, exe: str) -> None:
    """Run signtool verify and print the result (best-effort, informational)."""
    try:
        result = subprocess.run(
            [signtool, 'verify', '/pa', '/all', exe],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f'sign: verify OK — {os.path.basename(exe)} is signed.')
        else:
            # /pa uses the Default Authenticode verification policy.
            # Self-signed certs will fail here unless trusted locally;
            # this is expected and not a build failure.
            print(f'sign: verify reports (expected for self-signed unless '
                  f'trusted locally):\n{result.stdout}{result.stderr}')
    except FileNotFoundError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description='Sign a Windows .exe (self-signed or PFX).')
    parser.add_argument('exe', help='Path to the .exe to sign')
    parser.add_argument('--subject', default=DEFAULT_SUBJECT,
                        help='Self-signed cert subject (CN=...). Default: Pylar self-signed.')
    parser.add_argument('--pfx', help='Sign with a .pfx file instead of a self-signed cert.')
    parser.add_argument('--pfx-pass', help='Password for the .pfx file.')
    parser.add_argument('--thumbprint',
                        help='Sign with a specific cert thumbprint from the store.')
    parser.add_argument('--no-verify', action='store_true',
                        help='Skip the post-sign signtool verify step.')
    args = parser.parse_args()

    if not os.path.isfile(args.exe):
        print(f'sign: file not found: {args.exe}')
        return 2

    if not is_windows():
        print('sign: not on Windows — Authenticode signing is N/A. Skipping.')
        return 0

    signtool = find_signtool()
    if not signtool:
        print('sign: signtool.exe not found. Install the Windows SDK '
              '(https://developer.microsoft.com/windows/downloads/windows-sdk/) '
              'and retry. Skipping signing.')
        return 0  # non-fatal for the overall build

    ok = False
    if args.pfx:
        ok = sign_with_pfx(signtool, args.exe, args.pfx, args.pfx_pass)
    elif args.thumbprint:
        ok = sign_with_store(signtool, args.exe, args.thumbprint)
    else:
        thumbprint = ensure_self_signed_cert(args.subject)
        if thumbprint:
            ok = sign_with_store(signtool, args.exe, thumbprint)

    if ok and not args.no_verify:
        verify_signature(signtool, args.exe)

    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
