"""
PalworldSaveTools — Nuitka builder (AV-hardened).

Usage:
    uv run python build/nuitka/build_nuitka.py --onefile        # single .exe (default)
    uv run python build/nuitka/build_nuitka.py --onedir         # directory build
    uv run python build/nuitka/build_nuitka.py --onefile --sign # build + self-sign
    uv run python build/nuitka/build_nuitka.py --no-sign        # skip signing

═══════════════════════════════════════════════════════════════════════════
AV-HARDENING (why this build config looks the way it does)
═══════════════════════════════════════════════════════════════════════════

Nuitka `--onefile` binaries are commonly flagged 5–15/65 on VirusTotal
because the default build:
  1. uses a generic Python-launcher stub + separate python3XX.dll,
  2. unpacks to a random `{TEMP}/onefile_{PID}_{TIME}` dir at run time
     (a near-exact match for dropper behavior),
  3. ships with empty company/product/publisher metadata ("Unknown
     publisher" is itself a reputation negative),
  4. has no Windows manifest (missing/malformed manifests are malware-
     typical), and
  5. is unsigned.

This script applies the mitigations that meaningfully reduce heuristic
hits:

  • `--lto=yes`                — LTO produces a denser, less generic PE.
  • `--static-libpython=yes`   — folds libpython into the binary; no
                                 loose python3XX.dll (cleaner PE, fewer
                                 "packed/bundled" tells).
  • `--onefile-tempdir-spec`   — a STABLE, version-pinned unpack path
                                 under %LOCALAPPDATA% instead of a random
                                 temp dir. Removes the
                                 "drop-to-temp-and-execute" signature.
  • full identity metadata     — company / product / copyright / file
                                 description on ALL platforms (previously
                                 Windows-only).
  • `--windows-manifest-file`  — embeds a proper asInvoker + DPI-aware +
                                 supportedOS manifest.
  • post-build signing         — self-signed Authenticode (see
                                 build/sign/sign_exe.py). Establishes a
                                 stable identity for reputation building.

DELIBERATELY NOT DONE:
  • UPX / packers  — UPX-packed exes are flagged FAR more often (often
    20+/65). Net negative. Do not add.
  • Splash image   — `--onefile-windows-splash-image` images themselves
    occasionally trigger detections; the app has its own PySide6 splash.

Code signing is the single biggest lever, but a self-signed cert will
NOT clear Windows SmartScreen on its own. For production releases you
want an OV cert (reputation builds over time) or an EV cert (instant
SmartScreen trust). The signing step here is written so swapping to a
real cert is a one-flag change — see build/sign/sign_exe.py.
"""

import os
import sys
import glob
import subprocess
import shutil
import argparse

# Shared config lives one level up; keep module/exclude/data lists there
# so identity metadata and data assets stay in one place.
_BUILD_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_BUILD_DIR, '..', '..'))
sys.path.insert(0, os.path.join(_ROOT_DIR, 'build'))

from build_config import (  # noqa: E402
    VENV_DIR,
    BUILD_CFG_PATH,
    BUILD_CFG_DIR,
    RES_DIR,
    SRC_DIR,
    ICON_PATH,
    MANIFEST_PATH,
    MAIN_SCRIPT,
    COMPANY_NAME,
    PRODUCT_NAME,
    FILE_DESCRIPTION,
    COPYRIGHT,
    INCLUDE_MODULES,
    EXCLUDE_MODULES,
    DATA_ASSETS,
    get_app_version,
    version_to_quad,
    output_filename,
)

os.chdir(_ROOT_DIR)


def resolve_python():
    """Return the Python invocation as a list (prefers the project venv)."""
    python_exe = (
        os.path.join(VENV_DIR, 'Scripts', 'python.exe')
        if sys.platform == 'win32'
        else os.path.join(VENV_DIR, 'bin', 'python')
    )
    if os.path.exists(python_exe):
        return [python_exe]
    return ['uv', 'run', 'python']


def check_nuitka(python_cmd):
    cmd = list(python_cmd) + ['-m', 'nuitka', '--version']
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def clean_build_artifacts():
    items = [
        'Backups', 'Logs',
    ]
    for item in items:
        if os.path.exists(item):
            if os.path.isdir(item):
                shutil.rmtree(item, ignore_errors=True)
            else:
                os.remove(item)
    for pattern in ['*egg-info', 'src/*egg-info', 'src/palsav/*egg-info', 'uv.lock']:
        for match in glob.glob(pattern):
            if os.path.isdir(match):
                shutil.rmtree(match, ignore_errors=True)
            elif os.path.isfile(match):
                os.remove(match)
    for root, dirs, files in os.walk('.', topdown=False):
        for d in dirs:
            if d == '__pycache__':
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
    palsav_build = os.path.join('src', 'palsav', 'build')
    if os.path.isdir(palsav_build):
        print(f'Removing {palsav_build}...')
        shutil.rmtree(palsav_build, ignore_errors=True)


def set_standalone_mode(enabled: bool):
    os.makedirs(BUILD_CFG_DIR, exist_ok=True)
    cfg_lines = [f'[build]\nstandalone = {"true" if enabled else "false"}\n']
    with open(BUILD_CFG_PATH, 'w', encoding='utf-8') as f:
        f.writelines(cfg_lines)
    print(f'Set build mode to: {"standalone" if enabled else "source"}')


def build_with_nuitka(onefile: bool = True):
    python_cmd = resolve_python()

    if not check_nuitka(python_cmd):
        print('Nuitka is not installed.')
        print('Install it with: uv pip install nuitka')
        return 1

    version = get_app_version()
    version_quad = version_to_quad(version)
    print(f'Running Nuitka build (version {version})...')

    cmd = python_cmd + ['-m', 'nuitka']

    if onefile:
        cmd.append('--onefile')
    else:
        cmd.append('--standalone')

    cmd.append('--prefer-source-code')

    # ── AV-hardening: compiler/link options ───────────────────────────
    # LTO + static-libpython produce a denser, less generic PE and remove
    # the loose python3XX.dll that heuristics associate with "bundled
    # interpreter" droppers.
    cmd += [
        '--lto=yes',
        '--static-libpython=yes',
    ]

    # ── AV-hardening: stable, version-pinned onefile unpack path ──────
    # Default spec is "{TEMP}/onefile_{PID}_{TIME}" — i.e. write an exe
    # to a random temp dir and exec it. That is textbook dropper
    # behavior and is the #1 behavioral heuristic trigger for onefile.
    # Pinning to %LOCALAPPDATA%/<Product>/<Version>/<pid>_<time> gives a
    # stable, app-named, version-scoped path that looks like normal app
    # caching. (Still includes PID+TIME so concurrent runs don't clash.)
    if onefile:
        product_slug = PRODUCT_NAME.replace(' ', '')
        cmd.append(
            '--onefile-tempdir-spec='
            f'{{LOCALAPPDATA}}/{product_slug}/{version}/{{PID}}_{{TIME}}'
        )

    cmd += [
        '--enable-plugin=pyside6',
        '--output-dir=dist',
        '--product-name=' + PRODUCT_NAME,
        f'--file-version={version_quad}',
        '--product-version=' + version_quad,
        '--file-description=' + FILE_DESCRIPTION,
        '--company-name=' + COMPANY_NAME,
        '--copyright=' + COPYRIGHT,
    ]

    # ── Data assets (shared list) ─────────────────────────────────────
    for src, dst, is_dir in DATA_ASSETS:
        if is_dir:
            cmd.append(f'--include-data-dir={src}={dst}')
        else:
            cmd.append(f'--include-data-file={src}={dst}')

    # ── Platform-specific identity & manifest ─────────────────────────
    if sys.platform == 'win32':
        cmd.append('--windows-console-mode=disable')
        # Embed the application manifest (asInvoker + DPI + supportedOS).
        # See build/nuitka/app.manifest for rationale.
        if os.path.exists(MANIFEST_PATH):
            cmd.append(f'--windows-manifest-file={MANIFEST_PATH}')
        else:
            print(f'WARNING: manifest not found at {MANIFEST_PATH}; '
                  f'building without an embedded manifest.')

    if os.path.exists(ICON_PATH):
        if sys.platform == 'win32':
            cmd.append(f'--windows-icon-from-ico={ICON_PATH}')
        elif sys.platform == 'darwin':
            cmd.append(f'--macos-app-icon={ICON_PATH}')

    if sys.platform == 'darwin':
        cmd.append('--macos-create-app-bundle')
        cmd.append('--macos-app-name=PalworldSaveTools')

    cmd.append('--assume-yes-for-downloads')

    for mod in INCLUDE_MODULES:
        cmd.append(f'--include-module={mod}')

    for mod in EXCLUDE_MODULES:
        cmd.append(f'--nofollow-import-to={mod}')

    ext = '.exe' if sys.platform == 'win32' else ''
    out_name = output_filename(version, ext)
    cmd.append(f'--output-filename={out_name}')

    cmd.append(MAIN_SCRIPT)

    print(f'Command: {" ".join(cmd)}')
    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join([
        os.path.join(_ROOT_DIR, 'src'),
        os.path.join(_ROOT_DIR, 'resources'),
        env.get('PYTHONPATH', ''),
    ])
    result = subprocess.run(cmd, env=env)
    return result.returncode


def post_build_rcedit(version: str) -> bool:
    """Re-stamp the icon via rcedit (matches the CI step).

    Nuitka usually embeds the icon fine, but re-stamping post-build is
    belt-and-braces and keeps behavior identical to the existing release
    workflow (.github/workflows/build-all-and-release.yml). Windows-only;
    no-op (returns True) elsewhere.
    """
    if sys.platform != 'win32':
        return True

    ext = '.exe'
    exe_path = os.path.join('dist', output_filename(version, ext))
    if not os.path.exists(exe_path):
        print(f'post_build_rcedit: {exe_path} not found, skipping.')
        return False

    # Locate rcedit: prefer a local download, fall back to a PATH copy.
    rcedit = os.path.join('dist', '.cache', 'rcedit-x64.exe')
    if not os.path.exists(rcedit):
        # Look on PATH as a fallback.
        found = shutil.which('rcedit') or shutil.which('rcedit-x64')
        if found:
            rcedit = found
        else:
            print('post_build_rcedit: rcedit not found, skipping icon re-stamp. '
                  '(Nuitka already embedded the icon, so this is non-fatal.)')
            return True

    try:
        subprocess.check_call([
            rcedit, exe_path,
            '--set-icon', ICON_PATH,
        ])
        print(f'rcedit: icon re-stamped on {os.path.basename(exe_path)}.')
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f'post_build_rcedit: rcedit failed ({exc}); icon left as-is.')
        return True  # non-fatal


def post_build_sign(version: str) -> bool:
    """Sign the built .exe with the self-signed helper. Windows-only.

    On non-Windows hosts Authenticode doesn't apply — return True and
    move on (the build is still valid for that platform).
    """
    if sys.platform != 'win32':
        print('sign: non-Windows host, skipping Authenticode signing.')
        return True

    ext = '.exe'
    exe_path = os.path.join('dist', output_filename(version, ext))
    if not os.path.exists(exe_path):
        print(f'sign: {exe_path} not found, cannot sign.')
        return False

    sign_script = os.path.join(_ROOT_DIR, 'build', 'sign', 'sign_exe.py')
    if not os.path.exists(sign_script):
        print(f'sign: {sign_script} not found, skipping signing.')
        return False

    print(f'sign: signing {exe_path}...')
    rc = subprocess.call([sys.executable, sign_script, exe_path])
    if rc == 0:
        print('sign: OK')
        return True
    print(f'sign: helper exited {rc} (build still valid, just unsigned).')
    return False


def main():
    parser = argparse.ArgumentParser(description='PalworldSaveTools Builder (Nuitka, AV-hardened)')
    parser.add_argument('--use-venv', action='store_true', help='Reuse existing venv')
    parser.add_argument('--onefile', action='store_true', help='Build single-file executable (default)')
    parser.add_argument('--onedir', action='store_true', help='Build directory distribution')
    parser.add_argument('--no-sign', action='store_true',
                        help='Skip the post-build Authenticode signing step (Windows)')
    parser.add_argument('--sign', action='store_true', default=True,
                        help='Sign the output (default on; use --no-sign to disable)')
    args = parser.parse_args()

    onefile = args.onefile or not args.onedir
    do_sign = args.sign and not args.no_sign

    clean_build_artifacts()
    set_standalone_mode(True)
    try:
        rc = build_with_nuitka(onefile)
    finally:
        set_standalone_mode(False)

    if rc == 0:
        return _report(onefile=onefile, version=get_app_version(), do_sign=do_sign)

    return rc


def _report(onefile: bool, version: str, do_sign: bool) -> int:
    """Run post-build steps (rcedit, sign) and print the final summary."""
    ext = '.exe' if sys.platform == 'win32' else ''
    exe_name = output_filename(version, ext)

    if onefile:
        # onedir builds leave the binary inside <name>.dist/
        if sys.platform == 'win32':
            post_build_rcedit(version)
            if do_sign:
                post_build_sign(version)

    exe_path = os.path.join('dist', exe_name)
    dist_dir = os.path.join('dist', f'{exe_name}.dist')

    if not onefile:
        default_dist = os.path.join('dist', 'main.dist')
        named_dist = dist_dir
        if os.path.isdir(default_dist) and not os.path.isdir(named_dist):
            os.rename(default_dist, named_dist)
            print(f'Renamed {default_dist} -> {named_dist}')

    if os.path.exists(exe_path):
        size_mb = os.path.getsize(exe_path) / (1024 * 1024)
        print(f'Build complete: {exe_path} ({size_mb:.1f} MB)')
    elif os.path.isdir(dist_dir):
        size_mb = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, fns in os.walk(dist_dir) for f in fns
        ) / (1024 * 1024)
        print(f'Build complete: {dist_dir}/ ({size_mb:.1f} MB)')
    else:
        print('Build complete. Check dist/ for output.')

    return 0


if __name__ == '__main__':
    sys.exit(main())
