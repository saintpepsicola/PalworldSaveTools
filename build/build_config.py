"""
Shared build configuration for PalworldSaveTools.

build/nuitka/build_nuitka.py imports from here so the module include/
exclude lists, data assets, and identity metadata live in one place.

Centralizing these avoids drift between the build script and any future
build helpers (e.g. an installer step, a CI check) that need the same
lists — diverging them is how runtime ImportError / missing-resource
bugs sneak in. Don't duplicate these lists.
"""

from __future__ import annotations

import os

# --- Paths --------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(_SCRIPT_DIR, '..'))

VENV_DIR = '.venv'
RES_DIR = os.path.join(ROOT_DIR, 'resources')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
ICON_PATH = os.path.join(RES_DIR, 'assets', 'icons', 'app', 'icon.ico')
ICON_PNG_PATH = os.path.join(RES_DIR, 'assets', 'icons', 'app', 'icon.png')
MANIFEST_PATH = os.path.join(ROOT_DIR, 'build', 'nuitka', 'app.manifest')
MAIN_SCRIPT = os.path.join(SRC_DIR, 'palworld_aio', 'main.py')

BUILD_CFG_PATH = os.path.join('src', 'data', 'configs', 'runtime.cfg')
BUILD_CFG_DIR = os.path.join('src', 'data', 'configs')

# --- App identity -------------------------------------------------------

# Applied to BOTH Nuitka and PyInstaller on ALL platforms. Consistent,
# non-empty identity metadata is itself a small antivirus reputation
# signal — "Unknown publisher" + blank fields is malware-typical.
COMPANY_NAME = 'Pylar'
PRODUCT_NAME = 'Palworld Save Tools'
FILE_DESCRIPTION = 'Palworld Save Tools'
COPYRIGHT = 'Copyright (c) 2026 Pylar'


def get_app_version() -> str:
    """Read APP_VERSION from src/common.py.

    Returns 'unknown' if the file or constant is missing — matches the
    behavior of the original build scripts.
    """
    common_file = os.path.join('src', 'common.py')
    if not os.path.exists(common_file):
        return 'unknown'
    with open(common_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip().startswith('APP_VERSION'):
                return line.split('=')[1].strip().strip('"').strip("'")
    return 'unknown'


def get_app_name() -> str:
    """Read APP_NAME from src/common.py (fallback: 'PalworldSaveTools')."""
    common_file = os.path.join('src', 'common.py')
    if not os.path.exists(common_file):
        return 'PalworldSaveTools'
    with open(common_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip().startswith('APP_NAME'):
                return line.split('=')[1].strip().strip('"').strip("'")
    return 'PalworldSaveTools'


def get_game_version() -> str:
    """Read GAME_VERSION from src/common.py (fallback: '1.0.0')."""
    common_file = os.path.join('src', 'common.py')
    if not os.path.exists(common_file):
        return '1.0.0'
    with open(common_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip().startswith('GAME_VERSION'):
                return line.split('=')[1].strip().strip('"').strip("'")
    return '1.0.0'


def version_to_quad(version: str) -> str:
    """Expand a dotted version to a 4-part quad for PE version resources.

    PE file/product versions must be `X.Y.Z.W`. We pad/truncate to 4 parts,
    defaulting missing components to 0. E.g. '2.0.5' -> '2.0.5.0'.
    """
    parts = (version.split('.') + ['0', '0', '0', '0'])[:4]
    # Strip any non-numeric suffix (e.g. '2.0.5rc1' -> '2.0.5')
    cleaned = []
    for p in parts:
        # keep leading digits only (e.g. '2.0.5rc1' -> '2','0','5')
        num = ''
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        cleaned.append(num or '0')
    return '.'.join(cleaned)


# --- Module lists -------------------------------------------------------

# PySide6 sub-modules we know we don't use. Excluding them shrinks the
# bundle (less surface for heuristics to score) and speeds the build.
PYSIDE6_EXCLUDES = [
    'PySide6.QtQuick', 'PySide6.QtQml', 'PySide6.QtDesigner',
    'PySide6.QtHelp', 'PySide6.QtTest', 'PySide6.QtDBus',
    'PySide6.QtPrintSupport', 'PySide6.QtSql', 'PySide6.QtUiTools',
    'PySide6.QtSvgWidgets', 'PySide6.QtXml', 'PySide6.QtBluetooth',
    'PySide6.QtNetwork', 'PySide6.QtOpenGL', 'PySide6.QtPositioning',
    'PySide6.QtSensors', 'PySide6.QtSerialPort', 'PySide6.QtWebSockets',
    'PySide6.QtMultimedia', 'PySide6.QtMultimediaWidgets',
    'PySide6.QtQuickWidgets', 'PySide6.QtQuickControls2',
    'PySide6.QtQuickTemplates2', 'PySide6.QtQuickDialogs2',
    'PySide6.QtQuickDialogs2QuickImpl', 'PySide6.QtQuickDialogs2Utils',
    'PySide6.QtQuickLayouts', 'PySide6.QtQuickParticles',
    'PySide6.QtQuickEffects', 'PySide6.QtQuickShapes',
    'PySide6.QtQuickTest', 'PySide6.QtQuickTimeline',
    'PySide6.QtQuickVectorImage', 'PySide6.QtQuickVectorImageGenerator',
    'PySide6.QtQuickVectorImageHelpers', 'PySide6.QtLabsAnimation',
    'PySide6.QtLabsFolderListModel', 'PySide6.QtLabsPlatform',
    'PySide6.QtLabsQmlModels', 'PySide6.QtLabsSettings',
    'PySide6.QtLabsSharedImage', 'PySide6.QtLabsStyleKit',
    'PySide6.QtLabsStyleKitImpl', 'PySide6.QtLabsSynchronizer',
    'PySide6.QtLabsWavefrontMesh', 'PySide6.QtLottie',
    'PySide6.QtLottieVectorImageGenerator', 'PySide6.QtQmlCore',
    'PySide6.QtQmlLocalStorage', 'PySide6.QtQmlMeta',
    'PySide6.QtQmlModels', 'PySide6.QtQmlNetwork',
    'PySide6.QtQmlWorkerScript', 'PySide6.QtQmlXmlListModel',
    'PySide6.QtQmlCompiler',
]

# Modules to explicitly include. Nuitka's static analysis misses some of
# these (dynamically imported, data-only packages, C extensions behind a
# lazy loader). PyInstaller's hiddenimports play the same role.
INCLUDE_MODULES = [
    'palsav', 'palsav.core', 'palsav.archive', 'palsav.paltypes',
    'palsav.gvas', 'palsav.json_tools', 'palsav._cityhash',
    'palsav.compressor', 'palsav.compressor.enums',
    'palsav.compressor.oozlib', 'palsav.compressor.zlib',
    'palsav.commands', 'palsav.commands.convert',
    'palsav.commands.backup', 'palsav.commands.diag',
    'palsav.commands.resave_test', 'palsav.commands.auto_update',
    'palsav.commands.roundtrip_validation',
    'palsav.rawdata',
    'palooz', 'palworld_coord',
    'palworld_toolsets', 'palworld_toolsets.game_pass_save_fix',
    'palworld_toolsets.convertids', 'palworld_toolsets.restore_map',
    'palworld_toolsets.slot_injector', 'palworld_toolsets.character_transfer',
    'palworld_toolsets.modify_save', 'palworld_toolsets.fix_host_save',
    'palworld_toolsets.convert_generic', 'palworld_toolsets.xgp_save_extract',
    'palworld_xgp_import', 'nerdfont', 'orjson', 'brotli',
    'cbor2', 'zstandard', 'py7zr', 'packaging',
]

# Modules to exclude. Stripping unused heavy/stdlib modules both shrinks
# the binary and removes surface that some heuristics key on (e.g. a
# bundled `unittest`/`tkinter`/`venv` is common in droppers).
EXCLUDE_MODULES = [
    'tkinter', 'unittest', 'pdb', 'lib2to3', 'distutils',
    'setuptools', 'pip', 'wheel', 'venv', 'ensurepip',
    'numpy', 'pandas', 'matplotlib', 'scipy', 'IPython',
] + PYSIDE6_EXCLUDES


# --- Data assets --------------------------------------------------------

# (source, dest) pairs for data files/dirs bundled into the output.
# Shared by Nuitka (--include-data-dir/file) and PyInstaller (--add-data /
# datas= in spec).
DATA_ASSETS = [
    # src, dest, is_dir
    ('resources', 'resources', True),
    (os.path.join('src', 'data'), os.path.join('src', 'data'), True),
    (os.path.join('src', 'games.json'), 'games.json', False),
    ('README.md', 'README.md', False),
    ('license', 'license', False),
]


def output_filename(version: str, ext: str = '') -> str:
    """Return the versioned, platform-tagged output filename.

    Mirrors the original naming so release tooling and verify_build.py
    keep working unchanged.
    """
    import sys
    platform_tag = {'win32': 'win', 'darwin': 'macos'}.get(sys.platform, 'linux')
    return f'PalworldSaveTools-V{version}-{platform_tag}{ext}'
