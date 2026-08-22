# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Build Specification for Helios.
Compiles Helios into a standalone single-file Windows executable (helios.exe)
incorporating all configuration files, HTML templates, external tool adapters, and dependencies.
"""

import sys
import os
import site
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

project_root = Path(os.path.abspath(".")).resolve()

datas = [
    ('config/*.yaml', 'config'),
    # Recursive glob so vendor/ (e.g. apexcharts.min.js) is bundled too:
    # PyInstaller walks glob-matched subdirectories preserving their layout.
    ('src/helios/reporting/templates/**', 'helios/reporting/templates'),
    ('src/helios/demo_data/**', 'helios/demo_data'),
]

# Include tools folder if present (recursive glob so subdirectories such as
# exiftool_files/, lib/, linux64/ and sigma_rules/ are bundled too)
tools_dir = project_root / 'tools'
if tools_dir.exists():
    datas.append(('tools/**', 'tools'))

binaries = []

# Explicitly list all submodules for click, rich, jinja2, and helios
hiddenimports = [
    'click',
    'click.core',
    'click.decorators',
    'click.exceptions',
    'click.formatting',
    'click.globals',
    'click.parser',
    'click.termui',
    'click.types',
    'click.utils',
    'click._compat',
    'click._winconsole',
    'rich',
    'rich.console',
    'rich.table',
    'rich.panel',
    'rich.progress',
    'rich.text',
    'rich.prompt',
    'rich.box',
    'rich.style',
    'rich.theme',
    'rich.segment',
    'rich.color',
    'rich.live',
    'yaml',
    'jinja2',
    'ctypes',
    'json',
    'platform',
    'socket',
    'subprocess',
    'sqlite3',
    'zipfile',
    'hashlib',
    'winreg',
    'Registry',
    'Registry.Registry',
    'Registry.RegistryParse',
    'Registry.RegistryLog',
    'Evtx',
    'Evtx.Evtx',
    'Evtx.Nodes',
    'helios',
]

# Collect all submodules and package resources for rich, jinja2, click, helios, Registry, Evtx
click_h = collect_submodules('click')
rich_d, rich_b, rich_h = collect_all('rich')
jinja_d, jinja_b, jinja_h = collect_all('jinja2')
helios_h = collect_submodules('helios')

datas += rich_d + jinja_d
binaries += rich_b + jinja_b
hiddenimports += click_h + rich_h + jinja_h + helios_h

try:
    reg_d, reg_b, reg_h = collect_all('Registry')
    datas += reg_d
    binaries += reg_b
    hiddenimports += reg_h
except Exception:
    pass

try:
    evtx_d, evtx_b, evtx_h = collect_all('Evtx')
    datas += evtx_d
    binaries += evtx_b
    hiddenimports += evtx_h
except Exception:
    pass

# Deduplicate lists
hiddenimports = sorted(list(set(hiddenimports)))

pathex = [str(project_root), str(project_root / 'src')]

a = Analysis(
    ['src/helios/cli.py'],
    pathex=pathex,
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'pydoc'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='helios.exe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
