#!/usr/bin/env python3
# Build script for creating multiple DLL fuzzer executables

import os
import sys
import shutil
import subprocess
from pathlib import Path

def create_fuzzer_variant(dll_path, output_name, workers=10, duration=3600):
    """
    Create a customized fuzzer for a specific DLL
    
    Args:
        dll_path: Path to the target DLL
        output_name: Name for the executable (without .exe)
        workers: Number of worker processes
        duration: Fuzzing duration in seconds
    """
    
    print(f"Creating fuzzer variant: {output_name}")
    print(f"  Target DLL: {dll_path}")
    print(f"  Workers: {workers}")
    print(f"  Duration: {duration}s")
    
    # Read the original dllfuz.py
    with open('dllfuz.py', 'r') as f:
        content = f.read()
    
    # Replace the configuration values
    replacements = {
        'TARGET_DLL_PATH = r"C:\\Windows\\System32\\kernel32.dll"': f'TARGET_DLL_PATH = r"{dll_path}"',
        'WORKERS = 10': f'WORKERS = {workers}',
        'TOTAL_DURATION_SEC = 3600': f'TOTAL_DURATION_SEC = {duration}',
    }
    
    for old, new in replacements.items():
        content = content.replace(old, new)
    
    # Write the customized file
    variant_filename = f'{output_name}_fuzzer.py'
    with open(variant_filename, 'w') as f:
        f.write(content)
    
    # Create a custom spec file
    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['{variant_filename}'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['dolboyob'],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
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
    name='{output_name}_fuzzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)"""
    
    spec_filename = f'{output_name}_fuzzer.spec'
    with open(spec_filename, 'w') as f:
        f.write(spec_content)
    
    print(f"  Created: {variant_filename}")
    print(f"  Created: {spec_filename}")
    
    return variant_filename, spec_filename

def build_executable(spec_file):
    """Build executable using PyInstaller"""
    print(f"Building executable from {spec_file}...")
    
    try:
        # Run PyInstaller
        result = subprocess.run(['pyinstaller', spec_file], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("  Build successful!")
            return True
        else:
            print(f"  Build failed: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("  PyInstaller not found. Install with: pip install pyinstaller")
        return False
    except Exception as e:
        print(f"  Build error: {e}")
        return False

def create_build_batch():
    """Create a Windows batch file for building"""
    batch_content = """@echo off
echo Building DLL Fuzzer Executables
echo ================================

echo Installing PyInstaller if needed...
pip install pyinstaller

echo Building kernel32 fuzzer...
pyinstaller kernel32_fuzzer.spec

echo Building user32 fuzzer...
pyinstaller user32_fuzzer.spec

echo Building ntdll fuzzer...
pyinstaller ntdll_fuzzer.spec

echo Building advapi32 fuzzer...
pyinstaller advapi32_fuzzer.spec

echo Build complete! Check the dist/ folder for executables.
pause"""
    
    with open('build_fuzzers.bat', 'w') as f:
        f.write(batch_content)
    print("Created build_fuzzers.bat for Windows")

def main():
    """Main build script"""
    print("DLL Fuzzer Build Script")
    print("=" * 30)
    
    # Define fuzzer variants to create
    variants = [
        {
            'dll_path': r'C:\Windows\System32\kernel32.dll',
            'name': 'kernel32',
            'workers': 15,
            'duration': 7200,  # 2 hours
        },
        {
            'dll_path': r'C:\Windows\System32\user32.dll',
            'name': 'user32',
            'workers': 10,
            'duration': 3600,  # 1 hour
        },
        {
            'dll_path': r'C:\Windows\System32\ntdll.dll',
            'name': 'ntdll',
            'workers': 20,
            'duration': 10800,  # 3 hours
        },
        {
            'dll_path': r'C:\Windows\System32\advapi32.dll',
            'name': 'advapi32',
            'workers': 12,
            'duration': 5400,  # 1.5 hours
        },
    ]
    
    created_files = []
    
    # Create fuzzer variants
    for variant in variants:
        try:
            py_file, spec_file = create_fuzzer_variant(
                variant['dll_path'],
                variant['name'],
                variant['workers'],
                variant['duration']
            )
            created_files.extend([py_file, spec_file])
            print()
        except Exception as e:
            print(f"Error creating {variant['name']} fuzzer: {e}")
            print()
    
    # Create build batch file
    create_build_batch()
    created_files.append('build_fuzzers.bat')
    
    print("Summary:")
    print("--------")
    print("Created the following files:")
    for file in created_files:
        print(f"  {file}")
    
    print("\nTo build executables:")
    print("1. On Windows: Run build_fuzzers.bat")
    print("2. Manual: pyinstaller <fuzzer_name>.spec")
    print("3. Check dist/ folder for executables")
    
    print("\nNote: Building requires Windows and PyInstaller")

if __name__ == "__main__":
    main()