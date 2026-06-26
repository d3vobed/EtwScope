@echo off
REM ==============================================================================
REM ETWScope - Build Standalone Executable
REM This script uses PyInstaller to bundle ETWScope into a single .exe
REM ==============================================================================

echo [*] Installing PyInstaller...
pip install pyinstaller

echo [*] Building ETWScope executable using etwscope.spec...
pyinstaller etwscope.spec --clean

echo [*] Build complete! The executable is located in the dist\ directory.
pause
