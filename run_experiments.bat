@echo off
REM ==============================================================================
REM ETWScope - Live Capture with All 4 Invocation Paths
REM Run this as Administrator!
REM ==============================================================================

set SILKETW=C:\Users\zerolapsintelli\Downloads\SilkETW_SilkService_v8\v8\SilkETW\SilkETW.exe
set BINDIR=C:\Users\zerolapsintelli\Desktop\final\binaries\src

echo [*] Starting ETWScope Active Measurement Framework...
echo [*] Make sure you are running this as Administrator!
echo.

python .\main.py capture ^
  --silketw "%SILKETW%" ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --payload-i1 "%BINDIR%\pocinjector.exe" ^
  --payload-i2 "%BINDIR%\tb_inject_directsyscall.exe" ^
  --payload-i3 "%BINDIR%\tb_inject_indirectsyscall.exe" ^
  --payload-i4 "%BINDIR%\tb_inject_hwbp.exe"

pause
