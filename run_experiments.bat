@echo off
REM ==============================================================================
REM ETWScope - Live Presentation Script
REM This script runs the ETWScope Live Capture mode with all 4 injection payloads.
REM Ensure SilkETW and all compiled payloads exist at the specified paths.
REM ==============================================================================

set SILKETW_PATH="C:\Users\zerolapsintelli\Downloads\SilkETW_SilkService_v8\v8\SilkETW\SilkETW.exe"
set PAYLOAD_DIR="C:\Users\zerolapsintelli\Desktop\final\mutated"

echo [*] Starting ETWScope Active Measurement Framework...

python .\main.py capture ^
  --silketw %SILKETW_PATH% ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --payload-i1 %PAYLOAD_DIR%\poc_injector.exe ^
  --payload-i2 %PAYLOAD_DIR%\tb_inject_directsyscall_I2.exe ^
  --payload-i3 %PAYLOAD_DIR%\tb_inject_indirectsyscall_I3.exe ^
  --payload-i4 %PAYLOAD_DIR%\tb_inject_hwbp_I4.exe

pause
