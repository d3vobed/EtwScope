@echo off
REM ==============================================================================
REM ETWScope - Headless Analysis with CSV Export
REM Compares your existing SilkETW JSON logs and exports TRS results to CSV.
REM ==============================================================================

set RESULTS=C:\Users\zerolapsintelli\Desktop\final
set BASELINE=%RESULTS%\clean_00_kp.json

echo [*] ETWScope Headless Telemetry Analysis
echo [*] Exporting results to: %RESULTS%\etwscope_results.csv
echo.

echo === Analyzing Intensity 1 (Win32 API) ===
python .\main.py analyze ^
  --baseline "%BASELINE%" ^
  --mutated "%RESULTS%\mut_I1_kp.json" ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --export "%RESULTS%\etwscope_results.csv"

echo.
echo === Analyzing Intensity 2 (Direct Syscall) ===
python .\main.py analyze ^
  --baseline "%BASELINE%" ^
  --mutated "%RESULTS%\mut_I2_kp.json" ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --export "%RESULTS%\etwscope_results.csv"

echo.
echo === Analyzing Intensity 3 (Indirect Syscall) ===
python .\main.py analyze ^
  --baseline "%BASELINE%" ^
  --mutated "%RESULTS%\mut_I3_kp.json" ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --export "%RESULTS%\etwscope_results.csv"

echo.
echo [*] Done! Results exported to: %RESULTS%\etwscope_results.csv
echo [*] You can also run the batch DDF fitting:
echo     python .\main.py batch --baseline "%BASELINE%" --mutated-dir "%RESULTS%\mutated_kp" --export "%RESULTS%\ddf_results.csv"

pause
