@echo off
REM ==============================================================================
REM ETWScope - Headless Analysis with CSV Export
REM Compares your existing SilkETW JSON logs and exports TRS results to CSV.
REM ==============================================================================

set RESULTS=C:\Users\Administrator\AppData\Local\Temp
set BASELINE=%RESULTS%\etwscope_live_1782496315.json

echo [*] ETWScope Headless Telemetry Analysis
echo [*] Exporting results to: %RESULTS%\etwscope_results.csv
echo.

echo === Analyzing Intensity 1 (from Temp Capture) ===
python .\main.py analyze ^
  --baseline "%BASELINE%" ^
  --mutated "%RESULTS%\etwscope_live_1782496823.json" ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --export "%RESULTS%\etwscope_results.csv"

echo.
echo === Analyzing Intensity 2 (from Temp Capture) ===
python .\main.py analyze ^
  --baseline "%BASELINE%" ^
  --mutated "%RESULTS%\etwscope_live_1782497450.json" ^
  --provider "Microsoft-Windows-Kernel-Process" ^
  --export "%RESULTS%\etwscope_results.csv"

echo.
echo [*] Done! Results exported to: %RESULTS%\etwscope_results.csv

pause
