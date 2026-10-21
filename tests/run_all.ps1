# Runs every Cloudie test (no database, no network, no VirusTotal key needed).
#   powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\cloudie\tests\run_all.ps1
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$fail = 0

Write-Host "=== PHP tests ===" -ForegroundColor Cyan
& "C:\xampp\php\php.exe" "$root\tests\php\run.php"
if ($LASTEXITCODE -ne 0) { $fail++ }

Write-Host "`n=== Flask tests ===" -ForegroundColor Cyan
Push-Location "$root\flask_api"
& ".\.venv\Scripts\python.exe" -m unittest discover -s tests
if ($LASTEXITCODE -ne 0) { $fail++ }
Pop-Location

Write-Host ""
if ($fail -eq 0) { Write-Host "ALL TESTS PASSED" -ForegroundColor Green; exit 0 }
else { Write-Host "$fail test suite(s) FAILED" -ForegroundColor Red; exit 1 }
