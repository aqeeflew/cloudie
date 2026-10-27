# Prints section heights of a poster at A1 size (2245 x 3179 CSS px).
# Usage: powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\cloudie\docs\thesis-and-presentation\poster\measure.ps1 cloudie-poster
param([string]$name = 'cloudie-poster')
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$url = 'file:///' + ((Join-Path $dir "$name.html").Replace('\', '/')) + '?measure'
$dom = Join-Path $env:TEMP 'cloudie-poster-dom.html'
Start-Process -FilePath 'C:\Program Files\Google\Chrome\Application\chrome.exe' -Wait -NoNewWindow `
    -RedirectStandardOutput $dom -RedirectStandardError (Join-Path $env:TEMP 'cloudie-poster-err.txt') `
    -ArgumentList @('--headless=new', '--disable-gpu', "--user-data-dir=$env:TEMP\cloudie-poster-chrome",
                    '--window-size=2245,3179', '--virtual-time-budget=10000', '--dump-dom', $url)
(Select-String -Path $dom -Pattern 'MEASURE').Line
