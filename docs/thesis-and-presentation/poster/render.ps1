# Renders the posters to print-ready PDFs (A1) and PNG previews with headless Chrome.
# Usage: powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\cloudie\docs\thesis-and-presentation\poster\render.ps1
$dir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$prof   = Join-Path $env:TEMP 'cloudie-poster-chrome'
foreach ($name in @('cloudie-poster', 'cloudie-business-model')) {
    $html = Join-Path $dir "$name.html"
    if (-not (Test-Path $html)) { continue }
    $url = 'file:///' + ($html -replace '\\', '/')
    $common = @('--headless=new', '--disable-gpu', '--hide-scrollbars', "--user-data-dir=$prof", '--virtual-time-budget=8000')
    Start-Process -FilePath $chrome -Wait -NoNewWindow -ArgumentList ($common + @(
        '--no-pdf-header-footer', "--print-to-pdf=$(Join-Path $dir "$name.pdf")", $url)) 2>$null
    # 2245 x 3179 CSS px = A1 at 96 px/in
    Start-Process -FilePath $chrome -Wait -NoNewWindow -ArgumentList ($common + @(
        '--window-size=2245,3179', '--force-device-scale-factor=0.5', "--screenshot=$(Join-Path $dir "$name-preview.png")", $url)) 2>$null
    Write-Output "rendered $name"
}
