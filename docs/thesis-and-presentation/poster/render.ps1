# Renders the posters to print-ready PDFs and PNG previews with headless Chrome.
# Usage: powershell -ExecutionPolicy Bypass -File C:\xampp\htdocs\cloudie\docs\thesis-and-presentation\poster\render.ps1
#        (add a name, e.g. cloudie-bunting, to render only that one)
$dir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$prof   = Join-Path $env:TEMP 'cloudie-poster-chrome'
# name = preview window size in CSS px (96 px/in) and preview scale
$posters = [ordered]@{
    'cloudie-poster'         = @('2245,3179', '0.5')    # A1
    'cloudie-business-model' = @('2245,3179', '0.5')    # A1
    'cloudie-pitch-poster'   = @('2245,3179', '0.5')    # A1
    'cloudie-pitch-business' = @('2245,3179', '0.5')    # A1
    'cloudie-bunting'        = @('2304,5760', '0.25')   # roll-up bunting 2 x 5 ft
}
$only = $args
foreach ($name in $posters.Keys) {
    if ($only -and $only -notcontains $name) { continue }
    $html = Join-Path $dir "$name.html"
    if (-not (Test-Path $html)) { continue }
    $url = 'file:///' + ($html -replace '\\', '/')
    $common = @('--headless=new', '--disable-gpu', '--hide-scrollbars', "--user-data-dir=$prof", '--virtual-time-budget=8000')
    Start-Process -FilePath $chrome -Wait -NoNewWindow -ArgumentList ($common + @(
        '--no-pdf-header-footer', "--print-to-pdf=$(Join-Path $dir "$name.pdf")", $url)) 2>$null
    $size, $scale = $posters[$name]
    Start-Process -FilePath $chrome -Wait -NoNewWindow -ArgumentList ($common + @(
        "--window-size=$size", "--force-device-scale-factor=$scale", "--screenshot=$(Join-Path $dir "$name-preview.png")", $url)) 2>$null
    Write-Output "rendered $name"
}
