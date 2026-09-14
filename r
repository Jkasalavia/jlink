$ErrorActionPreference = 'Stop'
$baseUrl = 'https://jkasalavia.github.io/jlink'
$base = Join-Path $env:TEMP 'jkelts-link'
$script = Join-Path $base 'jkelts-link.ps1'
Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $base -Force | Out-Null
Invoke-WebRequest -Uri "$baseUrl/jkelts-link.ps1" -OutFile $script -UseBasicParsing
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script
