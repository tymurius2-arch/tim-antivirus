# Скачивает официальную сборку ClamAV для Windows (Cisco Talos) в vendor\clamav
param([string]$Version = "1.5.5")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$dest = Join-Path $root "vendor\clamav"
if (Test-Path (Join-Path $dest "clamscan.exe")) { Write-Host "ClamAV уже есть: $dest"; return }
$tmp = Join-Path $env:TEMP "clamav_dl_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force $tmp | Out-Null
$zip = Join-Path $tmp "clamav.zip"
$url = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$Version/clamav-$Version.win.x64.zip"
Write-Host "Загрузка $url"
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest $url -OutFile $zip
Expand-Archive $zip -DestinationPath $tmp -Force
$src = Get-ChildItem $tmp -Directory | Where-Object Name -like "clamav-*" | Select-Object -First 1
New-Item -ItemType Directory -Force $dest | Out-Null
Get-ChildItem $src.FullName -File | Where-Object { $_.Extension -in ".exe", ".dll" -or $_.Name -like "COPYING*" } |
    Where-Object { $_.Name -notin "clambc.exe", "clamdtop.exe", "clamsubmit.exe" } | Copy-Item -Destination $dest
Copy-Item (Join-Path $src.FullName "certs") (Join-Path $dest "certs") -Recurse -Force
Remove-Item $tmp -Recurse -Force
Write-Host "Готово: $dest"
