# Полная сборка: тесты -> PyInstaller -> (подпись) -> установщик Inno Setup -> (подпись)
#
# Подпись кода (необязательно). Задайте одну из переменных окружения:
#   TIMAV_SIGN_PFX       путь к .pfx (+ TIMAV_SIGN_PASSWORD)
#   TIMAV_SIGN_THUMBPRINT отпечаток сертификата в хранилище «Личные» (в т.ч. токен EV / Azure Trusted Signing через CSP)
#   TIMAV_SIGN_TIMESTAMP  сервер метки времени (по умолчанию http://timestamp.digicert.com)
#   TIMAV_SIGN_DRYRUN=1   только показать команды подписи
param([switch]$SkipTests)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = ".\.venv\Scripts\python.exe"

$signArgs = $null
if ($env:TIMAV_SIGN_PFX -or $env:TIMAV_SIGN_THUMBPRINT) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $signtool) { throw "signtool.exe не найден (установите Windows SDK)" }
    $ts = if ($env:TIMAV_SIGN_TIMESTAMP) { $env:TIMAV_SIGN_TIMESTAMP } else { "http://timestamp.digicert.com" }
    $signArgs = @("sign", "/fd", "SHA256", "/tr", $ts, "/td", "SHA256", "/d", "Tim Antivirus")
    if ($env:TIMAV_SIGN_PFX) {
        $signArgs += @("/f", $env:TIMAV_SIGN_PFX)
        if ($env:TIMAV_SIGN_PASSWORD) { $signArgs += @("/p", $env:TIMAV_SIGN_PASSWORD) }
    } else {
        $signArgs += @("/sha1", $env:TIMAV_SIGN_THUMBPRINT)
    }
    Write-Host "Подпись включена: $signtool"
}

function Invoke-Sign([string]$file) {
    if (-not $signArgs) { return }
    if ($env:TIMAV_SIGN_DRYRUN) { Write-Host "[dry-run] signtool $($signArgs -join ' ') `"$file`""; return }
    & $signtool @signArgs $file
    if ($LASTEXITCODE -ne 0) { throw "Не удалось подписать $file" }
}

& $py tools\make_icon.py
if (-not $SkipTests) {
    & $py -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Тесты не прошли" }
}

& $py -m PyInstaller TimAntivirus.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { throw "PyInstaller завершился с ошибкой" }
Invoke-Sign "dist\TimAntivirus\TimAntivirus.exe"

$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 не найден (winget install JRSoftware.InnoSetup)" }
$isccArgs = @("installer\TimAntivirus.iss")
if ($signArgs -and -not $env:TIMAV_SIGN_DRYRUN) {
    $quoted = ($signArgs | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join " "
    $isccArgs = @("/DSIGN", "/Ssigntool=`"$signtool`" $quoted `$f") + $isccArgs
}
& $iscc @isccArgs
if ($LASTEXITCODE -ne 0) { throw "ISCC завершился с ошибкой" }
if ($env:TIMAV_SIGN_DRYRUN) { Invoke-Sign "dist\TimAntivirus-Setup-*.exe" }

# контрольная сумма для канала обновлений
$setup = Get-ChildItem dist\TimAntivirus-Setup-*.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$hash = (Get-FileHash $setup.FullName -Algorithm SHA256).Hash.ToLower()
"$hash  $($setup.Name)" | Set-Content "$($setup.FullName).sha256" -Encoding ascii
$ver = (& $py -c "import timav; print(timav.__version__)").Trim()
@{ version = $ver; url = "https://example.com/$($setup.Name)"; sha256 = $hash; notes = "" } |
    ConvertTo-Json | Set-Content dist\latest.json -Encoding utf8
Write-Host "Готово: $($setup.FullName)`nSHA-256: $hash`n(в dist\latest.json замените url на адрес, где лежит установщик)"
