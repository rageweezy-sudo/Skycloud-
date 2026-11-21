param(
    [string]$Python = "python",
    [string]$InnoCompiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Project = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $Project "build\windows"
$Output = Join-Path $Project "dist"

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Build command failed with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw "Supply the path to the installed Inno Setup 6 compiler with -InnoCompiler."
}

Push-Location $Project
try {
    Invoke-Checked $Python @("-c", "import sys, platform, struct; assert sys.platform == 'win32' and sys.version_info[:2] == (3, 12) and platform.machine().lower() in ('amd64', 'x86_64') and struct.calcsize('P') == 8; import PySide6, PyInstaller, pytest; from sqlcipher3 import dbapi2; assert dbapi2.connect(':memory:').execute('PRAGMA cipher_version').fetchone()[0]")
    Invoke-Checked $Python @("-m", "pytest", "-q")
    Invoke-Checked $Python @("-m", "PyInstaller", "--noconfirm", "--clean",
        "--distpath", (Join-Path $BuildRoot "app"),
        "--workpath", (Join-Path $BuildRoot "work"),
        (Join-Path $PSScriptRoot "account_privacy.spec"))
    $App = Join-Path $BuildRoot "app\AccountPrivacy"
    Invoke-Checked $InnoCompiler @(
        "/DPackageDir=$App",
        "/DInstallerOutput=$Output",
        (Join-Path $PSScriptRoot "installer.iss")
    )
    $Installer = Join-Path $Output "AccountPrivacy-Setup-x64.exe"
    if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
        throw "The installer was not produced."
    }
    Write-Output $Installer
} finally {
    Pop-Location
}
