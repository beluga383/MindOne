param(
    [Parameter(Mandatory = $true)]
    [string]$Binary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
    throw "Windows PE 自包含检查只能在 Windows 上运行。"
}

$resolvedBinary = (Resolve-Path -LiteralPath $Binary -ErrorAction Stop).Path
$binaryItem = Get-Item -LiteralPath $resolvedBinary -Force
if ($binaryItem.PSIsContainer -or $binaryItem.LinkType) {
    throw "Windows PE 自包含检查要求普通文件，拒绝目录或重解析点：$resolvedBinary"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "找不到 Visual Studio vswhere，无法验证 Windows PE 导入表。"
}

$dumpbinCandidates = @(
    & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find "VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe"
)
if ($LASTEXITCODE -ne 0 -or $dumpbinCandidates.Count -eq 0) {
    throw "找不到 Visual C++ dumpbin，无法验证 Windows PE 导入表。"
}
$dumpbin = $dumpbinCandidates[0]

$dependencies = @(& $dumpbin /nologo /dependents $resolvedBinary 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin 无法读取 Windows PE 依赖。"
}
$dependencyText = $dependencies -join "`n"
$forbiddenRuntime = [regex]::Match(
    $dependencyText,
    "(?im)^\s*(?:VCRUNTIME|MSVCP|CONCRT|UCRTBASE|api-ms-win-crt-)[^\r\n]*\.dll\s*$"
)
if ($forbiddenRuntime.Success) {
    throw "Windows 发行二进制仍依赖外部 VC/UCRT Runtime：$($forbiddenRuntime.Value.Trim())"
}
if ($dependencyText -notmatch "(?im)^\s*KERNEL32\.dll\s*$") {
    throw "Windows PE 依赖表缺少 KERNEL32.dll，拒绝状态不明的发行物。"
}

$imports = @(& $dumpbin /nologo /imports $resolvedBinary 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin 无法读取 Windows PE 导入符号。"
}
$importText = $imports -join "`n"
foreach ($requiredSymbol in @(
    "CreateJobObjectW",
    "AssignProcessToJobObject",
    "SetInformationJobObject"
)) {
    if ($importText -notmatch "(?m)\b$([regex]::Escape($requiredSymbol))\b") {
        throw "Windows 发行二进制缺少 Job Object 导入：$requiredSymbol"
    }
}

Write-Host "Windows PE 自包含检查通过：未依赖外部 VC/UCRT Runtime，Job Object 导入完整。"
