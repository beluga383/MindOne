[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Launch,
    [switch]$NoModifyPath,
    [switch]$AllowDowngrade,
    [string]$Version = $env:MINDONE_VERSION,
    [string]$InstallDir = $env:MINDONE_INSTALL_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "MindOne 安装失败：$Message"
}

function Add-MindOneToUserPath([string]$Directory) {
    if ($Directory.Contains(';')) {
        Fail "安装目录包含 PATH 分隔符，无法安全写入用户 PATH：$Directory"
    }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @()
    if (-not [string]::IsNullOrWhiteSpace($userPath)) {
        $entries = @($userPath.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $alreadyPresent = $false
    foreach ($entry in $entries) {
        $candidate = $entry.Trim().Trim('"')
        try {
            if (Test-SamePath $candidate $Directory) {
                $alreadyPresent = $true
                break
            }
        }
        catch {
            # 用户 PATH 可能含有尚未展开的变量；它不是本安装目录的精确绝对路径。
        }
    }
    if (-not $alreadyPresent) {
        $newUserPath = if ($entries.Count -eq 0) {
            $Directory
        } else {
            "$Directory;$($entries -join ';')"
        }
        if ($newUserPath.Length -gt 32767) {
            Fail "用户 PATH 超过 Windows 长度上限，无法安全加入 MindOne"
        }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        Write-Host "已把 MindOne 命令目录写入用户 PATH；新终端可直接运行 mindone。"
    }

    $processEntries = @($env:Path.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $processHasDirectory = $false
    foreach ($entry in $processEntries) {
        try {
            if (Test-SamePath $entry.Trim().Trim('"') $Directory) {
                $processHasDirectory = $true
                break
            }
        }
        catch {
        }
    }
    if (-not $processHasDirectory) {
        $env:Path = "$Directory;$env:Path"
    }
}

function Normalize-ComparisonPath([string]$Path) {
    return ([IO.Path]::GetFullPath($Path)).TrimEnd([char[]]@('\', '/'))
}

function Test-SamePath([string]$Left, [string]$Right) {
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    return [string]::Equals(
        (Normalize-ComparisonPath $Left),
        (Normalize-ComparisonPath $Right),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Test-ReparsePoint([IO.FileSystemInfo]$Item) {
    return ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
}

function Assert-NoExistingReparsePointInChain([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (Test-ReparsePoint $item) {
                Fail "安装目录或其现有父目录是重解析点：$cursor"
            }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }
        $cursor = $parent.FullName
    }
}

function Get-SafeInstallDirectory([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Fail "安装目录不能为空"
    }
    if (-not [IO.Path]::IsPathRooted($Path) -or
        $Path -notmatch '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+)') {
        Fail "安装目录必须是完全限定的绝对路径：$Path"
    }
    if ($Path -match '(^|[\\/])\.{1,2}([\\/]|$)') {
        Fail "安装目录包含未规范化的 . 或 .. 路径组件：$Path"
    }
    if ($Path -match '(?i)(^|[\\/])(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.[^\\/]*)?([\\/]|$)') {
        Fail "安装目录包含 Windows 保留设备名：$Path"
    }
    $withoutPrefix = if ($Path -match '^[A-Za-z]:') {
        $Path.Substring(2)
    } elseif ($Path.StartsWith('\\')) {
        $Path.Substring(2)
    } else {
        $Path
    }
    if ($withoutPrefix -match '[\\/]{2,}' -or
        $Path -match '[\x00-\x1f]' -or
        $Path -match '[ .]([\\/]|$)') {
        Fail "安装目录包含 Windows 会重解释的非规范路径：$Path"
    }
    $withoutDrive = if ($Path -match '^[A-Za-z]:') { $Path.Substring(2) } else { $Path }
    if ($withoutDrive.Contains(':') -or $withoutDrive -match '[<>"|?*]') {
        Fail "安装目录包含备用数据流、通配符或 Windows 无效字符：$Path"
    }

    try {
        $full = [IO.Path]::GetFullPath($Path)
    }
    catch {
        Fail "安装目录无法规范化：$Path"
    }
    $userProfilesRoot = if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $userProfileParent = [IO.Directory]::GetParent($env:USERPROFILE)
        if ($null -ne $userProfileParent) { $userProfileParent.FullName } else { $null }
    } else {
        $null
    }
    foreach ($protected in @(
            [IO.Path]::GetPathRoot($full),
            $env:USERPROFILE,
            $userProfilesRoot,
            $env:LOCALAPPDATA,
            $env:APPDATA,
            [IO.Path]::GetTempPath(),
            $env:SystemRoot,
            $env:ProgramData,
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)}
        )) {
        if (-not [string]::IsNullOrWhiteSpace($protected) -and (Test-SamePath $full $protected)) {
            Fail "拒绝把安装目录设为根目录或宽泛用户目录：$full"
        }
    }
    Assert-NoExistingReparsePointInChain $full
    return $full
}

function Test-MindOneBinary([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }
    try {
        $output = (& $Path --version 2>&1 | Out-String).Trim()
        return $LASTEXITCODE -eq 0 -and
            $output -match '^mindone [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$'
    }
    catch {
        return $false
    }
}

function Get-MindOneVersion([string]$Path) {
    $output = (& $Path --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or
        $output -notmatch '^mindone ([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)$') {
        Fail "可执行文件无法返回有效版本：$Path"
    }
    return $Matches[1]
}

function Get-NormalizedNumericIdentifier([string]$Value) {
    $normalized = $Value.TrimStart('0')
    if ($normalized.Length -eq 0) {
        return "0"
    }
    return $normalized
}

function Compare-NumericIdentifier([string]$Left, [string]$Right) {
    $normalizedLeft = Get-NormalizedNumericIdentifier $Left
    $normalizedRight = Get-NormalizedNumericIdentifier $Right
    if ($normalizedLeft.Length -lt $normalizedRight.Length) { return -1 }
    if ($normalizedLeft.Length -gt $normalizedRight.Length) { return 1 }
    $ordinal = [string]::CompareOrdinal($normalizedLeft, $normalizedRight)
    if ($ordinal -lt 0) { return -1 }
    if ($ordinal -gt 0) { return 1 }
    return 0
}

function Get-SemVerParts([string]$VersionValue) {
    $value = if ($VersionValue.StartsWith('v', [StringComparison]::Ordinal)) {
        $VersionValue.Substring(1)
    } else {
        $VersionValue
    }
    $plus = $value.IndexOf('+')
    $withoutBuild = if ($plus -ge 0) { $value.Substring(0, $plus) } else { $value }
    $dash = $withoutBuild.IndexOf('-')
    $core = if ($dash -ge 0) { $withoutBuild.Substring(0, $dash) } else { $withoutBuild }
    $prerelease = if ($dash -ge 0) { $withoutBuild.Substring($dash + 1) } else { "" }
    $coreParts = $core.Split('.')
    if ($coreParts.Count -ne 3) {
        Fail "无法比较非 SemVer 版本：$VersionValue"
    }
    return [PSCustomObject]@{
        Core = $coreParts
        Prerelease = $prerelease
    }
}

function Compare-SemVer([string]$Left, [string]$Right) {
    $leftVersion = Get-SemVerParts $Left
    $rightVersion = Get-SemVerParts $Right
    for ($index = 0; $index -lt 3; $index++) {
        $result = Compare-NumericIdentifier $leftVersion.Core[$index] $rightVersion.Core[$index]
        if ($result -ne 0) { return $result }
    }
    if ($leftVersion.Prerelease.Length -eq 0 -and $rightVersion.Prerelease.Length -eq 0) {
        return 0
    }
    if ($leftVersion.Prerelease.Length -eq 0) { return 1 }
    if ($rightVersion.Prerelease.Length -eq 0) { return -1 }

    $leftIdentifiers = $leftVersion.Prerelease.Split('.')
    $rightIdentifiers = $rightVersion.Prerelease.Split('.')
    $count = [Math]::Min($leftIdentifiers.Count, $rightIdentifiers.Count)
    for ($index = 0; $index -lt $count; $index++) {
        $leftIdentifier = $leftIdentifiers[$index]
        $rightIdentifier = $rightIdentifiers[$index]
        $leftNumeric = $leftIdentifier -cmatch '^[0-9]+$'
        $rightNumeric = $rightIdentifier -cmatch '^[0-9]+$'
        if ($leftNumeric -and $rightNumeric) {
            $result = Compare-NumericIdentifier $leftIdentifier $rightIdentifier
        } elseif ($leftNumeric) {
            $result = -1
        } elseif ($rightNumeric) {
            $result = 1
        } else {
            $ordinal = [string]::CompareOrdinal($leftIdentifier, $rightIdentifier)
            $result = if ($ordinal -lt 0) { -1 } elseif ($ordinal -gt 0) { 1 } else { 0 }
        }
        if ($result -ne 0) { return $result }
    }
    if ($leftIdentifiers.Count -lt $rightIdentifiers.Count) { return -1 }
    if ($leftIdentifiers.Count -gt $rightIdentifiers.Count) { return 1 }
    return 0
}

function Invoke-SafeDownload(
    [string]$Uri,
    [string]$OutFile,
    [bool]$AllowLoopbackHttp,
    [long]$MaximumBytes
) {
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(30)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("MindOne-Installer/1.0")
    $current = [Uri]$Uri
    $redirects = 0
    $deadline = [Threading.CancellationTokenSource]::new()
    $deadline.CancelAfter([TimeSpan]::FromMinutes(30))
    try {
        while ($true) {
            if (-not [string]::IsNullOrEmpty($current.UserInfo)) {
                Fail "下载链中的地址不得内嵌用户名或密码"
            }
            $isLoopbackHttp = $AllowLoopbackHttp -and
                $current.Scheme -eq "http" -and $current.IsLoopback
            if ($current.Scheme -ne "https" -and -not $isLoopbackHttp) {
                Fail "下载链包含非 HTTPS 地址：$current"
            }

            $response = $client.GetAsync(
                $current,
                [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                $deadline.Token
            ).GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308)) {
                    if ($AllowLoopbackHttp -or $redirects -ge 5) {
                        Fail "下载重定向次数超限或本机测试地址发生重定向：$current"
                    }
                    $location = $response.Headers.Location
                    if ($null -eq $location) {
                        Fail "下载重定向缺少 Location：$current"
                    }
                    $current = if ($location.IsAbsoluteUri) {
                        $location
                    } else {
                        [Uri]::new($current, $location)
                    }
                    $redirects++
                    continue
                }
                if (-not $response.IsSuccessStatusCode) {
                    Fail "下载失败，HTTP 状态 $status：$current"
                }
                $contentLength = $response.Content.Headers.ContentLength
                if ($null -ne $contentLength -and $contentLength -gt $MaximumBytes) {
                    Fail "下载内容超过大小上限 $MaximumBytes 字节：$current"
                }

                $downloadStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $output = [IO.File]::Open($OutFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = [byte[]]::new(81920)
                    [long]$written = 0
                    while (($read = $downloadStream.ReadAsync(
                                    $buffer,
                                    0,
                                    $buffer.Length,
                                    $deadline.Token
                                ).GetAwaiter().GetResult()) -gt 0) {
                        $written += $read
                        if ($written -gt $MaximumBytes) {
                            Fail "下载内容超过大小上限 $MaximumBytes 字节：$current"
                        }
                        $output.Write($buffer, 0, $read)
                    }
                    $output.Flush($true)
                }
                finally {
                    $output.Dispose()
                    $downloadStream.Dispose()
                }
                return
            }
            finally {
                $response.Dispose()
            }
        }
    }
    catch {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        if ($_.Exception.Message.StartsWith("MindOne 安装失败：")) {
            throw
        }
        Fail "下载请求失败：$($_.Exception.Message)"
    }
    finally {
        $deadline.Dispose()
        $client.Dispose()
    }
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows)) {
    Fail "install.ps1 仅支持 Windows；macOS/Linux 请使用 scripts/install.sh"
}

if ($Check -and $Launch) {
    Fail "-Check 与 -Launch 不能同时使用"
}

if ($env:MINDONE_INSTALL_ALLOW_DOWNGRADE -notin @($null, "", "0", "1")) {
    Fail "MINDONE_INSTALL_ALLOW_DOWNGRADE 只能是 0 或 1"
}
$allowDowngradeEffective = $AllowDowngrade -or $env:MINDONE_INSTALL_ALLOW_DOWNGRADE -eq "1"
if ($env:MINDONE_INSTALL_NO_MODIFY_PATH -notin @($null, "", "0", "1")) {
    Fail "MINDONE_INSTALL_NO_MODIFY_PATH 只能是 0 或 1"
}
$noModifyPathEffective = $NoModifyPath -or $env:MINDONE_INSTALL_NO_MODIFY_PATH -eq "1"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Fail "无法确定 LOCALAPPDATA；请设置 MINDONE_INSTALL_DIR"
    }
    $InstallDir = Join-Path $env:LOCALAPPDATA "MindOne\bin"
}
$InstallDir = Get-SafeInstallDirectory $InstallDir

if (-not [string]::IsNullOrWhiteSpace($Version) -and $Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
    Fail "发行标签必须形如 v1.0.0"
}

$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($architecture -ne "X64") {
    Fail "当前 Windows CPU 架构没有官方发行包：$architecture（当前仅发布 x86_64）"
}
$target = "x86_64-pc-windows-msvc"
$artifact = "mindone-$target.zip"
$binaryPath = Join-Path $InstallDir "mindone.exe"

if (Test-Path -LiteralPath $InstallDir) {
    $installDirectoryItem = Get-Item -LiteralPath $InstallDir -Force
    if (($installDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "安装目录是重解析点，拒绝写入：$InstallDir"
    }
    if (-not $installDirectoryItem.PSIsContainer) {
        Fail "安装目录路径不是目录：$InstallDir"
    }
}

$repository = if ([string]::IsNullOrWhiteSpace($env:MINDONE_REPOSITORY)) {
    "beluga383/MindOne"
} else {
    $env:MINDONE_REPOSITORY
}
$releasesBase = if ([string]::IsNullOrWhiteSpace($env:MINDONE_RELEASE_BASE_URL)) {
    "https://github.com/$repository/releases"
} else {
    $env:MINDONE_RELEASE_BASE_URL.TrimEnd('/')
}
$releaseUrl = if (-not [string]::IsNullOrWhiteSpace($env:MINDONE_RELEASE_URL)) {
    $env:MINDONE_RELEASE_URL.TrimEnd('/')
} elseif (-not [string]::IsNullOrWhiteSpace($Version)) {
    "$releasesBase/download/$Version"
} else {
    "$releasesBase/latest/download"
}

$parsedRelease = $null
if (-not [Uri]::TryCreate($releaseUrl, [UriKind]::Absolute, [ref]$parsedRelease)) {
    Fail "发行地址无效：$releaseUrl"
}
if (-not [string]::IsNullOrEmpty($parsedRelease.UserInfo)) {
    Fail "发行地址不得内嵌用户名或密码"
}
if (-not [string]::IsNullOrEmpty($parsedRelease.Query) -or
    -not [string]::IsNullOrEmpty($parsedRelease.Fragment)) {
    Fail "发行地址必须是目录 URL，不得包含查询参数或片段"
}
$loopbackHttpAllowed = $env:MINDONE_INSTALL_ALLOW_LOOPBACK_HTTP -eq "1" -and
    $parsedRelease.Scheme -eq "http" -and $parsedRelease.IsLoopback
if ($parsedRelease.Scheme -ne "https" -and -not $loopbackHttpAllowed) {
    Fail "发行地址必须使用 HTTPS（显式启用的本机自动化测试例外）：$releaseUrl"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("mindone-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporary | Out-Null
$staged = $null
try {
    $releaseVersionFile = Join-Path $temporary "release-version.txt"
    Invoke-SafeDownload "$releaseUrl/release-version.txt" $releaseVersionFile $loopbackHttpAllowed 4096
    $releaseVersionLines = @(Get-Content -LiteralPath $releaseVersionFile)
    if ($releaseVersionLines.Count -ne 1) {
        Fail "发行版本文件必须且只能包含一行"
    }
    $releaseTag = $releaseVersionLines[0].Trim()
    if ($releaseTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
        Fail "发行版本文件格式无效"
    }
    if (-not [string]::IsNullOrWhiteSpace($Version) -and $releaseTag -ne $Version) {
        Fail "发行目录版本为 $releaseTag，与请求的 $Version 不一致"
    }

    if ($Check) {
        if (-not (Test-MindOneBinary $binaryPath)) {
            Write-Host "MindOne 尚未安装在 $binaryPath"
            Write-Host "最新发行版：$releaseTag"
            return
        }
        $currentVersion = Get-MindOneVersion $binaryPath
        $latestVersion = $releaseTag.Substring(1)
        $versionOrder = Compare-SemVer $currentVersion $latestVersion
        if ($versionOrder -eq 0) {
            Write-Host "MindOne 已是最新版本：$currentVersion"
        } elseif ($versionOrder -lt 0) {
            Write-Host "MindOne 可更新：已安装 $currentVersion，发行版 $latestVersion"
        } else {
            Write-Host "MindOne 已安装版本 $currentVersion 高于所查发行版 $latestVersion，无需更新。"
        }
        return
    }

    if (Test-MindOneBinary $binaryPath) {
        $currentVersion = Get-MindOneVersion $binaryPath
        $targetVersion = $releaseTag.Substring(1)
        $versionOrder = Compare-SemVer $currentVersion $targetVersion
        if ($versionOrder -gt 0) {
            if (-not $allowDowngradeEffective) {
                Fail "拒绝把 MindOne 从 ${currentVersion} 降级到 ${targetVersion}；如确有需要，请显式传入 -AllowDowngrade"
            }
            Write-Warning "已明确允许把 MindOne 从 $currentVersion 降级到 $targetVersion。"
        }
    }

    $archive = Join-Path $temporary $artifact
    $checksumFile = Join-Path $temporary "checksums.sha256"
    Write-Host "正在下载 MindOne $releaseTag（$target）…"
    Invoke-SafeDownload "$releaseUrl/checksums.sha256" $checksumFile $loopbackHttpAllowed (8MB)
    Invoke-SafeDownload "$releaseUrl/$artifact" $archive $loopbackHttpAllowed ([long](4GB))

    $matchingChecksums = @()
    foreach ($line in Get-Content -LiteralPath $checksumFile) {
        if ($line -match '^([0-9A-Fa-f]{64})\s+\*?(.+)$' -and $Matches[2] -eq $artifact) {
            $matchingChecksums += $Matches[1].ToLowerInvariant()
        }
    }
    if ($matchingChecksums.Count -ne 1) {
        Fail "SHA-256 清单中必须且只能有一条 $artifact 记录"
    }
    $actualChecksum = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualChecksum -ne $matchingChecksums[0]) {
        Fail "发行包 SHA-256 不匹配，已拒绝安装"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $expectedEntries = @("mindone.exe", "LICENSE", "CODE_SIGNING.txt")
        $entryLimits = @{
            "mindone.exe" = [long](1GB)
            "LICENSE" = [long](2MB)
            "CODE_SIGNING.txt" = [long](1MB)
        }
        if ($zip.Entries.Count -ne $expectedEntries.Count) {
            Fail "发行包文件数量与发布合同不一致"
        }
        $seenEntries = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ($name.StartsWith('/') -or $name -match '(^|/)\.\.(/|$)') {
                Fail "发行包包含路径穿越，已拒绝解压"
            }
            if ($name -notin $expectedEntries) {
                Fail "发行包包含未声明文件：$name"
            }
            if (-not $seenEntries.Add($name)) {
                Fail "发行包包含重复文件：$name"
            }
            if ($entry.Length -le 0 -or $entry.Length -gt $entryLimits[$name]) {
                Fail "发行包文件大小异常：$name（$($entry.Length) 字节）"
            }
            $unixMode = ($entry.ExternalAttributes -shr 16) -band 0xFFFF
            $unixType = $unixMode -band 0xF000
            if (($entry.ExternalAttributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($unixType -ne 0 -and $unixType -ne 0x8000)) {
                Fail "发行包包含链接、目录或特殊文件：$name"
            }
        }
        foreach ($expectedEntry in $expectedEntries) {
            if (-not $seenEntries.Contains($expectedEntry)) {
                Fail "发行包缺少声明文件：$expectedEntry"
            }
        }
    }
    finally {
        $zip.Dispose()
    }

    $extractDir = Join-Path $temporary "extract"
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractDir)
    $candidate = Join-Path $extractDir "mindone.exe"
    if (-not (Test-MindOneBinary $candidate)) {
        Fail "发行包缺少可通过 --version 自检的 mindone.exe"
    }
    $downloadedVersion = Get-MindOneVersion $candidate
    if ($downloadedVersion -ne $releaseTag.Substring(1)) {
        Fail "可执行文件版本 $downloadedVersion 与发行版本 $($releaseTag.Substring(1)) 不一致"
    }

    if (Test-Path -LiteralPath $binaryPath) {
        $existing = Get-Item -LiteralPath $binaryPath -Force
        if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "安装目标是重解析点，拒绝覆盖：$binaryPath"
        }
        if (-not (Test-MindOneBinary $binaryPath)) {
            Fail "安装目标已有非 MindOne 文件，拒绝覆盖：$binaryPath"
        }
    }

    [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    Assert-NoExistingReparsePointInChain $InstallDir
    $staged = Join-Path $InstallDir (".mindone.new." + [Guid]::NewGuid().ToString("N") + ".exe")
    [IO.File]::Copy($candidate, $staged, $false)
    if (-not (Test-MindOneBinary $staged)) {
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        Fail "暂存文件自检失败"
    }
    if (Test-Path -LiteralPath $binaryPath) {
        $replaceTarget = Get-Item -LiteralPath $binaryPath -Force
        if ((Test-ReparsePoint $replaceTarget) -or -not (Test-MindOneBinary $binaryPath)) {
            Fail "原子替换前安装目标已变化，拒绝覆盖：$binaryPath"
        }
        [IO.File]::Replace($staged, $binaryPath, $null)
    } else {
        Move-Item -LiteralPath $staged -Destination $binaryPath
    }
    $staged = $null

    Write-Host "MindOne $downloadedVersion 已安装：$binaryPath"
    if ($noModifyPathEffective) {
        Write-Host "已按要求不修改 PATH；可直接运行 $binaryPath。"
    } else {
        Add-MindOneToUserPath $InstallDir
    }
    Write-Host "再次运行 install.ps1 -Check 可检查更新。"
    if ($Launch) {
        $interactive = [Environment]::UserInteractive -and
            -not [Console]::IsInputRedirected -and
            -not [Console]::IsOutputRedirected -and
            $env:CI -ne "true"
        if ($interactive) {
            Write-Host "正在打开 MindOne TUI…"
            & $binaryPath
        } else {
            Write-Host "当前不是交互式终端；已完成安装并用帮助页验证 CLI，未进入 TUI。"
            & $binaryPath --help
        }
        if ($LASTEXITCODE -ne 0) {
            Fail "安装后的 MindOne 启动验证失败，退出码 $LASTEXITCODE"
        }
    }
}
finally {
    if ($null -ne $staged -and (Test-Path -LiteralPath $staged)) {
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
