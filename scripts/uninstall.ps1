[CmdletBinding()]
param(
    [Alias("y")]
    [switch]$Yes,
    [switch]$PurgeData,
    [switch]$Force,
    [switch]$KeepPath,
    [string]$InstallDir = $env:MINDONE_INSTALL_DIR,
    [string]$StopTimeout = $env:MINDONE_UNINSTALL_STOP_TIMEOUT,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "MindOne 卸载失败：$Message"
}

function Show-Usage {
    @"
MindOne 卸载器

用法：uninstall.ps1 [-Yes] [-PurgeData] [-Force] [-KeepPath] [-InstallDir 目录] [-StopTimeout 秒]

默认只删除 MindOne CLI，保留模型、引擎、日志和配置。
-PurgeData 会额外删除 MindOne 自有数据目录，并再次显示准确路径。
-Force 仅在服务无法正常停止时跳过安全停止检查；可能留下运行进程。
-KeepPath 保留用户 PATH 中的安装目录；默认只移除与安装目录精确匹配的用户 PATH 项。
"@ | Write-Host
}

function Test-ReparsePoint([IO.FileSystemInfo]$Item) {
    return ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
}

function Normalize-ComparisonPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    return $full.TrimEnd([char[]]@('\', '/'))
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

function Remove-MindOneFromUserPath([string]$Directory) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        return
    }
    $kept = [Collections.Generic.List[string]]::new()
    $removed = $false
    foreach ($entry in $userPath.Split(';')) {
        $matchesInstall = $false
        if (-not [string]::IsNullOrWhiteSpace($entry)) {
            try {
                $matchesInstall = Test-SamePath $entry.Trim().Trim('"') $Directory
            }
            catch {
                $matchesInstall = $false
            }
        }
        if ($matchesInstall) {
            $removed = $true
        } else {
            $kept.Add($entry)
        }
    }
    if ($removed) {
        $updated = if ($kept.Count -eq 0) { $null } else { $kept -join ';' }
        [Environment]::SetEnvironmentVariable("Path", $updated, "User")
        Write-Host "已从用户 PATH 移除 MindOne 安装目录：$Directory"
    }

    $processKept = [Collections.Generic.List[string]]::new()
    foreach ($entry in $env:Path.Split(';')) {
        $matchesInstall = $false
        if (-not [string]::IsNullOrWhiteSpace($entry)) {
            try {
                $matchesInstall = Test-SamePath $entry.Trim().Trim('"') $Directory
            }
            catch {
                $matchesInstall = $false
            }
        }
        if (-not $matchesInstall) {
            $processKept.Add($entry)
        }
    }
    $env:Path = $processKept -join ';'
}

function Assert-AbsoluteNormalizedDirectoryPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Fail "无法确定$Label"
    }
    if (-not [IO.Path]::IsPathRooted($Path) -or
        $Path -notmatch '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+)') {
        Fail "$Label必须是完全限定的绝对路径：$Path"
    }
    if ($Path -match '(^|[\\/])\.{1,2}([\\/]|$)') {
        Fail "$Label包含未规范化的 . 或 .. 路径组件：$Path"
    }
    if ($Path -match '(?i)(^|[\\/])(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.[^\\/]*)?([\\/]|$)') {
        Fail "$Label包含 Windows 保留设备名：$Path"
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
        Fail "$Label包含 Windows 会重解释的路径字符：$Path"
    }
    $withoutDrive = if ($Path -match '^[A-Za-z]:') { $Path.Substring(2) } else { $Path }
    if ($withoutDrive.Contains(':') -or $withoutDrive -match '[<>"|?*]') {
        Fail "$Label包含备用数据流、通配符或 Windows 无效字符：$Path"
    }
    try {
        return [IO.Path]::GetFullPath($Path)
    }
    catch {
        Fail "$Label无法规范化：$Path"
    }
}

function Assert-NotBroadDirectory([string]$Path, [string]$Label) {
    $protected = @([IO.Path]::GetPathRoot($Path), [IO.Path]::GetTempPath())
    $userProfilesRoot = if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $userProfileParent = [IO.Directory]::GetParent($env:USERPROFILE)
        if ($null -ne $userProfileParent) { $userProfileParent.FullName } else { $null }
    } else {
        $null
    }
    foreach ($candidate in @(
            $env:USERPROFILE,
            $userProfilesRoot,
            $env:LOCALAPPDATA,
            $env:APPDATA,
            $env:SystemRoot,
            $env:ProgramData,
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)}
        )) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $protected += $candidate
        }
    }
    foreach ($candidate in $protected) {
        if (Test-SamePath $Path $candidate) {
            Fail "拒绝把$Label设为根目录或宽泛用户目录：$Path"
        }
    }
}

function Assert-NoExistingReparsePointInChain([string]$Path, [string]$Label) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (Test-ReparsePoint $item) {
                Fail "$Label或其现有父目录是重解析点：$cursor"
            }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }
        $cursor = $parent.FullName
    }
}

function Test-MindOneBinary([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (Test-ReparsePoint $item) {
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

function Confirm-Action([string]$Prompt) {
    if ($Yes) {
        return $true
    }
    $answer = Read-Host "$Prompt 输入 yes 继续"
    return $answer -ceq "yes"
}

function Get-DefaultControlDirectory {
    if (Test-Path Env:MINDONE_HOME) {
        if ([string]::IsNullOrWhiteSpace($env:MINDONE_HOME)) {
            Fail "MINDONE_HOME 不能为空；请删除该变量或设置绝对路径"
        }
        return $env:MINDONE_HOME
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Fail "无法确定 LOCALAPPDATA；请设置 MINDONE_HOME"
    }
    return Join-Path $env:LOCALAPPDATA "MindOne"
}

function Get-ResolvedPathFromBinary(
    [string]$BinaryPath,
    [string]$ResolverCommand,
    [string]$Label
) {
    try {
        $output = (& $BinaryPath __worker $ResolverCommand | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            Fail "无法通过已验证的 MindOne CLI 解析$Label；拒绝猜测路径"
        }
        if ([string]::IsNullOrWhiteSpace($output) -or $output -match "[`r`n]") {
            Fail "MindOne CLI 返回了空或不唯一的$Label，拒绝继续"
        }
        return $output
    }
    catch {
        Fail "无法通过已验证的 MindOne CLI 解析$Label；拒绝猜测路径：$($_.Exception.Message)"
    }
}

function Resolve-ManagedDirectory([string]$Path, [string]$Label) {
    $resolved = Assert-AbsoluteNormalizedDirectoryPath $Path $Label
    Assert-NotBroadDirectory $resolved $Label
    Assert-NoExistingReparsePointInChain $resolved $Label
    if (Test-Path -LiteralPath $resolved) {
        $item = Get-Item -LiteralPath $resolved -Force
        if (-not $item.PSIsContainer) {
            Fail "$Label路径不是目录：$resolved"
        }
        $resolved = $item.FullName
        Assert-NotBroadDirectory $resolved $Label
    }
    return $resolved
}

function Test-ConfigDeclaresCustomDataDir([string]$ConfigPath) {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        return $false
    }
    $item = Get-Item -LiteralPath $ConfigPath -Force
    if ($item.PSIsContainer -or (Test-ReparsePoint $item)) {
        Fail "配置路径不是普通文件，无法安全判断 data_dir：$ConfigPath"
    }
    return $null -ne (Select-String -LiteralPath $ConfigPath `
        -Pattern '^[\s]*(?:data_dir|"data_dir"|''data_dir'')[\s]*=' `
        -CaseSensitive)
}

function Assert-OwnedDataTree([string]$DataDir, [string]$InstallDir, [string]$BinaryPath) {
    if (-not (Test-Path -LiteralPath $DataDir)) {
        return
    }
    $root = Get-Item -LiteralPath $DataDir -Force
    if (-not $root.PSIsContainer -or (Test-ReparsePoint $root)) {
        Fail "数据路径不是普通目录：$DataDir"
    }

    $ownedDirectories = @("models", "engines", "runtime", "logs", "cache")
    $ownedFiles = @("config.toml", ".DS_Store")
    foreach ($entry in Get-ChildItem -LiteralPath $DataDir -Force) {
        if (Test-ReparsePoint $entry) {
            Fail "数据目录含有重解析点，拒绝递归删除：$($entry.FullName)"
        }
        if ($entry.Name -in $ownedDirectories) {
            if (-not $entry.PSIsContainer) {
                Fail "MindOne 数据目录项类型异常：$($entry.FullName)"
            }
            continue
        }
        if ($entry.Name -in $ownedFiles) {
            if ($entry.PSIsContainer) {
                Fail "MindOne 数据文件类型异常：$($entry.FullName)"
            }
            continue
        }
        if ((Test-SamePath $InstallDir $DataDir) -and
            (Test-SamePath $entry.FullName $BinaryPath)) {
            if ($entry.PSIsContainer -or -not (Test-MindOneBinary $entry.FullName)) {
                Fail "数据目录根部的安装目标不是 MindOne 普通可执行文件：$($entry.FullName)"
            }
            continue
        }
        if ($entry.Name -eq "bin" -and (Test-SamePath $entry.FullName $InstallDir)) {
            if (-not $entry.PSIsContainer) {
                Fail "安装目录项类型异常：$($entry.FullName)"
            }
            foreach ($installedEntry in Get-ChildItem -LiteralPath $entry.FullName -Force) {
                if ((Test-ReparsePoint $installedEntry) -or $installedEntry.PSIsContainer -or
                    -not (Test-SamePath $installedEntry.FullName $BinaryPath)) {
                    Fail "数据目录内的安装目录含有非 MindOne 目标：$($installedEntry.FullName)"
                }
            }
            continue
        }
        Fail "数据目录含有非 MindOne 顶层项目，拒绝递归删除：$($entry.FullName)"
    }

    foreach ($entry in Get-ChildItem -LiteralPath $DataDir -Force -Recurse) {
        if (Test-ReparsePoint $entry) {
            Fail "数据目录树含有重解析点，拒绝递归删除：$($entry.FullName)"
        }
    }
}

function Invoke-MindOneStop(
    [string]$BinaryPath,
    [string]$DataDir,
    [bool]$UseConfiguredContext,
    [string[]]$Arguments
) {
    $hadMindOneHome = Test-Path Env:MINDONE_HOME
    $previousMindOneHome = if ($hadMindOneHome) { $env:MINDONE_HOME } else { $null }
    try {
        if ($UseConfiguredContext) {
            $resolvedAgain = Get-ResolvedPathFromBinary $BinaryPath "resolve-data-dir" "实际数据目录"
            $resolvedAgain = Resolve-ManagedDirectory $resolvedAgain "实际数据目录"
            if (-not (Test-SamePath $resolvedAgain $DataDir)) {
                Fail "停止前 data_dir 已从 $DataDir 变为 $resolvedAgain，拒绝向不确定进程发送信号"
            }
        }
        else {
            $env:MINDONE_HOME = $DataDir
        }
        & $BinaryPath @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        return $LASTEXITCODE -eq 0
    }
    catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    finally {
        if (-not $UseConfiguredContext) {
            if ($hadMindOneHome) {
                $env:MINDONE_HOME = $previousMindOneHome
            }
            else {
                Remove-Item Env:MINDONE_HOME -ErrorAction SilentlyContinue
            }
        }
    }
}

function Stop-MindOneManagedRoot(
    [string]$BinaryPath,
    [bool]$BinaryAvailable,
    [string]$DataDir,
    [bool]$UseConfiguredContext
) {
    $runtimeDir = Join-Path $DataDir "runtime"
    $shareState = Join-Path $runtimeDir "share.json"
    $serveState = Join-Path $runtimeDir "serve.json"
    foreach ($statePath in @($runtimeDir, $shareState, $serveState)) {
        if (Test-Path -LiteralPath $statePath) {
            $stateItem = Get-Item -LiteralPath $statePath -Force
            if (Test-ReparsePoint $stateItem) {
                Fail "runtime 状态路径包含重解析点，拒绝执行或删除：$statePath"
            }
        }
    }
    $shareMayBeRunning = Test-Path -LiteralPath $shareState -PathType Leaf
    $serveMayBeRunning = Test-Path -LiteralPath $serveState -PathType Leaf
    if (-not $shareMayBeRunning -and -not $serveMayBeRunning) {
        return
    }
    if (-not $BinaryAvailable) {
        if (-not $Force) {
            Fail "数据目录 $DataDir 存在服务状态但缺少可验证的 MindOne CLI，无法按 PID 与启动身份安全停止；请恢复 CLI 后重试，或明确使用 -Force"
        }
        Write-Warning "数据目录 $DataDir 存在服务状态，但 -Force 已跳过安全停止；可能仍有运行进程"
        return
    }
    if ($shareMayBeRunning) {
        $stopped = Invoke-MindOneStop $BinaryPath $DataDir $UseConfiguredContext `
            @("share", "unpublish", "--timeout", $StopTimeout)
        if (-not $stopped) {
            if (-not $Force) {
                Fail "共享 worker 未能按 PID 与启动身份安全排空；恢复协调服务器后重试，或明确使用 -Force"
            }
            Write-Warning "已通过 -Force 跳过共享 worker 安全停止检查"
        }
    }
    if ($serveMayBeRunning) {
        $stopped = Invoke-MindOneStop $BinaryPath $DataDir $UseConfiguredContext `
            @("serve", "stop", "--timeout", $StopTimeout)
        if (-not $stopped) {
            if (-not $Force) {
                Fail "推理服务未能按 PID 与启动身份安全停止；请处理错误后重试，或明确使用 -Force"
            }
            Write-Warning "已通过 -Force 跳过推理服务安全停止检查"
        }
    }
    if (((Test-Path -LiteralPath $shareState -PathType Leaf) -or
            (Test-Path -LiteralPath $serveState -PathType Leaf)) -and -not $Force) {
        Fail "安全停止返回后仍存在 runtime 状态：$runtimeDir；拒绝继续卸载"
    }
}

if ($Help) {
    Show-Usage
    exit 0
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows)) {
    Fail "uninstall.ps1 仅支持 Windows；macOS/Linux 请使用 scripts/uninstall.sh"
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Fail "无法确定 LOCALAPPDATA；请设置 MINDONE_INSTALL_DIR"
    }
    $InstallDir = Join-Path $env:LOCALAPPDATA "MindOne\bin"
}
if ([string]::IsNullOrWhiteSpace($StopTimeout)) {
    $StopTimeout = "15"
}
if ($StopTimeout -notmatch '^[0-9]+$') {
    Fail "停止超时必须是非负整数"
}

$InstallDir = Assert-AbsoluteNormalizedDirectoryPath $InstallDir "安装目录"
Assert-NotBroadDirectory $InstallDir "安装目录"
Assert-NoExistingReparsePointInChain $InstallDir "安装目录"
if (Test-Path -LiteralPath $InstallDir) {
    $installDirectoryItem = Get-Item -LiteralPath $InstallDir -Force
    if (-not $installDirectoryItem.PSIsContainer) {
        Fail "安装目录路径不是目录：$InstallDir"
    }
}
$binaryPath = Join-Path $InstallDir "mindone.exe"
if (Test-Path -LiteralPath $binaryPath) {
    $binaryItem = Get-Item -LiteralPath $binaryPath -Force
    if ((Test-ReparsePoint $binaryItem) -or -not (Test-MindOneBinary $binaryPath)) {
        Fail "目标不是可识别的普通 MindOne 可执行文件，拒绝删除：$binaryPath"
    }
}
$binaryAvailable = Test-MindOneBinary $binaryPath

$controlDir = Get-DefaultControlDirectory
if ($binaryAvailable) {
    $dataDir = Get-ResolvedPathFromBinary $binaryPath "resolve-data-dir" "实际数据目录"
    $configHome = Get-ResolvedPathFromBinary $binaryPath "resolve-config-home" "配置控制目录"
}
else {
    $controlDir = Resolve-ManagedDirectory $controlDir "配置控制目录"
    $dataDir = $controlDir
    $configHome = $controlDir
    $configPath = Join-Path $controlDir "config.toml"
    if (-not (Test-Path Env:MINDONE_HOME) -and
        (Test-ConfigDeclaresCustomDataDir $configPath)) {
        Fail "配置文件声明了自定义 data_dir，但已缺少可验证的 MindOne CLI；请恢复 CLI 解析真实路径，或显式设置 MINDONE_HOME 后重试"
    }
}

$dataDir = Resolve-ManagedDirectory $dataDir "实际数据目录"
$configHome = Resolve-ManagedDirectory $configHome "配置控制目录"

if ($PurgeData) {
    Assert-OwnedDataTree $dataDir $InstallDir $binaryPath
    if (-not (Test-SamePath $configHome $dataDir)) {
        Assert-OwnedDataTree $configHome $InstallDir $binaryPath
    }
}

Stop-MindOneManagedRoot $binaryPath $binaryAvailable $dataDir $true
if (-not (Test-SamePath $configHome $dataDir)) {
    Stop-MindOneManagedRoot $binaryPath $binaryAvailable $configHome $false
}

if (Test-Path -LiteralPath $binaryPath) {
    if (-not (Confirm-Action "将删除 $binaryPath。")) {
        Fail "已取消卸载，未删除文件"
    }
    Assert-NoExistingReparsePointInChain $InstallDir "安装目录"
    if (-not (Test-MindOneBinary $binaryPath)) {
        Fail "删除前安装目标已变化，拒绝继续：$binaryPath"
    }
    Remove-Item -LiteralPath $binaryPath -Force
    if (Test-Path -LiteralPath $binaryPath) {
        Fail "无法删除 $binaryPath"
    }
    Write-Host "已删除 MindOne CLI：$binaryPath"
    if ((Test-Path -LiteralPath $InstallDir -PathType Container) -and
        @(Get-ChildItem -LiteralPath $InstallDir -Force).Count -eq 0) {
        Remove-Item -LiteralPath $InstallDir -Force
    }
} else {
    Write-Host "MindOne CLI 已不在安装目录：$binaryPath"
}

if ($KeepPath) {
    Write-Host "已按要求保留用户 PATH 中的 MindOne 安装目录。"
} else {
    Remove-MindOneFromUserPath $InstallDir
}

if ($PurgeData) {
    $dataDir = Resolve-ManagedDirectory $dataDir "实际数据目录"
    $configHome = Resolve-ManagedDirectory $configHome "配置控制目录"
    Assert-OwnedDataTree $dataDir $InstallDir $binaryPath
    if (-not (Test-SamePath $configHome $dataDir)) {
        Assert-OwnedDataTree $configHome $InstallDir $binaryPath
        $purgePrompt = "将永久删除 MindOne 实际数据目录 $dataDir 以及配置控制目录 $configHome（模型、引擎、日志和配置）。"
    }
    else {
        $purgePrompt = "将永久删除 MindOne 自有数据与配置目录 $dataDir（模型、引擎、日志和配置）。"
    }
    if (-not (Confirm-Action $purgePrompt)) {
        Fail "已保留 MindOne 数据目录"
    }

    if (Test-Path -LiteralPath $dataDir) {
        Assert-NoExistingReparsePointInChain $dataDir "数据目录"
        Assert-OwnedDataTree $dataDir $InstallDir $binaryPath
        Remove-Item -LiteralPath $dataDir -Recurse -Force
        if (Test-Path -LiteralPath $dataDir) {
            Fail "无法完整删除数据目录：$dataDir"
        }
        Write-Host "已删除 MindOne 数据目录：$dataDir"
    } else {
        Write-Host "MindOne 数据目录已不存在：$dataDir"
    }
    if (-not (Test-SamePath $configHome $dataDir)) {
        if (Test-Path -LiteralPath $configHome) {
            Assert-NoExistingReparsePointInChain $configHome "配置控制目录"
            Assert-OwnedDataTree $configHome $InstallDir $binaryPath
            Remove-Item -LiteralPath $configHome -Recurse -Force
            if (Test-Path -LiteralPath $configHome) {
                Fail "无法完整删除配置控制目录：$configHome"
            }
            Write-Host "已删除 MindOne 配置控制目录：$configHome"
        }
        else {
            Write-Host "MindOne 配置控制目录已不存在：$configHome"
        }
    }
}
elseif (Test-SamePath $configHome $dataDir) {
    Write-Host "已保留 MindOne 数据：$dataDir"
}
else {
    Write-Host "已保留 MindOne 实际数据：$dataDir"
    Write-Host "已保留 MindOne 配置：$configHome"
}
