#!/bin/sh

set -eu

INSTALL_DIR="${MINDONE_INSTALL_DIR:-${HOME:?无法确定 HOME}/.local/bin}"
ASSUME_YES=0
PURGE_DATA=0
FORCE=0
KEEP_PATH=0
STOP_TIMEOUT="${MINDONE_UNINSTALL_STOP_TIMEOUT:-15}"

usage() {
    cat <<'EOF'
MindOne 卸载器

用法：uninstall.sh [--yes] [--purge-data] [--force] [--keep-path] [--install-dir 目录]

默认只删除 MindOne CLI，保留模型、引擎、日志和配置。
--purge-data 会额外删除 MindOne 自有数据目录，并再次显示准确路径。
--force 仅在服务无法正常停止时跳过安全停止检查；可能留下运行进程。
--keep-path 保留安装器写入 shell 配置的受管 PATH 块；默认安全移除该块。
EOF
}

die() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

warn() {
    printf '警告：%s\n' "$*" >&2
}

remove_managed_path_blocks() {
    marker_start='# >>> MindOne CLI PATH (managed) >>>'
    marker_end='# <<< MindOne CLI PATH (managed) <<<'
    for profile_path in \
        "$HOME/.zshrc" \
        "$HOME/.bash_profile" \
        "$HOME/.bashrc" \
        "$HOME/.profile" \
        "$HOME/.config/fish/conf.d/mindone.fish"
    do
        [ -e "$profile_path" ] || continue
        if [ -L "$profile_path" ] || [ ! -f "$profile_path" ]; then
            warn "shell 配置不是普通文件，未移除受管 PATH 块：$profile_path"
            continue
        fi
        start_count=$(grep -Fxc "$marker_start" "$profile_path" || true)
        end_count=$(grep -Fxc "$marker_end" "$profile_path" || true)
        if [ "$start_count" -eq 0 ] && [ "$end_count" -eq 0 ]; then
            continue
        fi
        if [ "$start_count" -ne 1 ] || [ "$end_count" -ne 1 ]; then
            warn "shell 配置中的 MindOne PATH 标记不完整或重复，未修改：$profile_path"
            continue
        fi
        start_line=$(grep -Fn "$marker_start" "$profile_path" | awk -F: 'NR == 1 { print $1 }')
        end_line=$(grep -Fn "$marker_end" "$profile_path" | awk -F: 'NR == 1 { print $1 }')
        if [ "$start_line" -ge "$end_line" ]; then
            warn "shell 配置中的 MindOne PATH 标记顺序无效，未修改：$profile_path"
            continue
        fi
        profile_parent=$(dirname -- "$profile_path")
        profile_tmp=$(mktemp "$profile_parent/.mindone-profile.XXXXXX") || {
            warn "无法创建 shell 配置暂存文件，未修改：$profile_path"
            continue
        }
        if ! cp -p "$profile_path" "$profile_tmp"; then
            rm -f -- "$profile_tmp"
            warn "无法暂存 shell 配置，未修改：$profile_path"
            continue
        fi
        if ! awk -v start="$marker_start" -v end="$marker_end" '
            $0 == start { skipping = 1; next }
            $0 == end { skipping = 0; next }
            !skipping { print }
        ' "$profile_path" >"$profile_tmp"; then
            rm -f -- "$profile_tmp"
            warn "无法更新 shell 配置，未修改：$profile_path"
            continue
        fi
        if [ -L "$profile_path" ] || ! mv -f -- "$profile_tmp" "$profile_path"; then
            rm -f -- "$profile_tmp"
            warn "shell 配置在更新期间发生变化，未移除受管 PATH 块：$profile_path"
            continue
        fi
        printf '已从 shell 配置移除 MindOne 受管 PATH 块：%s\n' "$profile_path"
    done
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -y|--yes) ASSUME_YES=1; shift ;;
        --purge-data) PURGE_DATA=1; shift ;;
        --force) FORCE=1; shift ;;
        --keep-path) KEEP_PATH=1; shift ;;
        --install-dir)
            [ "$#" -ge 2 ] || die "--install-dir 缺少目录"
            INSTALL_DIR=$2
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "未知参数：$1" ;;
    esac
done

printf '%s\n' "$STOP_TIMEOUT" | grep -Eq '^[0-9]+$' || die "停止超时必须是非负整数"

default_control_dir() {
    if [ "${MINDONE_HOME+x}" = "x" ]; then
        [ -n "$MINDONE_HOME" ] || die "MINDONE_HOME 不能为空；请删除该变量或设置绝对路径"
        printf '%s\n' "$MINDONE_HOME"
        return
    fi
    case "$(uname -s 2>/dev/null || true)" in
        Darwin) printf '%s\n' "$HOME/Library/Application Support/MindOne" ;;
        Linux)
            if [ -n "${XDG_DATA_HOME:-}" ]; then
                printf '%s\n' "$XDG_DATA_HOME/mindone"
            else
                printf '%s\n' "$HOME/.local/share/mindone"
            fi
            ;;
        *) printf '%s\n' "" ;;
    esac
}

validate_normalized_absolute_path() {
    path_value=$1
    path_label=$2
    [ -n "$path_value" ] || die "无法确定$path_label"
    case "$path_value" in
        /*) ;;
        *) die "${path_label}必须是绝对路径：$path_value" ;;
    esac
    case "$path_value" in
        /) die "拒绝把${path_label}设为根目录" ;;
        *//*|*/./*|*/.|*/../*|*/..|*/)
            die "${path_label}包含未规范化的路径组件：$path_value"
            ;;
    esac
    if printf '%s' "$path_value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        die "${path_label}包含控制字符"
    fi
}

assert_no_symlink_in_chain() {
    path_value=$1
    path_label=$2
    old_ifs=$IFS
    IFS=/
    set -f
    # 这里只按斜杠拆分已经验证过的绝对路径；禁用 glob，保留空格等合法字符。
    set -- $path_value
    set +f
    IFS=$old_ifs
    cursor=
    for component do
        [ -n "$component" ] || continue
        cursor="$cursor/$component"
        [ ! -L "$cursor" ] || die "${path_label}或其父目录是符号链接：$cursor"
    done
}

canonical_existing_directory() {
    CDPATH= cd -- "$1" && pwd -P
}

reject_broad_install_path() {
    path_value=$1
    canonical_home=$(canonical_existing_directory "$HOME") \
        || die "无法规范化 HOME：$HOME"
    home_parent=$(dirname -- "$canonical_home")
    for protected in \
        / /bin /sbin /usr /usr/bin /usr/sbin /usr/local \
        /etc /var /var/tmp /private /private/tmp /tmp /opt /srv \
        /Applications /Library /System \
        "$canonical_home" "$home_parent" \
        "$canonical_home/.local" "$canonical_home/Library"
    do
        [ "$path_value" != "$protected" ] \
            || die "拒绝把安装目录设为根目录或宽泛用户/系统目录：$path_value"
    done
    if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
        canonical_tmp=$(canonical_existing_directory "$TMPDIR") \
            || die "无法规范化 TMPDIR：$TMPDIR"
        [ "$path_value" != "$canonical_tmp" ] \
            || die "拒绝把安装目录设为临时目录根：$path_value"
    fi
}

reject_broad_data_path() {
    path_value=$1
    canonical_home=$(canonical_existing_directory "$HOME") \
        || die "无法规范化 HOME：$HOME"
    home_parent=$(dirname -- "$canonical_home")
    xdg_data_root=${XDG_DATA_HOME:-"$canonical_home/.local/share"}
    for protected in \
        / /bin /sbin /usr /usr/bin /usr/sbin /usr/local /usr/local/bin \
        /etc /var /var/tmp /private /private/tmp /tmp /opt /srv \
        /Applications /Library /System \
        "$canonical_home" "$home_parent" \
        "$canonical_home/.local" "$canonical_home/.local/share" \
        "$canonical_home/Library" "$canonical_home/Library/Application Support" \
        "$xdg_data_root"
    do
        [ "$path_value" != "$protected" ] \
            || die "拒绝把数据目录设为根目录或宽泛用户/系统目录：$path_value"
    done
    if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
        canonical_tmp=$(canonical_existing_directory "$TMPDIR") \
            || die "无法规范化 TMPDIR：$TMPDIR"
        [ "$path_value" != "$canonical_tmp" ] \
            || die "拒绝把数据目录设为临时目录根：$path_value"
    fi
}

is_mindone_binary() {
    candidate=$1
    [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -x "$candidate" ] || return 1
    version_output=$("$candidate" --version 2>&1) || return 1
    [ "$(printf '%s\n' "$version_output" | wc -l | tr -d '[:space:]')" -eq 1 ] || return 1
    printf '%s\n' "$version_output" \
        | grep -Eq '^mindone [0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'
}

confirm() {
    prompt=$1
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    [ -r /dev/tty ] \
        || die "当前没有可用的交互终端；通过管道或自动化运行卸载器时必须显式传入 --yes"
    printf '%s 输入 yes 继续：' "$prompt" >/dev/tty 2>/dev/null \
        || die "无法访问交互终端；请在确认路径后使用 --yes"
    if ! IFS= read -r answer </dev/tty; then
        die "无法从交互终端读取确认；请在确认路径后使用 --yes"
    fi
    [ "$answer" = "yes" ]
}

validate_purge_target() {
    purge_candidate=$1
    validate_normalized_absolute_path "$purge_candidate" "数据目录"
    assert_no_symlink_in_chain "$purge_candidate" "数据目录"
    reject_broad_data_path "$purge_candidate"
    if [ ! -e "$purge_candidate" ]; then
        validated_purge_path=$purge_candidate
        return
    fi
    [ -d "$purge_candidate" ] || die "数据路径不是目录：$purge_candidate"
    canonical_data_dir=$(canonical_existing_directory "$purge_candidate") \
        || die "无法规范化数据目录：$purge_candidate"
    purge_candidate=$canonical_data_dir
    reject_broad_data_path "$purge_candidate"
    current_user=$(id -un 2>/dev/null) || die "无法确定当前用户，拒绝递归删除"
    foreign_owner=$(find "$purge_candidate" ! -user "$current_user" -print) \
        || die "无法审计数据目录所有者：$purge_candidate"
    [ -z "$foreign_owner" ] \
        || die "数据目录树含有不属于当前用户的项目，拒绝递归删除：$foreign_owner"
    for owned_entry in "$purge_candidate"/* "$purge_candidate"/.[!.]* "$purge_candidate"/..?*; do
        if [ ! -e "$owned_entry" ] && [ ! -L "$owned_entry" ]; then
            continue
        fi
        entry_name=${owned_entry##*/}
        case "$entry_name" in
            models|engines|runtime|logs|cache)
                [ -d "$owned_entry" ] && [ ! -L "$owned_entry" ] \
                    || die "MindOne 数据目录项类型异常：$owned_entry"
                ;;
            config.toml|.DS_Store)
                [ -f "$owned_entry" ] && [ ! -L "$owned_entry" ] \
                    || die "MindOne 数据文件类型异常：$owned_entry"
                ;;
            mindone)
                if [ "$purge_candidate" = "$INSTALL_DIR" ] && [ "$owned_entry" = "$binary_path" ] \
                    && is_mindone_binary "$owned_entry"; then
                    continue
                fi
                die "数据目录含有非 MindOne 顶层项目，拒绝递归删除：$owned_entry"
                ;;
            bin)
                if [ "$owned_entry" = "$INSTALL_DIR" ] && [ -d "$owned_entry" ] \
                    && [ ! -L "$owned_entry" ]; then
                    for installed_entry in \
                        "$owned_entry"/* "$owned_entry"/.[!.]* "$owned_entry"/..?*
                    do
                        if [ ! -e "$installed_entry" ] && [ ! -L "$installed_entry" ]; then
                            continue
                        fi
                        [ "$installed_entry" = "$binary_path" ] \
                            && is_mindone_binary "$installed_entry" \
                            || die "安装目录含有非 MindOne 目标：$installed_entry"
                    done
                    continue
                fi
                die "数据目录含有非 MindOne 顶层项目，拒绝递归删除：$owned_entry"
                ;;
            *) die "数据目录含有非 MindOne 顶层项目，拒绝递归删除：$owned_entry" ;;
        esac
    done
    unsafe_entries=$(find "$purge_candidate" ! -type d ! -type f -print) \
        || die "无法审计数据目录树：$purge_candidate"
    [ -z "$unsafe_entries" ] \
        || die "数据目录树包含链接或特殊文件，拒绝递归删除：$unsafe_entries"
    validated_purge_path=$purge_candidate
}

validate_normalized_absolute_path "$INSTALL_DIR" "安装目录"
reject_broad_install_path "$INSTALL_DIR"
assert_no_symlink_in_chain "$INSTALL_DIR" "安装目录"
if [ -e "$INSTALL_DIR" ]; then
    [ -d "$INSTALL_DIR" ] || die "安装目录路径不是目录：$INSTALL_DIR"
    INSTALL_DIR=$(canonical_existing_directory "$INSTALL_DIR") \
        || die "无法规范化安装目录：$INSTALL_DIR"
    reject_broad_install_path "$INSTALL_DIR"
fi
binary_path="$INSTALL_DIR/mindone"
if [ -L "$binary_path" ]; then
    die "安装目标是符号链接，拒绝删除：$binary_path"
fi
if [ -e "$binary_path" ] && ! is_mindone_binary "$binary_path"; then
    die "目标不是可识别的 MindOne 可执行文件，拒绝删除：$binary_path"
fi

resolve_path_from_binary() {
    resolver_command=$1
    resolver_label=$2
    resolved_output=$("$binary_path" __worker "$resolver_command") \
        || die "无法通过已验证的 MindOne CLI 解析${resolver_label}；拒绝猜测路径"
    resolved_lines=$(printf '%s\n' "$resolved_output" | wc -l | tr -d '[:space:]')
    [ "$resolved_lines" -eq 1 ] \
        || die "MindOne CLI 返回了不唯一的${resolver_label}，拒绝继续"
    printf '%s\n' "$resolved_output"
}

validate_managed_directory() {
    managed_candidate=$1
    managed_label=$2
    validate_normalized_absolute_path "$managed_candidate" "$managed_label"
    assert_no_symlink_in_chain "$managed_candidate" "$managed_label"
    reject_broad_data_path "$managed_candidate"
    if [ -e "$managed_candidate" ]; then
        [ -d "$managed_candidate" ] || die "${managed_label}路径不是目录：$managed_candidate"
        managed_candidate=$(canonical_existing_directory "$managed_candidate") \
            || die "无法规范化${managed_label}：$managed_candidate"
        reject_broad_data_path "$managed_candidate"
    fi
    validated_managed_path=$managed_candidate
}

config_declares_custom_data_dir() {
    config_path=$1
    [ -e "$config_path" ] || return 1
    [ -f "$config_path" ] && [ ! -L "$config_path" ] \
        || die "配置路径不是普通文件，无法安全判断 data_dir：$config_path"
    LC_ALL=C grep -Eq "^[[:space:]]*(data_dir|\"data_dir\"|'data_dir')[[:space:]]*=" "$config_path"
}

binary_available=0
if is_mindone_binary "$binary_path"; then
    binary_available=1
fi

control_dir=$(default_control_dir)
if [ "$binary_available" -eq 1 ]; then
    data_dir=$(resolve_path_from_binary resolve-data-dir "实际数据目录")
    config_home=$(resolve_path_from_binary resolve-config-home "配置控制目录")
else
    validate_managed_directory "$control_dir" "配置控制目录"
    control_dir=$validated_managed_path
    data_dir=$control_dir
    config_home=$control_dir
    if [ "${MINDONE_HOME+x}" != "x" ] \
        && config_declares_custom_data_dir "$control_dir/config.toml"; then
        die "配置文件声明了自定义 data_dir，但已缺少可验证的 MindOne CLI；请恢复 CLI 解析真实路径，或显式设置 MINDONE_HOME 后重试"
    fi
fi

validate_managed_directory "$data_dir" "实际数据目录"
data_dir=$validated_managed_path
validate_managed_directory "$config_home" "配置控制目录"
config_home=$validated_managed_path

validate_all_purge_targets() {
    validate_purge_target "$data_dir"
    data_dir=$validated_purge_path
    if [ "$config_home" != "$data_dir" ]; then
        validate_purge_target "$config_home"
        config_home=$validated_purge_path
    fi
}

invoke_stop_for_root() {
    stop_root=$1
    stop_role=$2
    shift 2
    if [ "$stop_role" = "active" ]; then
        resolved_again=$(resolve_path_from_binary resolve-data-dir "实际数据目录")
        validate_managed_directory "$resolved_again" "实际数据目录"
        [ "$validated_managed_path" = "$stop_root" ] \
            || die "停止前 data_dir 已从 $stop_root 变为 $validated_managed_path，拒绝向不确定进程发送信号"
        "$binary_path" "$@"
    else
        MINDONE_HOME="$stop_root" "$binary_path" "$@"
    fi
}

stop_managed_root() {
    stop_root=$1
    stop_role=$2
    runtime_dir="$stop_root/runtime"
    share_state="$runtime_dir/share.json"
    serve_state="$runtime_dir/serve.json"
    if [ -L "$runtime_dir" ] || [ -L "$share_state" ] || [ -L "$serve_state" ]; then
        die "runtime 状态路径包含符号链接，拒绝执行或删除：$runtime_dir"
    fi
    share_may_be_running=0
    serve_may_be_running=0
    [ -f "$share_state" ] && share_may_be_running=1
    [ -f "$serve_state" ] && serve_may_be_running=1
    if [ "$share_may_be_running" -eq 0 ] && [ "$serve_may_be_running" -eq 0 ]; then
        return
    fi
    if [ "$binary_available" -ne 1 ]; then
        if [ "$FORCE" -ne 1 ]; then
            die "数据目录 $stop_root 存在服务状态但缺少可验证的 MindOne CLI，无法按 PID 与启动身份安全停止；请恢复 CLI 后重试，或明确使用 --force"
        fi
        warn "数据目录 $stop_root 存在服务状态，但 --force 已跳过安全停止；可能仍有运行进程"
        return
    fi
    if [ "$share_may_be_running" -eq 1 ]; then
        if ! invoke_stop_for_root "$stop_root" "$stop_role" \
            share unpublish --timeout "$STOP_TIMEOUT"; then
            if [ "$FORCE" -ne 1 ]; then
                die "共享 worker 未能按 PID 与启动身份安全排空；恢复协调服务器后重试，或明确使用 --force"
            fi
            warn "已通过 --force 跳过共享 worker 安全停止检查"
        fi
    fi
    if [ "$serve_may_be_running" -eq 1 ]; then
        if ! invoke_stop_for_root "$stop_root" "$stop_role" \
            serve stop --timeout "$STOP_TIMEOUT"; then
            if [ "$FORCE" -ne 1 ]; then
                die "推理服务未能按 PID 与启动身份安全停止；请处理错误后重试，或明确使用 --force"
            fi
            warn "已通过 --force 跳过推理服务安全停止检查"
        fi
    fi
    if { [ -f "$share_state" ] || [ -f "$serve_state" ]; } && [ "$FORCE" -ne 1 ]; then
        die "安全停止返回后仍存在 runtime 状态：$runtime_dir；拒绝继续卸载"
    fi
}

if [ "$PURGE_DATA" -eq 1 ]; then
    validate_all_purge_targets
fi

stop_managed_root "$data_dir" active
if [ "$config_home" != "$data_dir" ]; then
    stop_managed_root "$config_home" alternate
fi

if [ -e "$binary_path" ]; then
    confirm "将删除 ${binary_path}。" || die "已取消卸载，未删除文件"
    assert_no_symlink_in_chain "$INSTALL_DIR" "安装目录"
    is_mindone_binary "$binary_path" \
        || die "删除前安装目标已变化，拒绝继续：$binary_path"
    rm -f -- "$binary_path"
    [ ! -e "$binary_path" ] || die "无法删除 $binary_path"
    printf '已删除 MindOne CLI：%s\n' "$binary_path"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
else
    printf 'MindOne CLI 已不在安装目录：%s\n' "$binary_path"
fi

if [ "$KEEP_PATH" -eq 0 ]; then
    remove_managed_path_blocks
else
    printf '%s\n' '已按要求保留 shell 配置中的 MindOne 受管 PATH 块。'
fi

if [ "$PURGE_DATA" -eq 1 ]; then
    validate_all_purge_targets
    if [ "$config_home" = "$data_dir" ]; then
        purge_prompt="将永久删除 MindOne 自有数据与配置目录 ${data_dir}（模型、引擎、日志和配置）。"
    else
        purge_prompt="将永久删除 MindOne 实际数据目录 ${data_dir} 以及配置控制目录 ${config_home}（模型、引擎、日志和配置）。"
    fi
    confirm "$purge_prompt" || die "已保留 MindOne 数据目录"
    validate_all_purge_targets
    if [ -e "$data_dir" ]; then
        rm -rf -- "$data_dir"
        [ ! -e "$data_dir" ] || die "无法完整删除数据目录：$data_dir"
        printf '已删除 MindOne 数据目录：%s\n' "$data_dir"
    else
        printf 'MindOne 数据目录已不存在：%s\n' "$data_dir"
    fi
    if [ "$config_home" != "$data_dir" ]; then
        if [ -e "$config_home" ]; then
            validate_purge_target "$config_home"
            config_home=$validated_purge_path
            rm -rf -- "$config_home"
            [ ! -e "$config_home" ] || die "无法完整删除配置控制目录：$config_home"
            printf '已删除 MindOne 配置控制目录：%s\n' "$config_home"
        else
            printf 'MindOne 配置控制目录已不存在：%s\n' "$config_home"
        fi
    fi
elif [ "$config_home" = "$data_dir" ]; then
    printf '已保留 MindOne 数据：%s\n' "$data_dir"
else
    printf '已保留 MindOne 实际数据：%s\n' "$data_dir"
    printf '已保留 MindOne 配置：%s\n' "$config_home"
fi
