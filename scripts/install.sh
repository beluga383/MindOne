#!/bin/sh

set -eu

REPOSITORY="${MINDONE_REPOSITORY:-beluga383/MindOne}"
RELEASES_BASE="${MINDONE_RELEASE_BASE_URL:-https://github.com/${REPOSITORY}/releases}"
INSTALL_DIR="${MINDONE_INSTALL_DIR:-${HOME:?无法确定 HOME}/.local/bin}"
REQUESTED_VERSION="${MINDONE_VERSION:-}"
EXACT_RELEASE_URL="${MINDONE_RELEASE_URL:-}"
ALLOW_LOOPBACK_HTTP="${MINDONE_INSTALL_ALLOW_LOOPBACK_HTTP:-0}"
ALLOW_DOWNGRADE="${MINDONE_INSTALL_ALLOW_DOWNGRADE:-0}"
MODE="install"
LAUNCH="0"
NO_MODIFY_PATH="${MINDONE_INSTALL_NO_MODIFY_PATH:-0}"

usage() {
    cat <<'EOF'
MindOne 安装器

用法：
  install.sh [--check] [--launch] [--no-modify-path] [--version v1.0.0] [--allow-downgrade] [--install-dir 目录]

选项：
  --check             只检查已安装版本和最新发行版，不修改文件
  --launch            安装成功后在交互式终端直接打开 TUI
  --no-modify-path    不把安装目录写入当前用户 shell 的 PATH
  --version TAG       安装指定 GitHub Release 标签
  --allow-downgrade   明确允许用较旧版本替换当前安装；默认失败关闭
  --install-dir DIR   安装目录，默认 ~/.local/bin
  -h, --help          显示帮助

也可使用 MINDONE_VERSION、MINDONE_INSTALL_DIR、MINDONE_RELEASE_URL、
MINDONE_INSTALL_ALLOW_DOWNGRADE=1 和 MINDONE_INSTALL_NO_MODIFY_PATH=1。
MINDONE_RELEASE_URL 仅用于指定一个精确的 HTTPS 发行目录；自动化测试可在
MINDONE_INSTALL_ALLOW_LOOPBACK_HTTP=1 时使用 127.0.0.1/localhost HTTP。
EOF
}

die() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

# 安装目标会承载可执行文件；在创建目录或原子替换前拒绝会被文件系统
# 重解析的路径。不要把 `cd -P` 的结果当作许可：一旦出现链接即 fail-closed。
validate_normalized_absolute_path() {
    path_value=$1
    path_label=$2
    [ -n "$path_value" ] || die "无法确定${path_label}"
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
    # 路径已验证为绝对且规范化；禁用 glob 后可保留空格等合法文件名。
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

warn() {
    printf '警告：%s\n' "$*" >&2
}

path_profile_for_current_shell() {
    shell_value=${SHELL:-}
    shell_name=${shell_value##*/}
    case "$shell_name" in
        zsh) printf '%s\n' "$HOME/.zshrc" ;;
        bash)
            case "$(uname -s 2>/dev/null || true)" in
                Darwin) printf '%s\n' "$HOME/.bash_profile" ;;
                *) printf '%s\n' "$HOME/.bashrc" ;;
            esac
            ;;
        fish) printf '%s\n' "$HOME/.config/fish/conf.d/mindone.fish" ;;
        *) printf '%s\n' "$HOME/.profile" ;;
    esac
}

# 只维护带固定边界的最小 PATH 块；不执行 profile，也不解释其中任何内容。
# 对带 shell 元字符的自定义安装目录保守降级为提示，避免生成可执行配置。
persist_install_dir_on_path() {
    if printf '%s' "$INSTALL_DIR" | LC_ALL=C grep -q '[^A-Za-z0-9_./ -]'; then
        warn "安装目录包含不适合自动写入 shell 配置的字符；未持久修改 PATH：$INSTALL_DIR"
        return 0
    fi

    profile_path=$(path_profile_for_current_shell)
    case "$profile_path" in
        "$HOME"/*) ;;
        *) warn "无法确定 HOME 内的 shell 配置文件；未持久修改 PATH"; return 0 ;;
    esac
    profile_parent=$(dirname -- "$profile_path")
    if [ -L "$profile_path" ] || { [ -e "$profile_path" ] && [ ! -f "$profile_path" ]; }; then
        warn "shell 配置不是普通文件；未持久修改 PATH：$profile_path"
        return 0
    fi
    if [ -L "$profile_parent" ] || { [ -e "$profile_parent" ] && [ ! -d "$profile_parent" ]; }; then
        warn "shell 配置目录不是普通目录；未持久修改 PATH：$profile_parent"
        return 0
    fi
    mkdir -p "$profile_parent" || {
        warn "无法创建 shell 配置目录；未持久修改 PATH：$profile_parent"
        return 0
    }

    marker_start='# >>> MindOne CLI PATH (managed) >>>'
    marker_end='# <<< MindOne CLI PATH (managed) <<<'
    start_count=0
    end_count=0
    if [ -f "$profile_path" ]; then
        start_count=$(grep -Fxc "$marker_start" "$profile_path" || true)
        end_count=$(grep -Fxc "$marker_end" "$profile_path" || true)
    fi
    if { [ "$start_count" -ne 0 ] || [ "$end_count" -ne 0 ]; } \
        && { [ "$start_count" -ne 1 ] || [ "$end_count" -ne 1 ]; }; then
        warn "shell 配置中的 MindOne PATH 标记不完整或重复；为保护用户内容未修改：$profile_path"
        return 0
    fi
    if [ "$start_count" -eq 1 ]; then
        start_line=$(grep -Fn "$marker_start" "$profile_path" | awk -F: 'NR == 1 { print $1 }')
        end_line=$(grep -Fn "$marker_end" "$profile_path" | awk -F: 'NR == 1 { print $1 }')
        if [ "$start_line" -ge "$end_line" ]; then
            warn "shell 配置中的 MindOne PATH 标记顺序无效；为保护用户内容未修改：$profile_path"
            return 0
        fi
    fi

    profile_tmp=$(mktemp "$profile_parent/.mindone-profile.XXXXXX") || {
        warn "无法创建 shell 配置暂存文件；未持久修改 PATH"
        return 0
    }
    if [ -f "$profile_path" ]; then
        cp -p "$profile_path" "$profile_tmp" || {
            rm -f -- "$profile_tmp"
            profile_tmp=""
            warn "无法暂存 shell 配置；未持久修改 PATH：$profile_path"
            return 0
        }
        awk -v start="$marker_start" -v end="$marker_end" '
            $0 == start { skipping = 1; next }
            $0 == end { skipping = 0; next }
            !skipping { print }
        ' "$profile_path" >"$profile_tmp" || {
            rm -f -- "$profile_tmp"
            profile_tmp=""
            warn "无法更新 shell 配置；未持久修改 PATH：$profile_path"
            return 0
        }
    else
        : >"$profile_tmp"
    fi

    {
        printf '\n%s\n' "$marker_start"
        shell_value=${SHELL:-}
        if [ "${shell_value##*/}" = "fish" ]; then
            printf "fish_add_path --prepend --path '%s'\n" "$INSTALL_DIR"
        else
            printf "export PATH='%s':\"\$PATH\"\n" "$INSTALL_DIR"
        fi
        printf '%s\n' "$marker_end"
    } >>"$profile_tmp"
    if [ -L "$profile_path" ]; then
        rm -f -- "$profile_tmp"
        profile_tmp=""
        warn "shell 配置在更新期间变成了符号链接；未修改：$profile_path"
        return 0
    fi
    mv -f -- "$profile_tmp" "$profile_path" || {
        rm -f -- "$profile_tmp"
        profile_tmp=""
        warn "无法原子更新 shell 配置；未持久修改 PATH：$profile_path"
        return 0
    }
    profile_tmp=""
    printf '已把 MindOne 命令目录写入 %s；新终端可直接运行 mindone。\n' "$profile_path"
}

# 发行根地址随后会拼接固定文件名，因此必须是没有凭据、查询或片段的目录
# URL。只用 shell 解析安全相关的最小子集，避免 curl 对 userinfo、反斜杠或
# 伪 loopback authority 的宽松解释改变下载目标。
validate_release_url() {
    url_value=$1
    [ -n "$url_value" ] || die "发行地址不能为空"
    if printf '%s' "$url_value" | LC_ALL=C grep -q '[[:cntrl:][:space:]]'; then
        die "发行地址包含空白或控制字符"
    fi
    case "$url_value" in
        *'?'*|*'#'*) die "发行地址必须是目录 URL，不得包含查询参数或片段" ;;
        *\\*) die "发行地址不得包含反斜杠" ;;
    esac

    case "$url_value" in
        https://*)
            DOWNLOAD_SCHEME="https"
            authority_and_path=${url_value#https://}
            ;;
        http://*)
            DOWNLOAD_SCHEME="loopback-http"
            authority_and_path=${url_value#http://}
            ;;
        *) die "发行地址必须使用 HTTPS（本机测试例外）：$url_value" ;;
    esac

    authority=${authority_and_path%%/*}
    [ -n "$authority" ] || die "发行地址缺少主机名"
    case "$authority" in
        *@*) die "发行地址不得内嵌用户名或密码" ;;
    esac

    if [ "$DOWNLOAD_SCHEME" = "loopback-http" ]; then
        [ "$ALLOW_LOOPBACK_HTTP" = "1" ] \
            || die "HTTP 下载仅允许显式启用的本机自动化测试"
        case "$authority" in
            127.0.0.1:*|localhost:*) loopback_port=${authority##*:} ;;
            *) die "本机 HTTP 测试地址只能使用 127.0.0.1 或 localhost 的显式端口" ;;
        esac
        case "$loopback_port" in
            ""|*[!0-9]*) die "本机 HTTP 测试地址端口无效" ;;
            ??????*) die "本机 HTTP 测试地址端口无效" ;;
        esac
        [ "$loopback_port" -ge 1 ] && [ "$loopback_port" -le 65535 ] \
            || die "本机 HTTP 测试地址端口必须在 1..65535"
    fi
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

while [ "$#" -gt 0 ]; do
    case "$1" in
        --check)
            MODE="check"
            shift
            ;;
        --launch)
            LAUNCH="1"
            shift
            ;;
        --no-modify-path)
            NO_MODIFY_PATH="1"
            shift
            ;;
        --version)
            [ "$#" -ge 2 ] || die "--version 缺少发行标签"
            REQUESTED_VERSION=$2
            shift 2
            ;;
        --allow-downgrade)
            ALLOW_DOWNGRADE="1"
            shift
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || die "--install-dir 缺少目录"
            INSTALL_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "未知参数：$1"
            ;;
    esac
done

[ "$MODE" != "check" ] || [ "$LAUNCH" = "0" ] \
    || die "--check 与 --launch 不能同时使用"

case "$ALLOW_DOWNGRADE" in
    0|1) ;;
    *) die "MINDONE_INSTALL_ALLOW_DOWNGRADE 只能是 0 或 1" ;;
esac
case "$NO_MODIFY_PATH" in
    0|1) ;;
    *) die "MINDONE_INSTALL_NO_MODIFY_PATH 只能是 0 或 1" ;;
esac

validate_normalized_absolute_path "$INSTALL_DIR" "安装目录"
reject_broad_install_path "$INSTALL_DIR"
assert_no_symlink_in_chain "$INSTALL_DIR" "安装目录"

case "$REQUESTED_VERSION" in
    "") ;;
    *)
        printf '%s\n' "$REQUESTED_VERSION" \
            | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' \
            || die "发行标签必须形如 v1.0.0"
        ;;
esac

if [ -n "$EXACT_RELEASE_URL" ]; then
    RELEASE_URL=${EXACT_RELEASE_URL%/}
elif [ -n "$REQUESTED_VERSION" ]; then
    RELEASE_URL="${RELEASES_BASE%/}/download/${REQUESTED_VERSION}"
else
    RELEASE_URL="${RELEASES_BASE%/}/latest/download"
fi

validate_release_url "$RELEASE_URL"

command -v curl >/dev/null 2>&1 || die "缺少 curl"

fetch() {
    source_url=$1
    destination=$2
    maximum_bytes=$3
    if [ "$DOWNLOAD_SCHEME" = "https" ]; then
        if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
                --location --max-redirs 5 --fail --silent --show-error \
                --connect-timeout 15 --max-time 600 --max-filesize "$maximum_bytes" \
                --output "$destination" "$source_url"; then
            return 1
        fi
    else
        if ! curl --max-redirs 0 --fail --silent --show-error \
                --connect-timeout 5 --max-time 600 --max-filesize "$maximum_bytes" \
                --output "$destination" "$source_url"; then
            return 1
        fi
    fi
    [ -f "$destination" ] && [ ! -L "$destination" ] \
        || die "下载结果不是常规文件：$source_url"
    actual_bytes=$(wc -c <"$destination" | tr -d '[:space:]')
    printf '%s\n' "$actual_bytes" | grep -Eq '^[0-9]+$' \
        || die "无法确认下载文件大小：$source_url"
    [ "$actual_bytes" -le "$maximum_bytes" ] \
        || die "下载文件超过 ${maximum_bytes} bytes 安全上限：$source_url"
}

detect_target() {
    os=$(uname -s 2>/dev/null || true)
    arch=$(uname -m 2>/dev/null || true)
    case "$os:$arch" in
        Darwin:arm64|Darwin:aarch64) printf '%s\n' 'aarch64-apple-darwin' ;;
        Darwin:x86_64|Darwin:amd64) printf '%s\n' 'x86_64-apple-darwin' ;;
        Linux:x86_64|Linux:amd64) printf '%s\n' 'x86_64-unknown-linux-gnu' ;;
        Linux:aarch64|Linux:arm64) printf '%s\n' 'aarch64-unknown-linux-gnu' ;;
        *) die "当前系统或 CPU 架构没有官方发行包：${os:-未知}/${arch:-未知}" ;;
    esac
}

is_mindone_binary() {
    candidate=$1
    [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -x "$candidate" ] || return 1
    version_output=$("$candidate" --version 2>&1) || return 1
    [ "$(printf '%s\n' "$version_output" | wc -l | tr -d '[:space:]')" -eq 1 ] || return 1
    printf '%s\n' "$version_output" \
        | grep -Eq '^mindone [0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'
}

installed_version() {
    "$1" --version 2>&1 | awk 'NR == 1 { print $2 }'
}

# 输出 -1、0 或 1，分别表示左侧版本低于、等于或高于右侧版本。
# 实现 SemVer 2.0.0 的 precedence；build metadata 不参与比较，并避免把
# 任意长度数字标识符塞进 shell/awk 的有限整数类型。
compare_semver() {
    left_version=${1#v}
    right_version=${2#v}
    awk -v left="$left_version" -v right="$right_version" '
        function trim_zeros(value) {
            sub(/^0+/, "", value)
            return value == "" ? "0" : value
        }
        function compare_numeric(left_number, right_number, normalized_left, normalized_right) {
            normalized_left = trim_zeros(left_number)
            normalized_right = trim_zeros(right_number)
            if (length(normalized_left) < length(normalized_right)) return -1
            if (length(normalized_left) > length(normalized_right)) return 1
            if (("x" normalized_left) < ("x" normalized_right)) return -1
            if (("x" normalized_left) > ("x" normalized_right)) return 1
            return 0
        }
        function is_numeric(value) {
            return value ~ /^[0-9]+$/
        }
        function compare_identifier(left_id, right_id, result) {
            if (is_numeric(left_id) && is_numeric(right_id)) {
                return compare_numeric(left_id, right_id)
            }
            if (is_numeric(left_id)) return -1
            if (is_numeric(right_id)) return 1
            if (("x" left_id) < ("x" right_id)) return -1
            if (("x" left_id) > ("x" right_id)) return 1
            return 0
        }
        function compare_version(left_value, right_value, left_dash, right_dash,
                                 left_core, right_core, left_pre, right_pre,
                                 left_core_parts, right_core_parts,
                                 left_pre_parts, right_pre_parts,
                                 left_pre_count, right_pre_count, part_index, result) {
            sub(/\+.*/, "", left_value)
            sub(/\+.*/, "", right_value)
            left_dash = index(left_value, "-")
            right_dash = index(right_value, "-")
            left_core = left_dash ? substr(left_value, 1, left_dash - 1) : left_value
            right_core = right_dash ? substr(right_value, 1, right_dash - 1) : right_value
            left_pre = left_dash ? substr(left_value, left_dash + 1) : ""
            right_pre = right_dash ? substr(right_value, right_dash + 1) : ""
            split(left_core, left_core_parts, ".")
            split(right_core, right_core_parts, ".")
            for (part_index = 1; part_index <= 3; part_index++) {
                result = compare_numeric(left_core_parts[part_index], right_core_parts[part_index])
                if (result != 0) return result
            }
            if (left_pre == "" && right_pre == "") return 0
            if (left_pre == "") return 1
            if (right_pre == "") return -1
            left_pre_count = split(left_pre, left_pre_parts, ".")
            right_pre_count = split(right_pre, right_pre_parts, ".")
            for (part_index = 1; part_index <= left_pre_count && part_index <= right_pre_count; part_index++) {
                result = compare_identifier(left_pre_parts[part_index], right_pre_parts[part_index])
                if (result != 0) return result
            }
            if (left_pre_count < right_pre_count) return -1
            if (left_pre_count > right_pre_count) return 1
            return 0
        }
        BEGIN { print compare_version(left, right) }
    '
}

tmp_dir=""
staged_binary=""
profile_tmp=""
cleanup() {
    if [ -n "$staged_binary" ]; then
        rm -f -- "$staged_binary"
    fi
    if [ -n "$tmp_dir" ]; then
        rm -rf -- "$tmp_dir"
    fi
    if [ -n "$profile_tmp" ]; then
        rm -f -- "$profile_tmp"
    fi
}
trap cleanup 0 1 2 15

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mindone-install.XXXXXX") || die "无法创建临时目录"
release_version_file="$tmp_dir/release-version.txt"
fetch "$RELEASE_URL/release-version.txt" "$release_version_file" 128 \
    || die "无法读取发行版本"
release_tag=$(sed -n '1{s/[[:space:]]//g;p;}' "$release_version_file")
[ "$(wc -l <"$release_version_file" | tr -d '[:space:]')" -eq 1 ] \
    || die "发行版本文件必须且只能包含一行"
printf '%s\n' "$release_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' \
    || die "发行版本文件格式无效"
if [ -n "$REQUESTED_VERSION" ] && [ "$release_tag" != "$REQUESTED_VERSION" ]; then
    die "发行目录版本为 ${release_tag}，与请求的 $REQUESTED_VERSION 不一致"
fi

binary_path="$INSTALL_DIR/mindone"
if [ "$MODE" = "check" ]; then
    if ! is_mindone_binary "$binary_path"; then
        printf 'MindOne 尚未安装在 %s\n' "$binary_path"
        printf '最新发行版：%s\n' "$release_tag"
        exit 0
    fi
    current=$(installed_version "$binary_path")
    latest=${release_tag#v}
    version_order=$(compare_semver "$current" "$latest")
    case "$version_order" in
        0) printf 'MindOne 已是最新版本：%s\n' "$current" ;;
        -1) printf 'MindOne 可更新：已安装 %s，发行版 %s\n' "$current" "$latest" ;;
        1) printf 'MindOne 已安装版本 %s 高于所查发行版 %s，无需更新。\n' "$current" "$latest" ;;
        *) die "无法比较已安装版本 $current 与发行版 $latest" ;;
    esac
    exit 0
fi

if is_mindone_binary "$binary_path"; then
    current=$(installed_version "$binary_path")
    target_version=${release_tag#v}
    version_order=$(compare_semver "$current" "$target_version")
    case "$version_order" in
        0|-1) ;;
        1)
            [ "$ALLOW_DOWNGRADE" = "1" ] \
                || die "拒绝把 MindOne 从 ${current} 降级到 ${target_version}；如确有需要，请显式传入 --allow-downgrade"
            printf '警告：已明确允许把 MindOne 从 %s 降级到 %s。\n' \
                "$current" "$target_version" >&2
            ;;
        *) die "无法比较已安装版本 $current 与发行版 $target_version" ;;
    esac
fi

command -v tar >/dev/null 2>&1 || die "缺少 tar"
target=$(detect_target)
artifact="mindone-${target}.tar.gz"
archive="$tmp_dir/$artifact"
checksums="$tmp_dir/checksums.sha256"

printf '正在下载 MindOne %s（%s）…\n' "$release_tag" "$target"
fetch "$RELEASE_URL/checksums.sha256" "$checksums" 262144 \
    || die "无法下载 SHA-256 清单"
fetch "$RELEASE_URL/$artifact" "$archive" 1073741824 \
    || die "无法下载发行包 $artifact"

expected=$(awk -v wanted="$artifact" '
    NF >= 2 {
        name=$2
        sub(/^\*/, "", name)
        if (name == wanted) print tolower($1)
    }
' "$checksums")
expected_count=$(printf '%s\n' "$expected" | awk 'NF { count++ } END { print count + 0 }')
[ "$expected_count" -eq 1 ] || die "SHA-256 清单中必须且只能有一条 $artifact 记录"
printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die "SHA-256 清单格式无效"

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive" | awk '{ print tolower($1) }')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$archive" | awk '{ print tolower($1) }')
elif command -v openssl >/dev/null 2>&1; then
    actual=$(openssl dgst -sha256 "$archive" | awk '{ print tolower($NF) }')
else
    die "缺少 sha256sum、shasum 或 openssl，无法验证发行包"
fi
[ "$actual" = "$expected" ] || die "发行包 SHA-256 不匹配，已拒绝安装"

listing="$tmp_dir/archive-list.txt"
tar -tzf "$archive" >"$listing" || die "发行包无法读取"
mindone_count=0
license_count=0
signing_count=0
while IFS= read -r entry; do
    normalized=${entry#./}
    case "$normalized" in
        mindone) mindone_count=$((mindone_count + 1)) ;;
        LICENSE) license_count=$((license_count + 1)) ;;
        CODE_SIGNING.txt) signing_count=$((signing_count + 1)) ;;
        "") die "发行包包含空路径记录，已拒绝解压" ;;
        /*) die "发行包包含绝对路径，已拒绝解压" ;;
        ../*|*/../*|*/..) die "发行包包含路径穿越，已拒绝解压" ;;
        *) die "发行包包含未声明文件：$normalized" ;;
    esac
done <"$listing"
[ "$mindone_count" -eq 1 ] \
    && [ "$license_count" -eq 1 ] \
    && [ "$signing_count" -eq 1 ] \
    || die "发行包必须且只能各包含一份 mindone、LICENSE 和 CODE_SIGNING.txt"
verbose_listing="$tmp_dir/archive-verbose-list.txt"
tar -tvzf "$archive" >"$verbose_listing" || die "发行包详细目录无法读取"
if awk 'substr($0, 1, 1) != "-" { bad = 1 } END { exit bad ? 0 : 1 }' "$verbose_listing"; then
    die "发行包包含非普通文件（目录、链接、设备或 FIFO），已拒绝解压"
fi

extract_dir="$tmp_dir/extract"
mkdir "$extract_dir"
tar -xzf "$archive" -C "$extract_dir" || die "发行包解压失败"
candidate="$extract_dir/mindone"
[ -f "$candidate" ] && [ ! -L "$candidate" ] || die "发行包缺少常规文件 mindone"
chmod 755 "$candidate" || die "无法设置可执行权限"
is_mindone_binary "$candidate" || die "下载的可执行文件无法通过 --version 自检"
downloaded_version=$(installed_version "$candidate")
[ "$downloaded_version" = "${release_tag#v}" ] \
    || die "可执行文件版本 $downloaded_version 与发行版本 ${release_tag#v} 不一致"

if [ -L "$binary_path" ]; then
    die "安装目标是符号链接，拒绝覆盖：$binary_path"
fi
if [ -e "$binary_path" ] && ! is_mindone_binary "$binary_path"; then
    die "安装目标已有非 MindOne 文件，拒绝覆盖：$binary_path"
fi
mkdir -p "$INSTALL_DIR" || die "无法创建安装目录：$INSTALL_DIR"
[ -d "$INSTALL_DIR" ] || die "安装目录路径不是目录：$INSTALL_DIR"
assert_no_symlink_in_chain "$INSTALL_DIR" "安装目录"
[ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ] || die "安装目录不可写：$INSTALL_DIR"

staged_binary=$(mktemp "$INSTALL_DIR/.mindone.new.XXXXXX") \
    || die "无法安全创建安装暂存文件"
[ -f "$staged_binary" ] && [ ! -L "$staged_binary" ] \
    || die "安装暂存文件不是常规文件"
cp "$candidate" "$staged_binary" || die "无法暂存 MindOne 可执行文件"
chmod 755 "$staged_binary" || die "无法设置暂存文件权限"
is_mindone_binary "$staged_binary" || die "暂存文件自检失败"
mv -f "$staged_binary" "$binary_path" || die "无法原子安装到 $binary_path"
staged_binary=""

printf 'MindOne %s 已安装：%s\n' "$downloaded_version" "$binary_path"
if [ "$NO_MODIFY_PATH" = "0" ]; then
    persist_install_dir_on_path
else
    printf '已按要求不修改 PATH；可直接运行 %s。\n' "$binary_path"
fi
PATH="$INSTALL_DIR:${PATH:-}"
export PATH
printf '%s\n' '再次运行安装器并传入 --check 可检查更新；卸载请使用 scripts/uninstall.sh。'

if [ "$LAUNCH" = "1" ]; then
    if [ -t 0 ] && [ -t 1 ]; then
        printf '%s\n' '正在打开 MindOne TUI…'
        cleanup
        tmp_dir=""
        exec "$binary_path"
    fi
    printf '%s\n' '当前不是交互式终端；已完成安装并用帮助页验证 CLI，未进入 TUI。'
    "$binary_path" --help
fi
