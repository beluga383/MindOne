#!/bin/sh

set -eu

fail() {
    printf '卸载安全 smoke 失败：%s\n' "$*" >&2
    exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
uninstaller="$script_dir/uninstall.sh"
test_shell=${MINDONE_TEST_SHELL:-sh}
command -v "$test_shell" >/dev/null 2>&1 || fail "找不到测试 shell：$test_shell"
[ "$#" -eq 1 ] || fail "用法：uninstall-smoke.sh /绝对或相对路径/mindone"

binary_input=$1
case "$binary_input" in
    /*) binary_source=$binary_input ;;
    *)
        binary_parent=$(CDPATH= cd -- "$(dirname -- "$binary_input")" && pwd -P) \
            || fail "无法解析测试二进制父目录"
        binary_source="$binary_parent/$(basename -- "$binary_input")"
        ;;
esac
[ -f "$binary_source" ] && [ ! -L "$binary_source" ] && [ -x "$binary_source" ] \
    || fail "测试二进制不是普通可执行文件：$binary_source"
"$binary_source" --version | grep -Eq '^mindone [0-9]+\.[0-9]+\.[0-9]+' \
    || fail "测试二进制不是 MindOne"

temporary_base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temporary_base=${temporary_base%/}
test_root=$(mktemp -d "$temporary_base/mindone-uninstall-smoke.XXXXXX") \
    || fail "无法创建隔离测试目录"
test_root=$(CDPATH= cd -- "$test_root" && pwd -P) \
    || fail "无法规范化隔离测试目录"
cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup 0 1 2 15

copy_binary() {
    destination=$1
    mkdir -p "$(dirname -- "$destination")"
    cp "$binary_source" "$destination"
    chmod 755 "$destination"
}

expect_failure() {
    label=$1
    log_file=$2
    shift 2
    if "$@" >"$log_file" 2>&1; then
        fail "$label 本应被拒绝"
    fi
    grep -F '错误：' "$log_file" >/dev/null \
        || fail "$label 没有返回中文错误"
}

# 默认卸载只删除 CLI；显式 purge 只删除经过所有权检查的数据目录。
normal="$test_root/normal"
normal_home="$normal/home"
normal_install="$normal/bin"
normal_data="$normal/data"
mkdir -p "$normal_home" "$normal_data/models"
printf 'preserve\n' >"$normal_data/models/marker"
copy_binary "$normal_install/mindone"
env HOME="$normal_home" MINDONE_HOME="$normal_data" MINDONE_INSTALL_DIR="$normal_install" \
    "$test_shell" "$uninstaller" --yes
[ ! -e "$normal_install/mindone" ] || fail "默认卸载没有删除 CLI"
[ -f "$normal_data/models/marker" ] || fail "默认卸载误删数据"
copy_binary "$normal_install/mindone"
env HOME="$normal_home" MINDONE_HOME="$normal_data" MINDONE_INSTALL_DIR="$normal_install" \
    "$test_shell" "$uninstaller" --yes --purge-data
[ ! -e "$normal_install/mindone" ] || fail "purge 没有删除 CLI"
[ ! -e "$normal_data" ] || fail "purge 没有删除自有数据目录"

# 未设置 MINDONE_HOME 时，卸载器必须通过已验证 CLI 解析 config.toml 中实际生效的
# data_dir；默认卸载保留实际数据和控制配置，purge 同时删除两处。
configured="$test_root/configured-data-dir"
configured_home="$configured/home"
configured_install="$configured/bin"
configured_data="$configured/active-data"
case "$(uname -s 2>/dev/null || true)" in
    Darwin) configured_control="$configured_home/Library/Application Support/MindOne" ;;
    Linux) configured_control="$configured_home/.local/share/mindone" ;;
    *) configured_control= ;;
esac
if [ -n "$configured_control" ]; then
    mkdir -p "$configured_control" "$configured_data/models"
    printf 'data_dir = "%s"\n' "$configured_data" >"$configured_control/config.toml"
    printf 'configured-preserve\n' >"$configured_data/models/marker"
    copy_binary "$configured_install/mindone"
    (
        unset MINDONE_HOME
        HOME="$configured_home" MINDONE_INSTALL_DIR="$configured_install" \
            "$test_shell" "$uninstaller" --yes
    )
    [ ! -e "$configured_install/mindone" ] || fail "自定义 data_dir 默认卸载没有删除 CLI"
    [ -f "$configured_data/models/marker" ] || fail "自定义 data_dir 默认卸载误删实际数据"
    [ -f "$configured_control/config.toml" ] || fail "自定义 data_dir 默认卸载误删控制配置"

    copy_binary "$configured_install/mindone"
    (
        unset MINDONE_HOME
        HOME="$configured_home" MINDONE_INSTALL_DIR="$configured_install" \
            "$test_shell" "$uninstaller" --yes --purge-data
    )
    [ ! -e "$configured_install/mindone" ] || fail "自定义 data_dir purge 没有删除 CLI"
    [ ! -e "$configured_data" ] || fail "自定义 data_dir purge 没有删除实际数据"
    [ ! -e "$configured_control" ] || fail "自定义 data_dir purge 没有删除控制配置"
fi

# 管道执行不能从脚本 stdin 偷读确认；无控制终端时必须明确要求 --yes。
if command -v setsid >/dev/null 2>&1; then
    piped="$test_root/piped-confirmation"
    mkdir -p "$piped/home" "$piped/data" "$piped/bin"
    copy_binary "$piped/bin/mindone"
    if printf 'yes\n' | setsid env HOME="$piped/home" MINDONE_HOME="$piped/data" \
        MINDONE_INSTALL_DIR="$piped/bin" "$test_shell" "$uninstaller" \
        >"$piped/rejected.log" 2>&1; then
        fail "无 TTY 的管道卸载本应要求 --yes"
    fi
    grep -F -- '--yes' "$piped/rejected.log" >/dev/null \
        || fail "无 TTY 的管道卸载没有说明 --yes 合同"
    [ -x "$piped/bin/mindone" ] || fail "无 TTY 确认失败前误删 CLI"
fi

# 安装目标本身是 symlink 时，不得执行或删除其目标。
target_link="$test_root/target-link"
mkdir -p "$target_link/home" "$target_link/bin" "$target_link/data"
copy_binary "$target_link/victim"
victim_before=$(cksum "$target_link/victim")
ln -s "$target_link/victim" "$target_link/bin/mindone"
expect_failure "安装目标 symlink" "$target_link/rejected.log" \
    env HOME="$target_link/home" MINDONE_HOME="$target_link/data" \
    MINDONE_INSTALL_DIR="$target_link/bin" "$test_shell" "$uninstaller" --yes
[ -L "$target_link/bin/mindone" ] || fail "拒绝后安装目标 symlink 已变化"
[ "$(cksum "$target_link/victim")" = "$victim_before" ] \
    || fail "拒绝安装目标 symlink 时修改了目标文件"

# 任何现有父目录是 symlink 都必须在删除前失败。
parent_link="$test_root/parent-link"
mkdir -p "$parent_link/home" "$parent_link/real/install" "$parent_link/data"
copy_binary "$parent_link/real/install/mindone"
parent_before=$(cksum "$parent_link/real/install/mindone")
ln -s "$parent_link/real" "$parent_link/linked-parent"
expect_failure "安装目录父链 symlink" "$parent_link/rejected.log" \
    env HOME="$parent_link/home" MINDONE_HOME="$parent_link/data" \
    MINDONE_INSTALL_DIR="$parent_link/linked-parent/install" "$test_shell" "$uninstaller" --yes
[ "$(cksum "$parent_link/real/install/mindone")" = "$parent_before" ] \
    || fail "拒绝父链 symlink 时修改了真实二进制"

# 数据根 symlink 也不得被 canonicalize 后当作自有目录递归删除。
data_link="$test_root/data-link"
mkdir -p "$data_link/home" "$data_link/bin" "$data_link/real-data/models"
printf 'keep\n' >"$data_link/real-data/models/sentinel"
copy_binary "$data_link/bin/mindone"
ln -s "$data_link/real-data" "$data_link/linked-data"
expect_failure "数据根 symlink" "$data_link/rejected.log" \
    env HOME="$data_link/home" MINDONE_HOME="$data_link/linked-data" \
    MINDONE_INSTALL_DIR="$data_link/bin" "$test_shell" "$uninstaller" --yes --purge-data
[ -f "$data_link/real-data/models/sentinel" ] || fail "拒绝数据 symlink 时误删目标"
[ -x "$data_link/bin/mindone" ] || fail "拒绝数据 symlink 前误删 CLI"

# HOME 是宽路径；即使它只含看似自有的目录，也不得作为 purge 根。
broad="$test_root/broad"
mkdir -p "$broad/home/models" "$broad/bin"
copy_binary "$broad/bin/mindone"
expect_failure "宽泛 HOME 数据路径" "$broad/rejected.log" \
    env HOME="$broad/home" MINDONE_HOME="$broad/home" MINDONE_INSTALL_DIR="$broad/bin" \
    "$test_shell" "$uninstaller" --yes --purge-data
[ -d "$broad/home" ] && [ -x "$broad/bin/mindone" ] \
    || fail "拒绝宽路径前发生删除"

# 有运行状态而 CLI 缺失时，除非显式 --force，否则不能 purge。
orphan="$test_root/orphan"
mkdir -p "$orphan/home" "$orphan/data/runtime" "$orphan/bin"
printf '{}\n' >"$orphan/data/runtime/serve.json"
expect_failure "缺少 CLI 的服务状态" "$orphan/rejected.log" \
    env HOME="$orphan/home" MINDONE_HOME="$orphan/data" MINDONE_INSTALL_DIR="$orphan/bin" \
    "$test_shell" "$uninstaller" --yes --purge-data
[ -f "$orphan/data/runtime/serve.json" ] \
    || fail "安全停止失败时误删服务状态"

# 服务状态与伪造 CLI 同时存在也必须拒绝：不能对未知二进制执行 stop，
# 更不能在拒绝前删除 CLI 或 runtime 状态。
mismatched="$test_root/mismatched-cli"
mkdir -p "$mismatched/home" "$mismatched/data/runtime" "$mismatched/bin"
printf '{}\n' >"$mismatched/data/runtime/share.json"
printf '%s\n' '#!/bin/sh' 'printf "not-mindone 9.9.9\\n"' >"$mismatched/bin/mindone"
chmod 755 "$mismatched/bin/mindone"
mismatched_before=$(cksum "$mismatched/bin/mindone")
expect_failure "服务状态与伪造 CLI 不一致" "$mismatched/rejected.log" \
    env HOME="$mismatched/home" MINDONE_HOME="$mismatched/data" \
    MINDONE_INSTALL_DIR="$mismatched/bin" "$test_shell" "$uninstaller" --yes --purge-data
[ -f "$mismatched/data/runtime/share.json" ] \
    && [ "$(cksum "$mismatched/bin/mindone")" = "$mismatched_before" ] \
    || fail "拒绝伪造 CLI 与服务状态不一致时发生删除"

# 外部顶层文件与伪装成 mindone 的非 MindOne 文件都必须原样保留。
foreign="$test_root/foreign"
mkdir -p "$foreign/home" "$foreign/data/models" "$foreign/bin"
printf 'not-owned\n' >"$foreign/data/foreign.txt"
copy_binary "$foreign/bin/mindone"
foreign_cli_before=$(cksum "$foreign/bin/mindone")
expect_failure "非 MindOne 顶层数据" "$foreign/data-rejected.log" \
    env HOME="$foreign/home" MINDONE_HOME="$foreign/data" MINDONE_INSTALL_DIR="$foreign/bin" \
    "$test_shell" "$uninstaller" --yes --purge-data
[ -f "$foreign/data/foreign.txt" ] \
    && [ "$(cksum "$foreign/bin/mindone")" = "$foreign_cli_before" ] \
    || fail "拒绝外部数据时发生删除"

fake="$test_root/fake"
mkdir -p "$fake/home" "$fake/data" "$fake/bin"
printf '%s\n' '#!/bin/sh' 'printf "not-mindone 9.9.9\\n"' >"$fake/bin/mindone"
chmod 755 "$fake/bin/mindone"
fake_before=$(cksum "$fake/bin/mindone")
expect_failure "非 MindOne 安装目标" "$fake/rejected.log" \
    env HOME="$fake/home" MINDONE_HOME="$fake/data" MINDONE_INSTALL_DIR="$fake/bin" \
    "$test_shell" "$uninstaller" --yes
[ "$(cksum "$fake/bin/mindone")" = "$fake_before" ] \
    || fail "拒绝非 MindOne 安装目标时修改了文件"

printf '%s\n' 'Unix 卸载安全 smoke 通过'
