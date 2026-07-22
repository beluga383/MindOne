#!/bin/sh

# 使用当前平台已构建的真实 CLI 组装本地发行包，并闭环验证安装、检查更新、
# 重装、默认卸载和显式 purge。只操作本脚本创建的 mktemp 目录。

set -eu

fail() {
    printf '发行安装烟测失败：%s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "用法：release-archive-smoke.sh /路径/mindone"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) \
    || fail "无法定位 scripts 目录"
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P) || fail "无法定位仓库根目录"
SOURCE_INPUT=$1
SOURCE_DIR=$(dirname -- "$SOURCE_INPUT")
SOURCE_NAME=$(basename -- "$SOURCE_INPUT")
SOURCE_DIR=$(CDPATH= cd -- "$SOURCE_DIR" && pwd -P) \
    || fail "无法定位 CLI 所在目录：$SOURCE_INPUT"
SOURCE_BINARY="$SOURCE_DIR/$SOURCE_NAME"
[ -f "$SOURCE_BINARY" ] && [ ! -L "$SOURCE_BINARY" ] && [ -x "$SOURCE_BINARY" ] \
    || fail "CLI 必须是可执行普通文件且不能是符号链接：$SOURCE_BINARY"
[ -f "$ROOT/LICENSE" ] && [ ! -L "$ROOT/LICENSE" ] || fail "仓库缺少普通文件 LICENSE"

VERSION_OUTPUT=$("$SOURCE_BINARY" --version 2>&1) || fail "CLI --version 自检失败"
[ "$(printf '%s\n' "$VERSION_OUTPUT" | wc -l | tr -d '[:space:]')" -eq 1 ] \
    || fail "CLI --version 必须只输出一行"
printf '%s\n' "$VERSION_OUTPUT" | grep -Eq \
    '^mindone [0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' \
    || fail "CLI --version 格式无效：$VERSION_OUTPUT"
VERSION=${VERSION_OUTPUT#mindone }
RELEASE_TAG="v$VERSION"

case "$(uname -s 2>/dev/null):$(uname -m 2>/dev/null)" in
    Darwin:arm64|Darwin:aarch64) TARGET=aarch64-apple-darwin ;;
    Darwin:x86_64|Darwin:amd64) TARGET=x86_64-apple-darwin ;;
    Linux:x86_64|Linux:amd64) TARGET=x86_64-unknown-linux-gnu ;;
    Linux:aarch64|Linux:arm64) TARGET=aarch64-unknown-linux-gnu ;;
    *) fail "当前平台没有 Unix 发行包合同" ;;
esac

TEMPORARY_BASE=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P) \
    || fail "无法规范化临时目录根"
TEST_ROOT=$(mktemp -d "$TEMPORARY_BASE/mindone-release-smoke.XXXXXX") \
    || fail "无法创建隔离临时目录"
TEST_ROOT=$(CDPATH= cd -- "$TEST_ROOT" && pwd -P) || fail "无法规范化临时目录"
SERVER_PID=

cleanup() {
    original_status=$?
    set +e
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    case "$TEST_ROOT" in
        "$TEMPORARY_BASE"/mindone-release-smoke.*)
            [ -d "$TEST_ROOT" ] && rm -rf -- "$TEST_ROOT"
            ;;
        *) printf '拒绝清理非烟测临时目录：%s\n' "$TEST_ROOT" >&2 ;;
    esac
    exit "$original_status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

RELEASE_DIR="$TEST_ROOT/release"
STAGE_DIR="$TEST_ROOT/stage"
INSTALL_DIR="$TEST_ROOT/install/bin"
TEST_HOME="$TEST_ROOT/home"
DATA_DIR="$TEST_ROOT/data"
PORT_FILE="$TEST_ROOT/http-port"
mkdir -p "$RELEASE_DIR" "$STAGE_DIR" "$INSTALL_DIR" "$TEST_HOME"
cp "$SOURCE_BINARY" "$STAGE_DIR/mindone"
cp "$ROOT/LICENSE" "$STAGE_DIR/LICENSE"
chmod 755 "$STAGE_DIR/mindone"
printf '%s\n' \
    'MindOne 本地发行安装烟测包。' \
    'SIGNING_STATUS=unsigned-local-smoke' \
    '正式公测发行需要平台代码签名凭据。' \
    >"$STAGE_DIR/CODE_SIGNING.txt"

ARTIFACT="mindone-${TARGET}.tar.gz"
(CDPATH= cd -- "$STAGE_DIR" && \
    tar -czf "$RELEASE_DIR/$ARTIFACT" mindone LICENSE CODE_SIGNING.txt) \
    || fail "无法组装本地发行包"
printf '%s\n' "$RELEASE_TAG" >"$RELEASE_DIR/release-version.txt"
if command -v shasum >/dev/null 2>&1; then
    (CDPATH= cd -- "$RELEASE_DIR" && shasum -a 256 "$ARTIFACT") \
        >"$RELEASE_DIR/checksums.sha256"
elif command -v sha256sum >/dev/null 2>&1; then
    (CDPATH= cd -- "$RELEASE_DIR" && sha256sum "$ARTIFACT") \
        >"$RELEASE_DIR/checksums.sha256"
else
    fail "缺少 shasum 或 sha256sum"
fi

python3 - "$RELEASE_DIR" "$PORT_FILE" <<'PY' >"$TEST_ROOT/http.log" 2>&1 &
import functools
import http.server
import pathlib
import sys

directory = pathlib.Path(sys.argv[1]).resolve(strict=True)
port_file = pathlib.Path(sys.argv[2])
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
port_file.write_text(str(server.server_address[1]), encoding="ascii")
server.serve_forever()
PY
SERVER_PID=$!
count=0
while [ ! -s "$PORT_FILE" ] && [ "$count" -lt 100 ]; do
    kill -0 "$SERVER_PID" 2>/dev/null || fail "loopback 发行服务提前退出"
    count=$((count + 1))
    sleep 0.05
done
[ -s "$PORT_FILE" ] || fail "loopback 发行服务未报告端口"
HTTP_PORT=$(cat "$PORT_FILE")
printf '%s\n' "$HTTP_PORT" | grep -Eq '^[0-9]+$' || fail "loopback 端口格式无效"
RELEASE_URL="http://127.0.0.1:${HTTP_PORT}"

run_installer() {
    env HOME="$TEST_HOME" SHELL=/bin/sh MINDONE_HOME="$DATA_DIR" \
        MINDONE_INSTALL_DIR="$INSTALL_DIR" \
        MINDONE_RELEASE_URL="$RELEASE_URL" \
        MINDONE_INSTALL_ALLOW_LOOPBACK_HTTP=1 \
        sh "$ROOT/scripts/install.sh" "$@"
}

run_uninstaller() {
    env HOME="$TEST_HOME" MINDONE_HOME="$DATA_DIR" \
        MINDONE_INSTALL_DIR="$INSTALL_DIR" \
        sh "$ROOT/scripts/uninstall.sh" "$@"
}

INSTALLED="$INSTALL_DIR/mindone"

verify_installed_binary() {
    [ -f "$INSTALLED" ] && [ ! -L "$INSTALLED" ] && [ -x "$INSTALLED" ] \
        || fail "安装器没有生成安全的可执行文件"
    installed_version=$("$INSTALLED" --version 2>&1) \
        || fail "安装后的 CLI --version 自检失败"
    [ "$installed_version" = "$VERSION_OUTPUT" ] || fail "安装后版本不匹配"
    cmp "$SOURCE_BINARY" "$INSTALLED" >/dev/null 2>&1 \
        || fail "安装后的 CLI 与归档源二进制内容不一致"
}

run_installer
verify_installed_binary
[ -f "$TEST_HOME/.profile" ] || fail "安装器没有创建当前 shell 的 PATH 配置"
[ "$(grep -Fxc '# >>> MindOne CLI PATH (managed) >>>' "$TEST_HOME/.profile")" -eq 1 ] \
    || fail "安装器没有生成唯一的受管 PATH 块"
env HOME="$TEST_HOME" PATH=/usr/bin:/bin sh -c \
    '. "$HOME/.profile"; mindone --version' \
    | grep -Fx "$VERSION_OUTPUT" >/dev/null \
    || fail "新 shell 无法通过裸 mindone 解析已安装 CLI"
run_installer --launch >"$TEST_ROOT/launch.txt"
grep -q '当前不是交互式终端' "$TEST_ROOT/launch.txt" \
    || fail "--launch 没有在非交互环境安全降级"
grep -q '用法：mindone' "$TEST_ROOT/launch.txt" \
    || fail "--launch 非交互降级没有执行真实 CLI 帮助"
verify_installed_binary
"$INSTALLED" --help >"$TEST_ROOT/help.txt"
grep -q '用法：mindone' "$TEST_ROOT/help.txt" || fail "安装后根帮助不是简体中文"
grep -q '管理身份、系统凭证和远程证明' "$TEST_ROOT/help.txt" \
    || fail "安装后根帮助缺少真实命令说明"
env HOME="$TEST_HOME" MINDONE_HOME="$DATA_DIR" \
    "$INSTALLED" config set server.url "$RELEASE_URL" --quiet

set +e
env HOME="$TEST_HOME" MINDONE_HOME="$DATA_DIR" \
    "$INSTALLED" --json doctor >"$TEST_ROOT/doctor.json" 2>"$TEST_ROOT/doctor.err"
DOCTOR_STATUS=$?
set -e
case "$DOCTOR_STATUS" in 0|1|31) ;; *) fail "doctor 返回未声明退出码 $DOCTOR_STATUS" ;; esac
python3 - "$TEST_ROOT/doctor.json" "$DOCTOR_STATUS" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
expected = int(sys.argv[2])
if not isinstance(value, dict):
    raise SystemExit("doctor JSON 顶层必须是对象")
if type(value.get("code")) is not int or value["code"] != expected:
    raise SystemExit("doctor JSON code 与退出码不一致")
if value.get("ok") is not (expected == 0):
    raise SystemExit("doctor JSON envelope 与退出码不一致")
data = value.get("data")
if not isinstance(data, dict) or not isinstance(data.get("checks"), list) or not data["checks"]:
    raise SystemExit("doctor 没有执行真实检查")
summary = data.get("summary")
names = ("passed", "warnings", "failures", "trust_downgrades")
if not isinstance(summary, dict) or any(
    type(summary.get(name)) is not int or summary[name] < 0 for name in names
):
    raise SystemExit("doctor 缺少结构化汇总")
passed, warnings, failures, trust_downgrades = (summary[name] for name in names)
if passed + warnings + failures != len(data["checks"]):
    raise SystemExit("doctor 汇总计数与检查列表不一致")
if trust_downgrades > warnings:
    raise SystemExit("doctor 信任降级数不能超过警告数")
if expected == 1:
    decision_matches = failures > 0
elif expected == 31:
    decision_matches = failures == 0 and trust_downgrades > 0
else:
    decision_matches = failures == 0 and trust_downgrades == 0
if not decision_matches:
    raise SystemExit("doctor 汇总无法推导出实际退出码")
PY

run_installer --check >"$TEST_ROOT/update-check.txt"
grep -q '已是最新版本' "$TEST_ROOT/update-check.txt" || fail "--check 未识别同版本"
verify_installed_binary
run_installer
verify_installed_binary
env HOME="$TEST_HOME" MINDONE_HOME="$DATA_DIR" \
    "$INSTALLED" config set log_level info --quiet
[ -d "$DATA_DIR" ] || fail "CLI 没有创建隔离数据目录"

run_uninstaller --yes
[ ! -e "$INSTALLED" ] || fail "默认卸载没有删除 CLI"
[ -d "$DATA_DIR" ] || fail "默认卸载错误删除了用户数据"
if grep -Fq '# >>> MindOne CLI PATH (managed) >>>' "$TEST_HOME/.profile"; then
    fail "默认卸载没有移除受管 PATH 块"
fi

run_installer --no-modify-path
verify_installed_binary
if grep -Fq '# >>> MindOne CLI PATH (managed) >>>' "$TEST_HOME/.profile"; then
    fail "--no-modify-path 仍写入了 shell 配置"
fi
run_uninstaller --yes
[ ! -e "$INSTALLED" ] || fail "关闭 PATH 修改后的卸载没有删除 CLI"

run_installer
verify_installed_binary
run_uninstaller --yes --purge-data
[ ! -e "$INSTALLED" ] || fail "purge 后 CLI 仍存在"
[ ! -e "$DATA_DIR" ] || fail "purge 没有删除经验证的自有数据目录"
[ -d "$TEST_HOME" ] || fail "purge 越界删除了隔离 HOME"

printf 'MindOne 本地发行安装烟测通过：%s（%s）\n' "$VERSION" "$TARGET"
