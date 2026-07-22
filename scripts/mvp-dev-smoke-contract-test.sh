#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd -P)
smoke_script=${repository_root}/scripts/mvp-dev-smoke.sh
dockerignore=${repository_root}/.dockerignore
temp_parent=${TMPDIR:-/tmp}
temp_parent=$(CDPATH= cd -- "${temp_parent}" && pwd -P)

case "${temp_parent}/" in
    "${repository_root}/"*) temp_parent=/tmp ;;
esac
test_dir=$(mktemp -d "${temp_parent%/}/mindone-mvp-smoke-contract.XXXXXX")
chmod 0700 "${test_dir}"

cleanup() {
    case ${test_dir} in
        "${temp_parent%/}"/mindone-mvp-smoke-contract.*)
            if [ -d "${test_dir}" ] && [ ! -L "${test_dir}" ]; then
                rm -rf -- "${test_dir}"
            fi
            ;;
        *)
            echo "开发 smoke 合同测试临时目录不符合预期，拒绝清理" >&2
            ;;
    esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "开发 smoke 安全合同测试失败：$1" >&2
    exit 1
}

command -v bash >/dev/null 2>&1 || fail "缺少 bash"
bash -n "${smoke_script}" || fail "smoke 脚本语法无效"

help_output=${test_dir}/help.txt
bash "${smoke_script}" --help >"${help_output}"
grep -q 'MINDONE_DEV_POSTGRES_PASSWORD' "${help_output}" \
    || fail "帮助未说明数据库密码环境变量"
grep -q 'MINDONE_DEV_STANDARD_DATA_KEY' "${help_output}" \
    || fail "帮助未说明 Standard key 环境变量"
if grep -Eq -- '--pass([[:space:]]|$)|--key([[:space:]]|$)' "${help_output}"; then
    fail "帮助仍暴露 Secret 命令行参数"
fi

password_marker=must-not-echo-password-marker
password_log=${test_dir}/legacy-password.log
if bash "${smoke_script}" --pass "${password_marker}" >"${password_log}" 2>&1; then
    fail "旧 --pass 参数必须在启动 Docker 前拒绝"
fi
if grep -Fq "${password_marker}" "${password_log}"; then
    fail "拒绝旧 --pass 时不得回显参数值"
fi

key_marker=must-not-echo-standard-key-marker
key_log=${test_dir}/legacy-key.log
if bash "${smoke_script}" --key "${key_marker}" >"${key_log}" 2>&1; then
    fail "旧 --key 参数必须在启动 Docker 前拒绝"
fi
if grep -Fq "${key_marker}" "${key_log}"; then
    fail "拒绝旧 --key 时不得回显参数值"
fi

grep -Eq '^umask 077$' "${smoke_script}" \
    || fail "smoke 必须先收紧文件创建权限"
grep -Fq 'mktemp -d "${TEMP_PARENT%/}/mindone-mvp-smoke.XXXXXX"' "${smoke_script}" \
    || fail "smoke 临时目录必须由仓库外父目录安全创建"
grep -Fq "trap cleanup EXIT" "${smoke_script}" \
    || fail "smoke 缺少退出清理 trap"
trap_line=$(grep -n -m 1 -F 'trap cleanup EXIT' "${smoke_script}" | cut -d: -f1)
mktemp_line=$(grep -n -m 1 -F 'WORK_DIR="$(mktemp -d ' "${smoke_script}" | cut -d: -f1)
if [ -z "${trap_line}" ] || [ -z "${mktemp_line}" ] || [ "${trap_line}" -ge "${mktemp_line}" ]; then
    fail "smoke 必须在创建临时目录前安装退出清理 trap"
fi
grep -Fq "trap 'exit 129' HUP" "${smoke_script}" \
    || fail "smoke 缺少 HUP 清理路径"
grep -Fq "trap 'exit 130' INT" "${smoke_script}" \
    || fail "smoke 缺少 INT 清理路径"
grep -Fq "trap 'exit 143' TERM" "${smoke_script}" \
    || fail "smoke 缺少 TERM 清理路径"
if grep -Fq 'credentials.txt' "${smoke_script}"; then
    fail "smoke 不得持久化 credentials.txt"
fi
grep -Fq 'CLI_HOME="$WORK_DIR/cli-home"' "${smoke_script}" \
    || fail "smoke CLI 必须使用受控临时 Home"
grep -Fq 'MINDONE_HOME="$CLI_HOME" "$CLI_BIN" "$@"' "${smoke_script}" \
    || fail "smoke CLI 调用未统一绑定隔离 MINDONE_HOME"
if grep -Eq '(\./|\$ROOT_DIR/)target/debug/mindone[[:space:]]' "${smoke_script}"; then
    fail "smoke 不得绕过 smoke_cli 直接调用 CLI"
fi

repository_tmp_log=${test_dir}/repository-tmp.log
if TMPDIR="${repository_root}" \
    MINDONE_DEV_POSTGRES_PASSWORD='contract-only-url-safe-password' \
    MINDONE_DEV_STANDARD_DATA_KEY='1111111111111111111111111111111111111111111111111111111111111111' \
        bash "${smoke_script}" --skip-cli >"${repository_tmp_log}" 2>&1; then
    fail "TMPDIR 位于仓库内时必须在创建临时文件前拒绝"
fi
grep -Fq 'TMPDIR 位于仓库内' "${repository_tmp_log}" \
    || fail "仓库内 TMPDIR 拒绝原因不明确"

# 用完全本地的命令替身跑完整 smoke 编排，不接触 Docker 或网络。替身会在脚本运行
# 期间验证受控目录/文件权限，并把目录路径写到父级报告；脚本退出后该目录必须消失。
probe_parent=${test_dir}/probe-parent
fake_bin=${test_dir}/fake-bin
probe_report=${test_dir}/probe-report.txt
cli_report=${test_dir}/cli-report.txt
install -d -m 0700 "${probe_parent}" "${fake_bin}"

cat >"${fake_bin}/docker" <<'SH'
#!/bin/sh
set -eu
if [ -n "${MINDONE_CONTRACT_DOCKER_MARKER:-}" ]; then
    : >"${MINDONE_CONTRACT_DOCKER_MARKER}"
fi
case " $* " in
    *" compose "*)
        test -n "${MINDONE_DEV_POSTGRES_PASSWORD:-}"
        test -n "${MINDONE_DEV_STANDARD_DATA_KEY:-}"
        ;;
    *)
        test -z "${MINDONE_DEV_POSTGRES_PASSWORD:-}"
        test -z "${MINDONE_DEV_STANDARD_DATA_KEY:-}"
        ;;
esac
case " $* " in
    *" logs "*) printf '%s\n' '数据库迁移已完成' ;;
    *" ps "*) printf '%s\n' 'contract-database-migrator-1' ;;
    *) : ;;
esac
SH

cat >"${fake_bin}/curl" <<'SH'
#!/bin/sh
set -eu
test -z "${MINDONE_DEV_POSTGRES_PASSWORD:-}"
test -z "${MINDONE_DEV_STANDARD_DATA_KEY:-}"
output_file=
url=
request_data=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            output_file=$2
            shift 2
            ;;
        -d|--data)
            request_data=$2
            shift 2
            ;;
        -w|-X|-H)
            shift 2
            ;;
        http://*)
            url=$1
            shift
            ;;
        *)
            shift
            ;;
    esac
done

work_dir=$(find "${MINDONE_CONTRACT_PROBE_PARENT}" -mindepth 1 -maxdepth 1 \
    -type d -name 'mindone-mvp-smoke.*' -print)
test -n "${work_dir}"
test "$(printf '%s\n' "${work_dir}" | wc -l | tr -d ' ')" = 1
find "${work_dir}" -maxdepth 0 -perm 0700 | grep -q .
if find "${work_dir}" -type f ! -perm 0600 | grep -q .; then
    exit 91
fi
test ! -e "${work_dir}/evidence/credentials.txt"
printf '%s\n' "${work_dir}" >"${MINDONE_CONTRACT_PROBE_REPORT}"

if [ -n "${output_file}" ]; then
    : >"${output_file}"
    case "${url}" in
        */v1/models) printf '401' ;;
        */v1/completions) printf '404' ;;
        */v1/jobs)
            case "${request_data}" in
                @*) printf '401' ;;
                *) printf '422' ;;
            esac
            ;;
        *) printf '500' ;;
    esac
else
    case "${url}" in
        */ready) printf '%s\n' '{"status":"ready"}' ;;
        */health) printf '%s\n' '{"status":"ok"}' ;;
        *) exit 92 ;;
    esac
fi
SH

cat >"${fake_bin}/mindone" <<'SH'
#!/bin/sh
set -eu

case ${MINDONE_HOME:-} in
    "${MINDONE_CONTRACT_PROBE_PARENT}"/mindone-mvp-smoke.*/cli-home) : ;;
    *)
        echo "fake CLI 未收到隔离 MINDONE_HOME" >&2
        exit 93
        ;;
esac
test -d "${MINDONE_HOME}"
find "${MINDONE_HOME}" -maxdepth 0 -perm 0700 | grep -q .
if find "${MINDONE_HOME%/cli-home}" -type f ! -perm 0600 | grep -q .; then
    exit 94
fi
printf '%s\n' "${MINDONE_HOME}" >"${MINDONE_CONTRACT_CLI_REPORT}"

case "$*" in
    --version)
        printf '%s\n' 'mindone 1.0.0'
        ;;
    --help)
        printf '%s\n' 'MindOne 帮助'
        ;;
    '--json auth status')
        if [ "${MINDONE_CONTRACT_CLI_MODE:-ok}" = bad-auth ]; then
            printf '%s\n' \
                '{"ok":false,"code":10,"error":{"type":"authentication_failed","message":"not logged in"}}' >&2
        else
            printf '%s\n' \
                '{"ok":false,"code":10,"error":{"type":"authentication_failed","message":"尚未登录 MindOne"}}' >&2
        fi
        exit 10
        ;;
    'config set server_url http://127.0.0.1:18890')
        printf '%s\n' '配置已更新'
        ;;
    'config get server_url')
        printf '%s\n' 'http://127.0.0.1:18890/'
        ;;
    '--json doctor')
        if [ "${MINDONE_CONTRACT_CLI_MODE:-ok}" = bad-doctor ]; then
            printf '%s\n' \
                '{"ok":true,"code":0,"data":{"summary":{"failures":1}}}'
        else
            printf '%s\n' \
                '{"ok":true,"code":0,"data":{"summary":{"failures":0}}}'
        fi
        ;;
    *)
        echo "fake CLI 收到未预期参数" >&2
        exit 95
        ;;
esac
SH

cat >"${fake_bin}/sleep" <<'SH'
#!/bin/sh
exit 0
SH

chmod 0700 \
    "${fake_bin}/docker" "${fake_bin}/curl" "${fake_bin}/mindone" "${fake_bin}/sleep"

preflight_marker=${test_dir}/preflight-docker-called
preflight_log=${test_dir}/preflight.log
if PATH="${fake_bin}:${PATH}" \
    TMPDIR="${probe_parent}" \
    MINDONE_CONTRACT_DOCKER_MARKER="${preflight_marker}" \
    MINDONE_DEV_CLI_BIN="${test_dir}/missing-mindone" \
    MINDONE_DEV_POSTGRES_PASSWORD='contract-only-url-safe-password' \
    MINDONE_DEV_STANDARD_DATA_KEY='1111111111111111111111111111111111111111111111111111111111111111' \
        bash "${smoke_script}" --project contract --port 18890 --skip-down \
            >"${preflight_log}" 2>&1; then
    fail "缺少 CLI 时 smoke 必须失败"
fi
grep -Fq '未找到可执行的非 symlink MindOne CLI' "${preflight_log}" \
    || fail "缺少 CLI 时未返回简体中文 preflight 错误"
test ! -e "${preflight_marker}" \
    || fail "CLI preflight 失败后仍启动了 Docker"

probe_log=${test_dir}/probe.log
PATH="${fake_bin}:${PATH}" \
TMPDIR="${probe_parent}" \
MINDONE_CONTRACT_PROBE_PARENT="${probe_parent}" \
MINDONE_CONTRACT_PROBE_REPORT="${probe_report}" \
MINDONE_CONTRACT_CLI_REPORT="${cli_report}" \
MINDONE_DEV_CLI_BIN="${fake_bin}/mindone" \
MINDONE_DEV_POSTGRES_PASSWORD='contract-only-url-safe-password' \
MINDONE_DEV_STANDARD_DATA_KEY='1111111111111111111111111111111111111111111111111111111111111111' \
    bash "${smoke_script}" \
        --project contract --port 18890 --skip-down >"${probe_log}" 2>&1 \
    || {
        sed -n '1,160p' "${probe_log}" >&2
        fail "本地替身 smoke 编排未完成"
    }
grep -Fq '[PASS] MVP smoke 全流程通过' "${probe_log}" \
    || fail "本地替身 smoke 未报告成功"
test -s "${probe_report}" || fail "运行期权限探针没有产生报告"
test -s "${cli_report}" || fail "隔离 CLI Home 动态探针没有产生报告"
observed_work_dir=$(sed -n '1p' "${probe_report}")
observed_cli_home=$(sed -n '1p' "${cli_report}")
case "${observed_work_dir}" in
    "${probe_parent}"/mindone-mvp-smoke.*) : ;;
    *) fail "smoke 运行目录不在指定仓库外父目录" ;;
esac
test "${observed_cli_home}" = "${observed_work_dir}/cli-home" \
    || fail "CLI 未使用 smoke 运行目录下的隔离 Home"
if [ -e "${observed_work_dir}" ]; then
    fail "smoke 退出后没有清理受控临时目录"
fi

run_negative_cli_contract() {
    negative_mode=$1
    expected_message=$2
    negative_log=${test_dir}/${negative_mode}.log
    if PATH="${fake_bin}:${PATH}" \
        TMPDIR="${probe_parent}" \
        MINDONE_CONTRACT_PROBE_PARENT="${probe_parent}" \
        MINDONE_CONTRACT_PROBE_REPORT="${probe_report}" \
        MINDONE_CONTRACT_CLI_REPORT="${cli_report}" \
        MINDONE_CONTRACT_CLI_MODE="${negative_mode}" \
        MINDONE_DEV_CLI_BIN="${fake_bin}/mindone" \
        MINDONE_DEV_POSTGRES_PASSWORD='contract-only-url-safe-password' \
        MINDONE_DEV_STANDARD_DATA_KEY='1111111111111111111111111111111111111111111111111111111111111111' \
            bash "${smoke_script}" --project contract --port 18890 --skip-down \
                >"${negative_log}" 2>&1; then
        fail "${negative_mode} 负向 CLI 合同未失败关闭"
    fi
    grep -Fq "${expected_message}" "${negative_log}" \
        || fail "${negative_mode} 负向 CLI 合同错误不明确"
}

run_negative_cli_contract bad-auth 'auth status JSON 合同异常'
run_negative_cli_contract bad-doctor 'doctor JSON 合同异常'

grep -Eq '^\.tmp/?$' "${dockerignore}" \
    || fail "Docker build context 未排除仓库根 .tmp"
grep -Eq '^\*\*/\.tmp/?$' "${dockerignore}" \
    || fail "Docker build context 未排除嵌套 .tmp"
grep -Eq '^\*\*/\*credential\*' "${dockerignore}" \
    || fail "Docker build context 未兜底排除 credential artifact"

echo "开发 smoke 凭据、CLI Home 与 Docker 构建上下文安全合同通过"
