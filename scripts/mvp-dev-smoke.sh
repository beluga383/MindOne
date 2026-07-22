#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEPLOY_DIR="$ROOT_DIR/deploy"
PROJECT_NAME="mindone-dev"
PORT="18890"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.dev.yml"
SKIP_CLI=0
SKIP_CLEANUP=0
SKIP_DOWN=0
WORK_DIR=""
COMPOSE_TOUCHED=0

function fail() {
  echo "[FAIL] $1" >&2
  return 1
}

function usage() {
  cat <<'USAGE'
用法:
  scripts/mvp-dev-smoke.sh [--port <port>] [--project <name>] [--skip-cli] [--skip-cleanup] [--skip-down] [--help]

参数说明:
  --port         覆盖 coordinator 监听端口（默认 18890）
  --project      覆盖 docker compose project 名称（默认 mindone-dev）
  --skip-cli     跳过 CLI 验证步骤
  --skip-cleanup 跳过退出时 down/v 清理
  --skip-down    跳过启动前的 down -v（用于已知空环境下的快速复测）
  --help         显示帮助

凭据输入:
  默认自动生成一次性开发密码和 Standard 数据密钥。若需要调用者提供，只能通过
  MINDONE_DEV_POSTGRES_PASSWORD 和 MINDONE_DEV_STANDARD_DATA_KEY 环境变量注入；
  禁止把 Secret 放入命令行参数。临时诊断材料位于仓库外的 0700 目录，退出时清理。

CLI 输入:
  默认检查 target/debug/mindone。只有本地合同测试或明确验证其他构建时，
  才设置 MINDONE_DEV_CLI_BIN 为绝对、非 symlink 的可执行文件。

示例:
  scripts/mvp-dev-smoke.sh

  MINDONE_DEV_POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
  MINDONE_DEV_STANDARD_DATA_KEY="$(openssl rand -hex 32)" \
    scripts/mvp-dev-smoke.sh --port 18890
USAGE
}

function require_option_value() {
  local option="$1"
  local count="$2"
  if [ "$count" -lt 2 ]; then
    fail "$option 缺少参数值"
    exit 2
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --pass|--key)
      fail "已移除 Secret 命令行参数；请改用专用环境变量（见 --help）"
      exit 2
      ;;
    --port)
      require_option_value "$1" "$#"
      PORT="$2"
      shift 2
      ;;
    --project)
      require_option_value "$1" "$#"
      PROJECT_NAME="$2"
      shift 2
      ;;
    --skip-cli)
      SKIP_CLI=1
      shift
      ;;
    --skip-cleanup)
      SKIP_CLEANUP=1
      shift
      ;;
    --skip-down)
      SKIP_DOWN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "未知参数；为避免回显敏感内容，未打印原始参数"
      usage
      exit 2
      ;;
  esac
done

PASS="${MINDONE_DEV_POSTGRES_PASSWORD:-}"
KEY="${MINDONE_DEV_STANDARD_DATA_KEY:-}"
unset MINDONE_DEV_POSTGRES_PASSWORD MINDONE_DEV_STANDARD_DATA_KEY
[ -n "$PASS" ] || PASS=$(openssl rand -hex 16)
[ -n "$KEY" ] || KEY=$(openssl rand -hex 32)

if [ "${#PASS}" -lt 16 ] || [ "${#PASS}" -gt 256 ] \
  || [[ ! "$PASS" =~ ^[A-Za-z0-9._~-]+$ ]]; then
  fail "MINDONE_DEV_POSTGRES_PASSWORD 必须是 16 到 256 字节的 URL-safe 字符串"
  exit 2
fi
if [[ ! "$KEY" =~ ^[0-9a-f]{64}$ ]]; then
  fail "MINDONE_DEV_STANDARD_DATA_KEY 必须是 64 位小写十六进制"
  exit 2
fi

TEMP_PARENT="${TMPDIR:-/tmp}"
if [ ! -d "$TEMP_PARENT" ]; then
  fail "临时目录父路径不存在"
  exit 1
fi
TEMP_PARENT="$(cd "$TEMP_PARENT" && pwd -P)"
case "$TEMP_PARENT/" in
  "$ROOT_DIR/"*)
    fail "TMPDIR 位于仓库内，拒绝让 smoke 临时材料进入 Git 或 Docker 构建上下文"
    exit 1
    ;;
esac
function cleanup_work_dir() {
  [ -n "$WORK_DIR" ] || return 0
  case "$WORK_DIR" in
    "${TEMP_PARENT%/}"/mindone-mvp-smoke.*)
      if [ -d "$WORK_DIR" ] && [ ! -L "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
      fi
      ;;
    *)
      echo "[WARN] 临时目录不符合受控前缀，拒绝清理" >&2
      ;;
  esac
}

function dev_compose() {
  MINDONE_DEV_POSTGRES_PASSWORD="$PASS" \
  MINDONE_DEV_STANDARD_DATA_KEY="$KEY" \
  MINDONE_COORDINATOR_HOST_PORT="$PORT" \
    docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

function cleanup() {
  local exit_code=$?
  trap - EXIT
  set +e
  if [ "$COMPOSE_TOUCHED" -eq 1 ] && [ "$SKIP_CLEANUP" -eq 0 ]; then
    (
      cd "$DEPLOY_DIR" || exit 0
      dev_compose down -v >/dev/null 2>&1
    ) || true
  fi
  PASS=""
  KEY=""
  unset MINDONE_DEV_POSTGRES_PASSWORD MINDONE_DEV_STANDARD_DATA_KEY
  cleanup_work_dir
  exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

WORK_DIR="$(mktemp -d "${TEMP_PARENT%/}/mindone-mvp-smoke.XXXXXX")"
chmod 0700 "$WORK_DIR"
LOG_DIR="$WORK_DIR/evidence"
CLI_HOME="$WORK_DIR/cli-home"
CLI_BIN="${MINDONE_DEV_CLI_BIN:-$ROOT_DIR/target/debug/mindone}"
unset MINDONE_DEV_CLI_BIN
install -d -m 0700 "$LOG_DIR" "$CLI_HOME"

PYTHON_BIN=""
if [ "$SKIP_CLI" -eq 0 ]; then
  case "$CLI_BIN" in
    /*) ;;
    *)
      fail "MINDONE_DEV_CLI_BIN 必须是绝对路径"
      exit 1
      ;;
  esac
  if [ -L "$CLI_BIN" ] || [ ! -f "$CLI_BIN" ] || [ ! -x "$CLI_BIN" ]; then
    fail "未找到可执行的非 symlink MindOne CLI；请先构建当前源码"
    exit 1
  fi
  CLI_BIN_DIR="$(cd "$(dirname "$CLI_BIN")" && pwd -P)"
  CLI_BIN="$CLI_BIN_DIR/$(basename "$CLI_BIN")"
  PYTHON_BIN="$(command -v python3 || true)"
  if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
    fail "CLI JSON 合同验证需要 python3"
    exit 1
  fi
fi

function smoke_cli() {
  MINDONE_HOME="$CLI_HOME" "$CLI_BIN" "$@"
}

function validate_auth_status_json() {
  "$PYTHON_BIN" - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        value = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit("认证状态未输出唯一合法 JSON")

error = value.get("error")
if value.get("ok") is not False or value.get("code") != 10:
    raise SystemExit("认证状态 JSON 的 ok/code 不符合稳定合同")
if not isinstance(error, dict) or error.get("type") != "authentication_failed":
    raise SystemExit("认证状态 JSON 缺少 authentication_failed")
message = error.get("message")
if not isinstance(message, str) or "尚未登录" not in message:
    raise SystemExit("认证状态未使用预期的简体中文错误")
PY
}

function validate_doctor_json() {
  "$PYTHON_BIN" - "$1" "$2" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        value = json.load(handle)
    expected_code = int(sys.argv[2])
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit("doctor 未输出唯一合法 JSON")

if value.get("code") != expected_code:
    raise SystemExit("doctor JSON code 与进程退出码不一致")
if value.get("ok") is not (expected_code == 0):
    raise SystemExit("doctor JSON ok 与进程退出码不一致")
data = value.get("data")
summary = data.get("summary") if isinstance(data, dict) else None
if not isinstance(summary, dict) or summary.get("failures") != 0:
    raise SystemExit("doctor JSON 未证明 failures 为 0")
PY
}

function ok() {
  echo "[PASS] $1"
}

function check_up() {
  local url="$1"
  local expect="$2"
  local response
  if ! response="$(curl -sS --max-time 5 "$url")"; then
    fail "GET $url request failed"
    return 1
  fi
  if [[ "$response" != *"$expect"* ]]; then
    fail "Unexpected response from $url: $response"
    return 1
  fi
  ok "$url => OK"
}

function check_status_code() {
  local method="$1"
  local expected_code="$2"
  local url="$3"
  local body_file
  body_file="$(mktemp "$WORK_DIR/http-body.XXXXXX")"
  local code
  if [ "$#" -gt 3 ]; then
    shift 3
    if ! code="$(curl -sS -o "$body_file" -w '%{http_code}' -X "$method" "$@" "$url")"; then
      rm -f "$body_file"
      fail "$method $url request failed"
      return 1
    fi
  else
    if ! code="$(curl -sS -o "$body_file" -w '%{http_code}' -X "$method" "$url")"; then
      rm -f "$body_file"
      fail "$method $url request failed"
      return 1
    fi
  fi
  if [[ "$code" != "$expected_code" ]]; then
    echo "[BODY] $(tr -d '\n' <"$body_file")"
    rm -f "$body_file"
    fail "$method $url -> $code, expected $expected_code"
    return 1
  fi
  rm -f "$body_file"
  ok "$method $url -> $code"
}

cd "$DEPLOY_DIR"

echo "[step] 1/7 启动 dev compose"
if [ "$SKIP_DOWN" -eq 0 ]; then
  dev_compose down -v >/dev/null 2>&1 || true
fi
COMPOSE_TOUCHED=1
dev_compose up -d

echo "[step] 2/7 验证迁移与容器状态"
for _ in $(seq 1 30); do
  if docker ps --filter "name=${PROJECT_NAME}-database-migrator-1" --filter "status=exited" --format '{{.Names}}' | rg -q "${PROJECT_NAME}-database-migrator-1"; then
    break
  fi
  sleep 1
done
docker logs --tail 120 "${PROJECT_NAME}-database-migrator-1" | tee "$LOG_DIR/migrator.log"
if ! docker logs --tail 120 "${PROJECT_NAME}-database-migrator-1" | rg -q "数据库迁移已完成|Database migration completed"; then
  fail "database-migrator 未完成"
  exit 1
fi
ok "database-migrator 迁移完成"

echo "[step] 3/7 检查服务健康"
sleep 2
check_up "http://127.0.0.1:$PORT/ready" '"status":"ready"'
check_up "http://127.0.0.1:$PORT/health" '"status":"ok"'

echo "[step] 4/7 检查鉴权与路由"
check_status_code GET 401 "http://127.0.0.1:$PORT/v1/models"
check_status_code POST 404 "http://127.0.0.1:$PORT/v1/completions" -H 'content-type: application/json' -d '{"model":"llama","prompt":"hi"}'
check_status_code POST 422 "http://127.0.0.1:$PORT/v1/jobs" -H 'content-type: application/json' -d '{"wrong":"x"}'

cat > "$LOG_DIR/jobs_payload.json" <<JSON
{
  "virtual_model": "mvp-test",
  "encrypted_payload": "dGVzdA==",
  "payload_encoding": "base64",
  "estimated_input_tokens": 1,
  "max_output_tokens": 1,
  "idempotency_key": "mvp-$(date +%s)"
}
JSON
check_status_code POST 401 "http://127.0.0.1:$PORT/v1/jobs" -H 'content-type: application/json' --data @"$LOG_DIR/jobs_payload.json"

if [ "$SKIP_CLI" -eq 0 ]; then
  echo "[step] 5/7 CLI 可用性"
  cd "$ROOT_DIR"

  if ! smoke_cli --version >/dev/null; then
    fail "mindone --version 失败"
    exit 1
  fi
  ok "mindone --version"

  if ! smoke_cli --help >/dev/null; then
    fail "mindone --help 失败"
    exit 1
  fi
  ok "mindone --help"

  auth_exit=0
  smoke_cli --json auth status > "$LOG_DIR/auth.stdout" 2> "$LOG_DIR/auth.json" \
    || auth_exit=$?
  if [ "$auth_exit" -ne 10 ]; then
    fail "隔离 CLI Home 的 auth status 必须以稳定认证退出码 10 拒绝"
    exit 1
  fi
  if [ -s "$LOG_DIR/auth.stdout" ] || ! validate_auth_status_json "$LOG_DIR/auth.json"; then
    fail "auth status JSON 合同异常"
    exit 1
  fi
  ok "auth status（未登录）"

  smoke_cli config set server_url "http://127.0.0.1:$PORT" > /dev/null
  if ! smoke_cli config get server_url | rg -q "http://127.0.0.1:$PORT"; then
    fail "config get server_url"
    exit 1
  fi
  ok "config server_url"

  doctor_exit=0
  smoke_cli --json doctor > "$LOG_DIR/doctor.json" 2> "$LOG_DIR/doctor.stderr" \
    || doctor_exit=$?
  case "$doctor_exit" in
    0|31) ;;
    *)
      fail "doctor 返回了非预期退出码"
      exit 1
      ;;
  esac
  if ! validate_doctor_json "$LOG_DIR/doctor.json" "$doctor_exit"; then
    fail "doctor JSON 合同异常"
    exit 1
  fi
  ok "doctor --json"
else
  echo "[step] 5/7 CLI 可用性（已跳过）"
fi

echo "[step] 6/7 输出日志与摘要"
docker logs --tail 120 "${PROJECT_NAME}-coordinator-1" | tee "$LOG_DIR/coordinator.log"
docker logs --tail 120 "${PROJECT_NAME}-database-migrator-1" | tee "$LOG_DIR/migrator.log"

if [ "$SKIP_CLEANUP" -eq 0 ]; then
  echo "[step] 7/7 清理"
  dev_compose down -v
  COMPOSE_TOUCHED=0
else
  echo "[step] 7/7 清理（已跳过）"
fi

echo "[PASS] MVP smoke 全流程通过"
echo "[INFO] 仓库外临时诊断材料将在进程退出时清理"
