#!/bin/sh

# 真实端到端测试：不使用 Mock 推理，不复用用户的 MindOne 数据目录。
# 外部前提：Docker、Rust/Cargo、curl、Python 3、可访问 GitHub 与 Hugging Face，
# 以及至少约 3 GiB 可用磁盘和可运行小型 GGUF 模型的内存。

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POSTGRES_IMAGE="${MINDONE_E2E_POSTGRES_IMAGE:-postgres:17-bookworm}"
POSTGRES_PORT="${MINDONE_E2E_POSTGRES_PORT:-55433}"
COORDINATOR_PORT="${MINDONE_E2E_COORDINATOR_PORT:-18787}"
LLAMA_PORT="${MINDONE_E2E_LLAMA_PORT:-18080}"
PROXY_PORT="${MINDONE_E2E_PROXY_PORT:-19090}"
MODEL_REPO="${MINDONE_E2E_MODEL_REPO:-ggml-org/Qwen3-0.6B-GGUF}"
MODEL_FILE="${MINDONE_E2E_MODEL_FILE:-Qwen3-0.6B-Q4_0.gguf}"
MODEL_BRANCH="${MINDONE_E2E_MODEL_BRANCH:-main}"
MODEL_NAME="${MINDONE_E2E_MODEL_NAME:-qwen3-e2e}"
MODEL_SHA256="${MINDONE_E2E_MODEL_SHA256:-da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4}"
LLAMA_VERSION="${MINDONE_E2E_LLAMA_VERSION:-b10064}"
CPU_ONLY="${MINDONE_E2E_CPU_ONLY:-1}"
KEEP_TMP="${MINDONE_E2E_KEEP_TMP:-0}"
PROFILE="${MINDONE_E2E_PROFILE:-release}"
CARGO_JOBS="${MINDONE_E2E_CARGO_JOBS:-1}"

die() {
    printf 'E2E 失败：%s\n' "$*" >&2
    # 若数据库容器仍可用，转储最近的失败 attempt，暴露协调器的确切拒绝原因，
    # 便于诊断（例如结果提交被判为 invalid_job_result/usage/model_binding_mismatch）。
    if [ -n "${DB_CONTAINER:-}" ] && docker exec "$DB_CONTAINER" true 2>/dev/null; then
        printf '=== 最近 job_attempts 失败诊断 ===\n' >&2
        docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' -c "
            SELECT j.status, ja.attempt_number, ja.error_class, ja.error_message
            FROM job_attempts ja
            JOIN jobs j ON j.id = ja.job_id
            WHERE ja.error_class IS NOT NULL OR ja.error_message IS NOT NULL
            ORDER BY ja.lease_started_at DESC
            LIMIT 8" >&2 2>/dev/null || true
        printf '%s\n' '=== 最近隐藏评价安全诊断 ===' >&2
        docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' -c "
            SELECT challenge.challenge_kind,challenge.status,
                   (challenge.challenge_seed IS NULL)::text,
                   (challenge.completed_at IS NOT NULL)::text,
                   COALESCE(challenge.worker_submission_kind,''),
                   ROUND(EXTRACT(EPOCH FROM (
                       challenge.lease_expires_at-challenge.issued_at
                   ))::numeric,3),
                   ROUND(EXTRACT(EPOCH FROM (
                       challenge.completed_at-challenge.issued_at
                   ))::numeric,3),
                   (challenge.lease_expires_at >
                       challenge.challenge_issued_expires_at)::text,
                   COALESCE((
                       SELECT string_agg(event.event_kind,',' ORDER BY event.created_at,event.event_kind)
                       FROM model_evaluation_challenge_events event
                       WHERE event.challenge_id=challenge.id
                   ),'')
            FROM model_evaluation_challenges challenge
            ORDER BY challenge.issued_at DESC
            LIMIT 5" >&2 2>/dev/null || true
        printf '=== 诊断结束 ===\n' >&2
    fi
    exit 1
}

step() {
    printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

for required in cargo curl docker python3; do
    command -v "$required" >/dev/null 2>&1 || die "缺少外部前提：$required"
done
docker info >/dev/null 2>&1 || die "Docker daemon 不可用"
case "$PROFILE" in
    release|debug) ;;
    *) die "MINDONE_E2E_PROFILE 只允许 release 或 debug" ;;
esac
case "$CPU_ONLY" in
    0|1) ;;
    *) die "MINDONE_E2E_CPU_ONLY 只允许 0 或 1" ;;
esac
printf '%s\n' "$CARGO_JOBS" | grep -Eq '^[1-9][0-9]*$' \
    || die "MINDONE_E2E_CARGO_JOBS 必须是正整数"
for port in "$POSTGRES_PORT" "$COORDINATOR_PORT" "$LLAMA_PORT" "$PROXY_PORT"; do
    printf '%s\n' "$port" | grep -Eq '^[0-9]+$' || die "端口不是整数：$port"
    [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || die "端口超出 1024..65535：$port"
done

python3 - "$POSTGRES_PORT" "$COORDINATOR_PORT" "$LLAMA_PORT" "$PROXY_PORT" <<'PY'
import socket
import sys

ports = [int(value) for value in sys.argv[1:]]
if len(set(ports)) != len(ports):
    raise SystemExit("E2E 端口必须互不相同")
for port in ports:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    except OSError as error:
        raise SystemExit(f"127.0.0.1:{port} 已占用：{error}")
    finally:
        sock.close()
PY

TEMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/mindone-e2e.XXXXXX") || die "无法创建临时目录"
TEMP_ROOT=$(CDPATH= cd -- "$TEMP_ROOT" && pwd -P) \
    || die "无法规范化临时目录"
CONSUMER_HOME="$TEMP_ROOT/consumer-a"
NODE_HOME="$TEMP_ROOT/node-b"
LOG_DIR="$TEMP_ROOT/logs"
mkdir -p "$CONSUMER_HOME" "$NODE_HOME" "$LOG_DIR"
DB_CONTAINER="mindone-e2e-postgres-$$"
DB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
STANDARD_DATA_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_URL="postgres://mindone:${DB_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/mindone_e2e"
COORDINATOR_PID=""
PROXY_PID=""
POLICY_LOCK_PID=""
POLICY_REQUEST_PID=""
SSE_SETTLEMENT_LOCK_PID=""
SSE_CURSOR_LOCK_PID=""
SSE_REQUEST_PID=""
CLI=""
NODE_LOGGED_IN=0
CONSUMER_LOGGED_IN=0
PUBLISHED=0
SERVING=0
DB_STARTED=0
SUCCESS=0
ORIGINAL_USER_KEYCHAIN=""
E2E_KEYCHAIN=""
E2E_KEYCHAIN_PASSWORD=""
E2E_KEYCHAIN_CREATED=0
E2E_KEYCHAIN_SWITCHED=0

cleanup() {
    original_status=$?
    set +e
    if [ -n "$SSE_REQUEST_PID" ]; then
        kill "$SSE_REQUEST_PID" 2>/dev/null
        wait "$SSE_REQUEST_PID" 2>/dev/null
    fi
    if [ -n "$SSE_CURSOR_LOCK_PID" ]; then
        kill "$SSE_CURSOR_LOCK_PID" 2>/dev/null
        wait "$SSE_CURSOR_LOCK_PID" 2>/dev/null
    fi
    if [ -n "$SSE_SETTLEMENT_LOCK_PID" ]; then
        kill "$SSE_SETTLEMENT_LOCK_PID" 2>/dev/null
        wait "$SSE_SETTLEMENT_LOCK_PID" 2>/dev/null
    fi
    if [ -n "$POLICY_REQUEST_PID" ]; then
        kill "$POLICY_REQUEST_PID" 2>/dev/null
        wait "$POLICY_REQUEST_PID" 2>/dev/null
    fi
    if [ -n "$POLICY_LOCK_PID" ]; then
        kill "$POLICY_LOCK_PID" 2>/dev/null
        wait "$POLICY_LOCK_PID" 2>/dev/null
    fi
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null
        wait "$PROXY_PID" 2>/dev/null
    fi
    if [ -n "$CLI" ] && [ -x "$CLI" ]; then
        if [ "$PUBLISHED" -eq 1 ]; then
            MINDONE_HOME="$NODE_HOME" "$CLI" share unpublish --timeout 5 --quiet \
                >>"$LOG_DIR/cleanup.log" 2>&1
        fi
        if [ "$SERVING" -eq 1 ]; then
            MINDONE_HOME="$NODE_HOME" "$CLI" serve stop --port "$LLAMA_PORT" \
                --timeout 5 --quiet \
                >>"$LOG_DIR/cleanup.log" 2>&1
        fi
        if [ "$CONSUMER_LOGGED_IN" -eq 1 ]; then
            MINDONE_HOME="$CONSUMER_HOME" "$CLI" auth logout --quiet \
                >>"$LOG_DIR/cleanup.log" 2>&1
        fi
        if [ "$NODE_LOGGED_IN" -eq 1 ]; then
            MINDONE_HOME="$NODE_HOME" "$CLI" auth logout --quiet \
                >>"$LOG_DIR/cleanup.log" 2>&1
        fi
    fi
    if [ -n "$COORDINATOR_PID" ]; then
        kill "$COORDINATOR_PID" 2>/dev/null
        wait "$COORDINATOR_PID" 2>/dev/null
    fi
    if [ "$DB_STARTED" -eq 1 ]; then
        docker logs "$DB_CONTAINER" >"$LOG_DIR/postgres.log" 2>&1
        docker inspect --format \
            '{"status":{{json .State.Status}},"exit_code":{{.State.ExitCode}},"error":{{json .State.Error}},"health":{{json .State.Health}}}' \
            "$DB_CONTAINER" >"$TEMP_ROOT/postgres-state.json" 2>/dev/null
        docker rm -f "$DB_CONTAINER" >/dev/null 2>&1
    fi
    if [ "$E2E_KEYCHAIN_SWITCHED" -eq 1 ]; then
        security default-keychain -d user -s "$ORIGINAL_USER_KEYCHAIN" >/dev/null 2>&1
    fi
    if [ "$E2E_KEYCHAIN_CREATED" -eq 1 ]; then
        security delete-keychain "$E2E_KEYCHAIN" >/dev/null 2>&1
    fi
    if [ "$KEEP_TMP" = "1" ]; then
        printf 'E2E 临时证据已保留：%s\n' "$TEMP_ROOT" >&2
    else
        rm -rf -- "$TEMP_ROOT"
    fi
    if [ "$SUCCESS" -eq 1 ]; then
        exit 0
    fi
    exit "$original_status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

wait_http_status() {
    url=$1
    expected=$2
    attempts=${3:-60}
    count=0
    while [ "$count" -lt "$attempts" ]; do
        status=$(curl --silent --connect-timeout 1 --max-time 2 \
            --output /dev/null --write-out '%{http_code}' "$url" || true)
        if [ "$status" = "$expected" ]; then
            return 0
        fi
        count=$((count + 1))
        sleep 1
    done
    return 1
}

wait_tcp() {
    host=$1
    port=$2
    attempts=${3:-60}
    python3 - "$host" "$port" "$attempts" <<'PY'
import socket
import sys
import time

host, port, attempts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for _ in range(attempts):
    try:
        with socket.create_connection((host, port), timeout=1):
            raise SystemExit(0)
    except OSError:
        time.sleep(1)
raise SystemExit(1)
PY
}

assert_port_closed() {
    port=$1
    python3 - "$port" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
        raise SystemExit("端口仍可连接")
except OSError:
    pass
PY
}

assert_cli_ok() {
    file=$1
    if ! python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
if value.get("ok") is not True or value.get("code") != 0:
    raise SystemExit(f"CLI JSON 不是成功响应：{sys.argv[1]}")
PY
    then
        printf 'CLI JSON 响应内容：\n' >&2
        cat "$file" >&2 2>/dev/null || true
        printf '\n' >&2
        die "CLI JSON 不是成功响应：$file"
    fi
}

json_number() {
    file=$1
    field=$2
    python3 - "$file" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
for component in sys.argv[2].split("."):
    value = value[component]
if not isinstance(value, int) or isinstance(value, bool):
    raise SystemExit(f"字段不是整数：{sys.argv[2]}")
print(value)
PY
}

# 节点在协调器侧的资格由 15 秒心跳驱动：publish 之后、以及节点阈值/策略在服务端
# 更新后（后者在下一次心跳前会 fail-closed 暂停节点），存在最多约一个心跳周期的
# 窗口，期间节点不是可路由候选。真实消费者遇到这种瞬时不可用会稍后重试；测试则在
# 每个推理阶段前显式等待该节点重新成为可路由候选（online、心跳新鲜、实例 published、
# 计费 profile 有效），使推理阶段本身保持确定性，而不放宽任何服务端资格判定。
wait_node_routable() {
    wnr_count=0
    while [ "$wnr_count" -lt 240 ]; do
        # 除路由候选资格（online/fresh/published/valid profile）外，还要求实例未被
        # canary 隔离、最新 RTT 合法、并发与普通/Regulated/隐藏任务槽全部空闲，并且
        # 服务端策略的资源阈值已回到本平台可满足的稳态：本机 macOS 无法读取 GPU 温度/显存，
        # 因此只要服务端仍保留非零 vram_reserve_mib 或非空 gpu_temp_limit_c，claim 时的
        # enforce_current_policy 会因“指标不可读”而 fail-closed 拒绝领取。等待这些阈值
        # 经心跳恢复清零后再发起推理，使阶段确定性，而不放宽任何资格判定。
        wnr_routable=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -c "
            SELECT COUNT(*)
            FROM model_instances mi
            JOIN nodes n ON n.id = mi.node_id
            JOIN node_policies p ON p.node_id = n.id
            LEFT JOIN LATERAL (
                SELECT nm.current_concurrent,nm.coordinator_rtt_ms
                FROM node_metrics nm
                WHERE nm.node_id=n.id
                ORDER BY nm.measured_at DESC,nm.id DESC
                LIMIT 1
            ) metrics ON TRUE
            JOIN billing_profiles bp
              ON bp.model_id = mi.model_id
             AND bp.contract_version = 'server_reference_upper_bound_v1'
             AND bp.valid_from <= now() AND bp.valid_until > now()
            WHERE mi.node_id = '${published_node_id}'::uuid
              AND mi.status = 'published'
              AND n.status = 'online'
              AND n.last_seen_at > now() - interval '90 seconds'
              AND NOT EXISTS (
                  SELECT 1 FROM model_instance_canary_state canary
                  WHERE canary.model_instance_id=mi.id AND canary.quarantined=TRUE
              )
              AND COALESCE(metrics.current_concurrent,0) = 0
              AND (
                  metrics.coordinator_rtt_ms IS NULL
                  OR metrics.coordinator_rtt_ms BETWEEN 1 AND 1000
              )
              AND NOT EXISTS (
                  SELECT 1 FROM jobs active_job
                  WHERE (
                      active_job.leased_to_node_id=n.id
                      AND active_job.status='leased'
                      AND active_job.lease_expires_at > now()
                  ) OR (
                      active_job.confidentiality_mode='regulated'
                      AND active_job.regulated_node_id=n.id
                      AND active_job.status IN ('queued','retry')
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM regulated_routes pending_route
                  WHERE pending_route.node_id=n.id
                    AND pending_route.status='prepared'
                    AND pending_route.expires_at > now()
              )
              AND NOT EXISTS (
                  SELECT 1 FROM model_evaluation_challenges hidden_work
                  WHERE hidden_work.node_id=n.id AND hidden_work.status='leased'
              )
              AND COALESCE(p.vram_reserve_mib,0) = 0
              AND p.gpu_temp_limit_c IS NULL" 2>/dev/null)
        [ "$wnr_routable" = "1" ] && return 0
        wnr_count=$((wnr_count + 1))
        sleep 0.25
    done
    die "节点在等待窗口内没有成为可路由候选（online/fresh/published/valid profile/空闲容量/可满足阈值）"
}

validate_real_sse() {
    headers_file=$1
    body_file=$2
    endpoint_kind=$3
    expected_nonce=$4
    summary_file=$5
    python3 - "$headers_file" "$body_file" "$endpoint_kind" "$expected_nonce" \
        >"$summary_file" <<'PY'
import json
import pathlib
import re
import sys

headers = pathlib.Path(sys.argv[1]).read_text(encoding="iso-8859-1")
body = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
kind = sys.argv[3]
nonce = sys.argv[4]

status_lines = re.findall(r"(?im)^HTTP/\S+\s+([0-9]{3})(?:\s|$)", headers)
if not status_lines or status_lines[-1] != "200":
    raise SystemExit(f"SSE HTTP 状态不是 200：{status_lines[-1:]}")
content_types = re.findall(r"(?im)^content-type:\s*([^\r\n]+)", headers)
if not content_types or not content_types[-1].lower().startswith("text/event-stream"):
    raise SystemExit(f"SSE Content-Type 错误：{content_types[-1:]}")

normalized = body.replace("\r\n", "\n").replace("\r", "\n")
blocks = [block for block in normalized.split("\n\n") if block.strip()]
records = []
for block in blocks:
    event_id = None
    data_lines = []
    for line in block.split("\n"):
        if not line or line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "id":
            if event_id is not None:
                raise SystemExit("单个 SSE event 含重复 id")
            event_id = value
        elif field == "data":
            data_lines.append(value)
        else:
            raise SystemExit(f"SSE 含不受支持字段：{field}")
    if data_lines:
        records.append((event_id, "\n".join(data_lines)))

if not records:
    raise SystemExit("SSE 没有 data event")
done_positions = [index for index, (_, data) in enumerate(records) if data == "[DONE]"]
if done_positions != [len(records) - 1]:
    raise SystemExit(f"[DONE] 必须唯一且最后出现：{done_positions}")
json_records = records[:-1]
if len(json_records) < 2:
    raise SystemExit("真实 SSE 增量不足两个 JSON event")

ids = []
fragments = []
usage_events = 0
expected_object = "chat.completion.chunk" if kind == "chat" else "text_completion"
for event_id, data in json_records:
    if event_id is None or not re.fullmatch(r"0|[1-9][0-9]*", event_id):
        raise SystemExit(f"SSE JSON event 缺少规范整数 id：{event_id!r}")
    ids.append(int(event_id))
    try:
        value = json.loads(data)
    except json.JSONDecodeError as error:
        raise SystemExit(f"SSE data 不是 JSON：{error}") from error
    if not isinstance(value, dict) or value.get("object") != expected_object:
        raise SystemExit(f"SSE object 与端点不匹配：{value.get('object') if isinstance(value, dict) else type(value)}")
    if not isinstance(value.get("model"), str) or not value["model"]:
        raise SystemExit("SSE event 缺少 model")
    choices = value.get("choices")
    if not isinstance(choices, list):
        raise SystemExit("SSE event 缺少 choices")
    if isinstance(value.get("usage"), dict):
        usage = value["usage"]
        if not isinstance(usage.get("completion_tokens"), int) or usage["completion_tokens"] <= 0:
            raise SystemExit("SSE 终态 usage 缺少正数 completion_tokens")
        usage_events += 1
    for choice in choices:
        if not isinstance(choice, dict):
            raise SystemExit("SSE choice 不是对象")
        if kind == "chat":
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                raise SystemExit("chat SSE choice 缺少 delta")
            for field in ("content", "reasoning_content"):
                fragment = delta.get(field)
                if isinstance(fragment, str) and fragment:
                    fragments.append(fragment)
        else:
            fragment = choice.get("text")
            if not isinstance(fragment, str):
                raise SystemExit("completions SSE choice 缺少 text")
            if fragment:
                fragments.append(fragment)

if ids != list(range(len(ids))):
    raise SystemExit(f"SSE 游标不连续、重复或丢失：{ids}")
if len(fragments) < 2:
    raise SystemExit("真实 SSE 没有产生至少两个非空增量")
if nonce not in "".join(fragments):
    raise SystemExit("真实 SSE 没有返回运行时动态 nonce，疑似固定响应或推理失败")
if usage_events != 1:
    raise SystemExit(f"SSE 必须只有一个终态 usage event：{usage_events}")

json.dump(
    {
        "event_count": len(json_records),
        "fragment_count": len(fragments),
        "done_count": 1,
        "cursor_first": ids[0],
        "cursor_next": ids[-1] + 1,
    },
    sys.stdout,
    ensure_ascii=False,
)
print()
PY
}

assert_unsupported_stream() {
    status_file=$1
    response_file=$2
    expected_jobs=$3
    status=$(cat "$status_file")
    [ "$status" = "400" ] || die "Regulated stream:true 未返回 HTTP 400（实际 ${status}）"
    python3 - "$response_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
error = response.get("error")
if not isinstance(error, dict):
    raise SystemExit("Regulated stream:true 响应缺少 OpenAI error")
if error.get("type") != "unsupported_stream" or error.get("code") != "unsupported_stream":
    raise SystemExit(f"Regulated stream:true 错误类型不稳定：{error}")
PY
    observed_jobs=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c 'SELECT COUNT(*) FROM jobs')
    [ "$observed_jobs" -eq "$expected_jobs" ] \
        || die "Regulated stream:true 被错误降级并创建了任务"
}

setup_macos_test_keychain() {
    [ "$(uname -s)" = "Darwin" ] || return 0
    command -v security >/dev/null 2>&1 || die "macOS 缺少 security，无法隔离系统凭证库"
    ORIGINAL_USER_KEYCHAIN=$(security default-keychain -d user | sed \
        -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')
    [ -n "$ORIGINAL_USER_KEYCHAIN" ] || die "无法读取原默认用户 Keychain"
    E2E_KEYCHAIN="$TEMP_ROOT/mindone-e2e.keychain-db"
    E2E_KEYCHAIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
    security create-keychain -p "$E2E_KEYCHAIN_PASSWORD" "$E2E_KEYCHAIN" >/dev/null
    E2E_KEYCHAIN_CREATED=1
    security set-keychain-settings -lut 21600 "$E2E_KEYCHAIN" >/dev/null
    security unlock-keychain -p "$E2E_KEYCHAIN_PASSWORD" "$E2E_KEYCHAIN" >/dev/null
    security default-keychain -d user -s "$E2E_KEYCHAIN" >/dev/null
    E2E_KEYCHAIN_SWITCHED=1
}

setup_macos_test_keychain

step "构建真实 CLI 与协调服务器"
cd "$ROOT"
if [ "$PROFILE" = "release" ]; then
    CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$CARGO_JOBS" \
        cargo build --locked -j "$CARGO_JOBS" --release \
            -p mindone-cli -p mindone-coordinator
    CLI="$ROOT/target/release/mindone"
    COORDINATOR="$ROOT/target/release/mindone-coordinator"
else
    CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="$CARGO_JOBS" \
        cargo build --locked -j "$CARGO_JOBS" \
            -p mindone-cli -p mindone-coordinator
    CLI="$ROOT/target/debug/mindone"
    COORDINATOR="$ROOT/target/debug/mindone-coordinator"
fi
[ -x "$CLI" ] && [ -x "$COORDINATOR" ] || die "构建未生成可执行文件"
expected_version=$(awk '
    $0 == "[workspace.package]" { section=1; next }
    /^\[/ { section=0 }
    section && $1 == "version" {
        value=$3
        gsub(/"/, "", value)
        print value
        exit
    }
' "$ROOT/Cargo.toml")
[ -n "$expected_version" ] || die "无法读取 workspace 版本"
[ "$("$CLI" --version)" = "mindone $expected_version" ] \
    || die "CLI 版本与 workspace 版本不一致"

step "启动隔离 PostgreSQL 17"
docker run --detach --name "$DB_CONTAINER" \
    --label org.mindone.test=e2e \
    --env POSTGRES_DB=mindone_e2e \
    --env POSTGRES_USER=mindone \
    --env "POSTGRES_PASSWORD=$DB_PASSWORD" \
    --publish "127.0.0.1:${POSTGRES_PORT}:5432" \
    --tmpfs /var/lib/postgresql/data:rw,size=512m \
    --health-cmd 'pg_isready -U mindone -d mindone_e2e' \
    --health-interval 2s --health-timeout 2s --health-retries 60 \
    "$POSTGRES_IMAGE" >/dev/null
DB_STARTED=1
count=0
while [ "$count" -lt 90 ]; do
    health=$(docker inspect --format '{{.State.Health.Status}}' "$DB_CONTAINER" 2>/dev/null || true)
    [ "$health" = "healthy" ] && break
    [ "$health" = "unhealthy" ] && die "PostgreSQL 容器健康检查失败"
    count=$((count + 1))
    sleep 1
done
[ "${health:-}" = "healthy" ] || die "PostgreSQL 未在 90 秒内就绪"

step "以数据库 owner 显式运行迁移"
if ! DATABASE_URL="$DATABASE_URL" \
MINDONE_ENV=development \
MINDONE_AUTH_PROVIDER=local-development \
MINDONE_BIND="127.0.0.1:${COORDINATOR_PORT}" \
MINDONE_REQUESTS_PER_MINUTE=10000 \
MINDONE_DEV_INITIAL_QUOTA_MICRO=10000000 \
MINDONE_STANDARD_DATA_KEY="$STANDARD_DATA_KEY" \
MINDONE_EVALUATION_DRAW_DENOMINATOR=1 \
MINDONE_EVALUATION_INSTANCE_COOLDOWN_SECONDS=3600 \
RUST_LOG=mindone_coordinator=info,sqlx=warn \
    "$COORDINATOR" database-migrate >"$LOG_DIR/database-migrate.log" 2>&1; then
    die "数据库 owner migration 失败"
fi

step "启动本地开发认证协调服务器"
# 先确定性地执行一次公开 canary，再以实例冷却隔离后续普通任务断言；不能让
# 生产默认的随机 draw 污染领取并发、SSE 与结算阶段。
DATABASE_URL="$DATABASE_URL" \
MINDONE_ENV=development \
MINDONE_AUTH_PROVIDER=local-development \
MINDONE_BIND="127.0.0.1:${COORDINATOR_PORT}" \
MINDONE_REQUESTS_PER_MINUTE=10000 \
MINDONE_DEV_INITIAL_QUOTA_MICRO=10000000 \
MINDONE_STANDARD_DATA_KEY="$STANDARD_DATA_KEY" \
MINDONE_EVALUATION_DRAW_DENOMINATOR=1 \
MINDONE_EVALUATION_INSTANCE_COOLDOWN_SECONDS=3600 \
RUST_LOG=mindone_coordinator=info,sqlx=warn \
    "$COORDINATOR" >"$LOG_DIR/coordinator.log" 2>&1 &
COORDINATOR_PID=$!
wait_http_status "http://127.0.0.1:${COORDINATOR_PORT}/health" 200 90 \
    || die "协调服务器 /health 未就绪"
wait_http_status "http://127.0.0.1:${COORDINATOR_PORT}/ready" 200 10 \
    || die "协调服务器 /ready 未确认数据库"
migration_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -At -F '|' \
    -c 'SELECT COUNT(*)::bigint,MIN(version),MAX(version),COALESCE(BOOL_AND(success),FALSE) FROM _sqlx_migrations')
latest_migration_version=$(
    for migration_path in "$ROOT"/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
        migration_name=${migration_path##*/}
        migration_version=${migration_name%%_*}
        printf '%s\n' "$migration_version"
    done | sort | tail -n 1 | sed 's/^0*//'
)
printf '%s\n' "$latest_migration_version" | grep -Eq '^[1-9][0-9]*$' \
    || die "无法从 migration 文件推导最新版本"
if [ -n "${MINDONE_EXPECTED_MIGRATION_VERSION:-}" ] \
    && [ "$MINDONE_EXPECTED_MIGRATION_VERSION" != "$latest_migration_version" ]; then
    die "CI migration 版本 ${MINDONE_EXPECTED_MIGRATION_VERSION} 与源码最新版本 ${latest_migration_version} 不一致"
fi
expected_migration_state="${latest_migration_version}|1|${latest_migration_version}|t"
[ "$migration_state" = "$expected_migration_state" ] \
    || die "迁移集合不完整（期望 ${expected_migration_state}，实际 ${migration_state}）"
unauthorized_status=$(curl --silent --connect-timeout 2 --max-time 5 \
    --output /dev/null --write-out '%{http_code}' \
    "http://127.0.0.1:${COORDINATOR_PORT}/v1/quota/balance")
[ "$unauthorized_status" = "401" ] || die "受保护 API 未拒绝匿名请求（HTTP ${unauthorized_status}）"

step "配置两个隔离 MINDONE_HOME 并分别登录"
for home in "$NODE_HOME" "$CONSUMER_HOME"; do
    MINDONE_HOME="$home" "$CLI" config set server.url \
        "http://127.0.0.1:${COORDINATOR_PORT}" --quiet
done
if ! MINDONE_HOME="$NODE_HOME" "$CLI" auth login --no-open --json \
    >"$TEMP_ROOT/node-login.json" 2>"$LOG_DIR/node-login.log"; then
    cat "$TEMP_ROOT/node-login.json" >&2 2>/dev/null || true
    cat "$LOG_DIR/node-login.log" >&2 2>/dev/null || true
    die "节点账号登录失败"
fi
assert_cli_ok "$TEMP_ROOT/node-login.json"
NODE_LOGGED_IN=1
if ! MINDONE_HOME="$CONSUMER_HOME" "$CLI" auth login --no-open --json \
    >"$TEMP_ROOT/consumer-login.json" 2>"$LOG_DIR/consumer-login.log"; then
    cat "$TEMP_ROOT/consumer-login.json" >&2 2>/dev/null || true
    cat "$LOG_DIR/consumer-login.log" >&2 2>/dev/null || true
    die "消费者账号登录失败"
fi
assert_cli_ok "$TEMP_ROOT/consumer-login.json"
CONSUMER_LOGGED_IN=1
python3 - "$TEMP_ROOT/node-login.json" "$TEMP_ROOT/consumer-login.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    node = json.load(stream)["data"]
with open(sys.argv[2], encoding="utf-8") as stream:
    consumer = json.load(stream)["data"]
if node["uid"] == consumer["uid"]:
    raise SystemExit("两个隔离 home 被错误映射到同一账号")
if node["key_fingerprint"] == consumer["key_fingerprint"]:
    raise SystemExit("两个隔离 home 复用了设备密钥")
PY

MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota balance --json >"$TEMP_ROOT/consumer-before.json"
MINDONE_HOME="$NODE_HOME" "$CLI" quota balance --json >"$TEMP_ROOT/node-before.json"
assert_cli_ok "$TEMP_ROOT/consumer-before.json"
assert_cli_ok "$TEMP_ROOT/node-before.json"
consumer_before=$(json_number "$TEMP_ROOT/consumer-before.json" data.spendable_micro)
node_spendable_before=$(json_number "$TEMP_ROOT/node-before.json" data.spendable_micro)
node_contribution_before=$(json_number "$TEMP_ROOT/node-before.json" data.contribution_micro)
reserve_before=$(json_number "$TEMP_ROOT/consumer-before.json" data.network_reserve_micro)

step "安装真实 llama.cpp 发行包 ${LLAMA_VERSION}"
MINDONE_HOME="$NODE_HOME" "$CLI" engine install --name llama.cpp --version "$LLAMA_VERSION" --json \
    >"$TEMP_ROOT/engine-install.json" 2>"$LOG_DIR/engine-install.log"
assert_cli_ok "$TEMP_ROOT/engine-install.json"
MINDONE_HOME="$NODE_HOME" "$CLI" engine set-default llama.cpp --quiet
MINDONE_HOME="$NODE_HOME" "$CLI" engine detect --json >"$TEMP_ROOT/hardware.json"
assert_cli_ok "$TEMP_ROOT/hardware.json"

step "下载并验证许可证允许测试的小型 GGUF 模型"
set -- model download --platform huggingface --repo "$MODEL_REPO" --branch "$MODEL_BRANCH" \
    --file "$MODEL_FILE" --name "$MODEL_NAME"
if [ -n "$MODEL_SHA256" ]; then
    set -- "$@" --sha256 "$MODEL_SHA256"
fi
# 公网模型下载可能因连接重置/响应体截断而瞬时失败（HuggingFace CDN）。这是外部
# 网络抖动，不是被测系统缺陷；对下载做有界重试，SHA-256/结构验证仍然强制执行，
# 不会接受不完整或不匹配的 artifact。
download_ok=0
download_attempt=0
while [ "$download_attempt" -lt 5 ]; do
    if MINDONE_HOME="$NODE_HOME" "$CLI" "$@" --json \
        >"$TEMP_ROOT/model-download.json" 2>"$LOG_DIR/model-download.log"; then
        download_ok=1
        break
    fi
    download_attempt=$((download_attempt + 1))
    printf '模型下载第 %s 次尝试失败，重试中……\n' "$download_attempt" >&2
    tail -1 "$LOG_DIR/model-download.log" >&2 2>/dev/null || true
    rm -f "$NODE_HOME/models/".*.part.gguf 2>/dev/null || true
    sleep 3
done
[ "$download_ok" -eq 1 ] || die "模型下载在多次重试后仍失败（外部网络问题）"
assert_cli_ok "$TEMP_ROOT/model-download.json"
MINDONE_HOME="$NODE_HOME" "$CLI" model verify "$MODEL_NAME" --json \
    >"$TEMP_ROOT/model-verify.json"
assert_cli_ok "$TEMP_ROOT/model-verify.json"
python3 - "$TEMP_ROOT/model-verify.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    model = json.load(stream)["data"]
if str(model.get("format", "")).lower() != "gguf":
    raise SystemExit("E2E 模型未被识别为 GGUF")
if not re.fullmatch(r"[0-9a-f]{64}", model.get("sha256", "")):
    raise SystemExit("E2E 模型缺少有效 SHA-256")
if model.get("size_bytes", 0) <= 1_000_000:
    raise SystemExit("E2E 模型大小异常")
PY

step "启动受管本地推理并通过 llama-server 健康检查"
if [ "$CPU_ONLY" = "1" ]; then
    printf 'cpu_only: true\n' >"$TEMP_ROOT/serve-config.yml"
else
    printf 'cpu_only: false\n' >"$TEMP_ROOT/serve-config.yml"
fi
if ! MINDONE_HOME="$NODE_HOME" "$CLI" serve run --model "$MODEL_NAME" \
    --engine llama.cpp --port "$LLAMA_PORT" --config "$TEMP_ROOT/serve-config.yml" \
    --json >"$TEMP_ROOT/serve.json" 2>"$LOG_DIR/serve-start.log"; then
    cat "$TEMP_ROOT/serve.json" >&2 2>/dev/null || true
    cat "$LOG_DIR/serve-start.log" >&2 2>/dev/null || true
    if [ "$LLAMA_PORT" -eq 8080 ]; then
        startup_log="$NODE_HOME/logs/llama-server.log"
    else
        startup_log="$NODE_HOME/logs/llama-server-${LLAMA_PORT}.log"
    fi
    # 此时尚未发送任何推理请求；若引擎在受管无明文日志策略下仍输出启动错误，
    # 只显示有界尾部用于区分加载缓慢与监督进程失败。
    if [ -f "$startup_log" ]; then
        tail -200 "$startup_log" >&2
    fi
    die "受管本地推理启动失败"
fi
assert_cli_ok "$TEMP_ROOT/serve.json"
SERVING=1
wait_http_status "http://127.0.0.1:${LLAMA_PORT}/health" 200 30 \
    || die "llama-server /health 未就绪"
MINDONE_HOME="$NODE_HOME" "$CLI" serve status --port "$LLAMA_PORT" --json \
    >"$TEMP_ROOT/serve-status.json"
assert_cli_ok "$TEMP_ROOT/serve-status.json"
expected_trust=$(python3 - "$TEMP_ROOT/serve.json" "$TEMP_ROOT/serve-status.json" <<'PY'
import json
import re
import sys

def canonical(value):
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", str(value))
    return value.replace("-", "_").lower()

with open(sys.argv[1], encoding="utf-8") as stream:
    serve = json.load(stream)["data"]
with open(sys.argv[2], encoding="utf-8") as stream:
    status = json.load(stream)["data"]["status"]
if not status.get("running") or not status.get("healthy") or not status.get("process_verified"):
    raise SystemExit("推理服务没有同时通过运行、健康与进程身份检查")
mechanisms = serve.get("sandbox_mechanisms")
if not isinstance(mechanisms, list) or not mechanisms:
    raise SystemExit("推理服务没有上报实际应用的 sandbox mechanism")
expected = canonical(serve.get("trust_level"))
observed = canonical(status.get("state", {}).get("trust_level"))
if expected != observed:
    raise SystemExit(f"serve run/status 信任等级不一致：{expected} != {observed}")
if expected not in ("standard", "standard_limited"):
    raise SystemExit(f"E2E 节点未达到 Standard 经济权重：{expected}")
if sys.platform == "darwin" and mechanisms != ["seatbelt"]:
    raise SystemExit(f"macOS E2E 应只上报实际应用的 seatbelt：{mechanisms}")
print(expected)
PY
)

step "发布贡献节点并确认真实心跳在线"
MINDONE_HOME="$NODE_HOME" "$CLI" share publish --model "$MODEL_NAME" --port "$LLAMA_PORT" \
    --alias e2e-node-b --tags e2e,gguf --json >"$TEMP_ROOT/publish.json"
assert_cli_ok "$TEMP_ROOT/publish.json"
PUBLISHED=1
published_model_id=$(python3 - "$TEMP_ROOT/publish.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["data"]["model_id"])
PY
)
published_model_instance_id=$(python3 - "$TEMP_ROOT/publish.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["data"]["model_instance_id"])
PY
)
billing_valid_from=$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
PY
)
billing_valid_until=$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) + timedelta(days=7)).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
PY
)
set -- billing-profile-record \
    --model-id "$published_model_id" \
    --profile-version 1 \
    --reference-hardware-class e2e-real-gguf-local \
    --maximum-input-tokens 65536 \
    --maximum-output-tokens 4096 \
    --fixed-gpu-time-us 100000 \
    --gpu-time-us-per-1k-tokens 2000000 \
    --reference-vram-mib 8192 \
    --token-rate-micro-per-1k 100000 \
    --gpu-rate-micro-per-second 1000 \
    --vram-rate-micro-per-gib-second 1000 \
    --evidence-file "$TEMP_ROOT/model-verify.json" \
    --valid-from "$billing_valid_from" \
    --valid-until "$billing_valid_until" \
    --operator e2e-operator \
    --reason "E2E 真实 GGUF 路由计费验证" \
    --idempotency-key e2e-real-gguf-profile-v1
DATABASE_URL="$DATABASE_URL" \
MINDONE_ENV=development \
MINDONE_AUTH_PROVIDER=local-development \
MINDONE_BIND="127.0.0.1:${COORDINATOR_PORT}" \
MINDONE_REQUESTS_PER_MINUTE=10000 \
MINDONE_DEV_INITIAL_QUOTA_MICRO=10000000 \
MINDONE_STANDARD_DATA_KEY="$STANDARD_DATA_KEY" \
    "$COORDINATOR" "$@" >"$TEMP_ROOT/billing-profile.json" \
    2>"$LOG_DIR/billing-profile.log"
DATABASE_URL="$DATABASE_URL" \
MINDONE_ENV=development \
MINDONE_AUTH_PROVIDER=local-development \
MINDONE_BIND="127.0.0.1:${COORDINATOR_PORT}" \
MINDONE_REQUESTS_PER_MINUTE=10000 \
MINDONE_DEV_INITIAL_QUOTA_MICRO=10000000 \
MINDONE_STANDARD_DATA_KEY="$STANDARD_DATA_KEY" \
    "$COORDINATOR" "$@" >"$TEMP_ROOT/billing-profile-replay.json" \
    2>>"$LOG_DIR/billing-profile.log"
python3 - "$TEMP_ROOT/billing-profile.json" "$TEMP_ROOT/billing-profile-replay.json" \
    "$published_model_id" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    first = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    replay = json.load(stream)
if first.get("contract_version") != "server_reference_upper_bound_v1":
    raise SystemExit("E2E 计费 profile 合同版本错误")
if first.get("model_id") != sys.argv[3] or replay.get("model_id") != sys.argv[3]:
    raise SystemExit("E2E 计费 profile 未绑定发布模型")
for field in ("profile_fingerprint", "request_fingerprint", "evidence_sha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", str(first.get(field, ""))):
        raise SystemExit(f"E2E 计费 profile 缺少规范 {field}")
    if replay.get(field) != first.get(field):
        raise SystemExit(f"E2E 计费 profile 幂等重放改变了 {field}")
if first.get("idempotent_replay") is not False:
    raise SystemExit("E2E 首次计费 profile 发布未标记为新写入")
if replay.get("idempotent_replay") is not True:
    raise SystemExit("E2E 计费 profile 相同幂等键未返回重放")
if replay.get("profile_id") != first.get("profile_id"):
    raise SystemExit("E2E 计费 profile 幂等重放改变 profile_id")
PY
MINDONE_HOME="$NODE_HOME" "$CLI" share stats --json >"$TEMP_ROOT/stats-before.json"
assert_cli_ok "$TEMP_ROOT/stats-before.json"
python3 - "$TEMP_ROOT/publish.json" "$TEMP_ROOT/stats-before.json" "$expected_trust" <<'PY'
import json
import re
import sys

def canonical(value):
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", str(value))
    return value.replace("-", "_").lower()

with open(sys.argv[1], encoding="utf-8") as stream:
    published = json.load(stream)["data"]
with open(sys.argv[2], encoding="utf-8") as stream:
    stats = json.load(stream)["data"]
expected = sys.argv[3]
if canonical(published.get("trust_level")) != expected:
    raise SystemExit(
        f"节点发布信任等级与本地 sandbox 不一致：{published.get('trust_level')} != {expected}"
    )
server_trust = stats.get("server", {}).get("trust_level")
if canonical(server_trust) != expected:
    raise SystemExit(f"协调服务器信任等级不一致：{server_trust} != {expected}")
if not stats.get("worker_running"):
    raise SystemExit("共享 worker 未运行")
if not stats.get("last_heartbeat_at"):
    raise SystemExit("尚未记录协调服务器心跳")
PY
published_node_id=$(python3 - "$TEMP_ROOT/publish.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["data"]["node_id"])
PY
)
rtt_ready=0
count=0
while [ "$count" -lt 20 ]; do
    coordinator_rtt_ms=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT coordinator_rtt_ms FROM node_metrics
            WHERE node_id = '${published_node_id}'::uuid
              AND coordinator_rtt_ms IS NOT NULL
            ORDER BY measured_at DESC LIMIT 1")
    case "$coordinator_rtt_ms" in
        ''|*[!0-9]*) ;;
        *)
            if [ "$coordinator_rtt_ms" -ge 1 ] && [ "$coordinator_rtt_ms" -le 60000 ]; then
                rtt_ready=1
                break
            fi
            ;;
    esac
    count=$((count + 1))
    sleep 1
done
[ "$rtt_ready" -eq 1 ] \
    || die "第二次及后续真实心跳没有写入正数 coordinator_rtt_ms"
docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT jsonb_build_object(
        'node_id', id,
        'trust_level', trust_level,
        'operating_system', hardware_profile->>'operating_system',
        'sandbox_mechanisms', hardware_profile->'sandbox_mechanisms'
    ) FROM nodes WHERE id = '${published_node_id}'::uuid" >"$TEMP_ROOT/node-db.json"
python3 - "$TEMP_ROOT/node-db.json" "$expected_trust" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    node = json.load(stream)
expected = sys.argv[2]
if node.get("trust_level", "").replace("-", "_") != expected:
    raise SystemExit(f"数据库节点信任等级不一致：{node.get('trust_level')} != {expected}")
if sys.platform == "darwin":
    if node.get("operating_system") != "macos":
        raise SystemExit(f"macOS 节点没有使用稳定协议标识 macos：{node.get('operating_system')}")
    if node.get("sandbox_mechanisms") != ["seatbelt"]:
        raise SystemExit(
            f"数据库节点没有只记录实际应用的 seatbelt：{node.get('sandbox_mechanisms')}"
        )
PY

step "启动消费者额度代理并发送动态真实推理请求"
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota use --model auto --port "$PROXY_PORT" --quiet \
    >"$LOG_DIR/quota-proxy.log" 2>&1 &
PROXY_PID=$!
wait_tcp 127.0.0.1 "$PROXY_PORT" 30 || die "额度代理未监听"
curl --fail --silent --show-error --connect-timeout 5 --max-time 30 \
    "http://127.0.0.1:${PROXY_PORT}/v1/models" \
    >"$TEMP_ROOT/proxy-models.json"
python3 - "$TEMP_ROOT/proxy-models.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
if response.get("object") != "list":
    raise SystemExit("OpenAI 模型列表缺少 object=list")
models = response.get("data")
if not isinstance(models, list) or not models:
    raise SystemExit("OpenAI 模型列表为空")
for model in models:
    if not isinstance(model, dict) or not isinstance(model.get("id"), str) or not model["id"]:
        raise SystemExit("OpenAI 模型列表含无效 model.id")
    if model.get("object") != "model":
        raise SystemExit("OpenAI 模型列表含无效 model.object")
PY
nonce="MINDONE-$(date +%s)-$$"
python3 - "$TEMP_ROOT/request.json" "$nonce" <<'PY'
import json
import sys

request = {
    "model": "auto",
    "messages": [{"role": "user", "content": f"/no_think\n只回复：MindOne 已连接 {sys.argv[2]}"}],
    "temperature": 0,
    "max_tokens": 96,
    "stream": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(request, stream, ensure_ascii=False)
PY
# 等待节点在协调器侧成为可路由候选，再发起首个推理请求（publish 后有心跳周期窗口）。
wait_node_routable
# 节点 publish 返回后到成为可路由候选之间存在窗口：`/v1/models` 已能列出实例，
# 但任务路由还要求节点 online 且心跳新鲜。除上面的就绪闸门外，仍对创建任务前的
# 瞬时 502/503 做有界重试；路由候选为空时协调器在创建任务前返回 503，不会创建任务，
# 因此重试安全，既不会重复建单或结算，也不放宽任何服务端资格判定。
chat_http_status=0
chat_attempt=0
while [ "$chat_attempt" -lt 20 ]; do
    chat_http_status=$(curl --silent --show-error --connect-timeout 5 --max-time 660 \
        -H 'Content-Type: application/json' \
        --data-binary "@$TEMP_ROOT/request.json" \
        -o "$TEMP_ROOT/inference.json" \
        -w '%{http_code}' \
        "http://127.0.0.1:${PROXY_PORT}/v1/chat/completions")
    if [ "$chat_http_status" = "200" ]; then
        break
    fi
    if [ "$chat_http_status" != "502" ] && [ "$chat_http_status" != "503" ]; then
        break
    fi
    chat_attempt=$((chat_attempt + 1))
    sleep 1
done
if [ "$chat_http_status" != "200" ]; then
    printf '真实 chat 推理返回 HTTP %s，响应体：\n' "$chat_http_status" >&2
    cat "$TEMP_ROOT/inference.json" >&2 || true
    printf '\n=== 最近 job_attempts 失败诊断 ===\n' >&2
    docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' -c "
        SELECT j.status, ja.attempt_number, ja.error_class, ja.error_message
        FROM jobs j
        LEFT JOIN job_attempts ja ON ja.job_id=j.id
        ORDER BY j.created_at DESC, ja.attempt_number DESC
        LIMIT 5" >&2 || true
    printf '=== 诊断结束 ===\n' >&2
    die "真实 chat 推理未返回 200"
fi
python3 - "$TEMP_ROOT/inference.json" "$nonce" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
choices = response.get("choices")
if not isinstance(choices, list) or not choices:
    raise SystemExit("真实推理响应缺少 choices")
content = choices[0].get("message", {}).get("content")
if not isinstance(content, str) or "MindOne" not in content or "已连接" not in content:
    raise SystemExit("真实模型未返回指定中文内容")
if sys.argv[2] not in content:
    raise SystemExit("真实模型未返回运行时动态 nonce，疑似固定响应或推理失败")
usage = response.get("usage", {})
if not isinstance(usage.get("completion_tokens"), int) or usage["completion_tokens"] <= 0:
    raise SystemExit("真实推理响应缺少正数 completion_tokens")
PY

# denominator=1 保证 worker 的首次可领取工作是公开 canary；一小时实例冷却
# 随后把本次 E2E 的普通任务路径与随机隐藏评价隔离。首个消费者请求已经成功，
# 因而此时 canary 必须存在且不再占用 worker slot。
evaluation_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' \
    -c "SELECT COUNT(*)::bigint,
               COUNT(*) FILTER (WHERE challenge_kind='canary')::bigint,
               COUNT(*) FILTER (WHERE status='leased')::bigint,
               COUNT(*) FILTER (
                   WHERE status IN ('succeeded','failed')
                     AND completed_at IS NOT NULL
                     AND challenge_seed IS NULL
                     AND worker_submission_kind IN ('result','fail')
               )::bigint
        FROM model_evaluation_challenges
        WHERE node_id='${published_node_id}'::uuid")
[ "$evaluation_state" = '1|1|0|1' ] \
    || die "确定性公开 canary 未完成或冷却隔离无效：$evaluation_state"

# 无条件诊断：转储首个推理相关的所有 attempt（含失败原因）。结果提交若被协调器
# 确定性判为 400（invalid_job_result/usage_binding/model_binding），worker 会提交一次固定、
# 脱敏且不可重试的 terminal failure；这里把服务端最终状态显式打印，便于确认失败已
# 正常收口，而不是遗留 leased/retry 并耗尽单 slot。
printf '=== 首个推理 job_attempts 诊断（不影响结果，仅供定位）===\n' >&2
docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' -c "
    SELECT j.status, ja.attempt_number, ja.status, ja.error_class, ja.error_message
    FROM job_attempts ja JOIN jobs j ON j.id = ja.job_id
    ORDER BY ja.lease_started_at DESC LIMIT 6" >&2 2>/dev/null || true
printf '=== 诊断结束 ===\n' >&2

standard_storage_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -At -F '|' -c "
        SELECT standard_payload_storage_version,
               standard_result_storage_version,
               encrypted_payload ~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$',
               result_ciphertext ~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$',
               standard_request_fingerprint ~ '^mindone-standard-hmac-v1:[0-9a-f]{64}$'
        FROM jobs
        WHERE confidentiality_mode='standard' AND status='succeeded'
        ORDER BY completed_at DESC
        LIMIT 1")
[ "$standard_storage_state" = '1|1|t|t|t' ] \
    || die "Standard payload/result 未使用数据库 AEAD v1 与 keyed fingerprint"

step "核对消费者、贡献节点、准备金与荣誉账单结算"
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota balance --json >"$TEMP_ROOT/consumer-after.json"
MINDONE_HOME="$NODE_HOME" "$CLI" quota balance --json >"$TEMP_ROOT/node-after.json"
assert_cli_ok "$TEMP_ROOT/consumer-after.json"
assert_cli_ok "$TEMP_ROOT/node-after.json"
consumer_after=$(json_number "$TEMP_ROOT/consumer-after.json" data.spendable_micro)
node_spendable_after=$(json_number "$TEMP_ROOT/node-after.json" data.spendable_micro)
node_contribution_after=$(json_number "$TEMP_ROOT/node-after.json" data.contribution_micro)
reserve_after=$(json_number "$TEMP_ROOT/consumer-after.json" data.network_reserve_micro)
[ "$consumer_after" -lt "$consumer_before" ] || die "消费者可用额度未减少"
[ "$node_spendable_after" -gt "$node_spendable_before" ] || die "贡献节点可用额度未增加"
[ "$node_contribution_after" -gt "$node_contribution_before" ] || die "贡献值未增加"
[ "$reserve_after" -gt "$reserve_before" ] || die "网络准备金未增加"

MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota history --page-size 200 --json \
    >"$TEMP_ROOT/history.json"
assert_cli_ok "$TEMP_ROOT/history.json"
receipt_id=$(python3 - "$TEMP_ROOT/history.json" <<'PY'
import json
import sys
import uuid

with open(sys.argv[1], encoding="utf-8") as stream:
    entries = json.load(stream)["data"].get("entries", [])
for entry in entries:
    receipt = entry.get("receipt_id")
    if receipt:
        try:
            receipt_id = uuid.UUID(str(receipt))
        except ValueError as error:
            raise SystemExit(f"额度历史返回无效 receipt_id：{error}") from error
        print(receipt_id)
        raise SystemExit(0)
raise SystemExit("额度历史没有公开结算 receipt_id")
PY
)
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota receipt --id "$receipt_id" --json \
    >"$TEMP_ROOT/receipt.json"
assert_cli_ok "$TEMP_ROOT/receipt.json"
python3 - "$TEMP_ROOT/receipt.json" "$receipt_id" "$expected_trust" \
    "$TEMP_ROOT/consumer-before.json" "$TEMP_ROOT/consumer-after.json" \
    "$TEMP_ROOT/node-before.json" "$TEMP_ROOT/node-after.json" \
    "$TEMP_ROOT/billing-profile.json" \
    >"$TEMP_ROOT/settlement-check.json" <<'PY'
import json
import re
import sys

def load_data(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)["data"]

receipt = load_data(sys.argv[1])
if str(receipt.get("receipt_id")) != sys.argv[2]:
    raise SystemExit("荣誉账单 ID 不匹配")
for field in ("user_deduction_micro", "node_quota_micro", "contribution_micro", "reserve_micro"):
    if not isinstance(receipt.get(field), int) or receipt[field] <= 0:
        raise SystemExit(f"荣誉账单字段不是正数：{field}")
if not re.fullmatch(r"[0-9a-f]{64}", receipt.get("settlement_hash", "")):
    raise SystemExit("荣誉账单缺少有效 settlement_hash")

expected_trust = sys.argv[3]
if receipt.get("trust_level", "").replace("-", "_") != expected_trust:
    raise SystemExit(
        f"荣誉账单信任等级与实际 sandbox 不一致：{receipt.get('trust_level')} != {expected_trust}"
    )
if expected_trust not in ("standard", "standard_limited"):
    raise SystemExit(f"荣誉账单没有使用 Standard 经济权重：{expected_trust}")

tier_milli = {"high": 1500, "medium": 1000, "low": 700}.get(receipt.get("tier"))
if tier_milli is None:
    raise SystemExit(f"荣誉账单 tier 无效：{receipt.get('tier')}")
base_cost = receipt.get("base_cost_micro")
if not isinstance(base_cost, int) or base_cost <= 0:
    raise SystemExit("荣誉账单 base_cost_micro 不是正整数")
billing = receipt.get("billing")
if not isinstance(billing, dict):
    raise SystemExit("荣誉账单缺少冻结物理计费明细")
with open(sys.argv[8], encoding="utf-8") as stream:
    provisioned_profile = json.load(stream)
if billing.get("contract_version") != "server_reference_upper_bound_v1":
    raise SystemExit("荣誉账单物理计费合同版本错误")
for field in ("profile_id", "profile_fingerprint", "profile_evidence_hash"):
    expected_field = "evidence_sha256" if field == "profile_evidence_hash" else field
    if billing.get(field) != provisioned_profile.get(expected_field):
        raise SystemExit(f"荣誉账单冻结计费字段与 provision audit 不一致：{field}")
for field in (
    "authorized_input_tokens",
    "authorized_max_output_tokens",
    "billable_tokens",
    "reference_gpu_time_us",
    "reference_vram_mib_microseconds",
    "token_cost_micro",
    "gpu_cost_micro",
    "vram_cost_micro",
    "base_cost_micro",
):
    if not isinstance(billing.get(field), int) or billing[field] <= 0:
        raise SystemExit(f"荣誉账单物理计费字段不是正整数：{field}")
if billing["billable_tokens"] != (
    billing["authorized_input_tokens"] + billing["authorized_max_output_tokens"]
):
    raise SystemExit("荣誉账单 billable token 上界不等于两项授权之和")
if billing["base_cost_micro"] != (
    billing["token_cost_micro"]
    + billing["gpu_cost_micro"]
    + billing["vram_cost_micro"]
):
    raise SystemExit("荣誉账单物理计费三分项与基础成本不守恒")
if billing["base_cost_micro"] != base_cost:
    raise SystemExit("荣誉账单总基础成本与冻结物理计费基础成本不一致")
contribution_weight_ppm = receipt.get("contribution_weight_ppm")
if contribution_weight_ppm != 1_000_000:
    raise SystemExit(f"干净 E2E 的贡献权重应为 1000000 ppm：{contribution_weight_ppm}")

user_deduction = (base_cost * tier_milli + 999) // 1000
node_quota = user_deduction * 800 * 1000 // 1_000_000
contribution_points = user_deduction * 1200 * 1000 // 1_000_000
contribution = contribution_points * contribution_weight_ppm // 1_000_000
reserve = user_deduction - node_quota
expected_amounts = {
    "user_deduction_micro": user_deduction,
    "node_quota_micro": node_quota,
    "contribution_micro": contribution,
    "reserve_micro": reserve,
}
for field, expected in expected_amounts.items():
    if receipt.get(field) != expected:
        raise SystemExit(f"Standard 整数结算不匹配：{field}={receipt.get(field)}，应为 {expected}")

consumer_before = load_data(sys.argv[4])
consumer_after = load_data(sys.argv[5])
node_before = load_data(sys.argv[6])
node_after = load_data(sys.argv[7])
balance_deltas = {
    "consumer_spendable_micro": consumer_before["spendable_micro"] - consumer_after["spendable_micro"],
    "node_spendable_micro": node_after["spendable_micro"] - node_before["spendable_micro"],
    "node_contribution_micro": node_after["contribution_micro"] - node_before["contribution_micro"],
    "network_reserve_micro": consumer_after["network_reserve_micro"] - consumer_before["network_reserve_micro"],
}
expected_deltas = {
    "consumer_spendable_micro": user_deduction,
    "node_spendable_micro": node_quota,
    "node_contribution_micro": contribution,
    "network_reserve_micro": reserve,
}
if balance_deltas != expected_deltas:
    raise SystemExit(f"余额变化与荣誉账单不一致：{balance_deltas} != {expected_deltas}")

json.dump(
    {
        "trust_level": expected_trust,
        "trust_class": "standard",
        "trust_multiplier_milli": 1000,
        "tier_multiplier_milli": tier_milli,
        "contribution_weight_ppm": contribution_weight_ppm,
        "expected_amounts": expected_amounts,
        "balance_deltas": balance_deltas,
    },
    sys.stdout,
    ensure_ascii=False,
    indent=2,
)
print()
PY
db_receipt_count=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT COUNT(*) FROM receipts WHERE id = '${receipt_id}'::uuid")
[ "$db_receipt_count" -eq 1 ] || die "数据库没有对应荣誉账单"
job_id=$(python3 - "$TEMP_ROOT/receipt.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["data"]["job_id"])
PY
)
docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT to_jsonb(receipts) FROM receipts WHERE id = '${receipt_id}'::uuid" \
    >"$TEMP_ROOT/receipt-db.json"
docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT COALESCE(jsonb_agg(to_jsonb(entries) ORDER BY ledger, entry_type), '[]'::jsonb) FROM (
        SELECT 'quota'::text AS ledger, user_id::text AS subject_id, entry_type,
               delta_micro, balance_before_micro, balance_after_micro, prev_hash, entry_hash
        FROM quota_ledger WHERE request_id = '${job_id}'::uuid
        UNION ALL
        SELECT 'contribution', user_id::text, entry_type,
               delta_micro, balance_before_micro, balance_after_micro, prev_hash, entry_hash
        FROM contribution_ledger WHERE request_id = '${job_id}'::uuid
        UNION ALL
        SELECT 'reserve', 'network', entry_type,
               delta_micro, balance_before_micro, balance_after_micro, prev_hash, entry_hash
        FROM reserve_ledger WHERE request_id = '${job_id}'::uuid
    ) AS entries" >"$TEMP_ROOT/ledger-db.json"
python3 - "$TEMP_ROOT/ledger-db.json" "$TEMP_ROOT/receipt.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    entries = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    receipt = json.load(stream)["data"]
expected = {
    ("quota", "consumer_deduction"): -receipt["user_deduction_micro"],
    ("quota", "node_reward"): receipt["node_quota_micro"],
    ("contribution", "node_contribution"): receipt["contribution_micro"],
    ("reserve", "settlement_inflow"): receipt["reserve_micro"],
}
observed = {(entry["ledger"], entry["entry_type"]): entry["delta_micro"] for entry in entries}
if observed != expected:
    raise SystemExit(f"追加账本与荣誉账单不一致：{observed} != {expected}")
for entry in entries:
    if not re.fullmatch(r"[0-9a-f]{64}", entry.get("prev_hash", "")):
        raise SystemExit("账本缺少有效 prev_hash")
    if not re.fullmatch(r"[0-9a-f]{64}", entry.get("entry_hash", "")):
        raise SystemExit("账本缺少有效 entry_hash")
    if entry["balance_after_micro"] - entry["balance_before_micro"] != entry["delta_micro"]:
        raise SystemExit(f"账本余额链不匹配：{entry}")
PY
reserve_ledger_count=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM reserve_ledger WHERE delta_micro > 0')
[ "$reserve_ledger_count" -gt 0 ] || die "准备金只改余额但没有追加账本"

metrics_ready=0
count=0
while [ "$count" -lt 15 ]; do
    MINDONE_HOME="$NODE_HOME" "$CLI" share stats --json >"$TEMP_ROOT/stats-after.json"
    if python3 - "$TEMP_ROOT/stats-after.json" "$expected_trust" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)["data"]
local = data.get("local") or {}
if local.get("requests", 0) < 1 or local.get("successes", 0) < 1:
    raise SystemExit("节点本地指标没有记录真实成功请求")
if not isinstance(local.get("tps"), (int, float)) or local["tps"] <= 0:
    raise SystemExit("节点本地指标缺少正数 tps")
if not isinstance(local.get("ttft_ms"), (int, float)) or local["ttft_ms"] <= 0:
    raise SystemExit("节点本地指标缺少正数 ttft_ms")

def canonical(value):
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", str(value))
    return value.replace("-", "_").lower()

expected = sys.argv[2]
if canonical(local.get("trust_level")) != expected:
    raise SystemExit(f"本地指标信任等级不一致：{local.get('trust_level')} != {expected}")
server_trust = data.get("server", {}).get("trust_level")
if canonical(server_trust) != expected:
    raise SystemExit(f"服务端指标信任等级不一致：{server_trust} != {expected}")
PY
    then
        metrics_ready=1
        break
    fi
    count=$((count + 1))
    sleep 1
done
[ "$metrics_ready" -eq 1 ] || die "节点本地指标没有记录真实成功请求"

step "在服务端领取检查后改变节点阈值，并证明执行前复核失败且零结算"
# 该步骤依赖任务被真实领取，再由执行前策略复核拒绝；发起前等待节点可路由，
# 避免因上一次任务刚结算的窗口导致任务无法被创建/领取。
wait_node_routable
POLICY_PATH="$NODE_HOME/runtime/node-policy.json"
[ -f "$POLICY_PATH" ] && [ ! -L "$POLICY_PATH" ] \
    || die "共享 worker 缺少可验证的本地策略文件"
cp "$POLICY_PATH" "$TEMP_ROOT/policy-before-post-claim.json"
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota balance --json \
    >"$TEMP_ROOT/policy-consumer-before.json"
MINDONE_HOME="$NODE_HOME" "$CLI" quota balance --json \
    >"$TEMP_ROOT/policy-node-before.json"
assert_cli_ok "$TEMP_ROOT/policy-consumer-before.json"
assert_cli_ok "$TEMP_ROOT/policy-node-before.json"
policy_jobs_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM jobs')
policy_receipts_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')

# 这个测试专用触发器只存在于即将销毁的 E2E 数据库。它在协调器已经完成
# 候选/策略检查并写入 leased 状态时阻塞事务，让测试能确定性地修改本地策略；
# 释放后 worker 收到 claim，必须在调用 llama-server 前重新读取策略并拒绝。
docker exec -i "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE FUNCTION mindone_e2e_pause_standard_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(62001, 62002);
    RETURN NEW;
END;
$$;

CREATE TRIGGER mindone_e2e_pause_standard_lease
BEFORE UPDATE OF status ON jobs
FOR EACH ROW
WHEN (
    NEW.status = 'leased'
    AND OLD.status IS DISTINCT FROM 'leased'
    AND NEW.confidentiality_mode = 'standard'
)
EXECUTE FUNCTION mindone_e2e_pause_standard_lease();
SQL

docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 \
    -c "SET application_name='mindone-e2e-policy-lock';
        SELECT pg_advisory_lock(62001,62002);
        SELECT pg_sleep(600);" \
    >"$LOG_DIR/policy-lock.log" 2>&1 &
POLICY_LOCK_PID=$!
policy_lock_backend=
count=0
while [ "$count" -lt 100 ]; do
    policy_lock_backend=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT a.pid FROM pg_stat_activity a
            WHERE a.application_name='mindone-e2e-policy-lock'
              AND EXISTS (
                  SELECT 1 FROM pg_locks l
                  WHERE l.pid=a.pid AND l.locktype='advisory' AND l.granted
                    AND l.classid=62001 AND l.objid=62002
              )")
    case "$policy_lock_backend" in
        ''|*[!0-9]*) ;;
        *) break ;;
    esac
    kill -0 "$POLICY_LOCK_PID" 2>/dev/null || die "策略并发锁持有进程提前退出"
    count=$((count + 1))
    sleep 0.05
done
case "$policy_lock_backend" in
    ''|*[!0-9]*) die "未确认测试事务持有策略并发 advisory lock" ;;
esac

policy_nonce="MINDONE-POLICY-$(date +%s)-$$"
python3 - "$TEMP_ROOT/policy-request.json" "$policy_nonce" <<'PY'
import json
import sys

request = {
    "model": "auto",
    "messages": [{"role": "user", "content": f"绝不能推理或记录：{sys.argv[2]}"}],
    "temperature": 0,
    "max_tokens": 32,
    "stream": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(request, stream, ensure_ascii=False)
PY
(
    curl --silent --show-error --connect-timeout 5 --max-time 180 \
        -H 'Content-Type: application/json' \
        --data-binary "@$TEMP_ROOT/policy-request.json" \
        --output "$TEMP_ROOT/policy-response.json" \
        --write-out '%{http_code}' \
        "http://127.0.0.1:${PROXY_PORT}/v1/chat/completions" \
        >"$TEMP_ROOT/policy-http-status"
) >"$LOG_DIR/policy-request.log" 2>&1 &
POLICY_REQUEST_PID=$!

# 先证明消费者已经且只创建了预期普通任务，再观察该任务的领取事务；这样失败时
# 能区分“尚未建单”和“已经建单但 worker 未到达 leased 写入点”。
expected_policy_jobs=$((policy_jobs_before + 1))
policy_job_created=0
count=0
while [ "$count" -lt 200 ]; do
    policy_jobs_now=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c 'SELECT COUNT(*) FROM jobs')
    if [ "$policy_jobs_now" -eq "$expected_policy_jobs" ]; then
        policy_job_created=1
        break
    fi
    [ "$policy_jobs_now" -lt "$expected_policy_jobs" ] \
        || die "策略并发阶段意外创建了多个普通任务"
    kill -0 "$POLICY_REQUEST_PID" 2>/dev/null \
        || die "策略并发阶段尚未建单，消费者请求已提前结束"
    count=$((count + 1))
    sleep 0.05
done
[ "$policy_job_created" -eq 1 ] || die "10 秒内未创建策略并发测试的普通任务"
policy_job_id=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT id::text FROM jobs ORDER BY created_at DESC,id DESC LIMIT 1')
printf '%s\n' "$policy_job_id" \
    | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
    || die "策略并发任务 ID 无效"

blocked_claim_seen=0
count=0
while [ "$count" -lt 900 ]; do
    blocked_claims=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT COUNT(*) FROM pg_locks waiting
            WHERE waiting.locktype='advisory'
              AND waiting.classid=62001 AND waiting.objid=62002
              AND NOT waiting.granted")
    if [ "$blocked_claims" -ge 1 ]; then
        blocked_claim_seen=1
        break
    fi
    kill -0 "$POLICY_REQUEST_PID" 2>/dev/null \
        || die "策略变更前请求已经结束，未形成领取后并发窗口"
    count=$((count + 1))
    sleep 0.05
done
[ "$blocked_claim_seen" -eq 1 ] \
    || die "45 秒内未观察到 claim 事务在领取写入点等待测试 advisory lock"

# 保留 1 PiB 显存会在“指标不可读”或“真实可用显存不足”两种情况下都失败关闭，
# 因而不依赖某个平台是否能读取 GPU 温度，也不会靠测试伪造硬件样本。
MINDONE_HOME="$NODE_HOME" "$CLI" node threshold set --vram-reserve 1048576 --quiet
terminated=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT pg_terminate_backend(${policy_lock_backend})")
[ "$terminated" = "t" ] || die "无法释放测试专用策略并发锁"
wait "$POLICY_LOCK_PID" 2>/dev/null || true
POLICY_LOCK_PID=""
if ! wait "$POLICY_REQUEST_PID"; then
    POLICY_REQUEST_PID=""
    die "策略拒绝请求发生 HTTP 传输失败"
fi
POLICY_REQUEST_PID=""
policy_http_status=$(cat "$TEMP_ROOT/policy-http-status")
case "$policy_http_status" in
    4??|5??) ;;
    *) die "领取后策略变化未向消费者返回失败（HTTP ${policy_http_status}）" ;;
esac

policy_jobs_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM jobs')
[ "$policy_jobs_after" -eq $((policy_jobs_before + 1)) ] \
    || die "领取后策略拒绝没有且仅生成一个普通任务"
policy_job_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' \
    -c "SELECT j.status,COALESCE(a.error_class,''),COUNT(r.id)
        FROM jobs j
        LEFT JOIN LATERAL (
            SELECT error_class FROM job_attempts
            WHERE job_id=j.id ORDER BY attempt_number DESC LIMIT 1
        ) a ON TRUE
        LEFT JOIN receipts r ON r.job_id=j.id
        WHERE j.id='${policy_job_id}'::uuid
        GROUP BY j.id,j.status,a.error_class")
[ "$policy_job_state" = 'failed|policy|0' ] \
    || die "领取后策略拒绝的任务/attempt/收据状态不正确：$policy_job_state"
policy_receipts_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
[ "$policy_receipts_after" -eq "$policy_receipts_before" ] \
    || die "领取后策略拒绝错误生成了结算收据"
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota balance --json \
    >"$TEMP_ROOT/policy-consumer-after.json"
MINDONE_HOME="$NODE_HOME" "$CLI" quota balance --json \
    >"$TEMP_ROOT/policy-node-after.json"
assert_cli_ok "$TEMP_ROOT/policy-consumer-after.json"
assert_cli_ok "$TEMP_ROOT/policy-node-after.json"
python3 - \
    "$TEMP_ROOT/policy-consumer-before.json" "$TEMP_ROOT/policy-consumer-after.json" \
    "$TEMP_ROOT/policy-node-before.json" "$TEMP_ROOT/policy-node-after.json" <<'PY'
import json
import sys

def data(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)["data"]

consumer_before, consumer_after, node_before, node_after = map(data, sys.argv[1:])
for field in ("spendable_micro", "reserved_micro", "network_reserve_micro"):
    if consumer_before[field] != consumer_after[field]:
        raise SystemExit(f"策略拒绝改变了消费者或准备金字段 {field}")
for field in ("spendable_micro", "reserved_micro", "contribution_micro"):
    if node_before[field] != node_after[field]:
        raise SystemExit(f"策略拒绝改变了节点经济字段 {field}")
PY

cp "$TEMP_ROOT/policy-before-post-claim.json" "$NODE_HOME/runtime/node-policy.restore"
mv "$NODE_HOME/runtime/node-policy.restore" "$POLICY_PATH"
docker exec -i "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP TRIGGER mindone_e2e_pause_standard_lease ON jobs;
DROP FUNCTION mindone_e2e_pause_standard_lease();
SQL
policy_reset=0
count=0
while [ "$count" -lt 30 ]; do
    server_limit=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At -F '|' \
        -c "SELECT COALESCE(p.gpu_temp_limit_c::text,''),p.vram_reserve_mib
            FROM node_policies p WHERE p.node_id='${published_node_id}'::uuid")
    if [ "$server_limit" = '|0' ]; then
        policy_reset=1
        break
    fi
    count=$((count + 1))
    sleep 1
done
[ "$policy_reset" -eq 1 ] || die "恢复本地策略后服务端心跳未清除临时资源阈值"

step "通过 /v1/completions 执行第二次动态真实推理并核对独立结算"
# 上一步在服务端修改并恢复了节点阈值，节点会经历 fail-closed 暂停到下一次心跳恢复
# online 的过程。发起下一次推理前等待节点重新成为可路由候选。
wait_node_routable
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota balance --json \
    >"$TEMP_ROOT/completion-consumer-before.json"
assert_cli_ok "$TEMP_ROOT/completion-consumer-before.json"
completion_consumer_before=$(json_number \
    "$TEMP_ROOT/completion-consumer-before.json" data.spendable_micro)
completion_receipts_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
completion_nonce="MINDONE-COMPLETION-$(date +%s)-$$"
python3 - "$TEMP_ROOT/completion-request.json" "$completion_nonce" <<'PY'
import json
import sys

# /v1/completions 是 OpenAI 兼容的原始文本补全端点，不套用 chat 模板，因此不能用
# chat 式“只回复：X”指令断言（基础小模型在原始补全下不遵循指令）。改用真实基础
# 模型在原始续写中会自然回显的提示，仍以运行时动态 nonce 出现在补全文本中作为
# 反 mock 证据；chat 用例继续验证模板下的指令遵循。
request = {
    "model": "auto",
    "prompt": f"验证码是 {sys.argv[2]}。请重复一遍这个验证码：",
    "temperature": 0,
    "max_tokens": 96,
    "stream": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(request, stream, ensure_ascii=False)
PY
# 上一步刚在服务端领取检查后修改并恢复节点策略，可能短暂经历 paused→online 过渡；
# 与首个 chat 请求同理，对创建任务前的瞬时 502/503 做有界重试（此时不会建单/结算）。
completion_http_status=0
completion_attempt=0
while [ "$completion_attempt" -lt 20 ]; do
    completion_http_status=$(curl --silent --show-error --connect-timeout 5 --max-time 660 \
        -H 'Content-Type: application/json' \
        --data-binary "@$TEMP_ROOT/completion-request.json" \
        -o "$TEMP_ROOT/completion-inference.json" \
        -w '%{http_code}' \
        "http://127.0.0.1:${PROXY_PORT}/v1/completions")
    if [ "$completion_http_status" = "200" ]; then
        break
    fi
    if [ "$completion_http_status" != "502" ] && [ "$completion_http_status" != "503" ]; then
        break
    fi
    completion_attempt=$((completion_attempt + 1))
    sleep 1
done
if [ "$completion_http_status" != "200" ]; then
    printf '真实 completions 推理返回 HTTP %s，响应体：\n' "$completion_http_status" >&2
    cat "$TEMP_ROOT/completion-inference.json" >&2 || true
    die "真实 completions 推理未返回 200"
fi
python3 - "$TEMP_ROOT/completion-inference.json" "$completion_nonce" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
if response.get("object") != "text_completion":
    raise SystemExit("真实 completions 响应缺少 object=text_completion")
choices = response.get("choices")
if not isinstance(choices, list) or not choices:
    raise SystemExit("真实 completions 响应缺少 choices")
text = choices[0].get("text")
if not isinstance(text, str) or not text:
    raise SystemExit("真实 completions 响应缺少补全文本")
if sys.argv[2] not in text:
    raise SystemExit("真实 completions 模型未回显运行时动态 nonce，疑似固定响应或推理失败")
usage = response.get("usage", {})
if not isinstance(usage.get("completion_tokens"), int) or usage["completion_tokens"] <= 0:
    raise SystemExit("真实 completions 响应缺少正数 completion_tokens")
PY
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota balance --json \
    >"$TEMP_ROOT/completion-consumer-after.json"
assert_cli_ok "$TEMP_ROOT/completion-consumer-after.json"
completion_consumer_after=$(json_number \
    "$TEMP_ROOT/completion-consumer-after.json" data.spendable_micro)
completion_receipts_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
[ "$completion_consumer_after" -lt "$completion_consumer_before" ] \
    || die "真实 completions 请求没有扣减消费者额度"
[ "$completion_receipts_after" -eq $((completion_receipts_before + 1)) ] \
    || die "真实 completions 请求没有且仅生成一张独立收据"

step "验证真实 chat SSE、游标故障恢复、密文持久化与最终唯一结算"
# 上一次任务刚结算完成、节点从 leased 回到 online 之间存在窗口；SSE 请求以背景流方式
# 直接创建任务，无法内联重试，因此发起前显式等待节点可路由。
wait_node_routable
stream_jobs_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM jobs')
stream_receipts_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')

# 这个测试专用 trigger 只存在于即将销毁的 E2E 数据库。它让全部 SSE chunk
# 和 upstream_done 先提交，再把最终 succeeded/receipt 事务阻塞在 advisory lock，
# 从而直接证明 chunk 本身不会触发结算。
docker exec -i "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE FUNCTION mindone_e2e_pause_stream_settlement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'succeeded'
       AND OLD.status IS DISTINCT FROM 'succeeded'
       AND EXISTS (
           SELECT 1 FROM job_stream_events stream_event
           WHERE stream_event.job_id = NEW.id
             AND stream_event.event_kind = 'upstream_done'
       )
    THEN
        PERFORM pg_advisory_xact_lock(62005, 62006);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER mindone_e2e_pause_stream_settlement
BEFORE UPDATE OF status ON jobs
FOR EACH ROW
EXECUTE FUNCTION mindone_e2e_pause_stream_settlement();
SQL

docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 \
    -c "SET application_name='mindone-e2e-sse-settlement-lock';
        SELECT pg_advisory_lock(62005,62006);
        SELECT pg_sleep(600);" \
    >"$LOG_DIR/sse-settlement-lock.log" 2>&1 &
SSE_SETTLEMENT_LOCK_PID=$!
sse_settlement_lock_backend=
count=0
while [ "$count" -lt 100 ]; do
    sse_settlement_lock_backend=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT a.pid FROM pg_stat_activity a
            WHERE a.application_name='mindone-e2e-sse-settlement-lock'
              AND EXISTS (
                  SELECT 1 FROM pg_locks l
                  WHERE l.pid=a.pid AND l.locktype='advisory' AND l.granted
                    AND l.classid=62005 AND l.objid=62006
              )")
    case "$sse_settlement_lock_backend" in
        ''|*[!0-9]*) ;;
        *) break ;;
    esac
    kill -0 "$SSE_SETTLEMENT_LOCK_PID" 2>/dev/null \
        || die "SSE 结算锁持有进程提前退出"
    count=$((count + 1))
    sleep 0.05
done
case "$sse_settlement_lock_backend" in
    ''|*[!0-9]*) die "未确认测试事务持有 SSE 结算 advisory lock" ;;
esac

chat_stream_nonce="MINDONE-SSE-CHAT-$(date +%s)-$$"
python3 - "$TEMP_ROOT/chat-stream-request.json" "$chat_stream_nonce" <<'PY'
import json
import sys

request = {
    "model": "auto",
    "messages": [{
        "role": "user",
        "content": f"/no_think\n只回复：MindOne SSE 已连接 {sys.argv[2]}",
    }],
    "temperature": 0,
    "max_tokens": 128,
    "stream": True,
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(request, stream, ensure_ascii=False)
PY
(
    curl --fail --silent --show-error --no-buffer --connect-timeout 5 --max-time 660 \
        --dump-header "$TEMP_ROOT/chat-stream-headers.txt" \
        -H 'Content-Type: application/json' \
        --data-binary "@$TEMP_ROOT/chat-stream-request.json" \
        --output "$TEMP_ROOT/chat-stream.sse" \
        "http://127.0.0.1:${PROXY_PORT}/v1/chat/completions"
) >"$LOG_DIR/chat-stream-request.log" 2>&1 &
SSE_REQUEST_PID=$!

chat_stream_job_id=
count=0
while [ "$count" -lt 200 ]; do
    observed_jobs=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c 'SELECT COUNT(*) FROM jobs')
    if [ "$observed_jobs" -eq $((stream_jobs_before + 1)) ]; then
        chat_stream_job_id=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
            -c "SELECT id FROM jobs
                WHERE confidentiality_mode='standard' AND max_attempts=1
                ORDER BY created_at DESC,id DESC LIMIT 1")
        [ -n "$chat_stream_job_id" ] && break
    fi
    kill -0 "$SSE_REQUEST_PID" 2>/dev/null \
        || die "真实 chat SSE 在创建唯一任务前提前退出"
    count=$((count + 1))
    sleep 0.05
done
[ -n "$chat_stream_job_id" ] || die "真实 chat SSE 没有创建唯一可恢复任务"

first_stream_event_seen=0
count=0
while [ "$count" -lt 1200 ]; do
    if [ -f "$TEMP_ROOT/chat-stream.sse" ] \
       && grep -Eq '^id: 0[[:space:]]*$' "$TEMP_ROOT/chat-stream.sse"; then
        first_stream_event_seen=1
        break
    fi
    kill -0 "$SSE_REQUEST_PID" 2>/dev/null \
        || die "真实 chat SSE 在首个增量前提前退出"
    count=$((count + 1))
    sleep 0.05
done
[ "$first_stream_event_seen" -eq 1 ] || die "真实 chat SSE 未在 60 秒内产生首个增量"

# 首个 event 已交给消费者后，用表锁确定性阻塞下一次游标读取，再终止那条
# coordinator PostgreSQL backend。代理必须从保存的 next_sequence 重试；最终
# 与数据库连续序列逐项计数可同时证明没有重复或丢失。
docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 \
    -c "SET application_name='mindone-e2e-sse-cursor-lock';
        BEGIN;
        LOCK TABLE job_stream_events IN ACCESS EXCLUSIVE MODE;
        SELECT pg_sleep(600);" \
    >"$LOG_DIR/sse-cursor-lock.log" 2>&1 &
SSE_CURSOR_LOCK_PID=$!
sse_cursor_lock_backend=
count=0
while [ "$count" -lt 200 ]; do
    sse_cursor_lock_backend=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT a.pid FROM pg_stat_activity a
            WHERE a.application_name='mindone-e2e-sse-cursor-lock'
              AND EXISTS (
                  SELECT 1 FROM pg_locks l
                  WHERE l.pid=a.pid AND l.locktype='relation' AND l.mode='AccessExclusiveLock'
                    AND l.granted
              )")
    case "$sse_cursor_lock_backend" in
        ''|*[!0-9]*) ;;
        *) break ;;
    esac
    kill -0 "$SSE_CURSOR_LOCK_PID" 2>/dev/null \
        || die "SSE 游标表锁持有进程提前退出"
    count=$((count + 1))
    sleep 0.05
done
case "$sse_cursor_lock_backend" in
    ''|*[!0-9]*) die "未确认测试事务持有 SSE 游标表锁" ;;
esac

sse_cursor_reader_backend=
count=0
while [ "$count" -lt 200 ]; do
    sse_cursor_reader_backend=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT a.pid FROM pg_stat_activity a
            WHERE a.query LIKE '%SELECT sequence_number,event_ciphertext%'
              AND ${sse_cursor_lock_backend}=ANY(pg_blocking_pids(a.pid))
            ORDER BY a.query_start LIMIT 1")
    case "$sse_cursor_reader_backend" in
        ''|*[!0-9]*) ;;
        *) break ;;
    esac
    kill -0 "$SSE_REQUEST_PID" 2>/dev/null \
        || die "真实 chat SSE 在游标故障窗口提前退出"
    count=$((count + 1))
    sleep 0.05
done
case "$sse_cursor_reader_backend" in
    ''|*[!0-9]*) die "没有观察到 coordinator SSE 游标读取等待测试表锁" ;;
esac
terminated=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT pg_terminate_backend(${sse_cursor_reader_backend})")
[ "$terminated" = "t" ] || die "无法中断 coordinator SSE 游标数据库连接"
released=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT pg_terminate_backend(${sse_cursor_lock_backend})")
[ "$released" = "t" ] || die "无法释放 SSE 游标测试表锁"
wait "$SSE_CURSOR_LOCK_PID" 2>/dev/null || true
SSE_CURSOR_LOCK_PID=""

sse_pre_settlement_state=
settlement_blocked=0
count=0
while [ "$count" -lt 1200 ]; do
    sse_pre_settlement_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
        -At -F '|' -c "
            SELECT j.status,
                   COUNT(e.*) FILTER (WHERE e.event_kind='data'),
                   COUNT(e.*) FILTER (WHERE e.event_kind='upstream_done'),
                   COUNT(r.*)
            FROM jobs j
            LEFT JOIN job_stream_events e ON e.job_id=j.id
            LEFT JOIN receipts r ON r.job_id=j.id
            WHERE j.id='${chat_stream_job_id}'::uuid
            GROUP BY j.id,j.status")
    blocked_settlements=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT COUNT(*) FROM pg_stat_activity waiting
            WHERE ${sse_settlement_lock_backend}=ANY(pg_blocking_pids(waiting.pid))")
    case "$sse_pre_settlement_state" in
        leased\|[1-9]*\|1\|0)
            if [ "$blocked_settlements" -ge 1 ]; then
                settlement_blocked=1
                break
            fi
            ;;
    esac
    kill -0 "$SSE_REQUEST_PID" 2>/dev/null \
        || die "真实 chat SSE 在最终结算闸门前提前退出"
    count=$((count + 1))
    sleep 0.05
done
[ "$settlement_blocked" -eq 1 ] \
    || die "未证明 SSE chunk/upstream_done 已持久化但尚未产生结算：$sse_pre_settlement_state"

sse_ciphertext_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -At -F '|' -c "
        SELECT COUNT(*) FILTER (WHERE event_kind='data'),
               COUNT(*) FILTER (WHERE event_kind='upstream_done'),
               COALESCE(BOOL_AND(
                   event_ciphertext ~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$'
                   AND standard_event_storage_version=1
                   AND plaintext_bytes > 0
                   AND POSITION('${chat_stream_nonce}' IN event_ciphertext)=0
               ) FILTER (WHERE event_kind='data'),FALSE),
               COALESCE(BOOL_AND(
                   event_ciphertext IS NULL
                   AND standard_event_storage_version IS NULL
                   AND plaintext_bytes=0
               ) FILTER (WHERE event_kind='upstream_done'),FALSE),
               COALESCE(MIN(sequence_number),-1),
               COALESCE(MAX(sequence_number),-1)
        FROM job_stream_events
        WHERE job_id='${chat_stream_job_id}'::uuid")
case "$sse_ciphertext_state" in
    [1-9]*\|1\|t\|t\|0\|*) ;;
    *) die "chat SSE 数据库事件不是连续 ciphertext-only 记录：$sse_ciphertext_state" ;;
esac

released=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT pg_terminate_backend(${sse_settlement_lock_backend})")
[ "$released" = "t" ] || die "无法释放 SSE 最终结算测试锁"
wait "$SSE_SETTLEMENT_LOCK_PID" 2>/dev/null || true
SSE_SETTLEMENT_LOCK_PID=""
if ! wait "$SSE_REQUEST_PID"; then
    SSE_REQUEST_PID=""
    die "真实 chat SSE 在游标恢复或最终结算后传输失败"
fi
SSE_REQUEST_PID=""

validate_real_sse "$TEMP_ROOT/chat-stream-headers.txt" \
    "$TEMP_ROOT/chat-stream.sse" chat "$chat_stream_nonce" \
    "$TEMP_ROOT/chat-stream-summary.json"
chat_stream_event_count=$(json_number "$TEMP_ROOT/chat-stream-summary.json" event_count)
chat_stream_db_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -At -F '|' -c "
        SELECT j.status,
               COUNT(e.*) FILTER (WHERE e.event_kind='data'),
               COUNT(e.*) FILTER (WHERE e.event_kind='upstream_done'),
               COALESCE(MIN(e.sequence_number),-1),
               COALESCE(MAX(e.sequence_number),-1),
               COUNT(DISTINCT r.id)
        FROM jobs j
        LEFT JOIN job_stream_events e ON e.job_id=j.id
        LEFT JOIN receipts r ON r.job_id=j.id
        WHERE j.id='${chat_stream_job_id}'::uuid
        GROUP BY j.id,j.status")
[ "$chat_stream_db_state" = "succeeded|${chat_stream_event_count}|1|0|${chat_stream_event_count}|1" ] \
    || die "chat SSE 游标/数据库序列/唯一结算不一致：$chat_stream_db_state"
chat_stream_ledger_count=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT
        (SELECT COUNT(*) FROM quota_ledger WHERE request_id='${chat_stream_job_id}'::uuid) +
        (SELECT COUNT(*) FROM contribution_ledger WHERE request_id='${chat_stream_job_id}'::uuid) +
        (SELECT COUNT(*) FROM reserve_ledger WHERE request_id='${chat_stream_job_id}'::uuid)")
[ "$chat_stream_ledger_count" -eq 4 ] \
    || die "chat SSE 最终结算没有且仅追加四条三轨账本记录"
chat_stream_receipts_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
[ "$chat_stream_receipts_after" -eq $((stream_receipts_before + 1)) ] \
    || die "chat SSE 最终没有且仅生成一张收据"

docker exec -i "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP TRIGGER mindone_e2e_pause_stream_settlement ON jobs;
DROP FUNCTION mindone_e2e_pause_stream_settlement();
SQL

step "验证真实 /v1/completions SSE 增量与独立唯一结算"
# 同理，等待上一次任务结算后节点回到可路由状态再发起 completions SSE。
wait_node_routable
completion_stream_jobs_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM jobs')
completion_stream_receipts_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
completion_stream_nonce="MINDONE-SSE-COMPLETION-$(date +%s)-$$"
python3 - "$TEMP_ROOT/completion-stream-request.json" "$completion_stream_nonce" <<'PY'
import json
import sys

request = {
    # /v1/completions 为原始文本补全，不套 chat 模板；使用基础模型会自然续写回显的
    # 提示，让运行时动态 nonce 出现在流式补全中作为反 mock 证据。
    "model": "auto",
    "prompt": f"验证码是 {sys.argv[2]}。请重复一遍这个验证码：",
    "temperature": 0,
    "max_tokens": 128,
    "stream": True,
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(request, stream, ensure_ascii=False)
PY
curl --fail --silent --show-error --no-buffer --connect-timeout 5 --max-time 660 \
    --dump-header "$TEMP_ROOT/completion-stream-headers.txt" \
    -H 'Content-Type: application/json' \
    --data-binary "@$TEMP_ROOT/completion-stream-request.json" \
    --output "$TEMP_ROOT/completion-stream.sse" \
    "http://127.0.0.1:${PROXY_PORT}/v1/completions"
validate_real_sse "$TEMP_ROOT/completion-stream-headers.txt" \
    "$TEMP_ROOT/completion-stream.sse" completion "$completion_stream_nonce" \
    "$TEMP_ROOT/completion-stream-summary.json"
completion_stream_event_count=$(json_number \
    "$TEMP_ROOT/completion-stream-summary.json" event_count)
completion_stream_jobs_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM jobs')
[ "$completion_stream_jobs_after" -eq $((completion_stream_jobs_before + 1)) ] \
    || die "completions SSE 没有且仅创建一个任务"
completion_stream_job_id=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT id FROM jobs
        WHERE confidentiality_mode='standard' AND max_attempts=1
        ORDER BY created_at DESC,id DESC LIMIT 1")
completion_stream_db_state=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e \
    -At -F '|' -c "
        SELECT j.status,
               COUNT(e.*) FILTER (WHERE e.event_kind='data'),
               COUNT(e.*) FILTER (WHERE e.event_kind='upstream_done'),
               COALESCE(MIN(e.sequence_number),-1),
               COALESCE(MAX(e.sequence_number),-1),
               COALESCE(BOOL_AND(
                   e.event_ciphertext ~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$'
                   AND e.standard_event_storage_version=1
                   AND e.plaintext_bytes > 0
                   AND POSITION('${completion_stream_nonce}' IN e.event_ciphertext)=0
               ) FILTER (WHERE e.event_kind='data'),FALSE),
               COUNT(DISTINCT r.id)
        FROM jobs j
        LEFT JOIN job_stream_events e ON e.job_id=j.id
        LEFT JOIN receipts r ON r.job_id=j.id
        WHERE j.id='${completion_stream_job_id}'::uuid
        GROUP BY j.id,j.status")
[ "$completion_stream_db_state" = "succeeded|${completion_stream_event_count}|1|0|${completion_stream_event_count}|t|1" ] \
    || die "completions SSE 事件、密文持久化或唯一结算不一致：$completion_stream_db_state"
completion_stream_receipts_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
[ "$completion_stream_receipts_after" -eq $((completion_stream_receipts_before + 1)) ] \
    || die "completions SSE 最终没有且仅生成一张独立收据"

step "验证 Regulated stream:true 明确拒绝且绝不降级创建任务"
kill "$PROXY_PID"
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
MINDONE_HOME="$CONSUMER_HOME" "$CLI" quota use --model auto --port "$PROXY_PORT" \
    --confidentiality regulated --quiet >"$LOG_DIR/quota-proxy-regulated.log" 2>&1 &
PROXY_PID=$!
wait_tcp 127.0.0.1 "$PROXY_PORT" 30 || die "Regulated 额度代理未监听"
regulated_jobs_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM jobs')
regulated_receipts_before=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
curl --silent --show-error --connect-timeout 5 --max-time 30 \
    -H 'Content-Type: application/json' \
    --data-binary "@$TEMP_ROOT/chat-stream-request.json" \
    --output "$TEMP_ROOT/regulated-chat-stream-error.json" \
    --write-out '%{http_code}' \
    "http://127.0.0.1:${PROXY_PORT}/v1/chat/completions" \
    >"$TEMP_ROOT/regulated-chat-stream-status"
assert_unsupported_stream "$TEMP_ROOT/regulated-chat-stream-status" \
    "$TEMP_ROOT/regulated-chat-stream-error.json" "$regulated_jobs_before"
curl --silent --show-error --connect-timeout 5 --max-time 30 \
    -H 'Content-Type: application/json' \
    --data-binary "@$TEMP_ROOT/completion-stream-request.json" \
    --output "$TEMP_ROOT/regulated-completion-stream-error.json" \
    --write-out '%{http_code}' \
    "http://127.0.0.1:${PROXY_PORT}/v1/completions" \
    >"$TEMP_ROOT/regulated-completion-stream-status"
assert_unsupported_stream "$TEMP_ROOT/regulated-completion-stream-status" \
    "$TEMP_ROOT/regulated-completion-stream-error.json" "$regulated_jobs_before"
regulated_receipts_after=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c 'SELECT COUNT(*) FROM receipts')
[ "$regulated_receipts_after" -eq "$regulated_receipts_before" ] \
    || die "Regulated stream:true 拒绝错误生成了结算收据"

step "取消发布、停止服务、注销会话并验证清理"
kill "$PROXY_PID"
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
# 最后一次 SSE 任务的最终结果提交与结算相对消费者收到 [DONE] 略有异步延迟。
# unpublish 需要在没有活动任务时才转为 unpublished；这里在调用前有界等待本实例的
# queued/leased/retry 任务全部到达终态，避免 drain 竞态误判为失败。这不放宽任何
# 服务端资格或结算保证，只等待既有任务自然收口。
drain_wait=0
while [ "$drain_wait" -lt 30 ]; do
    active_jobs_now=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
        -c "SELECT COUNT(*) FROM jobs
            WHERE model_instance_id='$published_model_instance_id'
              AND status IN ('queued','leased','retry')")
    [ "$active_jobs_now" = "0" ] && break
    drain_wait=$((drain_wait + 1))
    sleep 1
done
MINDONE_HOME="$NODE_HOME" "$CLI" share unpublish --timeout 30 --json \
    >"$TEMP_ROOT/unpublish.json"
assert_cli_ok "$TEMP_ROOT/unpublish.json"
PUBLISHED=0
published_count=$(docker exec "$DB_CONTAINER" psql -U mindone -d mindone_e2e -At \
    -c "SELECT COUNT(*) FROM model_instances WHERE status = 'published'")
[ "$published_count" -eq 0 ] || die "数据库仍有发布中的模型实例"
MINDONE_HOME="$NODE_HOME" "$CLI" serve stop --port "$LLAMA_PORT" --timeout 15 --json \
    >"$TEMP_ROOT/stop.json"
assert_cli_ok "$TEMP_ROOT/stop.json"
SERVING=0
assert_port_closed "$LLAMA_PORT" || die "停止后 llama-server 端口仍开放"

step "确认受管引擎与 worker 的活动/轮转日志不含 Prompt 或 Response 明文"
python3 - "$TEMP_ROOT/request.json" "$TEMP_ROOT/inference.json" \
    "$TEMP_ROOT/completion-request.json" "$TEMP_ROOT/completion-inference.json" \
    "$TEMP_ROOT/policy-request.json" "$NODE_HOME/logs" \
    "$chat_stream_nonce" "$completion_stream_nonce" <<'PY'
import json
import pathlib
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    request = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    response = json.load(stream)
with open(sys.argv[3], encoding="utf-8") as stream:
    completion_request = json.load(stream)
with open(sys.argv[4], encoding="utf-8") as stream:
    completion_response = json.load(stream)
with open(sys.argv[5], encoding="utf-8") as stream:
    policy_request = json.load(stream)

messages = request.get("messages")
if not isinstance(messages, list) or not messages:
    raise SystemExit("E2E 请求缺少可验证的 Prompt")
prompt = messages[0].get("content")
choices = response.get("choices")
if not isinstance(choices, list) or not choices:
    raise SystemExit("E2E 响应缺少可验证的 Response")
content = choices[0].get("message", {}).get("content")
if not isinstance(prompt, str) or not prompt:
    raise SystemExit("E2E Prompt 不是非空字符串")
if not isinstance(content, str) or not content:
    raise SystemExit("E2E Response 不是非空字符串")
nonce_match = re.search(r"MINDONE-[0-9]+-[0-9]+", prompt)
if nonce_match is None:
    raise SystemExit("E2E Prompt 缺少动态日志 canary")

markers = {
    "chat prompt": prompt.encode("utf-8"),
    "chat response": content.encode("utf-8"),
    "chat nonce": nonce_match.group(0).encode("utf-8"),
}
completion_prompt = completion_request.get("prompt")
completion_choices = completion_response.get("choices")
if not isinstance(completion_prompt, str) or not completion_prompt:
    raise SystemExit("E2E completions Prompt 不是非空字符串")
if not isinstance(completion_choices, list) or not completion_choices:
    raise SystemExit("E2E completions 响应缺少 choices")
completion_text = completion_choices[0].get("text")
if not isinstance(completion_text, str) or not completion_text:
    raise SystemExit("E2E completions Response 不是非空字符串")
completion_nonce_match = re.search(r"MINDONE-COMPLETION-[0-9]+-[0-9]+", completion_prompt)
if completion_nonce_match is None:
    raise SystemExit("E2E completions Prompt 缺少动态日志 canary")
markers.update({
    "completion prompt": completion_prompt.encode("utf-8"),
    "completion response": completion_text.encode("utf-8"),
    "completion nonce": completion_nonce_match.group(0).encode("utf-8"),
})
policy_messages = policy_request.get("messages")
if not isinstance(policy_messages, list) or not policy_messages:
    raise SystemExit("E2E 策略拒绝请求缺少 Prompt")
policy_prompt = policy_messages[0].get("content")
if not isinstance(policy_prompt, str) or not policy_prompt:
    raise SystemExit("E2E 策略拒绝 Prompt 不是非空字符串")
policy_nonce_match = re.search(r"MINDONE-POLICY-[0-9]+-[0-9]+", policy_prompt)
if policy_nonce_match is None:
    raise SystemExit("E2E 策略拒绝 Prompt 缺少动态日志 canary")
markers.update({
    "policy-rejected prompt": policy_prompt.encode("utf-8"),
    "policy-rejected nonce": policy_nonce_match.group(0).encode("utf-8"),
    "chat stream nonce": sys.argv[7].encode("utf-8"),
    "completion stream nonce": sys.argv[8].encode("utf-8"),
})
log_dir = pathlib.Path(sys.argv[6])
paths = []
for basename in ("llama-server.log", "share-worker.log"):
    matches = sorted(log_dir.glob(f"{basename}*"))
    if not matches:
        raise SystemExit(f"缺少应受检查的日志：{basename}")
    paths.extend(matches)

for path in paths:
    data = path.read_bytes()
    for marker_name, marker in markers.items():
        if marker in data:
            raise SystemExit(f"{path.name} 泄漏了 {marker_name} 明文")
PY

MINDONE_HOME="$CONSUMER_HOME" "$CLI" auth logout --json >"$TEMP_ROOT/consumer-logout.json"
assert_cli_ok "$TEMP_ROOT/consumer-logout.json"
CONSUMER_LOGGED_IN=0
MINDONE_HOME="$NODE_HOME" "$CLI" auth logout --json >"$TEMP_ROOT/node-logout.json"
assert_cli_ok "$TEMP_ROOT/node-logout.json"
NODE_LOGGED_IN=0
if MINDONE_HOME="$CONSUMER_HOME" "$CLI" auth status --quiet >/dev/null 2>&1; then
    die "注销后消费者 auth status 仍成功"
fi
if MINDONE_HOME="$NODE_HOME" "$CLI" auth status --quiet >/dev/null 2>&1; then
    die "注销后节点 auth status 仍成功"
fi

SUCCESS=1
printf '\nMindOne 真实 E2E 通过：双账号、真实 llama.cpp/GGUF、非流式与双端点 SSE 动态推理、游标恢复、密文事件、三轨唯一结算、Regulated 拒绝与安全清理均已验证。\n'
