#!/bin/sh
set -eu

# 只验证 Compose 渲染合同；不得在这里加入 up/run/build/start/stop 等状态变更。
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
base_compose=${repository_root}/deploy/docker-compose.yml
private_overlay=${repository_root}/deploy/docker-compose.quality-operator.yml
cloudflare_overlay=${repository_root}/deploy/docker-compose.cloudflared.yml
temp_parent=${TMPDIR:-/tmp}
temp_parent=${temp_parent%/}
temp_dir=$(mktemp -d "${temp_parent}/mindone-private-v2-compose.XXXXXX")

cleanup() {
    case ${temp_dir} in
        "${temp_parent}"/mindone-private-v2-compose.*)
            rm -rf -- "${temp_dir}"
            ;;
        *)
            echo "临时目录不符合预期，拒绝清理：${temp_dir}" >&2
            ;;
    esac
}
trap cleanup EXIT HUP INT TERM

fail() {
    echo "private v2 Compose 静态校验失败：$1" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "未找到 docker compose v2"
command -v python3 >/dev/null 2>&1 || fail "未找到 python3"

install -d -m 0700 \
    "${temp_dir}/postgres-tls" \
    "${temp_dir}/trusted-keys" \
    "${temp_dir}/quality-evidence"
printf '%s\n' 'static-ca-placeholder' >"${temp_dir}/postgres-tls/ca.crt"
printf '%s\n' 'static-server-cert-placeholder' >"${temp_dir}/postgres-tls/server.crt"
printf '%s\n' 'static-server-key-placeholder' >"${temp_dir}/postgres-tls/server.key"
printf '%064d\n' 0 >"${temp_dir}/standard-data-key"
printf '%s\n' 'static-cloudflared-token-placeholder' >"${temp_dir}/cloudflared-token"
hmac_marker=mindone-private-hidden-hmac-v1:1111111111111111111111111111111111111111111111111111111111111111
printf '%s\n' "${hmac_marker}" >"${temp_dir}/private-evaluation-hmac-key"
chmod 0600 \
    "${temp_dir}/standard-data-key" \
    "${temp_dir}/cloudflared-token" \
    "${temp_dir}/private-evaluation-hmac-key"

base_env=${temp_dir}/base.env
{
    printf '%s\n' \
        'MINDONE_POSTGRES_PASSWORD=static-owner-password' \
        'MINDONE_POSTGRES_APP_PASSWORD=static-runtime-password' \
        'MINDONE_GITHUB_CLIENT_ID=static-client-id' \
        'MINDONE_TOKEN_PEPPER=static-token-pepper-material-00000000' \
        "MINDONE_POSTGRES_TLS_DIR=${temp_dir}/postgres-tls" \
        "MINDONE_STANDARD_DATA_KEY_FILE=${temp_dir}/standard-data-key" \
        'MINDONE_COORDINATOR_IMAGE=mindone-coordinator:static-validation' \
        "MINDONE_QUALITY_KEYS_HOST_DIR=${temp_dir}/trusted-keys" \
        "MINDONE_QUALITY_EVIDENCE_HOST_DIR=${temp_dir}/quality-evidence" \
        "MINDONE_CLOUDFLARED_TOKEN_FILE=${temp_dir}/cloudflared-token" \
        'MINDONE_COORDINATOR_HOST_PORT=18789'
} >"${base_env}"

base_json=${temp_dir}/base.json
docker compose --env-file "${base_env}" \
    -f "${base_compose}" \
    config --format json >"${base_json}" \
    || fail "无 private 配置的基础 public-canary 栈应可渲染"

complete_env=${temp_dir}/complete.env
cp -- "${base_env}" "${complete_env}"
{
    printf '%s\n' \
        "MINDONE_PRIVATE_EVALUATION_HMAC_KEY_HOST_FILE=${temp_dir}/private-evaluation-hmac-key" \
        'MINDONE_PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT=101' \
        'MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT=102' \
        'MINDONE_PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT=103' \
        'MINDONE_PRIVATE_EVALUATION_NODE_HOURLY_LIMIT=104' \
        'MINDONE_PRIVATE_EVALUATION_COOLDOWN_SECONDS=105' \
        'MINDONE_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES=106'
} >>"${complete_env}"

missing_key_env=${temp_dir}/missing-key.env
grep -v '^MINDONE_PRIVATE_EVALUATION_HMAC_KEY_HOST_FILE=' \
    "${complete_env}" >"${missing_key_env}"
if docker compose --env-file "${missing_key_env}" \
    -f "${base_compose}" -f "${private_overlay}" \
    --profile operator config --quiet >/dev/null 2>&1; then
    fail "缺 private HMAC 宿主路径时 overlay 必须拒绝渲染"
fi

for omitted_budget in \
    MINDONE_PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT \
    MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT \
    MINDONE_PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT \
    MINDONE_PRIVATE_EVALUATION_NODE_HOURLY_LIMIT \
    MINDONE_PRIVATE_EVALUATION_COOLDOWN_SECONDS \
    MINDONE_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES
do
    missing_budget_env=${temp_dir}/missing-${omitted_budget}.env
    grep -v "^${omitted_budget}=" "${complete_env}" >"${missing_budget_env}"
    if docker compose --env-file "${missing_budget_env}" \
        -f "${base_compose}" -f "${private_overlay}" \
        --profile operator config --quiet >/dev/null 2>&1; then
        fail "缺 ${omitted_budget} 时 overlay 必须拒绝渲染"
    fi
done

private_json=${temp_dir}/private.json
docker compose --env-file "${complete_env}" \
    -f "${base_compose}" -f "${private_overlay}" \
    --profile operator config --format json >"${private_json}" \
    || fail "完整 private v2 overlay 应可渲染"
docker compose --env-file "${complete_env}" \
    -f "${base_compose}" -f "${private_overlay}" -f "${cloudflare_overlay}" \
    --profile operator config --quiet >/dev/null \
    || fail "private v2 与 Cloudflare overlay 组合后应可渲染"

python3 - "${base_json}" "${private_json}" \
    "${temp_dir}/private-evaluation-hmac-key" "${hmac_marker}" <<'PY'
import json
import pathlib
import sys

base_path, private_path, host_key_path, marker = sys.argv[1:]
base = json.loads(pathlib.Path(base_path).read_text(encoding="utf-8"))
rendered_text = pathlib.Path(private_path).read_text(encoding="utf-8")
private = json.loads(rendered_text)

base_environment = base["services"]["coordinator"].get("environment", {})
assert "MINDONE_PRIVATE_EVALUATION_HMAC_KEY_FILE" not in base_environment
assert not any(name.startswith("MINDONE_PRIVATE_EVALUATION_") for name in base_environment)
assert "private_evaluation_hmac_key" not in base.get("secrets", {})

coordinator = private["services"]["coordinator"]
environment = coordinator["environment"]
assert environment["MINDONE_PRIVATE_EVALUATION_HMAC_KEY_FILE"] == (
    "/run/secrets/mindone_private_evaluation_hmac_key"
)
expected_budget = {
    "MINDONE_PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT": "101",
    "MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT": "102",
    "MINDONE_PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT": "103",
    "MINDONE_PRIVATE_EVALUATION_NODE_HOURLY_LIMIT": "104",
    "MINDONE_PRIVATE_EVALUATION_COOLDOWN_SECONDS": "105",
    "MINDONE_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES": "106",
}
for name, value in expected_budget.items():
    assert environment[name] == value
assert "MINDONE_PRIVATE_EVALUATION_HMAC_KEY" not in environment

coordinator_secrets = {
    item["source"]: item.get("target") for item in coordinator.get("secrets", [])
}
assert coordinator_secrets["postgres_ca"] == "mindone_postgres_ca"
assert coordinator_secrets["standard_data_key"] == "mindone_standard_data_key"
assert coordinator_secrets["private_evaluation_hmac_key"] == (
    "mindone_private_evaluation_hmac_key"
)
secret = private["secrets"]["private_evaluation_hmac_key"]
assert secret["file"] == host_key_path

quality_operator = private["services"]["quality-operator"]
operator_environment = quality_operator.get("environment", {})
assert "MINDONE_PRIVATE_EVALUATION_HMAC_KEY_FILE" not in operator_environment
assert not any(name in operator_environment for name in expected_budget)
assert not any(
    item["source"] == "private_evaluation_hmac_key"
    for item in quality_operator.get("secrets", [])
)
assert marker not in rendered_text
PY

grep -Eq '^/deploy/secrets/?$' "${repository_root}/.gitignore" \
    || fail "Git 排除规则没有覆盖 deploy/secrets"
grep -Eq '^(deploy/secrets|\*\*/secrets)/?$' "${repository_root}/.dockerignore" \
    || fail "Docker build context 排除规则没有覆盖 deploy/secrets"
if grep -Eq '^[[:space:]]*COPY[[:space:]].*secrets' "${repository_root}/deploy/Dockerfile"; then
    fail "Dockerfile 不得显式复制 Secret"
fi

echo "private v2 Compose 静态校验通过（未启动、停止或构建任何容器）"
