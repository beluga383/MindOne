#!/bin/sh
set -eu

# 只读取 Hugging Face tree/LFS 元数据，不请求权重内容。该审计依赖实时外部状态，
# 因而供发布前显式运行，不进入离线/确定性测试门禁。

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
binary=${MINDONE_BINARY:-$repo_root/target/debug/mindone}
jobs=${MINDONE_HF_AUDIT_JOBS:-4}

case "$jobs" in
    ''|*[!0-9]*)
        printf '%s\n' "错误：MINDONE_HF_AUDIT_JOBS 必须是 1..8 的整数" >&2
        exit 2
        ;;
esac
if [ "$jobs" -lt 1 ] || [ "$jobs" -gt 8 ]; then
    printf '%s\n' "错误：MINDONE_HF_AUDIT_JOBS 必须是 1..8 的整数" >&2
    exit 2
fi
if [ ! -x "$binary" ]; then
    printf '错误：找不到可执行 MindOne：%s\n' "$binary" >&2
    printf '%s\n' "请先运行 cargo build --locked -p mindone-cli，或设置 MINDONE_BINARY。" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    printf '%s\n' "错误：HF 目录审计需要 jq" >&2
    exit 2
fi

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
tmp_root=$(CDPATH= cd -- "$tmp_root" && pwd -P)
audit_home=$(mktemp -d "$tmp_root/mindone-hf-audit.XXXXXX")
models_file=$audit_home/models.txt
results_file=$audit_home/results.tsv
results_dir=$audit_home/results
mkdir -p "$results_dir"
cleanup() {
    rm -rf "$audit_home"
}
trap cleanup EXIT HUP INT TERM

awk '
    /^pub const OFFICIAL_MODEL_REPOSITORIES/ { active = 1; next }
    active && /^];/ { exit }
    active && match($0, /"[^"]+"/) {
        print substr($0, RSTART + 1, RLENGTH - 2)
    }
' "$repo_root/crates/mindone-cli/src/model_catalog.rs" > "$models_file"

model_count=$(wc -l < "$models_file" | tr -d ' ')
if [ "$model_count" -ne 65 ]; then
    printf '错误：预期 65 个模型，实际解析到 %s 个\n' "$model_count" >&2
    exit 2
fi

export MINDONE_HF_AUDIT_BINARY=$binary
export MINDONE_HF_AUDIT_HOME=$audit_home
export MINDONE_HF_AUDIT_RESULTS=$results_dir
xargs -P "$jobs" -n 1 sh -c '
    model=$1
    safe=$(printf "%s" "$model" | tr "/:" "__")
    attempt=1
    while :; do
        result=$(env MINDONE_HOME="$MINDONE_HF_AUDIT_HOME/home-$safe" \
            "$MINDONE_HF_AUDIT_BINARY" --json model probe "$model" \
            --deployment --metadata-only 2>&1)
        status=$?
        if [ "$status" -eq 0 ] || [ "$attempt" -ge 3 ] || \
            ! printf "%s" "$result" | grep -q "HTTP 429"; then
            break
        fi
        sleep_seconds=$((attempt * 5))
        sleep "$sleep_seconds"
        attempt=$((attempt + 1))
    done
    if [ "$status" -eq 0 ]; then
        if detail=$(printf "%s" "$result" | jq -er \
            "\"OK\\t\" + .data.repository + \"\\t\" + (.data.shard_count | tostring) + \"\\t\" + (.data.total_size_bytes | tostring) + \"\\t\" + .data.primary_file + \"\\t-\""); then
            printf "%s\t%s\n" "$model" "$detail" > "$MINDONE_HF_AUDIT_RESULTS/$safe.tsv"
        else
            printf "%s\tERROR\t-\t-\t-\t-\t%s\n" "$model" "成功响应不符合元数据审计 JSON 合同" > "$MINDONE_HF_AUDIT_RESULTS/$safe.tsv"
        fi
    else
        message=$(printf "%s" "$result" | jq -r ".error.message // \"无法解析错误\"" 2>/dev/null || printf "%s" "无法解析错误")
        message=$(printf "%s" "$message" | tr "\t\r\n" "   ")
        printf "%s\tERROR\t-\t-\t-\t-\t%s\n" "$model" "$message" > "$MINDONE_HF_AUDIT_RESULTS/$safe.tsv"
    fi
' sh < "$models_file"

result_count=$(find "$results_dir" -type f -name '*.tsv' | wc -l | tr -d ' ')
if [ "$result_count" -ne "$model_count" ]; then
    printf '错误：预期 %s 个审计结果，实际只有 %s 个\n' "$model_count" "$result_count" >&2
    exit 2
fi
find "$results_dir" -type f -name '*.tsv' -exec cat {} \; | sort > "$results_file"

printf '%s\n' "model\tstatus\trepository\tshards\ttotal_size_bytes\tprimary_file\terror"
cat "$results_file"
if grep -q "$(printf '\tERROR\t')" "$results_file"; then
    exit 1
fi
