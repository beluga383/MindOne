#!/usr/bin/env bash
# MindOne 协调服务器配置验证入口。
#
# 默认只复用 coordinator 的 Rust 启动合同做离线校验；只有显式 --live 才连接
# PostgreSQL 与 SMTP。两种模式都不迁移数据库、不发送邮件，也不回显配置值。

set -u

if [ "$#" -gt 1 ]; then
    printf '错误：参数过多；请使用 --help 查看用法。\n' >&2
    exit 2
fi

live_checks=0
case "${1:-}" in
    "") ;;
    --live) live_checks=1 ;;
    -h|--help)
        printf '%s\n' \
            '用法：./verify-config.sh [--live]' \
            '默认：复用 coordinator 启动合同离线校验环境变量和 Secret 文件。' \
            '--live：另行连接 PostgreSQL 并精确比对 schema；邮箱模式建立 SMTP 会话但不发信。'
        exit 0
        ;;
    *)
        printf '错误：未知参数；请使用 --help 查看用法。\n' >&2
        exit 2
        ;;
esac

if [ "${MINDONE_AUTH_PROVIDER:-}" != "email" ]; then
    printf '错误：本脚本用于邮箱身份配置，MINDONE_AUTH_PROVIDER 必须为 email。\n' >&2
    exit 1
fi

script_source=${BASH_SOURCE[0]}
if [ -L "$script_source" ]; then
    printf '错误：拒绝通过符号链接运行配置检查脚本。\n' >&2
    exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$script_source")" && pwd -P) || {
    printf '错误：无法解析配置检查脚本目录。\n' >&2
    exit 1
}
manifest_path=$script_dir/Cargo.toml
if [ ! -f "$manifest_path" ] || [ -L "$manifest_path" ]; then
    printf '错误：脚本目录中缺少可信的 Cargo.toml。\n' >&2
    exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
    printf '错误：未找到 cargo，无法构建并运行当前 coordinator 配置合同。\n' >&2
    exit 1
fi

if [ "$live_checks" -eq 1 ]; then
    exec cargo +1.88 run --quiet --locked --offline \
        --manifest-path "$manifest_path" \
        -p mindone-coordinator --bin mindone-coordinator -- \
        config-check --live
fi
exec cargo +1.88 run --quiet --locked --offline \
    --manifest-path "$manifest_path" \
    -p mindone-coordinator --bin mindone-coordinator -- \
    config-check
