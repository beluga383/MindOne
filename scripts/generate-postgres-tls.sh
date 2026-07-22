#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
output_dir=${1:-"${repository_root}/deploy/secrets/postgres-tls"}

if ! command -v openssl >/dev/null 2>&1; then
    echo "未找到 openssl，无法生成 PostgreSQL TLS 材料" >&2
    exit 1
fi
if [ -e "${output_dir}" ]; then
    echo "目标目录已存在，拒绝覆盖 PostgreSQL TLS 材料：${output_dir}" >&2
    exit 1
fi

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/mindone-postgres-tls.XXXXXX")
cleanup() {
    rm -rf -- "${temporary_dir}"
}
trap cleanup EXIT HUP INT TERM

openssl genrsa -out "${temporary_dir}/ca.key" 3072 >/dev/null 2>&1
openssl req -new -x509 -sha256 -days 3650 \
    -key "${temporary_dir}/ca.key" \
    -out "${temporary_dir}/ca.crt" \
    -subj "/CN=MindOne local PostgreSQL CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

openssl genrsa -out "${temporary_dir}/server.key" 3072 >/dev/null 2>&1
openssl req -new -sha256 \
    -key "${temporary_dir}/server.key" \
    -out "${temporary_dir}/server.csr" \
    -subj "/CN=postgres"
printf '%s\n' \
    '[v3_server]' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid,issuer' \
    'subjectAltName=DNS:postgres,DNS:localhost,IP:127.0.0.1,IP:::1' \
    >"${temporary_dir}/server.ext"
openssl x509 -req -sha256 -days 825 \
    -in "${temporary_dir}/server.csr" \
    -CA "${temporary_dir}/ca.crt" \
    -CAkey "${temporary_dir}/ca.key" \
    -CAcreateserial \
    -extfile "${temporary_dir}/server.ext" \
    -extensions v3_server \
    -out "${temporary_dir}/server.crt" \
    >/dev/null 2>&1

openssl verify -purpose sslserver \
    -CAfile "${temporary_dir}/ca.crt" \
    "${temporary_dir}/server.crt" \
    >/dev/null
openssl x509 -checkend 2592000 -noout \
    -in "${temporary_dir}/server.crt" \
    >/dev/null

mkdir -p -- "$(dirname -- "${output_dir}")"
install -d -m 0700 "${output_dir}"
install -m 0600 "${temporary_dir}/ca.key" "${output_dir}/ca.key"
install -m 0644 "${temporary_dir}/ca.crt" "${output_dir}/ca.crt"
install -m 0600 "${temporary_dir}/server.key" "${output_dir}/server.key"
install -m 0644 "${temporary_dir}/server.crt" "${output_dir}/server.crt"

echo "已生成 PostgreSQL TLS 材料：${output_dir}"
openssl x509 -in "${output_dir}/server.crt" -noout -sha256 -fingerprint
