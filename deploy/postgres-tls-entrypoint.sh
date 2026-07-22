#!/bin/sh
set -eu

source_dir=/run/secrets
target_dir=/run/mindone-postgres-tls

for source_file in \
    mindone_postgres_ca \
    mindone_postgres_server_cert \
    mindone_postgres_server_key
do
    if [ ! -f "${source_dir}/${source_file}" ]; then
        echo "PostgreSQL TLS 文件缺失，拒绝启动" >&2
        exit 1
    fi
done

mkdir -p "${target_dir}"
chown postgres:postgres "${target_dir}"
chmod 0700 "${target_dir}"
cp "${source_dir}/mindone_postgres_ca" "${target_dir}/ca.crt"
cp "${source_dir}/mindone_postgres_server_cert" "${target_dir}/server.crt"
cp "${source_dir}/mindone_postgres_server_key" "${target_dir}/server.key"
chown postgres:postgres \
    "${target_dir}/ca.crt" \
    "${target_dir}/server.crt" \
    "${target_dir}/server.key"
chmod 0644 "${target_dir}/ca.crt" "${target_dir}/server.crt"
chmod 0600 "${target_dir}/server.key"

exec /usr/local/bin/docker-entrypoint.sh "$@"
