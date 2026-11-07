#!/usr/bin/env bash
# Gom cấu hình ELK (cài bằng apt) trên Ubuntu server vào ./elk-config, đã che mật khẩu.
#   sudo bash collect_elk_config.sh                       # chỉ lấy file cấu hình
#   sudo ES_PASS='...' bash collect_elk_config.sh          # lấy thêm index template / ingest pipeline
# Sau đó: tar czf elk-config.tgz elk-config  -> copy về máy, giải nén vào platform/wazuh_elastic/
set -uo pipefail
OUT=${OUT:-./elk-config}
ES_URL=${ES_URL:-https://localhost:9200}
mkdir -p "$OUT"

copy() {  # copy file/thư mục nếu tồn tại, giữ cấu trúc
  local src=$1 dst=$OUT/$2
  [[ -e $src ]] || return 0
  mkdir -p "$(dirname "$dst")"
  cp -r "$src" "$dst" && echo "  + $src"
}

echo "[1/3] File cấu hình"
copy /etc/elasticsearch/elasticsearch.yml elasticsearch/elasticsearch.yml
copy /etc/elasticsearch/jvm.options.d    elasticsearch/jvm.options.d
copy /etc/kibana/kibana.yml              kibana/kibana.yml
copy /etc/logstash/logstash.yml          logstash/logstash.yml
copy /etc/logstash/pipelines.yml         logstash/pipelines.yml
copy /etc/logstash/conf.d                logstash/conf.d
copy /etc/filebeat/filebeat.yml          filebeat/filebeat.yml
copy /etc/filebeat/modules.d             filebeat/modules.d
# chỉ giữ module đang bật (file .yml, không phải .disabled)
find "$OUT/filebeat/modules.d" -name '*.disabled' -delete 2>/dev/null

echo "[2/3] Che thông tin nhạy cảm"
# password / api_key / token / secret / keystore -> \${BIEN_MOI_TRUONG}
find "$OUT" -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.conf' \) -print0 |
  xargs -0 -r sed -i -E \
    -e 's/^([[:space:]#]*[A-Za-z0-9_.]*(password|passwd|api_key|apikey|token|secret|encryptionKey)[A-Za-z0-9_.]*[[:space:]]*(:|=>|=)[[:space:]]*).+$/\1"${REDACTED}"/I'
# chứng chỉ / khoá không bao giờ đưa vào git
find "$OUT" -type f \( -name '*.p12' -o -name '*.key' -o -name '*.pem' -o -name '*.crt' -o -name '*.keystore' \) -delete

echo "[3/3] Index template / ingest pipeline / phiên bản"
if [[ -n ${ES_PASS:-} ]]; then
  c() { curl -sk -u "elastic:$ES_PASS" "$ES_URL/$1"; }
  c ''                                  > "$OUT/es_info.json"
  c '_index_template?pretty'            > "$OUT/index_templates.json"
  c '_ingest/pipeline?pretty'           > "$OUT/ingest_pipelines.json"
  c '_cat/indices?v&s=index'            > "$OUT/indices.txt"
  # 1 document mẫu mỗi loại -> dùng để kiểm tra adapter ml/src/ecs_to_auth.py
  c 'winlogbeat-*/_search?size=3&q=event.code:4624&pretty' > "$OUT/sample_win_4624.json"
  c 'winlogbeat-*/_search?size=3&q=event.code:4625&pretty' > "$OUT/sample_win_4625.json"
  c 'filebeat-*/_search?size=3&q=process.name:sshd&pretty' > "$OUT/sample_linux_sshd.json"
  echo "  + es_info, index_templates, ingest_pipelines, indices, sample_*.json"
else
  echo "  (bỏ qua – đặt ES_PASS để lấy)"
fi
for p in elasticsearch kibana logstash filebeat; do
  dpkg-query -W -f='${Package} ${Version}\n' "$p" 2>/dev/null
done > "$OUT/versions.txt"

chown -R "${SUDO_USER:-$USER}" "$OUT" 2>/dev/null
echo "Xong -> $OUT  (kiểm tra lại bằng: grep -rniE 'password|token|api_key' $OUT)"
