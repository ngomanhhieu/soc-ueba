# platform/ – Người B (Platform, Agent, Web)

- `wazuh_elastic/`: cấu hình Wazuh/Elastic Stack, index mapping, pipeline nạp log
- `rules/`: rule Sigma-style / Wazuh rule + test case
- `agent/`: AI Agent (LangChain + LLM), tools, prompt, output JSON
- `api/`: backend FastAPI (đọc alert, gọi agent, nhận duyệt hành động)
- `dashboard/`: Kibana export hoặc React app

Dùng `../schema/alerts_sample.json` để dựng dashboard/agent trước khi có alert thật từ `ml/`.
