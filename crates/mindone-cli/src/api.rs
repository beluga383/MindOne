use std::collections::BTreeSet;

use mindone_protocol::{
    ApiKeyListResponse, CreateApiKeyRequest, CreateApiKeyResponse, RevokeApiKeyResponse,
};
use serde_json::Value;

use crate::{
    cli::{ApiCreateArgs, ApiRevokeArgs},
    context::AppContext,
    error::CliResult,
    output::CommandOutput,
};

pub fn info(context: &AppContext) -> CliResult<CommandOutput> {
    let server = context.coordinator.server_url().trim_end_matches('/');
    let base_url = format!("{server}/v1");
    CommandOutput::new(
        format!(
            "远程推理配置\nBase URL：{base_url}\n聊天：{base_url}/chat/completions\n补全：{base_url}/completions\n模型：{base_url}/models\n认证：Authorization: Bearer <API_KEY>\n\n速度后缀：\n-fast：只选整台空闲贡献端，再按真实 TPS；全部忙碌时排队，不与现有任务争抢算力\n无后缀：沿用质量/健康路由，但同样只使用整台空闲贡献端，避免多槽拖慢单请求\n-slow：在真实多 slot 节点上优先合并负载；否则使用空闲节点或排队，不虚报并发\n\n官方贡献客户端为本机调用保留 slot 0，并提供三个相互隔离、逐请求清理的贡献 slot；节点主可用 max_concurrent 1..=3 收紧容量。"
        ),
        serde_json::json!({
            "base_url": base_url,
            "endpoints": {
                "chat_completions": "/v1/chat/completions",
                "completions": "/v1/completions",
                "models": "/v1/models",
            },
            "authentication": "bearer_api_key",
            "speed_classes": [
                {"suffix": "-fast", "class": "fast"},
                {"suffix": "", "class": "standard"},
                {"suffix": "-slow", "class": "slow"},
            ],
        }),
    )
}

pub async fn create(context: &AppContext, args: &ApiCreateArgs) -> CliResult<CommandOutput> {
    let response: CreateApiKeyResponse = context
        .authorized_post(
            "/v1/api-keys",
            &CreateApiKeyRequest {
                name: args.name.clone(),
            },
        )
        .await?;
    CommandOutput::new(
        format!(
            "API Key 创建成功（Secret 仅显示本次，请立即保存到客户端凭证库）\n名称：{}\nID：{}\nAPI Key：{}\n前缀：{}",
            response.record.name,
            response.record.id,
            response.api_key,
            response.record.key_prefix,
        ),
        response,
    )
}

pub async fn list(context: &AppContext) -> CliResult<CommandOutput> {
    let response: ApiKeyListResponse = context.authorized_get("/v1/api-keys").await?;
    if response.data.is_empty() {
        return CommandOutput::new("尚未创建 API Key", response);
    }
    let lines = response
        .data
        .iter()
        .map(|record| {
            format!(
                "{} | {} | {} | {}",
                record.id,
                record.name,
                record.key_prefix,
                if record.revoked_at.is_some() {
                    "已撤销"
                } else {
                    "有效"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput::new(format!("ID | 名称 | 前缀 | 状态\n{lines}"), response)
}

pub async fn revoke(context: &AppContext, args: &ApiRevokeArgs) -> CliResult<CommandOutput> {
    let path = format!("/v1/api-keys/{}", args.id);
    let response: RevokeApiKeyResponse = context.authorized_delete::<(), _>(&path, None).await?;
    CommandOutput::new(
        if response.revoked {
            format!("API Key {} 已撤销", response.id)
        } else {
            format!("API Key {} 之前已撤销，本次未重复修改", response.id)
        },
        response,
    )
}

pub async fn models(context: &AppContext) -> CliResult<CommandOutput> {
    let response: Value = context.authorized_get("/v1/models?limit=200").await?;
    let names = response
        .get("models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| model.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expanded = names
        .iter()
        .flat_map(|name| [format!("{name}-fast"), name.clone(), format!("{name}-slow")])
        .collect::<Vec<_>>();
    let human = if expanded.is_empty() {
        "当前没有在线且通过门禁的远程模型".to_owned()
    } else {
        format!(
            "模型名称（fast / standard / slow）\n{}",
            expanded.join("\n")
        )
    };
    CommandOutput::new(
        human,
        serde_json::json!({
            "object": "list",
            "data": expanded.into_iter().map(|id| serde_json::json!({
                "id": id,
                "object": "model",
                "owned_by": "mindone",
            })).collect::<Vec<_>>(),
        }),
    )
}
