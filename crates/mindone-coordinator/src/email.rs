//! SMTP 邮件发送模块。
//!
//! 从稳定的 `MINDONE_SMTP_*` 环境变量读取配置并发送验证邮件。

use std::{env, fmt, net::IpAddr, time::Duration};

use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};

use crate::config::RuntimeEnvironment;
use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

/// SMTP 配置，从环境变量加载。
#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    username: Option<String>,
    password: Option<String>,
    pub from_email: String,
    pub from_name: String,
    security: SmtpSecurity,
}

impl fmt::Debug for SmtpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "[已脱敏]"))
            .field("password", &self.password.as_ref().map(|_| "[已脱敏]"))
            .field("from_email", &self.from_email)
            .field("from_name", &self.from_name)
            .field("security", &self.security)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmtpSecurity {
    Tls,
    StartTls,
    Plain,
}

impl SmtpConfig {
    /// 从环境变量加载，缺失关键配置时返回错误。
    pub fn from_env(environment: RuntimeEnvironment) -> Result<Self> {
        Self::from_lookup(environment, |name| env::var(name).ok())
    }

    fn from_lookup(
        environment: RuntimeEnvironment,
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        let required = |value: Option<String>, name: &'static str| {
            value
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| ApiError::internal_msg(format!("{name} 未设置")))
        };
        let host = required(lookup("MINDONE_SMTP_HOST"), "MINDONE_SMTP_HOST")?;
        let port = required(lookup("MINDONE_SMTP_PORT"), "MINDONE_SMTP_PORT")?
            .parse::<u16>()
            .map_err(|_| ApiError::internal_msg("MINDONE_SMTP_PORT 必须是 1..=65535"))?;
        if port == 0 {
            return Err(ApiError::internal_msg("MINDONE_SMTP_PORT 必须是 1..=65535"));
        }
        let from_email = required(lookup("MINDONE_SMTP_FROM_EMAIL"), "MINDONE_SMTP_FROM_EMAIL")?;
        let from_name = lookup("MINDONE_SMTP_FROM_NAME")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "MindOne".to_owned());
        let username = lookup("MINDONE_SMTP_USERNAME").filter(|value| !value.is_empty());
        let password = lookup("MINDONE_SMTP_PASSWORD").filter(|value| !value.is_empty());
        if username.is_some() != password.is_some() {
            return Err(ApiError::internal_msg(
                "MINDONE_SMTP_USERNAME 与 MINDONE_SMTP_PASSWORD 必须同时配置或同时留空",
            ));
        }
        let security = match lookup("MINDONE_SMTP_SECURITY")
            .as_deref()
            .unwrap_or("starttls")
        {
            "tls" => SmtpSecurity::Tls,
            "starttls" => SmtpSecurity::StartTls,
            "plain"
                if environment != RuntimeEnvironment::Production
                    && lookup("MINDONE_SMTP_ALLOW_INSECURE_DEV").as_deref() == Some("true") =>
            {
                if !insecure_dev_host_allowed(&host) {
                    return Err(ApiError::internal_msg(
                        "开发 SMTP 明文传输只允许 loopback 或精确 mailhog 服务名",
                    ));
                }
                SmtpSecurity::Plain
            }
            "plain" => return Err(ApiError::internal_msg(
                "SMTP 明文传输只允许非 production 显式设置 MINDONE_SMTP_ALLOW_INSECURE_DEV=true",
            )),
            _ => {
                return Err(ApiError::internal_msg(
                    "MINDONE_SMTP_SECURITY 只允许 tls、starttls 或开发环境 plain",
                ))
            }
        };

        Ok(Self {
            host,
            port,
            username,
            password,
            from_email,
            from_name,
            security,
        })
    }

    /// 构造 SMTP 传输器（连接池）。
    pub fn mailer(&self) -> Result<SmtpTransport> {
        let mut builder = match self.security {
            SmtpSecurity::Tls => SmtpTransport::relay(&self.host),
            SmtpSecurity::StartTls => SmtpTransport::starttls_relay(&self.host),
            SmtpSecurity::Plain => Ok(SmtpTransport::builder_dangerous(&self.host)),
        }
        .map_err(|error| {
            tracing::error!(error = %error, "无法配置 SMTP 传输");
            ApiError::internal()
        })?
        .port(self.port)
        .timeout(Some(Duration::from_secs(10)));
        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        }
        Ok(builder.build())
    }

    /// 在服务器开始监听前验证发件人地址和传输构造参数；不建立网络连接。
    pub fn validate(&self) -> Result<()> {
        self.sender_mailbox()?;
        self.mailer()?;
        Ok(())
    }

    /// 显式建立一次 SMTP 会话验证连通性，不发送邮件。
    ///
    /// 调用方必须只在用户明确请求 live 检查时调用；普通启动前配置校验只构造
    /// transport，不访问网络。
    pub fn test_connection(&self) -> Result<()> {
        let mailer = self.mailer()?;
        match mailer.test_connection() {
            Ok(true) => Ok(()),
            Ok(false) => Err(ApiError::internal_msg("SMTP 服务器拒绝连接检查")),
            Err(error) => {
                tracing::error!(error = %error, "SMTP 连接检查失败");
                Err(ApiError::internal())
            }
        }
    }

    fn sender_mailbox(&self) -> Result<Mailbox> {
        format!("{} <{}>", self.from_name, self.from_email)
            .parse::<Mailbox>()
            .map_err(|error| {
                tracing::error!(error = %error, "SMTP 发件人配置无效");
                ApiError::internal()
            })
    }
}

fn insecure_dev_host_allowed(host: &str) -> bool {
    host == "localhost"
        || host == "mailhog"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// 发送邮箱验证邮件。
pub async fn send_verification_email(
    config: &SmtpConfig,
    to_email: &str,
    username: &str,
    verification_url: &str,
) -> Result<()> {
    let from = config.sender_mailbox()?;

    let to = to_email.parse::<Mailbox>().map_err(|error| {
        tracing::warn!(error = %error, "已校验邮箱无法构造 SMTP 收件人");
        ApiError::bad_request("invalid_email", "收件人邮箱格式无效")
    })?;

    let subject = "验证你的 MindOne 账户";
    let body = format!(
        "你好 {username}，\n\n\
        感谢注册 MindOne AI 算力网络。\n\n\
        请点击以下链接验证你的邮箱：\n\
        {verification_url}\n\n\
        该链接将在 24 小时后过期。\n\n\
        如果你没有注册过 MindOne，请忽略此邮件。\n\n\
        —— MindOne 团队"
    );

    let email = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|error| {
            tracing::error!(error = %error, "构造邮箱验证邮件失败");
            ApiError::internal()
        })?;

    let mailer = config.mailer()?;
    tokio::time::timeout(
        Duration::from_secs(12),
        tokio::task::spawn_blocking(move || mailer.send(&email)),
    )
    .await
    .map_err(|_| {
        tracing::error!("SMTP 发送超时");
        ApiError::internal()
    })?
    .map_err(|error| {
        tracing::error!(error = %error, "SMTP 发送任务失败");
        ApiError::internal()
    })?
    .map_err(|error| {
        tracing::error!(error = %error, "SMTP 发送失败");
        ApiError::internal()
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{RuntimeEnvironment, SmtpConfig, SmtpSecurity};

    #[test]
    fn compose_email_environment_is_read_without_process_global_mutation() {
        let values = BTreeMap::from([
            ("MINDONE_SMTP_HOST", "mailhog"),
            ("MINDONE_SMTP_PORT", "1025"),
            ("MINDONE_SMTP_USERNAME", ""),
            ("MINDONE_SMTP_PASSWORD", ""),
            ("MINDONE_SMTP_FROM_EMAIL", "noreply@mindone.local"),
            ("MINDONE_SMTP_FROM_NAME", "MindOne Test"),
            ("MINDONE_SMTP_SECURITY", "plain"),
            ("MINDONE_SMTP_ALLOW_INSECURE_DEV", "true"),
        ]);
        let config = SmtpConfig::from_lookup(RuntimeEnvironment::Development, |name| {
            values.get(name).map(ToString::to_string)
        })
        .expect("test Compose 的 SMTP 配置应可读取");
        assert_eq!(config.host, "mailhog");
        assert_eq!(config.port, 1025);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
        assert_eq!(config.security, SmtpSecurity::Plain);
        assert_eq!(config.from_email, "noreply@mindone.local");
        assert_eq!(config.from_name, "MindOne Test");
        config
            .validate()
            .expect("发件人与 Mailhog 传输配置应在启动期通过校验");
    }

    #[test]
    fn smtp_credentials_are_paired_and_plaintext_is_development_only() {
        let base = BTreeMap::from([
            ("MINDONE_SMTP_HOST", "smtp.example.com"),
            ("MINDONE_SMTP_PORT", "587"),
            ("MINDONE_SMTP_FROM_EMAIL", "noreply@example.com"),
        ]);
        let unpaired = SmtpConfig::from_lookup(RuntimeEnvironment::Production, |name| {
            if name == "MINDONE_SMTP_USERNAME" {
                Some("mailer".to_owned())
            } else {
                base.get(name).map(ToString::to_string)
            }
        });
        assert!(unpaired.is_err());

        let plain = SmtpConfig::from_lookup(RuntimeEnvironment::Production, |name| {
            if name == "MINDONE_SMTP_SECURITY" {
                Some("plain".to_owned())
            } else {
                base.get(name).map(ToString::to_string)
            }
        });
        assert!(plain.is_err());

        let remote_plain =
            SmtpConfig::from_lookup(RuntimeEnvironment::Development, |name| match name {
                "MINDONE_SMTP_SECURITY" => Some("plain".to_owned()),
                "MINDONE_SMTP_ALLOW_INSECURE_DEV" => Some("true".to_owned()),
                _ => base.get(name).map(ToString::to_string),
            });
        assert!(remote_plain.is_err());

        let invalid_sender =
            SmtpConfig::from_lookup(RuntimeEnvironment::Production, |name| match name {
                "MINDONE_SMTP_FROM_EMAIL" => Some("not-an-email".to_owned()),
                _ => base.get(name).map(ToString::to_string),
            })
            .expect("非空配置先完成结构读取");
        assert!(invalid_sender.validate().is_err());
    }
}
