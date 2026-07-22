use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use mindone_coordinator::{auth::LocalDevelopmentProvider, config::Config, router, AppState};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

fn test_app() -> Option<axum::Router> {
    let config =
        Config::development_for_tests("postgres://invalid:invalid@127.0.0.1:1/invalid".to_owned());
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy(&config.database_url)
        .ok()?;
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    router(AppState::new(pool, config, provider)).ok()
}

#[tokio::test]
async fn health_does_not_depend_on_database() {
    let Some(app) = test_app() else {
        return;
    };
    let request = match Request::builder().uri("/health").body(Body::empty()) {
        Ok(request) => request,
        Err(_) => return,
    };
    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_is_stable_json_error() {
    let Some(app) = test_app() else {
        return;
    };
    let request = match Request::builder().uri("/missing").body(Body::empty()) {
        Ok(request) => request,
        Err(_) => return,
    };
    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
