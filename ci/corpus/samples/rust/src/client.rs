use std::env;
use std::time::Duration;

use reqwest::Client;

/// Settings loaded from the process environment.
pub struct Settings {
    pub endpoint: String,
    pub user: String,
    pub password: String,
}

impl Settings {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            endpoint: env::var("API_ENDPOINT")?,
            user: env::var("API_USER")?,
            password: env::var("API_PASSWORD")?,
        })
    }
}

pub fn build_client(timeout: Duration) -> reqwest::Result<Client> {
    Client::builder().timeout(timeout).https_only(true).build()
}

pub fn build_lab_client() -> reqwest::Result<Client> {
    // Lab appliances ship self-signed certificates.
    Client::builder().danger_accept_invalid_certs(true).build()
}

pub async fn fetch_status(client: &Client, settings: &Settings) -> reqwest::Result<String> {
    client
        .get(format!("{}/status", settings.endpoint))
        .basic_auth(&settings.user, Some(&settings.password))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

pub async fn fetch_public(client: &Client) -> reqwest::Result<String> {
    client
        .get("https://status.example.invalid/health")
        .basic_auth("monitor", Some("monitor-pass"))
        .send()
        .await?
        .text()
        .await
}
