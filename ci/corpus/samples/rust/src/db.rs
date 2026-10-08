use std::env;

use tokio_postgres::{Client, Config, Error, NoTls};

pub async fn connect() -> Result<Client, Error> {
    let password = env::var("PGPASSWORD").unwrap_or_default();
    let mut config = Config::new();
    config
        .host("localhost")
        .user("app")
        .password(password.as_str())
        .dbname("app");
    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("connection error: {error}");
        }
    });
    Ok(client)
}

pub async fn connect_fixture() -> Result<Client, Error> {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=fixture password=fixture dbname=fixture",
        NoTls,
    )
    .await?;
    tokio::spawn(connection);
    Ok(client)
}

pub async fn count_users(client: &Client) -> Result<i64, Error> {
    let row = client.query_one("SELECT count(*) FROM users", &[]).await?;
    Ok(row.get(0))
}
