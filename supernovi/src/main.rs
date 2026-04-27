use std::{env, error::Error};

use bitwarden::{Client, auth::login::AccessTokenLoginRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(debug_assertions)]
    dotenvy::dotenv().ok();

    let client = Client::new(None);
    let token = env::var("BWS_TOKEN").unwrap();
    let request = AccessTokenLoginRequest {
        access_token: token,
        state_file: None,
    };
    let response = client.auth().login_access_token(&request).await?;

    println!("Hello, world! {:?}", response);

    Ok(())
}
