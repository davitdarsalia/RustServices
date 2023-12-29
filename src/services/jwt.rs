use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize};

#[derive(Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize
}

pub fn generate_jwt_token(username: &str, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
}