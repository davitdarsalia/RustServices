use argon2::{password_hash::{rand_core::OsRng, SaltString, PasswordHasher}, Algorithm, Argon2, Params, Version};
use crate::auth::auth_service_server::AuthService;
use crate::auth::{SignUpRequest, AuthResponse, LogoutResponse, LogoutRequest, RefreshLoginRequest , SignInRequest};
use crate::services::jwt::generate_jwt_token;
use tonic::{Request, Response, Status};

#[derive(Default)]
pub struct MyAuthService {}

#[tonic::async_trait]
impl AuthService for MyAuthService {
    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();

        // Argon2 password hashing
        let params = Params::new(95000, 4000, 1500, None)
            .map_err(|_| Status::internal("Invalid Argon2 parameters"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2.hash_password(req.password.as_bytes(), &salt)
            .map_err(|_| Status::internal("Failed to hash password"))?
            .to_string();

        // Generate JWT token using "hello world" as the secret key
        let jwt_secret = "hello world".as_bytes();
        let token = match generate_jwt_token(&req.username, jwt_secret) {
            Ok(t) => t,
            Err(_) => return Err(Status::internal("Failed to generate token")),
        };

        // TODO: Generate refresh token and handle it accordingly
        // TODO: Store `password_hash`, `token`, and other user data in the database

        Ok(Response::new(AuthResponse {
            success: true,
            message: "User created successfully".into(),
            token, // JWT token
            refresh_token: "generated_refresh_token".into(), // Replace with actual refresh token
        }))
    }




    async fn sign_in(
        &self,
        _request: Request<SignInRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        // Placeholder implementation
        Ok(Response::new(AuthResponse {
            success: true,
            message: "Sign in successful".into(),
            token: "user_token".into(),
            refresh_token: "user_refresh_token".into(),
        }))
    }

    async fn refresh_login(
        &self,
        _request: Request<RefreshLoginRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        // Placeholder implementation
        Ok(Response::new(AuthResponse {
            success: true,
            message: "Login refreshed".into(),
            token: "new_user_token".into(),
            refresh_token: "new_refresh_token".into(),
        }))
    }

    async fn logout(
        &self,
        _request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        // Placeholder implementation
        Ok(Response::new(LogoutResponse {
            success: true,
            message: "Logged out successfully".into(),
        }))
    }


}


