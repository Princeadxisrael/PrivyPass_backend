use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber;

mod crypto;
mod models;
mod routes;
mod solana;


#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load environment variables
    dotenv::dotenv().ok();

    // Build our application with routes
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        
        // Account management
        .route("/api/account/create", post(routes::account::create_confidential_account))
        .route("/api/account/balance", post(routes::account::get_balance))
        
        // Confidential operations
        .route("/api/deposit", post(routes::deposit::deposit_tokens))
        .route("/api/apply", post(routes::deposit::apply_pending_balance))
        .route("/api/transfer", post(routes::transfer::confidential_transfer))
        .route("/api/withdraw", post(routes::withdraw::withdraw_tokens))
        
        // Proof generation (for frontend verification)
        .route("/api/proof/generate", post(routes::account::generate_proof))
        
        // CORS layer
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Run server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    tracing::info!("Private Pass Backend listening on {}", addr);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}
