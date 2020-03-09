use hyper::{Body, Response, StatusCode};
use serde_json::{json};
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;

use crate::{Token, util};

pub async fn post_users(user_spec: serde_json::Value, db: &Client) -> Response<Body> {
    let (email, password) = match util::get_email_pass(&user_spec) {
        Err(response) => return response,
        Ok(email_password) => email_password
    };

    // I have no idea if this is a good way to generate a salt
    let salt = rand::random::<u128>();

    let config = argon2::Config::default();
    let password_hash =
        argon2::hash_encoded(password, &salt.to_be_bytes(), &config).unwrap();

    let result = db.query(
        "INSERT INTO identity VALUES (default, $1, $2) RETURNING id",
        &[&email, &password_hash]
    ).await;

    match result {
        Err(e) => {
            if *e.code().unwrap() == SqlState::UNIQUE_VIOLATION {
                return util::json_err(StatusCode::BAD_REQUEST, "'email' is already in use")
            }
            println!("error inserting identity {:?}", e);
            util::json_err(StatusCode::SERVICE_UNAVAILABLE, "service unavailable")
        }
        Ok(rows) => {
            let id: i32 = rows.get(0).unwrap().get("id");

            util::json_ok(json!({"id": id, "email": email }))
        }
    }
}

pub async fn post_tokens(token_spec: serde_json::Value, db: &Client) -> Response<Body> {
    let (email, password) = match util::get_email_pass(&token_spec) {
        Err(response) => return response,
        Ok(email_password) => email_password
    };

    let lifetime_option = token_spec["lifetime"].as_str();
    if lifetime_option.is_none() {
        return util::json_err(StatusCode::BAD_REQUEST, "'lifetime' is required and must be a string")
    }
    let lifetime = lifetime_option.unwrap();

    if lifetime != "until-idle"
        && lifetime != "remember-me"
        && lifetime != "no-expiration"
    {
        return util::json_err(StatusCode::BAD_REQUEST, "'lifetime' must be 'until-idle', 'remember-me', or 'no-expiration'")
    }

    // get user record for the e-mail
    let rows = db
        .query(
            "SELECT id, password FROM identity WHERE email = $1",
            &[&email],
        )
        .await
        .unwrap();
    if rows.len() != 1 {
        return util::json_err(StatusCode::BAD_REQUEST, "email not found or password invalid")
    }
    let user = rows.get(0).unwrap();

    // verify the password
    let password_hash: String = user.get("password");
    let matches = argon2::verify_encoded(&password_hash, &password).unwrap();
    if !matches {
        return util::json_err(StatusCode::BAD_REQUEST, "email not found or password invalid")
    }

    // create a token
    let user_id: i32 = user.get("id");
    let token_id = format!("{:0>32x}", rand::random::<u128>());
    let token_secret = format!(
        "{:0>32x}{:0>32x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    );
    let rows = db
        .query(
            "INSERT INTO token VALUES ($1, $2, $3, $4, now(), now()) \
            RETURNING cast(extract(epoch from created) as integer) created, \
                      cast(extract(epoch from last_active) as integer) last_active",
            &[&token_id, &user_id, &token_secret, &lifetime],
        )
        .await
        .unwrap();

    let token = rows.get(0).unwrap();
    let created: i32 = token.get("created");
    let last_active: i32 = token.get("last_active");

    util::json_ok(json!({
        "id": token_id,
        "secret": token_secret,
        "lifetime": lifetime,
        "created": created,
        "last_active": last_active
    }))
}

pub async fn get_tokens(db: &Client, user_id: i32) -> Response<Body> {
    let rows = db
    .query(
        "SELECT id, lifetime, cast(extract(epoch from created) as integer) created, \
            cast(extract(epoch from last_active) as integer) last_active FROM token_active \
        WHERE identity_id = $1",
        &[&user_id],
    )
    .await
    .unwrap();

    let tokens: Vec<serde_json::Value> = rows.iter().map(
        |token| {
            let id: String = token.get("id");
            let lifetime: String = token.get("lifetime");
            let created: i32 = token.get("created");
            let last_active: i32 = token.get("last_active");
            json!({ "id": id, "lifetime": lifetime, "created": created, "last_active": last_active })
        }
    ).collect();

    util::json_ok(json!({"user_id": user_id, "tokens": tokens }))
}

pub async fn get_tokens_current(db: &Client, token: Token) -> Response<Body> {
    query_token_details(token.id, token.user_id, db).await
}

pub async fn delete_tokens_current(db: &Client, token_id: String) -> Response<Body> {
    db.execute("DELETE FROM token WHERE id = $1", &[&token_id])
        .await
        .unwrap();

    util::json_ok(json!({"success":"the token used to make this request was deleted"}))
}

pub async fn post_tokens_current_refresh(db: &Client, token_id: String) -> Response<Body> {
    let rows = db.query(
        "UPDATE token SET last_active = now() WHERE id = $1 \
        RETURNING lifetime, cast(extract(epoch from created) as integer) created, \
        cast(extract(epoch from last_active) as integer) last_active",
        &[&token_id],
    )
        .await
        .unwrap();

    let token = rows.get(0).unwrap();
    let lifetime: String = token.get("lifetime");
    let created: i32 = token.get("created");
    let last_active: i32 = token.get("last_active");

    util::json_ok(json!({
        "id": token_id,
        "lifetime": lifetime,
        "created": created,
        "last_active": last_active
    }))
}

pub fn get_tokens_current_valid() -> Response<Body> {
    Response::builder().body(Body::empty()).unwrap()
}

pub async fn get_tokens_id(db: &Client, user_id: i32, token_id: &str) -> Response<Body> {
    query_token_details(token_id.to_string(), user_id, db).await
}

pub async fn delete_tokens_id(db: &Client, token: Token, token_id: &str) -> Response<Body> {
    if *token_id == token.id {
        return util::json_err(StatusCode::BAD_REQUEST, "to delete current token, use the /tokens/current endpoint")
    }

    let rows_deleted = db
        .execute(
            "DELETE FROM token_active WHERE id = $1 AND identity_id=$2",
            &[&token_id, &token.user_id],
        )
        .await
        .unwrap();

    if rows_deleted < 1 {
        return util::json_err(StatusCode::NOT_FOUND, "invalid or expired token id")
    }

    util::json_ok(json!({"success": "the token was deleted"}))
}

async fn query_token_details(token_id: String, user_id: i32, db: &Client) -> Response<Body> {
    let rows = db
        .query(
            "SELECT lifetime, cast(extract(epoch from created) as integer) created, \
                cast(extract(epoch from last_active) as integer) last_active \
            FROM token_active WHERE id = $1 AND identity_id = $2",
            &[&token_id, &user_id],
        )
        .await
        .unwrap();
    if rows.len() != 1 {
        return util::json_err(StatusCode::NOT_FOUND, "invalid or expired token id")
    }
    let other_token = rows.get(0).unwrap();
    let lifetime: String = other_token.get("lifetime");
    let created: i32 = other_token.get("created");
    let last_active: i32 = other_token.get("last_active");

    util::json_ok(json!({
        "id": token_id,
        "user_id": user_id,
        "lifetime": lifetime,
        "created": created,
        "last_active": last_active
    }))
}
