extern crate argon2;
extern crate rand;

#[macro_use]
extern crate lazy_static;

use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use bytes::buf::BufExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json::{self, json};
use std::convert::Infallible;
use tokio_postgres::error::Error as TokioPostgresError;
use tokio_postgres::{Client, NoTls};

struct Token {
    id: String,
    user_id: i32,
}

enum Handler {
    PostUsers,
    GetTokens,
    PostTokens,
    GetTokensCurrent,
    DeleteTokensCurrent,
    PostTokensCurrentRefresh,
    GetTokensCurrentValid,
    GetTokensId,
    DeleteTokensId,
}

struct Route {
    auth_required: bool,
    handler: Handler,
    path_params: Vec<String>,
}

fn route(handler: Handler) -> Route {
    Route { auth_required: true, handler, path_params: [].to_vec() }
}

fn route_path_params(handler: Handler, path_params: Vec<String>) -> Route {
    Route { auth_required: true, handler, path_params }
}

fn route_anon(handler: Handler) -> Route {
    Route { auth_required: false, handler, path_params: [].to_vec() }
}

lazy_static! {
    static ref TOKEN_SECRET_REGEX: regex::Regex = regex::Regex::new("^[a-fA-F0-9]{64}$").unwrap();
    static ref TOKENS_ID_PATH_REGEX: regex::Regex = regex::Regex::new("^/tokens/([a-fA-F0-9]{32})$").unwrap();
}

fn get_route(request: &Request<Body>) -> Result<Route, Response<Body>> {
    println!("get_route");

    let orig_path = request.uri().path();

    let path = if orig_path.ends_with('/') {
        &orig_path[..orig_path.len() - 1]
    } else {
        orig_path
    };

    let mut path_found = true;

    match path {
        "/users" => match *request.method() {
            Method::POST => return Ok(route_anon(Handler::PostUsers)),
            _ => ()
        },
        "/tokens" => match *request.method() {
            Method::GET => return Ok(route(Handler::GetTokens)),
            Method::POST => return Ok(route_anon(Handler::PostTokens)),
            _ => ()
        },
        "/tokens/current" => match *request.method() {
            Method::GET => return Ok(route(Handler::GetTokensCurrent)),
            Method::DELETE => return Ok(route(Handler::DeleteTokensCurrent)),
            _ => ()
        },
        "/tokens/current/refresh" => match *request.method() {
            Method::POST => return Ok(route(Handler::PostTokensCurrentRefresh)),
            _ => ()
        },
        "/tokens/current/valid" => match *request.method() {
            Method::GET => return Ok(route(Handler::GetTokensCurrentValid)),
            _ => ()
        },
        _ => path_found = false
    };

    if !path_found {
        match TOKENS_ID_PATH_REGEX.captures(path).unwrap().get(1) {
            Some(id_match) => {
                path_found = true;
                let path_params = [id_match.as_str().to_string()].to_vec();

                match *request.method() {
                    Method::GET => return Ok(route_path_params(Handler::GetTokensId, path_params)),
                    Method::DELETE => return Ok(route_path_params(Handler::DeleteTokensId, path_params)),
                    _ => ()
                };
            }
            None => ()
        }
    }

    if path_found {
        return Err(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("method not allowed\n"))
                .unwrap())
    }

    Err(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("resource not found\n"))
        .unwrap())
}

async fn handle_anonymous_request(handler: Handler, request: Request<Body>, db: &Client) -> Response<Body> {
    // TODO check content-type
    let whole_body_result = hyper::body::aggregate(request).await;
    if whole_body_result.is_err() {
        println!("could not get whole body");
        return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("service unavailable\n"))
                .unwrap()
    }
    let data_result: Result<serde_json::Value, _> = serde_json::from_reader(whole_body_result.unwrap().reader());
    if data_result.is_err() {
        println!("could not parse body {}", data_result.unwrap_err());
        return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("could not parse body\n"))
                .unwrap()
    }

    let data = data_result.unwrap();

    match handler {
        Handler::PostUsers => post_users(data, db).await,
        Handler::PostTokens => post_tokens(data, db).await,
        _ => Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("service unavailable\n"))
                .unwrap()
    }
}

fn get_email_pass(spec: &serde_json::Value) -> Result<(String, &[u8]), Response<Body>> {
    let email_option = spec["email"].as_str();
    if email_option.is_none() {
        return Err(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json!({ "error": "'email' is required and must be a string" }).to_string()+"\n"))
                .unwrap())
    }
    let email = email_option.unwrap();

    if email.len() > 150 {
        return Err(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json!({ "error": "'email' must be 150 characters or less" }).to_string()+"\n"))
                .unwrap())
    }

    let password_option = spec["password"].as_str();
    if password_option.is_none() {
        return Err(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json!({ "error": "'password' is required and must be a string" }).to_string()+"\n"))
                .unwrap())
    }
    let password = password_option.unwrap();

    Ok((email.to_string(), password.as_bytes()))
}

async fn post_users(user_spec: serde_json::Value, db: &Client) -> Response<Body> {
    let (email, password) = match get_email_pass(&user_spec) {
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
            if *e.code().unwrap() == tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(json!({"error": "'email' is already in use"}).to_string()+"\n"))
                    .unwrap()
            }
            println!("error inserting identity {:?}", e);
            Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("service unavailable\n"))
                    .unwrap()
        }
        Ok(rows) => {
            let id: i32 = rows.get(0).unwrap().get("id");

            Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(json!({"id": id, "email": email }).to_string()+"\n"))
                .unwrap()
        }
    }
}

async fn post_tokens(token_spec: serde_json::Value, db: &Client) -> Response<Body> {
    let (email, password) = match get_email_pass(&token_spec) {
        Err(response) => return response,
        Ok(email_password) => email_password
    };

    let lifetime_option = token_spec["lifetime"].as_str();
    if lifetime_option.is_none() {
        return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json!({"error": "'lifetime' is required and must be a string"}).to_string()+"\n"))
                .unwrap()
    }
    let lifetime = lifetime_option.unwrap();

    if lifetime != "until-idle"
        && lifetime != "remember-me"
        && lifetime != "no-expiration"
    {
        return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json!({"error": "'lifetime' must be 'until-idle', 'remember-me', or 'no-expiration'"}).to_string()+"\n"))
                .unwrap()
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
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(json!({"error": "email not found or password invalid"}).to_string()+"\n"))
            .unwrap()
    }
    let user = rows.get(0).unwrap();

    // verify the password
    let password_hash: String = user.get("password");
    let matches = argon2::verify_encoded(&password_hash, &password).unwrap();
    if !matches {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(json!({"error": "email not found or password invalid"}).to_string()+"\n"))
            .unwrap()
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

    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(json!({
            "id": token_id,
            "token_secret": token_secret,
            "lifetime": lifetime,
            "created": created,
            "last_active": last_active
        }).to_string() + "\n"))
        .unwrap()
}

async fn handle_authenticated_request(route: Route, db: &Client, token: Token) -> Response<Body> {
    match route.handler {
        Handler::GetTokens => get_tokens(db, token.user_id).await,
        Handler::GetTokensCurrent => get_tokens_current(db, token).await,
        Handler::DeleteTokensCurrent => delete_tokens_current(db, token.id).await,
        Handler::PostTokensCurrentRefresh => post_tokens_current_refresh(db, token.id).await,
        Handler::GetTokensCurrentValid => get_tokens_current_valid(),
        Handler::GetTokensId => get_tokens_id(db, token.user_id, &route.path_params[0]).await,
        Handler::DeleteTokensId => delete_tokens_id(db, token.user_id).await,
        _ => Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("service unavailable\n"))
                .unwrap()
    }
}

async fn get_tokens(db: &Client, user_id: i32) -> Response<Body> {
    let rows = db
    .query(
        "SELECT id, lifetime, cast(extract(epoch from created) as integer) created, \
            cast(extract(epoch from last_active) as integer) last_active FROM token_active \
        WHERE identity_id = $1",
        &[&user_id],
    )
    .await
    .unwrap();

    let tokens: Vec<serde_json::value::Value> = rows.iter().map(
        |token| {
            let id: String = token.get("id");
            let lifetime: String = token.get("lifetime");
            let created: i32 = token.get("created");
            let last_active: i32 = token.get("last_active");
            json!({ "id": id, "lifetime": lifetime, "created": created, "last_active": last_active })
        }
    ).collect();

    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(json!({"user_id": user_id, "tokens": tokens }).to_string() + "\n"))
        .unwrap()
}

async fn get_tokens_current(db: &Client, token: Token) -> Response<Body> {
    query_token_details(token.id, token.user_id, db).await
}

async fn delete_tokens_current(db: &Client, token_id: String) -> Response<Body> {
    db.execute("DELETE FROM token WHERE id = $1", &[&token_id])
        .await
        .unwrap();

    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(json!({"success":"the token used to make this request was deleted"}).to_string() + "\n"))
        .unwrap()
}

async fn post_tokens_current_refresh(db: &Client, token_id: String) -> Response<Body> {
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

    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(json!({
            "id": token_id,
            "lifetime": lifetime,
            "created": created,
            "last_active": last_active
        }).to_string() + "\n"))
        .unwrap()
}

fn get_tokens_current_valid() -> Response<Body> {
    Response::builder()
        .body(Body::empty())
        .unwrap()
}

async fn get_tokens_id(db: &Client, user_id: i32, token_id: &String) -> Response<Body> {
    query_token_details(token_id.to_string(), user_id, db).await
}

async fn delete_tokens_id(db: &Client, user_id: i32) -> Response<Body> {
    Response::builder()
        .body(Body::from(format!("delete_tokens_id {}\n", user_id)))
        .unwrap()
}


#[tokio::main]
async fn main() {
    println!("main");
    let pg_mgr = PostgresConnectionManager::new_from_stringlike(
        "postgresql://auth:auth@localhost:5432",
        NoTls,
    )
    .unwrap();

    let pool = match Pool::builder().build(pg_mgr).await {
        Ok(pool) => pool,
        Err(e) => panic!("bb8 error {:?}", e),
    };

    let make_svc = make_service_fn(move |_socket| {
        let pool = pool.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |request: Request<_>| {
                let pool = pool.clone();
                async move { process_request(request, pool).await }
            }))
        }
    });

    let addr = ([127, 0, 0, 1], 3000).into();
    let server = Server::bind(&addr).serve(make_svc);

    let graceful = server.with_graceful_shutdown(shutdown_signal());

    // Run this server until CTRL+C
    if let Err(e) = graceful.await {
        eprintln!("server error: {}", e);
    } else {
        println!("\ngracefully shutdown");
    }
}

async fn process_request(
    request: Request<Body>,
    pool: Pool<PostgresConnectionManager<NoTls>>,
) -> Result<Response<Body>, Infallible> {
    println!("process_request");
    // do anything that doesn't need DB here before pool.run
    // (routing, token cookie presence/format)
    let route = get_route(&request);
    if route.is_err() {
        return Ok(route.err().unwrap());
    }
    let route = route.unwrap();

    let mut token_secret_option = None;
    if route.auth_required {
        match get_token_secret(&request) {
            Ok(secret) => token_secret_option = Some(secret),
            Err(response) => return Ok(response),
        }
    }

    println!("get db connection");
    let result = pool.run(move |db| {
        async move {
            let response = if let Some(token_secret) = token_secret_option {
                match query_token_by_secret(token_secret, &db).await {
                    Ok(token) => handle_authenticated_request(route, &db, token).await,
                    Err(e) => e
                }
            } else {
                handle_anonymous_request(route.handler, request, &db).await
            };

            println!("send response\n");
            Ok::<_, (TokioPostgresError, Client)>((response, db))
        }
    }).await;

    Ok(match result {
        Ok(response) => response,
        Err(e) => {
            println!("TokioPostgresError: {}", e);
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("service unavailable\n"))
                .unwrap()
        }
    })
}

async fn query_token_by_secret(token_secret: String, db: &Client) -> Result<Token, Response<Body>> {
    println!("query_token_by_secret");
    let rows = db.query(
        "SELECT id, identity_id FROM token_active WHERE secret = $1",
        &[&token_secret],
    ).await.unwrap();

    if rows.len() != 1 {
        return Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("invalid or expired token\n"))
            .unwrap());
    }

    let row = rows.get(0).unwrap();
    let id: String = row.get("id");
    let user_id: i32 = row.get("identity_id");

    Ok(Token{ id, user_id })
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
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("invalid or expired token id\n"))
            .unwrap()
    }
    let other_token = rows.get(0).unwrap();
    let lifetime: String = other_token.get("lifetime");
    let created: i32 = other_token.get("created");
    let last_active: i32 = other_token.get("last_active");

    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(json!({
            "id": token_id,
            "user_id": user_id,
            "lifetime": lifetime,
            "created": created,
            "last_active": last_active
        }).to_string() + "\n"))
        .unwrap()
}

fn get_token_secret(request: &Request<Body>) -> Result<String, Response<Body>> {
    println!("get_token_secret");
    let mut token_secret_option = None;
    let mut found_token_cookie = false;

    for cookie_header in request.headers().get_all("cookie") {
        for cookie in cookie_header.to_str().unwrap().split(';') {
            let cookie_pair: Vec<&str> = cookie.split('=').collect();

            if cookie_pair.len() != 2 || cookie_pair.get(0).unwrap().trim() != "token" {
                continue;
            }

            let token_secret = cookie_pair.get(1).unwrap().trim();
            found_token_cookie = true;

            if !TOKEN_SECRET_REGEX.is_match(token_secret) {
                continue;
            }

            match token_secret_option {
                Some(first_token_secret) => {
                    if first_token_secret != token_secret {
                        return Err(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from("multiple token cookies\n"))
                            .unwrap());
                    }
                }
                None => token_secret_option = Some(token_secret),
            }
        }
    }

    match token_secret_option {
        Some(token_secret) => Ok(token_secret.to_string()),
        None => Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from(if found_token_cookie {
                "token cookie invalid format\n"
            } else {
                "missing token cookie\n"
            }))
            .unwrap()),
    }
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c().await
        .expect("failed to install CTRL+C signal handler");
}
