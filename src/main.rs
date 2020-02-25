use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use bytes::buf::BufExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use lazy_static::*;
use regex::Regex;
use std::convert::Infallible;
use tokio_postgres::error::Error as TokioPostgresError;
use tokio_postgres::{Client, NoTls};

mod handlers;
mod util;

pub struct Token {
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
    static ref TOKEN_SECRET_REGEX: Regex = Regex::new("^[a-fA-F0-9]{64}$").unwrap();
    static ref TOKENS_ID_PATH_REGEX: Regex = Regex::new("^/tokens/([a-fA-F0-9]{32})$").unwrap();
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
        if let Some(id_match) = TOKENS_ID_PATH_REGEX.captures(path) {
            path_found = true;
            let path_params = [id_match.get(1).unwrap().as_str().to_string()].to_vec();

            match *request.method() {
                Method::GET => return Ok(route_path_params(Handler::GetTokensId, path_params)),
                Method::DELETE => return Ok(route_path_params(Handler::DeleteTokensId, path_params)),
                _ => ()
            };
        }
    }

    if path_found {
        return Err(util::json_err(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"))
    }

    Err(util::json_err(StatusCode::NOT_FOUND, "resource not found"))
}

async fn handle_anonymous_request(handler: Handler, request: Request<Body>, db: &Client) -> Response<Body> {
    // TODO check content-type
    let data = match hyper::body::aggregate(request).await {
        Err(e) => {
            println!("could not get whole body {:?}", e);
            return util::json_err(StatusCode::SERVICE_UNAVAILABLE, "service unavailable")
        }
        Ok(whole_body) => match serde_json::from_reader(whole_body.reader()) {
            Err(_) => return util::json_err(StatusCode::BAD_REQUEST, "could not parse body"),
            Ok(data) => data
        }
    };

    match handler {
        Handler::PostUsers => handlers::post_users(data, db).await,
        Handler::PostTokens => handlers::post_tokens(data, db).await,
        _ => util::json_err(StatusCode::SERVICE_UNAVAILABLE, "service unavailable")
    }
}

async fn handle_authenticated_request(route: Route, db: &Client, token: Token) -> Response<Body> {
    match route.handler {
        Handler::GetTokens => handlers::get_tokens(db, token.user_id).await,
        Handler::GetTokensCurrent => handlers::get_tokens_current(db, token).await,
        Handler::DeleteTokensCurrent => handlers::delete_tokens_current(db, token.id).await,
        Handler::PostTokensCurrentRefresh => handlers::post_tokens_current_refresh(db, token.id).await,
        Handler::GetTokensCurrentValid => handlers::get_tokens_current_valid(),
        Handler::GetTokensId => handlers::get_tokens_id(db, token.user_id, &route.path_params[0]).await,
        Handler::DeleteTokensId => handlers::delete_tokens_id(db, token, &route.path_params[0]).await,
        _ => util::json_err(StatusCode::SERVICE_UNAVAILABLE, "service unavailable")
    }
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
            util::json_err(StatusCode::SERVICE_UNAVAILABLE, "service unavailable")
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
        return Err(util::json_err(StatusCode::UNAUTHORIZED, "invalid or expired token"))
    }

    let row = rows.get(0).unwrap();
    let id: String = row.get("id");
    let user_id: i32 = row.get("identity_id");

    Ok(Token{ id, user_id })
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
                        return Err(util::json_err(StatusCode::BAD_REQUEST, "multiple token cookies"))
                    }
                }
                None => token_secret_option = Some(token_secret),
            }
        }
    }

    match token_secret_option {
        Some(token_secret) => Ok(token_secret.to_string()),
        None => Err(util::json_err(StatusCode::UNAUTHORIZED, if found_token_cookie {
                "token cookie invalid format"
            } else {
                "missing token cookie"
            }))
    }
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c().await
        .expect("failed to install CTRL+C signal handler");
}
