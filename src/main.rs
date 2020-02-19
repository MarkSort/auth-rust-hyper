#[macro_use]
extern crate lazy_static;

use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::collections::HashMap;
use std::convert::Infallible;
use tokio_postgres::error::Error as TokioPostgresError;
use tokio_postgres::{Client, NoTls};

lazy_static! {
    static ref TOKEN_SECRET_REGEX: regex::Regex = regex::Regex::new("^[a-fA-F0-9]{64}$").unwrap();

    static ref ROUTES: HashMap<&'static str, HashMap<Method, Route>> = {
        println!("build ROUTES static");
        let mut routes = HashMap::new();

        routes.insert(
            "/users",
            [
                (Method::POST, Route{ auth_required: false, message: "POST /users!"})
            ].iter().cloned().collect(),
        );

        routes.insert(
            "/tokens",
            [
                (Method::GET, Route{ auth_required: true, message: "GET /tokens!"}),
                (Method::POST, Route{ auth_required: false, message: "POST /tokens!"}),
            ].iter().cloned().collect(),
        );

        routes.insert(
            "/tokens/current",
            [
                (Method::GET, Route{ auth_required: true, message: "GET /tokens/current!"}),
                (Method::DELETE, Route{ auth_required: true, message: "DELETE /tokens/current!"}),
            ].iter().cloned().collect(),
        );

        routes.insert(
            "/tokens/current/refresh",
            [
                (Method::POST, Route{ auth_required: true, message: "POST /tokens/current/refresh!"})
            ].iter().cloned().collect(),
        );

        routes.insert(
            "/tokens/current/valid",
            [
                (Method::GET, Route{ auth_required: true, message: "GET /tokens/current/valid!"})
            ].iter().cloned().collect(),
        );

        routes
    };

    static ref ROUTES_REGEX: Vec<(regex::Regex, HashMap<Method, Route>)> = {
        println!("build ROUTES_REGEX static");
        let mut routes = Vec::new();

        routes.push((
            regex::Regex::new("^/tokens/[a-fA-F0-9]{32}$").unwrap(),
            [
                (Method::GET, Route{ auth_required: true, message: "GET /tokens/<id>!"}),
                (Method::DELETE, Route{ auth_required: true, message: "DELETE /tokens/<id>!"}),
            ].iter().cloned().collect(),
        ));

        routes
    };
}

#[derive(Copy, Clone)]
struct Route {
    auth_required: bool,
    message: &'static str,
}

fn route_request(request: &Request<Body>) -> Result<Route, Response<Body>> {
    println!("route_request");

    let orig_path = request.uri().path();

    let path = if orig_path.ends_with('/') {
        &orig_path[..orig_path.len() - 1]
    } else {
        orig_path
    };

    let mut path_routes = ROUTES.get(path);

    if path_routes.is_none() {
        for route_regex in ROUTES_REGEX.iter() {
            if route_regex.0.is_match(path) {
                path_routes = Some(&route_regex.1);
                break;
            }
        }

        if path_routes.is_none() {
            return Err(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("resource not found\n"))
                .unwrap());
        }
    }
    let path_routes = path_routes.unwrap();

    let route = path_routes.get(request.method());

    if route.is_none() {
        return Err(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("method not allowed\n"))
            .unwrap());
    }

    Ok(*route.unwrap())
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
                async move { handle_request(request, pool).await }
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

async fn handle_request(
    request: Request<Body>,
    pool: Pool<PostgresConnectionManager<NoTls>>,
) -> Result<Response<Body>, Infallible> {
    println!("handle_request");
    // do anything that doesn't need DB here before pool.run
    // (routing, token cookie presence/format)
    let route = route_request(&request);
    if route.is_err() {
        return Ok(route.err().unwrap());
    }
    let route = route.unwrap();

    let mut token_secret_option = None;
    if route.auth_required {
        match get_token_secret(request) {
            Ok(secret) => token_secret_option = Some(secret),
            Err(response) => return Ok(response),
        }
    }

    let result = pool.run(move |db| {
        let mut message = route.message.to_string();
        async move {
            if let Some(token_secret) = token_secret_option {
                match get_user_id(token_secret, &db).await {
                    Ok(id) => message = format!("as user_id {}, {}", id, message),
                    Err(response) => return Ok::<_, (TokioPostgresError, Client)>((response, db)),
                }
            }
            println!("send response\n");
            Ok::<_, (TokioPostgresError, Client)>((Response::new(Body::from(message)), db))
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

async fn get_user_id(token_secret: String, db: &Client) -> Result<i32, Response<Body>> {
    println!("get_user_id");
    let rows = db.query(
        "SELECT identity_id FROM token_active WHERE secret = $1",
        &[&token_secret],
    ).await.unwrap();

    if rows.len() != 1 {
        return Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("invalid or expired token\n"))
            .unwrap());
    }

    let user_id: i32 = rows.get(0).unwrap().get("identity_id");

    Ok(user_id)
}

fn get_token_secret(request: Request<Body>) -> Result<String, Response<Body>> {
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
