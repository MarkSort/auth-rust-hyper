use hyper::{Body, Response, StatusCode};
use serde_json::{json};

pub fn get_email_pass(spec: &serde_json::Value) -> Result<(String, &[u8]), Response<Body>> {
    let email_option = spec["email"].as_str();
    if email_option.is_none() {
        return Err(json_err(StatusCode::BAD_REQUEST, "'email' is required and must be a string"))
    }
    let email = email_option.unwrap();

    if email.len() > 150 {
        return Err(json_err(StatusCode::BAD_REQUEST, "'email' must be 150 characters or less"))
    }

    let password_option = spec["password"].as_str();
    if password_option.is_none() {
        return Err(json_err(StatusCode::BAD_REQUEST, "'password' is required and must be a string"))
    }
    let password = password_option.unwrap();

    Ok((email.to_string(), password.as_bytes()))
}

pub fn json_ok(json: serde_json::Value) -> Response<Body> {
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()+"\n"))
        .unwrap()
}

pub fn json_err(status_code: StatusCode, error: &str) -> Response<Body> {
    Response::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(Body::from(json!({"error": error}).to_string()+"\n"))
        .unwrap()
}
