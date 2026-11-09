use fornthulani::{Params, Request, Response, Router, Server, Status, ThulaniError};
use fornthulani_plugin_cors::Cors;
use std::net::TcpListener;
use std::thread;

fn hello(_: &Request, _: &Params) -> Result<Response, ThulaniError> {
    Ok(Response::text(Status::OK, "hello"))
}

fn spawn_with(mw: Cors) -> (String, fornthulani::ServerHandle, thread::JoinHandle<()>) {
    let mut router = Router::new();
    router.get("/hello", hello);

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let (handle, join) = Server::new(router)
        .with_middleware(mw)
        .spawn(&addr.to_string())
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));
    (format!("http://{addr}"), handle, join)
}

#[test]
fn permissive_allows_any_origin() {
    let (base, handle, join) = spawn_with(Cors::permissive());

    let res = reqwest::blocking::Client::new()
        .get(format!("{base}/hello"))
        .header("origin", "https://anywhere.example")
        .send()
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["access-control-allow-origin"], "*");
    assert_eq!(res.text().unwrap(), "hello");

    handle.shutdown();
    join.join().unwrap();
}

#[test]
fn preflight_returns_204_with_headers() {
    let (base, handle, join) = spawn_with(Cors::restricted(["https://app.example"]));

    let res = reqwest::blocking::Client::new()
        .request(reqwest::Method::OPTIONS, format!("{base}/hello"))
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .send()
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(
        res.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert!(
        res.headers()["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .contains("POST")
    );
    assert!(
        res.headers()["access-control-allow-headers"]
            .to_str()
            .unwrap()
            .contains("Content-Type")
    );

    handle.shutdown();
    join.join().unwrap();
}

#[test]
fn restricted_rejects_unknown_origin() {
    let (base, handle, join) = spawn_with(Cors::restricted(["https://app.example"]));

    let res = reqwest::blocking::Client::new()
        .get(format!("{base}/hello"))
        .header("origin", "https://attacker.example")
        .send()
        .unwrap();
    assert_eq!(res.status(), 403);

    handle.shutdown();
    join.join().unwrap();
}
