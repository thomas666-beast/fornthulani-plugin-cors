//! CORS middleware for fornthulani.
//!
//! ```no_run
//! use fornthulani::{Router, Server};
//! use fornthulani_plugin_cors::Cors;
//!
//! let router = Router::new();
//! let server = Server::new(router).with_middleware(Cors::permissive());
//! ```

use fornthulani::{Middleware, Request, Response, Status, ThulaniError};
use std::sync::Arc;

#[derive(Clone, Debug)]
enum Origins {
    Any,
    List(Arc<Vec<String>>),
}

#[derive(Clone, Debug)]
pub struct Cors {
    origins: Origins,
    allow_methods: String,
    allow_headers: String,
    max_age: String,
    allow_credentials: bool,
}

impl Cors {
    /// Allow any origin (`Access-Control-Allow-Origin: *`).
    pub fn permissive() -> Self {
        Self {
            origins: Origins::Any,
            allow_methods: "GET, POST, PUT, DELETE, OPTIONS".into(),
            allow_headers: "Content-Type, Authorization".into(),
            max_age: "86400".into(),
            allow_credentials: false,
        }
    }

    /// Allow only the given origins. Requests from other origins get `403`.
    pub fn restricted<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            origins: Origins::List(Arc::new(origins.into_iter().map(Into::into).collect())),
            allow_methods: "GET, POST, PUT, DELETE, OPTIONS".into(),
            allow_headers: "Content-Type, Authorization".into(),
            max_age: "86400".into(),
            allow_credentials: false,
        }
    }

    /// Allow cookies / `Authorization` headers cross-origin.
    /// When true, `Access-Control-Allow-Origin` echoes the request's
    /// actual `Origin` (never `*`).
    pub fn allow_credentials(mut self, yes: bool) -> Self {
        self.allow_credentials = yes;
        self
    }

    fn is_allowed(&self, origin: &str) -> bool {
        match &self.origins {
            Origins::Any => true,
            Origins::List(list) => list.iter().any(|o| o == origin),
        }
    }

    fn allow_origin_header(&self, origin: &str) -> String {
        match (&self.origins, self.allow_credentials) {
            (Origins::Any, false) => "*".to_string(),
            _ => origin.to_string(),
        }
    }

    fn base_headers(&self, origin: &str) -> Vec<(String, String)> {
        let mut headers = vec![
            (
                "Access-Control-Allow-Origin".into(),
                self.allow_origin_header(origin),
            ),
            (
                "Access-Control-Allow-Methods".into(),
                self.allow_methods.clone(),
            ),
            (
                "Access-Control-Allow-Headers".into(),
                self.allow_headers.clone(),
            ),
        ];
        if self.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }
        headers
    }
}

impl Middleware for Cors {
    fn before(&self, req: &mut Request) -> Result<Option<Response>, ThulaniError> {
        // Non-CORS requests (no Origin header) pass through unchanged.
        let origin = match req.header("origin") {
            Some(o) => o.to_string(),
            None => return Ok(None),
        };

        if !self.is_allowed(&origin) {
            return Err(ThulaniError::Forbidden(format!(
                "origin `{origin}` not allowed"
            )));
        }

        // OPTIONS preflight -> 204 No Content with CORS headers.
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            let mut resp = Response::new(Status::NO_CONTENT, "text/plain", Vec::new());
            for (k, v) in self.base_headers(&origin) {
                resp = resp.header(&k, &v);
            }
            resp = resp.header("Access-Control-Max-Age", &self.max_age);
            return Ok(Some(resp));
        }

        // Simple request from an allowed origin -> continue dispatch.
        Ok(None)
    }

    fn after(&self, req: &Request, resp: &mut Response) {
        // Only add headers to requests that actually carry an Origin.
        let origin = match req.header("origin") {
            Some(o) => o,
            None => return,
        };

        // Origin was rejected in `before` — don't add CORS headers to
        // that error response.
        if !self.is_allowed(origin) {
            return;
        }

        for (k, v) in self.base_headers(origin) {
            resp.extra_headers.push((k, v));
        }

        // Expose common response headers to browser JS.
        resp.extra_headers.push((
            "Access-Control-Expose-Headers".into(),
            "Content-Type, Content-Length, Content-Disposition".into(),
        ));
    }
}
