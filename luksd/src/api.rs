use aide::{axum::ApiRouter, openapi::OpenApi, transform::TransformOpenApi};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Json, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use base64::{engine::general_purpose, Engine};
use core::future::Future;
use hyper::{Body, Request};
use log::*;
use passwords::PasswordGenerator;
use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap};
use std::ffi::OsStr;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use tempdir::TempDir;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::oneshot::{channel, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use triggered::{trigger, Trigger};

use std::sync::Arc;

pub fn router(luksd: Arc<Luksd>) -> Router {
    let mut api = OpenApi::default();

    // TODO: OpenAPI generation
    ApiRouter::new()
        .route("/admin/servers", get(admin_list))
        .route("/admin/approve", post(admin_approve))
        .route("/admin/reject", post(admin_reject))
        .route("/machine/key", get(get_key))
        .route("/machine/register", post(register))
        .finish_api_with(&mut api, api_docs)
        .route("/api.json", get(serve_api))
        .layer(Extension(api))
        .with_state(luksd)
        .layer(DefaultBodyLimit::max(1024 * 1024 * 64))
}

fn api_docs(api: TransformOpenApi) -> TransformOpenApi {
    api.title("LUKSd API").summary("LUKS encryption server")
}

async fn serve_api(Extension(api): Extension<OpenApi>) -> Json<OpenApi> {
    Json(api)
}

async fn admin_list(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> axum::response::Result<Json<Vec<LuksRequestInfo>>> {
    debug!("List");
    let list = luksd
        .map
        .lock()
        .await
        .iter()
        .map(|(&ip, e)| LuksRequestInfo {
            ip,
            mode: e.mode.to_string(),
        })
        .collect();
    debug!("List: {list:?}");
    Ok(Json(list))
}

async fn admin_approve(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ip: String,
) -> axum::response::Result<()> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;

    let guard = luksd.map.lock().await;

    let entry = guard.get(&ip).ok_or(StatusCode::NOT_FOUND)?;

    if entry.join.is_finished() {
        Err(StatusCode::UNPROCESSABLE_ENTITY)?;
    }

    entry.approval.trigger();

    Ok(())
}

async fn admin_reject(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ip: String,
) -> axum::response::Result<()> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;

    let mut guard = luksd.map.lock().await;

    let entry = guard.remove(&ip).ok_or(StatusCode::NOT_FOUND)?;

    entry.join.abort();
    let _ = entry.join.await;

    Ok(())
}

async fn get_key(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> axum::response::Result<Json<Data>> {
    let mut guard = luksd.map.lock().await;

    let ip = addr.ip();

    // TODO: verify IP address

    debug!("Get key {ip:?}");

    let (tx, rx) = channel();

    let luksd = luksd.clone();

    let create_entry = move || {
        let (trigger, listener) = trigger();
        LuksRequest {
            join: tokio::spawn(adapter(tx, async move {
                debug!("Awaiting for approval");
                listener.await;

                let key = fs::read(luksd.keys_dir.join(ip.to_string())).await?;
                let header = fs::read(luksd.headers_dir.join(ip.to_string())).await?;

                Ok(Data {
                    header: general_purpose::STANDARD.encode(&header),
                    key: general_purpose::STANDARD.encode(&key),
                })
            })),
            approval: trigger,
            mode: "Get key",
        }
    };

    match guard.entry(ip) {
        Entry::Vacant(e) => {
            e.insert(create_entry());
        }
        Entry::Occupied(mut e) if e.get().join.is_finished() => {
            *e.get_mut() = create_entry();
        }
        _ => Err(StatusCode::CONFLICT)?,
    }

    core::mem::drop(guard);

    let ret = rx
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ret))
}

async fn adapter<T>(tx: Sender<anyhow::Result<T>>, fut: impl Future<Output = anyhow::Result<T>>) {
    let _ = tx.send(fut.await);
}

async fn cmd_stdin(cmd: impl AsRef<OsStr>, args: &[&OsStr], input: &[u8]) -> anyhow::Result<()> {
    debug!("cmd: {:?}", cmd.as_ref());

    let mut child = Command::new(cmd).args(args).stdin(Stdio::piped()).spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stdin"))?;

    stdin.write_all(input).await?;
    core::mem::drop(stdin);

    let out = child.wait_with_output().await?;

    if out.status.code().unwrap_or_default() != 0 {
        return Err(anyhow::anyhow!(
            "command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    Ok(())
}

async fn register(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> axum::response::Result<()> {
    let mut guard = luksd.map.lock().await;

    let ip = addr.ip();

    // TODO: verify IP address

    debug!("Register {ip:?}");

    let Json(data): Json<Data> = FromRequest::from_request(req, &()).await?;

    let header = general_purpose::STANDARD
        .decode(data.header)
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;

    let tmp_key = general_purpose::STANDARD
        .decode(data.key)
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;

    let tmp_key = std::str::from_utf8(&tmp_key).map_err(|_| StatusCode::NOT_ACCEPTABLE)?;
    // Only take one line of the input
    let tmp_key = tmp_key.lines().next().unwrap_or("").to_string();

    let (tx, rx) = channel();

    let luksd = luksd.clone();

    let create_entry = move || {
        let (trigger, listener) = trigger();
        LuksRequest {
            join: tokio::spawn(adapter(tx, async move {
                debug!("Awaiting for approval");
                listener.await;

                let dir = TempDir::new("luksd")?;
                let path = dir.path().join("hdr.img");

                fs::write(&path, &header).await?;

                let master_key = fs::read_to_string(&luksd.master_key).await?;
                let random_key = gen_pwd();

                fs::write(luksd.keys_dir.join(ip.to_string()), random_key.as_bytes()).await?;

                for key in [master_key, random_key] {
                    let mut input = tmp_key.to_string();
                    input.push_str("\n");
                    input.push_str(&key);

                    cmd_stdin(
                        "/usr/sbin/cryptsetup",
                        &["luksAddKey".as_ref(), path.as_ref(), "-q".as_ref()],
                        input.as_bytes(),
                    )
                    .await?;
                }

                cmd_stdin(
                    "/usr/sbin/cryptsetup",
                    &["luksRemoveKey".as_ref(), path.as_ref(), "-q".as_ref()],
                    tmp_key.as_bytes(),
                )
                .await?;

                fs::copy(path, luksd.headers_dir.join(ip.to_string())).await?;
                debug!("Success! {ip}");

                Ok(())
            })),
            approval: trigger,
            mode: "Register",
        }
    };

    match guard.entry(ip) {
        Entry::Vacant(e) => {
            e.insert(create_entry());
        }
        Entry::Occupied(mut e) if e.get().join.is_finished() => {
            *e.get_mut() = create_entry();
        }
        _ => Err(StatusCode::CONFLICT)?,
    }

    core::mem::drop(guard);

    rx.await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Data {
    header: String,
    key: String,
}

struct LuksRequest {
    join: JoinHandle<()>,
    approval: Trigger,
    mode: &'static str,
}

#[derive(Serialize, Deserialize, Debug)]
struct LuksRequestInfo {
    ip: IpAddr,
    mode: String,
}

pub struct Luksd {
    map: Mutex<BTreeMap<IpAddr, LuksRequest>>,
    keys_dir: PathBuf,
    headers_dir: PathBuf,
    master_key: PathBuf,
}

impl Luksd {
    pub fn new(config: super::Config) -> Self {
        Self {
            map: Default::default(),
            keys_dir: config.keys,
            headers_dir: config.headers,
            master_key: config.master_key,
        }
    }
}

fn gen_pwd() -> String {
    let pg = PasswordGenerator {
        length: 64,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: true,
        exclude_similar_characters: false,
        strict: true,
    };

    pg.generate_one().unwrap()
}
