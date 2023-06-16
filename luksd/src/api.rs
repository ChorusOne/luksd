use aide::{axum::ApiRouter, openapi::OpenApi, transform::TransformOpenApi};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Json, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine};
use core::future::Future;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use hyper::{Body, Request};
use log::*;
use passwords::PasswordGenerator;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap};
use std::ffi::OsStr;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tempdir::TempDir;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use triggered::{trigger, Trigger};
use yaml_rust::{Yaml, YamlEmitter, YamlLoader};

use std::sync::Arc;

const PCR_MAP: &[(&str, &str)] = &[
    ("firmware", "bios was updated?"),
    ("firmware data", "bios settings changed?"),
    ("ext code", ""),
    ("ext data", ""),
    ("boot mgr code", "boot device order changed?"),
    (
        "boot mgr cfg",
        "bootloader config changed / GPT table changed",
    ),
    ("resume", "resume from S4/S5 changed"),
    ("secure boot", "secure boot state changed"),
    ("cmdline", "cmdline changed"),
    ("initrd/efi", "initrd/EFI load options"),
];

pub fn router(luksd: Arc<Luksd>) -> Router {
    let mut api = OpenApi::default();

    // TODO: OpenAPI generation
    ApiRouter::new()
        .route("/admin/servers", get(admin_list))
        .route("/admin/approve", post(admin_approve))
        .route("/admin/reject", post(admin_reject))
        .route("/machine/nonce", get(get_nonce))
        .route("/machine/key", post(get_key))
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

fn verify_admin_ip(addr: SocketAddr) -> axum::response::Result<()> {
    let ip = addr.ip();
    let ret = match ip {
        IpAddr::V4(v4) => {
            // See https://doc.rust-lang.org/src/core/net/ip_addr.rs.html#726
            // the function is nightly only
            let is_shared = v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000 == 0b0100_0000);
            v4.is_loopback() || is_shared
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    };

    if ret {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)?
    }
}

async fn admin_list(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> axum::response::Result<Json<Vec<LuksRequestInfo>>> {
    verify_admin_ip(addr)?;

    debug!("List");

    let mut list = vec![];
    let mut map = luksd.map.lock().await;

    map.retain(|_, v| !v.join.is_finished());

    for (&ip, e) in &*map {
        list.push(LuksRequestInfo {
            ip,
            mode: e.mode.to_string(),
            extra_info: e.extra_info.lock().await.clone(),
            extra_info_detailed: e.extra_info_detailed.lock().await.clone(),
        })
    }

    Ok(Json(list))
}

async fn admin_approve(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ip: String,
) -> axum::response::Result<()> {
    verify_admin_ip(addr)?;

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
    verify_admin_ip(addr)?;

    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;
    let mut guard = luksd.map.lock().await;

    let entry = guard.remove(&ip).ok_or(StatusCode::NOT_FOUND)?;

    entry.join.abort();
    let _ = entry.join.await;

    Ok(())
}

async fn get_nonce(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> axum::response::Result<String> {
    let ip = addr.ip();
    Ok(luksd.get_nonce(ip).await.to_string())
}

async fn get_key(
    luksd: State<Arc<Luksd>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(data): Json<KeyRequest>,
) -> axum::response::Result<Json<KeyResponseData>> {
    let mut guard = luksd.map.lock().await;

    let ip = addr.ip();

    // TODO: verify IP address

    if !luksd.verify_nonce(&data.nonce, ip).await {
        Err(StatusCode::UNAUTHORIZED)?;
    }

    debug!("Get key {ip:?}");

    let (tx, rx) = channel();
    let (tx2, rx2) = channel();

    let luksd = luksd.clone();

    let create_entry = move || {
        let (trigger, listener) = trigger();

        let extra_info = Arc::new(Mutex::new(String::new()));
        let extra_info_detailed = Arc::new(Mutex::new(String::new()));

        LuksRequest {
            extra_info: extra_info.clone(),
            extra_info_detailed: extra_info_detailed.clone(),
            join: tokio::spawn(adapter(tx, rx2, async move {
                match data.mode {
                    KeyRequestMode::Tpm {
                        quote1,
                        quote256,
                        quote384,
                        eventlog,
                    } => {
                        let v1 = quote1
                            .verify(&luksd.pcr_dir, &luksd.pubkeys_dir, ip, "sha1", &data.nonce)
                            .await?;
                        let v256 = quote256
                            .verify(
                                &luksd.pcr_dir,
                                &luksd.pubkeys_dir,
                                ip,
                                "sha256",
                                &data.nonce,
                            )
                            .await?;
                        let v384 = quote384
                            .verify(
                                &luksd.pcr_dir,
                                &luksd.pubkeys_dir,
                                ip,
                                "sha384",
                                &data.nonce,
                            )
                            .await?;

                        // Wait for approval
                        if !v1.is_empty() || !v256.is_empty() || !v384.is_empty() {
                            debug!("TPM measurement mismatch! Awaiting for approval");
                            trace!("{ip}: sha1 - {v1:?}; sha256 - {v256:?}; sha384 - {v384:?}");

                            let mut extra_info = extra_info.lock().await;
                            let mut extra_info_detailed = extra_info_detailed.lock().await;

                            let eventlog_dir = luksd.eventlog_dir.join(ip.to_string());
                            let sub_eventlog = EventLog::parse_b64(&eventlog).await;
                            let exp_eventlog = EventLog::from_path(&eventlog_dir).await;

                            *extra_info += "TPM PCR mismatch:\n";

                            for (algo, idx, expected, submitted) in
                                core::iter::IntoIterator::into_iter([
                                    ("sha1", v1),
                                    ("sha256", v256),
                                    ("sha384", v384),
                                ])
                                .flat_map(|(algo, vals)| {
                                    vals.into_iter().map(move |(idx, expected, submitted)| {
                                        (algo, idx, expected, submitted)
                                    })
                                })
                            {
                                if let Ok(eventlog) = &sub_eventlog {
                                    if let Some(entry) = eventlog.log.get(&(idx as _)) {
                                        if let Some(hash) = entry.1.get(algo) {
                                            if Some(hash.to_lowercase())
                                                != submitted.as_ref().map(|v| v.to_lowercase())
                                            {
                                                *extra_info_detailed += &format!("# WARNING!!! PCR {idx} IN EVENT LOG ({hash}) DOES NOT MATCH SIGNED PCR VALUE ({submitted:?})!! DO NOT TRUST THE FOLLOWING OUTPUT!!!\n");
                                            }
                                            if let Some(log) = exp_eventlog
                                                .as_ref()
                                                .ok()
                                                .and_then(|l| l.log.get(&(idx as _)))
                                            {
                                                *extra_info_detailed +=
                                                    &format!("{idx} ({algo}):\n");
                                                // Compute diff
                                                for d in diff::slice(&entry.0, &log.0) {
                                                    match d {
                                                        diff::Result::Left(t) => {
                                                            let num = t.0;
                                                            let Event { data, ty, digests } = &t.1;
                                                            let digest = digests.get(algo);
                                                            *extra_info_detailed += &format!("  - submitted {num}: Event {{\n        ty: {ty},\n        digest: {digest:?}\n        data: {data}\n    }}\n");
                                                        }
                                                        diff::Result::Right(t) => {
                                                            let num = t.0;
                                                            let Event { data, ty, digests } = &t.1;
                                                            let digest = digests.get(algo);
                                                            *extra_info_detailed += &format!("  - stored {num}: Event {{\n        ty: {ty},\n        digest: {digest:?}\n        data: {data}\n    }}\n");
                                                        }
                                                        diff::Result::Both(t1, t2) => {
                                                            let num1 = t1.0;
                                                            let num2 = t2.0;
                                                            let Event { digests, .. } = &t1.1;
                                                            let digest = digests.get(algo);
                                                            *extra_info_detailed += &format!("  - Event {num1} Match Expected ({num2}; {digest:?})\n");
                                                        }
                                                    }
                                                }
                                            } else {
                                                *extra_info_detailed += &format!("{idx}:\n");
                                                for (i, EventEntry(num, event)) in
                                                    entry.0.iter().enumerate()
                                                {
                                                    let Event { data, ty, digests } = event;
                                                    let digest = digests.get(algo);
                                                    *extra_info_detailed += &format!("  - {i}:\n    submitted {num}: Event {{\n        ty: {ty},\n        digest: {digest:?}\n        data: {data}\n    }}\n");
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some((short, long)) = PCR_MAP.get(idx as usize) {
                                    *extra_info += &format!(
                                        "{algo}[{idx} ({short})] - expected {expected}, got {submitted:?}. {long}\n"
                                    );
                                } else {
                                    *extra_info += &format!(
                                        "{algo}[{idx}] - expected {expected}, got {submitted:?}\n"
                                    );
                                }
                            }

                            core::mem::drop(extra_info);
                            core::mem::drop(extra_info_detailed);

                            listener.await;

                            // Write all PCRs to permanent storage
                            debug!("Writing updated PCR values");

                            quote1.write_pcrs(&luksd.pcr_dir, ip, "sha1").await?;
                            quote256.write_pcrs(&luksd.pcr_dir, ip, "sha256").await?;
                            quote384.write_pcrs(&luksd.pcr_dir, ip, "sha384").await?;

                            if sub_eventlog.is_ok() {
                                debug!("Writing updated event log");
                                EventLog::write(&eventlog_dir, eventlog).await?;
                            }
                        } else {
                            debug!("PCR values match, unlocking...");
                        }
                    }
                    KeyRequestMode::Disk { nonce_signature } => {
                        debug!("Awaiting for approval");

                        /*let pubkey = fs::read(luksd.pubkeys_dir.join(ip.to_string())).await?;
                        let pubkey = PublicKey::from_bytes(&pubkey)?;

                        let signature = STANDARD.decode(nonce_signature)?;
                        let signature = Signature::from_bytes(&signature)?;

                        pubkey.verify(data.nonce.as_bytes(), &signature)?;*/

                        {
                            let mut extra_info = extra_info.lock().await;
                            *extra_info += "No TPM\n";
                            *extra_info += "Nonce signature verified\n";
                        }

                        listener.await;
                    }
                }

                let key = fs::read(luksd.keys_dir.join(ip.to_string())).await?;
                let header = fs::read(luksd.headers_dir.join(ip.to_string())).await?;

                Ok(KeyResponseData {
                    header: STANDARD.encode(&header),
                    key: STANDARD.encode(&key),
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
        .map_err(|e| {
            error!("{e}");
            StatusCode::UNAUTHORIZED
        })?
        .map_err(|e| {
            error!("{e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    core::mem::drop(tx2);

    Ok(Json(ret))
}

async fn adapter<T>(
    tx: Sender<anyhow::Result<T>>,
    rx: Receiver<()>,
    fut: impl Future<Output = anyhow::Result<T>>,
) {
    tokio::select! {
        _ = rx => (),
        v = fut => {
            let _ = tx.send(v);
        }
    }
}

async fn cmd_stdin_raw(
    cmd: impl AsRef<OsStr>,
    args: &[&OsStr],
    input: &[u8],
) -> anyhow::Result<(String, String, i32)> {
    debug!("cmd: {:?}", cmd.as_ref());

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stdin"))?;

    stdin.write_all(input).await?;
    core::mem::drop(stdin);

    let out = child.wait_with_output().await?;

    Ok((
        String::from_utf8(out.stdout)?,
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or_default(),
    ))
}

async fn cmd_stdin(
    cmd: impl AsRef<OsStr>,
    args: &[&OsStr],
    input: &[u8],
) -> anyhow::Result<String> {
    let (output, stderr, code) = cmd_stdin_raw(cmd, args, input).await?;

    if code != 0 {
        return Err(anyhow::anyhow!("command failed: {}", stderr));
    }

    Ok(output)
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

    let Json(data): Json<RegistrationData> = FromRequest::from_request(req, &()).await?;

    let header = STANDARD
        .decode(data.header)
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;

    let tmp_key = STANDARD
        .decode(data.key)
        .map_err(|_| StatusCode::NOT_ACCEPTABLE)?;

    let tmp_key = std::str::from_utf8(&tmp_key).map_err(|_| StatusCode::NOT_ACCEPTABLE)?;
    // Only take one line of the input
    let tmp_key = tmp_key.lines().next().unwrap_or("").to_string();

    let (tx, rx) = channel();
    let (tx2, rx2) = channel();

    let luksd = luksd.clone();

    let create_entry = move || {
        let (trigger, listener) = trigger();
        let extra_info = Arc::new(Mutex::new(String::new()));
        let extra_info_detailed = Arc::new(Mutex::new(String::new()));
        LuksRequest {
            extra_info: extra_info.clone(),
            extra_info_detailed,
            join: tokio::spawn(adapter(tx, rx2, async move {
                match data.mode {
                    RegistrationMode::Tpm {
                        eventlog,
                        pubkey,
                        quote1,
                        quote256,
                        quote384,
                    } => {
                        let sub_eventlog = EventLog::parse_b64(&eventlog).await;

                        {
                            let mut extra_info = extra_info.lock().await;
                            *extra_info += "Has TPM\n";
                            *extra_info += &format!("pubkey - {pubkey}\n");
                            *extra_info +=
                                &format!("event log parsed - {}\n", sub_eventlog.is_ok());
                        }

                        debug!("Awaiting for approval");
                        listener.await;

                        let pubkey = STANDARD.decode(&pubkey)?;
                        let pubkey_path = luksd.pubkeys_dir.join(ip.to_string());
                        fs::write(pubkey_path, pubkey).await?;

                        quote1.write_pcrs(&luksd.pcr_dir, ip, "sha1").await?;
                        quote256.write_pcrs(&luksd.pcr_dir, ip, "sha256").await?;
                        quote384.write_pcrs(&luksd.pcr_dir, ip, "sha384").await?;

                        if sub_eventlog.is_ok() {
                            EventLog::write(&luksd.eventlog_dir.join(ip.to_string()), eventlog)
                                .await?;
                        }
                    }
                    RegistrationMode::Disk { pubkey } => {
                        {
                            let mut extra_info = extra_info.lock().await;
                            *extra_info += "No TPM\n";
                            *extra_info += &format!("pubkey - {pubkey}\n");
                        }

                        /*let pubkey = STANDARD.decode(pubkey)?;

                        if pubkey.len() < 32 {
                            return Err(anyhow::anyhow!("Invalid pubkey length"));
                        }*/

                        debug!("Awaiting for approval");
                        listener.await;

                        /*let pubkey_path = luksd.pubkeys_dir.join(ip.to_string());

                        fs::write(pubkey_path, &pubkey[pubkey.len()-32..]).await?;*/
                    }
                }

                let dir = TempDir::new("luksd")?;
                let path = dir.path().join("hdr.img");

                fs::write(&path, &header).await?;

                let random_key = gen_pwd();

                fs::write(luksd.keys_dir.join(ip.to_string()), random_key.as_bytes()).await?;

                let mut input = tmp_key.to_string();
                input.push_str("\n");
                input.push_str(&random_key);

                cmd_stdin(
                    "/usr/sbin/cryptsetup",
                    &["luksAddKey".as_ref(), path.as_ref(), "-q".as_ref()],
                    input.as_bytes(),
                )
                .await?;

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
        .map_err(|e| {
            error!("{e}");
            StatusCode::UNAUTHORIZED
        })?
        .map_err(|e| {
            error!("{e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    core::mem::drop(tx2);

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Quote {
    msg: String,
    pcr: BTreeMap<String,String>,
    sig: String,
}

impl Quote {
    pub async fn verify(
        &self,
        pcrs_dir: &Path,
        pubkeys_dir: &Path,
        ip: IpAddr,
        algo: &str,
        nonce: &str,
    ) -> anyhow::Result<Vec<(i64, String, Option<String>)>> {
        let dir = TempDir::new("luksd")?;

        // Write data for verification

        let quote_path = dir.path().join("quote.msg");
        let quote = STANDARD.decode(&self.msg)?;
        fs::write(&quote_path, &quote).await?;

        let sig_path = dir.path().join("quote.sig");
        let sig = STANDARD.decode(&self.sig)?;
        fs::write(&sig_path, &sig).await?;

        let pcrs_path = dir.path().join(format!("{ip}_{algo}.pcrs"));
        let pcrs = STANDARD.decode(&self.pcr)?;
        fs::write(&pcrs_path, &pcrs).await?;

        let mut data = [(); 2].map(|_| Default::default());

        for (data, pcrs) in data
            .iter_mut()
            .zip([pcrs_dir.join(format!("{ip}_{algo}.pcrs")), pcrs_path])
        {
            let (stdin, stderr, code) = cmd_stdin_raw(
                "/usr/bin/tpm2",
                &[
                    "checkquote".as_ref(),
                    "-u".as_ref(),
                    pubkeys_dir.join(ip.to_string()).as_ref(),
                    "-q".as_ref(),
                    nonce.as_ref(),
                    "-m".as_ref(),
                    quote_path.as_ref(),
                    "-s".as_ref(),
                    sig_path.as_ref(),
                    "-f".as_ref(),
                    pcrs.as_ref(),
                    "-g".as_ref(),
                    "sha256".as_ref(),
                ],
                &[],
            )
            .await?;

            let stdin = YamlLoader::load_from_str(&stdin).ok();

            let pcrs = stdin
                .as_ref()
                .and_then(|p| p.get(0))
                .and_then(|p| {
                    if let Yaml::Hash(h) = &p["pcrs"][algo] {
                        Some(h)
                    } else {
                        None
                    }
                })
                .map(|p| {
                    p.iter()
                        .filter_map(|(k, v)| {
                            k.as_i64().zip(
                                v.as_i64()
                                    .map(|v| v.to_string())
                                    .or_else(|| v.clone().into_string()),
                            )
                        })
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default();

            *data = (pcrs, stderr, code);
        }

        let [(exp_pcrs, _, _), (mut sub_pcrs, sub_stderr, sub_code)] = data;

        if sub_code != 0 {
            return Err(anyhow::anyhow!("Could not verify quote: {sub_stderr}"));
        }

        let mut mapping = BTreeMap::new();

        for (id, val) in exp_pcrs {
            let sub_val = sub_pcrs.remove(&id);
            mapping.insert(id, (val, sub_val));
        }

        // Verify PCRs

        let mut out = vec![];

        let mut verify_pcr = |i| {
            if let Some((exp, sub)) = mapping.remove(&i) {
                trace!("{i}: {exp} - {sub:?}");
                if Some(&exp) != sub.as_ref() {
                    out.push((i, exp, sub))
                }
            }
        };

        for i in [0, 1, 2, 3, 4, 5, 7, 8, 9, 23] {
            verify_pcr(i);
        }

        Ok(out)
    }

    pub async fn write_pcrs(&self, pcr_dir: &Path, ip: IpAddr, algo: &str) -> anyhow::Result<()> {
        let pcrs_path = pcr_dir.join(format!("{ip}_{algo}.pcrs"));
        let pcrs = STANDARD.decode(&self.pcr)?;
        fs::write(&pcrs_path, &pcrs).await?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
struct Event {
    data: String,
    ty: String,
    digests: BTreeMap<String, String>,
}

impl Event {
    fn parse(yaml: &Yaml) -> anyhow::Result<(usize, Self, usize)> {
        let num = yaml["EventNum"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("invalid event num"))? as usize;
        let pcr_index = yaml["PCRIndex"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("invalid event num"))? as usize;

        Ok((
            num,
            Self {
                data: yaml_to_string(&yaml["Event"]),
                ty: yaml_to_string(&yaml["EventType"]),
                digests: if let Yaml::Array(a) = &yaml["Digests"] {
                    a.iter()
                        .filter_map(|v| {
                            Some((
                                v["AlgorithmId"].clone().into_string()?,
                                v["Digest"].clone().into_string()?,
                            ))
                        })
                        .collect()
                } else {
                    Default::default()
                },
            },
            pcr_index,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct EventEntry(usize, Event);

impl PartialEq for EventEntry {
    fn eq(&self, other: &Self) -> bool {
        &self.1 == &other.1
    }
}

#[derive(Serialize, Deserialize)]
struct EventLog {
    log: BTreeMap<usize, (Vec<EventEntry>, BTreeMap<String, String>)>,
}

impl EventLog {
    pub async fn write(path: &Path, log_b64: String) -> anyhow::Result<()> {
        let data = STANDARD.decode(&log_b64)?;
        fs::write(&path, &data).await?;
        Ok(())
    }

    pub fn parse(log_yaml: String) -> anyhow::Result<Self> {
        let mut log: BTreeMap<usize, (Vec<EventEntry>, BTreeMap<String, String>)> = BTreeMap::new();

        let yaml = YamlLoader::load_from_str(&log_yaml)?;
        let yaml = yaml.get(0).ok_or_else(|| anyhow::anyhow!("Empty yaml"))?;

        let Yaml::Array(v) = &yaml["events"] else {return Err(anyhow::anyhow!("Invalid events format"))};

        for e in v {
            let (idx, entry, pcr) = Event::parse(e)?;
            log.entry(pcr).or_default().0.push(EventEntry(idx, entry));
        }

        for algo in ["sha1", "sha256", "sha384"] {
            let Yaml::Hash(v) = &yaml["pcrs"][algo] else { continue };

            for (pcr, hash) in v.iter().filter_map(|(k, v)| {
                Some((
                    k.as_i64()? as usize,
                    v.as_i64()
                        .map(|v| v.to_string())
                        .or_else(|| v.clone().into_string())?,
                ))
            }) {
                log.entry(pcr).or_default().1.insert(algo.to_string(), hash);
            }
        }

        Ok(Self { log })
    }

    pub async fn parse_b64(log_b64: &str) -> anyhow::Result<Self> {
        let data = STANDARD.decode(log_b64)?;

        let dir = TempDir::new("luksd")?;
        let eventlog_path = dir.path().join("eventlog");

        fs::write(&eventlog_path, &data).await?;

        Self::from_path(&eventlog_path).await
    }

    pub async fn from_path(path: &Path) -> anyhow::Result<Self> {
        let stdout = cmd_stdin("/usr/bin/tpm2", &["eventlog".as_ref(), path.as_ref()], &[]).await?;

        Self::parse(stdout)
    }
}

#[derive(Serialize, Deserialize)]
enum RegistrationMode {
    Tpm {
        eventlog: String,
        pubkey: String,
        quote1: Quote,
        quote256:Quote,
        quote384: Quote,
    },
    Disk {
        pubkey: String,
    },
}

#[derive(Serialize, Deserialize)]
struct RegistrationData {
    header: String,
    key: String,
    mode: RegistrationMode,
}

#[derive(Serialize, Deserialize)]
struct KeyResponseData {
    header: String,
    key: String,
}

#[derive(Serialize, Deserialize)]
enum KeyRequestMode {
    Tpm {
        eventlog: String,
        quote1: Quote,
        quote256: Quote,
        quote384: Quote,
    },
    Disk {
        nonce_signature: String,
    },
}

#[derive(Serialize, Deserialize)]
struct KeyRequest {
    nonce: String,
    mode: KeyRequestMode,
}

struct LuksRequest {
    join: JoinHandle<()>,
    approval: Trigger,
    mode: &'static str,
    extra_info: Arc<Mutex<String>>,
    extra_info_detailed: Arc<Mutex<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct LuksRequestInfo {
    ip: IpAddr,
    mode: String,
    extra_info: String,
    extra_info_detailed: String,
}

pub struct Luksd {
    map: Mutex<BTreeMap<IpAddr, LuksRequest>>,
    keys_dir: PathBuf,
    headers_dir: PathBuf,
    pcr_dir: PathBuf,
    pubkeys_dir: PathBuf,
    eventlog_dir: PathBuf,
    nonces: Mutex<BTreeMap<Instant, u64>>,
}

impl Luksd {
    pub fn new(config: super::Config) -> Self {
        Self {
            map: Default::default(),
            keys_dir: config.keys,
            headers_dir: config.headers,
            pcr_dir: config.pcrs,
            pubkeys_dir: config.pubkeys,
            eventlog_dir: config.eventlogs,
            nonces: Default::default(),
        }
    }

    fn update_nonces(nonces: &mut BTreeMap<Instant, u64>) {
        let now = Instant::now();

        // Clear any old nonces
        *nonces = nonces.split_off(&now);

        let then = now + Duration::from_secs(30);

        // If the last value is over 5 seconds past the current then value, insert it
        if nonces
            .last_key_value()
            .map(|(k, _)| then.saturating_duration_since(*k).as_secs_f64() >= 5.0)
            .unwrap_or(true)
        {
            nonces.insert(then, thread_rng().gen());
        }
    }

    pub async fn get_nonce(&self, ip: IpAddr) -> String {
        let mut nonces = self.nonces.lock().await;

        Self::update_nonces(&mut nonces);

        // update_nonces ensures that there is at least one entry
        let nonce = *nonces.last_key_value().unwrap().1;

        // Hash the nonce with the IP address so that all hosts have unique nonces
        let mut hash = hmac_sha256::Hash::new();
        hash.update(nonce.to_le_bytes());
        hash.update(ip.to_string().as_bytes());
        hash.finalize()
            .into_iter()
            .map(|v| format!("{v:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }

    pub async fn verify_nonce(&self, nonce: &str, ip: IpAddr) -> bool {
        let mut nonces = self.nonces.lock().await;

        Self::update_nonces(&mut nonces);

        nonces
            .values()
            .find(|v| {
                // We must do the same process as in get_nonce
                let mut hash = hmac_sha256::Hash::new();
                hash.update(v.to_le_bytes());
                hash.update(ip.to_string().as_bytes());
                let stored_nonce = hash
                    .finalize()
                    .into_iter()
                    .map(|v| format!("{v:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                debug!("{stored_nonce} | {nonce}");
                stored_nonce == nonce
            })
            .is_some()
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

fn yaml_to_string(yaml: &Yaml) -> String {
    let mut out = String::new();

    let mut emitter = YamlEmitter::new(&mut out);

    let _ = emitter.dump(yaml);

    out
}
