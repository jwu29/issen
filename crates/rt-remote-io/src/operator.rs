use anyhow::{anyhow, Result};
use opendal::{Operator, services};

/// Build an OpenDAL [`Operator`] for the given URI, and return the relative path
/// within that backend.
///
/// Supported URI schemes:
/// - `mem://` — in-process memory backend; path = everything after `mem://`
/// - `s3://` — AWS S3; authority = bucket, path = key
/// - `gcs://` — Google Cloud Storage; authority = bucket, path = object
/// - `azblob://` — Azure Blob Storage; authority = container, path = blob
/// - `webdav://` — WebDAV; authority+path = endpoint+remote path
/// - `http://` / `https://` — HTTP(S); full URI used as endpoint + path
/// - `file://` — Local filesystem; path portion used
/// - `sftp://` — SFTP; `[user@]host[:port]/path`
/// - `hdfs://` — HDFS (native); `namenode:port/path`
/// - `webhdfs://` — `WebHDFS` (HTTP REST); `namenode:port/path`
///
/// Returns an error for unknown or unsupported schemes.
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    let Some(scheme_end) = uri.find("://") else {
        return Err(anyhow!("URI has no scheme: {uri}"));
    };
    let scheme = &uri[..scheme_end];
    let rest = &uri[scheme_end + 3..]; // everything after "://"

    match scheme {
        "mem" => {
            // mem://bucket/key → operator root="/", path = "bucket/key"
            let builder = services::Memory::default();
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "s3" => {
            // s3://bucket/key
            let (bucket, path) = split_authority_path(rest);
            let builder = services::S3::default().bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "gcs" => {
            // gcs://bucket/object
            let (bucket, path) = split_authority_path(rest);
            let builder = services::Gcs::default().bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "azblob" => {
            // azblob://container/blob
            let (container, path) = split_authority_path(rest);
            let builder = services::Azblob::default().container(container);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "webdav" => {
            // webdav://host/path
            let endpoint = format!("http://{rest}");
            let builder = services::Webdav::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, "/".to_string()))
        }

        "http" | "https" => {
            // http://host/path → endpoint = scheme://host, path = /path
            let url = uri;
            let (endpoint, path) = if let Some(slash) = rest.find('/') {
                let host = &rest[..slash];
                let path = &rest[slash..];
                (format!("{scheme}://{host}"), path.to_string())
            } else {
                (format!("{scheme}://{rest}"), "/".to_string())
            };
            let builder = services::Http::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            let _ = url; // suppress unused warning
            Ok((op, path))
        }

        "file" => {
            // file:///path → local FS rooted at /
            let builder = services::Fs::default().root("/");
            let op = Operator::new(builder)?.finish();
            // rest after "file://" is "//path" for file:///path, or "/path" for file://host/path
            let path = if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{rest}")
            };
            Ok((op, path))
        }

        "sftp" => {
            // sftp://user@host:port/path  or  sftp://host/path
            let (userinfo, hostpath) = if rest.contains('@') {
                rest.split_once('@').unwrap_or(("", rest))
            } else {
                ("", rest)
            };
            let (hostport, path) = hostpath.split_once('/').unwrap_or((hostpath, ""));
            let endpoint = if userinfo.is_empty() {
                hostport.to_string()
            } else {
                format!("{userinfo}@{hostport}")
            };
            let builder = services::Sftp::default().endpoint(&endpoint).root("/");
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "hdfs" => {
            // hdfs://namenode:port/path
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let name_node = format!("hdfs://{hostport}");
            let builder = services::HdfsNative::default().name_node(&name_node).root("/");
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "webhdfs" => {
            // webhdfs://namenode:port/path
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = format!("http://{hostport}");
            let builder = services::Webhdfs::default().endpoint(&endpoint).root("/");
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        other => Err(anyhow!("Unsupported URI scheme: {other}")),
    }
}

/// Split `"authority/path"` into `("authority", "path")`.
/// If there is no slash, returns `(rest, "")`.
fn split_authority_path(rest: &str) -> (&str, &str) {
    if let Some(slash) = rest.find('/') {
        (&rest[..slash], &rest[slash + 1..])
    } else {
        (rest, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_uri_returns_ok_with_path() {
        let (_, path) = operator_for_uri("mem://bucket/key").expect("should succeed for mem://");
        assert_eq!(path, "bucket/key");
    }

    #[test]
    fn unknown_scheme_returns_err() {
        let result = operator_for_uri("bad://host/path");
        assert!(result.is_err(), "expected error for unknown scheme");
    }

    #[test]
    fn sftp_uri_returns_ok() {
        let result = operator_for_uri("sftp://user@host:22/data");
        // Must NOT be an unsupported-scheme error — scheme is recognised
        match &result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "expected sftp to be a supported scheme, got: {msg}"
                );
            }
            Ok(_) => {}
        }
    }

    #[test]
    fn sftp_uri_path_extraction() {
        // Path is everything after the host:port — operator_for_uri returns it
        // even if the operator itself cannot connect without a real server.
        let result = operator_for_uri("sftp://host/remote/path");
        match result {
            Ok((_, path)) => assert_eq!(path, "remote/path"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn hdfs_uri_returns_ok() {
        let result = operator_for_uri("hdfs://namenode:9000/user/data");
        match &result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "expected hdfs to be a supported scheme, got: {msg}"
                );
            }
            Ok(_) => {}
        }
    }

    #[test]
    fn hdfs_uri_path_extraction() {
        let result = operator_for_uri("hdfs://namenode:9000/user/data");
        match result {
            Ok((_, path)) => assert_eq!(path, "user/data"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn webhdfs_uri_returns_ok() {
        let result = operator_for_uri("webhdfs://namenode:50070/user/data");
        match &result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "expected webhdfs to be a supported scheme, got: {msg}"
                );
            }
            Ok(_) => {}
        }
    }

    #[test]
    fn webhdfs_uri_path_extraction() {
        let result = operator_for_uri("webhdfs://namenode:50070/user/data");
        match result {
            Ok((_, path)) => assert_eq!(path, "user/data"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    // ── RED tests for 38 missing schemes ────────────────────────────────────

    macro_rules! scheme_recognised {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let result = operator_for_uri($uri);
                match &result {
                    Err(e) => assert!(
                        !e.to_string().contains("Unsupported URI scheme"),
                        "expected {} to be a supported scheme, got: {}",
                        $uri,
                        e
                    ),
                    Ok(_) => {}
                }
            }
        };
    }

    // Cloud object storage
    scheme_recognised!(azdls_uri_returns_ok, "azdls://filesystem/path");
    scheme_recognised!(azfile_uri_returns_ok, "azfile://share/path");
    scheme_recognised!(b2_uri_returns_ok, "b2://bucket/key");
    scheme_recognised!(cos_uri_returns_ok, "cos://bucket/key");
    scheme_recognised!(obs_uri_returns_ok, "obs://bucket/key");
    scheme_recognised!(oss_uri_returns_ok, "oss://bucket/key");
    scheme_recognised!(swift_uri_returns_ok, "swift://container/path");
    scheme_recognised!(upyun_uri_returns_ok, "upyun://bucket/key");

    // Cloud drives
    scheme_recognised!(onedrive_uri_returns_ok, "onedrive://path/to/file");
    scheme_recognised!(dropbox_uri_returns_ok, "dropbox://path/to/file");
    scheme_recognised!(aliyun_drive_uri_returns_ok, "aliyun-drive://path/to/file");
    scheme_recognised!(yandex_disk_uri_returns_ok, "yandex-disk://path/to/file");
    scheme_recognised!(pcloud_uri_returns_ok, "pcloud://path/to/file");
    scheme_recognised!(koofr_uri_returns_ok, "koofr://path/to/file");
    scheme_recognised!(seafile_uri_returns_ok, "seafile://server/repo/path");

    // Dev / ML / infra
    scheme_recognised!(github_uri_returns_ok, "github://owner/repo/path");
    scheme_recognised!(huggingface_uri_returns_ok, "huggingface://owner/model/file");
    scheme_recognised!(vercel_blob_uri_returns_ok, "vercel-blob://key");
    scheme_recognised!(vercel_artifacts_uri_returns_ok, "vercel-artifacts://key");
    scheme_recognised!(ghac_uri_returns_ok, "ghac://key");
    scheme_recognised!(dbfs_uri_returns_ok, "dbfs://path/to/file");

    // Big data
    scheme_recognised!(alluxio_uri_returns_ok, "alluxio://host:19999/path");
    scheme_recognised!(lakefs_uri_returns_ok, "lakefs://repo/main/path");

    // Decentralized
    scheme_recognised!(ipfs_uri_returns_ok, "ipfs://QmHash/path");
    scheme_recognised!(ipmfs_uri_returns_ok, "ipmfs:///path/to/file");

    // Network KV / databases
    scheme_recognised!(redis_uri_returns_ok, "redis://localhost:6379/key");
    scheme_recognised!(rediss_uri_returns_ok, "rediss://localhost:6380/key");
    scheme_recognised!(memcached_uri_returns_ok, "memcached://localhost:11211/key");
    scheme_recognised!(etcd_uri_returns_ok, "etcd://localhost:2379/key");
    scheme_recognised!(tikv_uri_returns_ok, "tikv://localhost:2379/key");
    scheme_recognised!(mongodb_uri_returns_ok, "mongodb://localhost/db/col/key");
    scheme_recognised!(gridfs_uri_returns_ok, "gridfs://localhost/db/bucket/key");
    scheme_recognised!(mysql_uri_returns_ok, "mysql://user:pass@localhost/db/key");
    scheme_recognised!(postgresql_uri_returns_ok, "postgresql://user:pass@localhost/db/key");
    scheme_recognised!(sqlite_uri_returns_ok, "sqlite:///tmp/test.db/key");
    scheme_recognised!(cloudflare_kv_uri_returns_ok, "cloudflare-kv://namespace/key");
    scheme_recognised!(d1_uri_returns_ok, "d1://database-id/key");

    // Filesystem
    scheme_recognised!(ftp_uri_returns_ok, "ftp://user:pass@host/path");
    scheme_recognised!(ftps_uri_returns_ok, "ftps://user:pass@host/path");
    scheme_recognised!(compfs_uri_returns_ok, "compfs:///abs/path/file");
}
