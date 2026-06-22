//! Zeek conn.log adapter.
//!
//! Converts Zeek conn.log lines (TSV or JSON) into `Evidence` objects.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use crate::evidence::{Evidence, EvidenceKind, EvidenceSource};

/// A parsed Zeek conn.log connection record.
#[derive(Debug, Clone)]
pub struct ZeekConn {
    pub ts: f64,
    pub uid: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub proto: String,
    pub orig_bytes: Option<u64>,
    pub resp_bytes: Option<u64>,
}

#[derive(Deserialize)]
struct RawZeekConn {
    ts: f64,
    uid: String,
    #[serde(rename = "id.orig_h")]
    id_orig_h: String,
    #[serde(rename = "id.orig_p")]
    id_orig_p: u16,
    #[serde(rename = "id.resp_h")]
    id_resp_h: String,
    #[serde(rename = "id.resp_p")]
    id_resp_p: u16,
    proto: String,
    orig_bytes: Option<u64>,
    resp_bytes: Option<u64>,
}

impl ZeekConn {
    /// Parse a single Zeek conn.log TSV line.
    ///
    /// Returns `Ok(None)` for header/comment lines (starting with `#`).
    ///
    /// Expected TSV column order:
    /// ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
    pub fn from_tsv_line(line: &str) -> Result<Option<Self>> {
        if line.starts_with('#') {
            return Ok(None);
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 11 {
            return Ok(None);
        }
        let ts: f64 = fields[0].parse().context("parse ts")?;
        let uid = fields[1].to_string();
        let src_ip = fields[2].to_string();
        let src_port: u16 = fields[3].parse().context("parse src_port")?;
        let dest_ip = fields[4].to_string();
        let dest_port: u16 = fields[5].parse().context("parse dest_port")?;
        let proto = fields[6].to_string();
        // fields[7] = service, fields[8] = duration
        let orig_bytes: Option<u64> = fields[9].parse().ok();
        let resp_bytes: Option<u64> = fields[10].parse().ok();

        Ok(Some(Self {
            ts,
            uid,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            proto,
            orig_bytes,
            resp_bytes,
        }))
    }

    /// Parse a Zeek conn.log JSON line.
    pub fn from_json(line: &str) -> Result<Self> {
        let raw: RawZeekConn = serde_json::from_str(line)?;
        Ok(Self {
            ts: raw.ts,
            uid: raw.uid,
            src_ip: raw.id_orig_h,
            src_port: raw.id_orig_p,
            dest_ip: raw.id_resp_h,
            dest_port: raw.id_resp_p,
            proto: raw.proto,
            orig_bytes: raw.orig_bytes,
            resp_bytes: raw.resp_bytes,
        })
    }
}

impl From<ZeekConn> for Evidence {
    fn from(conn: ZeekConn) -> Self {
        let id = format!("zeek-{}", conn.uid);
        let value = format!(
            "{}:{} -> {}:{}",
            conn.src_ip, conn.src_port, conn.dest_ip, conn.dest_port
        );

        let mut attrs: HashMap<String, String> = HashMap::new();
        attrs.insert("uid".to_string(), conn.uid.clone());
        attrs.insert("src_ip".to_string(), conn.src_ip.clone());
        attrs.insert("src_port".to_string(), conn.src_port.to_string());
        attrs.insert("dest_ip".to_string(), conn.dest_ip.clone());
        attrs.insert("dest_port".to_string(), conn.dest_port.to_string());
        attrs.insert("proto".to_string(), conn.proto.clone());
        attrs.insert("ts".to_string(), conn.ts.to_string());
        if let Some(ob) = conn.orig_bytes {
            attrs.insert("orig_bytes".to_string(), ob.to_string());
        }
        if let Some(rb) = conn.resp_bytes {
            attrs.insert("resp_bytes".to_string(), rb.to_string());
        }

        Evidence {
            id,
            source: EvidenceSource::Zeek,
            kind: EvidenceKind::Custom("Network".to_string()),
            value,
            subject: None,
            timestamp_ns: None,
            confidence: 80,
            attrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TSV_LINE: &str =
        "1000000000.0\tCz1234\t192.168.1.100\t54321\t10.0.0.1\t3333\ttcp\t-\t1.234\t1024\t512\tSF";
    const JSON_LINE: &str = r#"{"ts": 1000000000.0, "uid": "Cz1234", "id.orig_h": "192.168.1.100", "id.orig_p": 54321, "id.resp_h": "10.0.0.1", "id.resp_p": 3333, "proto": "tcp", "orig_bytes": 1024, "resp_bytes": 512}"#;

    #[test]
    fn test_zeek_conn_parses_tsv_line() {
        let conn = ZeekConn::from_tsv_line(TSV_LINE)
            .expect("should parse")
            .expect("should be Some");
        assert_eq!(conn.uid, "Cz1234");
        assert_eq!(conn.src_ip, "192.168.1.100");
        assert_eq!(conn.src_port, 54321);
        assert_eq!(conn.dest_ip, "10.0.0.1");
        assert_eq!(conn.dest_port, 3333);
        assert_eq!(conn.proto, "tcp");
        assert_eq!(conn.orig_bytes, Some(1024));
        assert_eq!(conn.resp_bytes, Some(512));
    }

    #[test]
    fn test_zeek_conn_converts_to_evidence_with_zeek_source() {
        use crate::evidence::{Evidence, EvidenceSource};
        let conn = ZeekConn::from_tsv_line(TSV_LINE)
            .expect("parse ok")
            .expect("is conn");
        let ev: Evidence = conn.into();
        assert_eq!(ev.source, EvidenceSource::Zeek);
    }

    #[test]
    fn test_zeek_conn_sets_network_kind() {
        use crate::evidence::{Evidence, EvidenceKind};
        let conn = ZeekConn::from_tsv_line(TSV_LINE)
            .expect("parse ok")
            .expect("is conn");
        let ev: Evidence = conn.into();
        assert_eq!(ev.kind, EvidenceKind::Custom("Network".to_string()));
    }

    #[test]
    fn test_zeek_conn_skips_header_lines() {
        let header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto";
        let result = ZeekConn::from_tsv_line(header).expect("should not error");
        assert!(
            result.is_none(),
            "header lines starting with # should return None"
        );
    }

    #[test]
    fn test_zeek_conn_parses_json_line() {
        let conn = ZeekConn::from_json(JSON_LINE).expect("should parse");
        assert_eq!(conn.uid, "Cz1234");
        assert_eq!(conn.src_ip, "192.168.1.100");
        assert_eq!(conn.src_port, 54321);
        assert_eq!(conn.dest_ip, "10.0.0.1");
        assert_eq!(conn.dest_port, 3333);
        assert_eq!(conn.proto, "tcp");
        assert_eq!(conn.orig_bytes, Some(1024));
        assert_eq!(conn.resp_bytes, Some(512));
    }
}
