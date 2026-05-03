//! Zeek conn.log adapter.
//!
//! Converts Zeek conn.log lines (TSV or JSON) into `Evidence` objects.

#[cfg(test)]
mod tests {
    use super::*;

    const TSV_LINE: &str = "1000000000.0\tCz1234\t192.168.1.100\t54321\t10.0.0.1\t3333\ttcp\t-\t1.234\t1024\t512\tSF";
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
        assert!(result.is_none(), "header lines starting with # should return None");
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
