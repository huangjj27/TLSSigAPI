use chrono::{DateTime, Duration, Utc};
use deflate::{deflate_bytes_zlib_conf, Compression};
use log::*;
use ring::hmac;
use serde_json::json;

mod b64_url_safe;

pub struct TlsSigApiVer2 {
    sdkappid: u64,
    tls_ver: &'static str,
    secret: String,
}

impl TlsSigApiVer2 {
    pub fn new(sdkappid: u64, key: &str) -> Self {
        TlsSigApiVer2 {
            sdkappid,
            tls_ver: "2.0",
            secret: key.to_string(),
        }
    }

    /// In case that the key is leaked, we want to update the key at runtime.
    pub fn update_key(&mut self, key: &str) {
        self.secret = key.to_string();
    }

    /// generate user sign with timestamp.
    /// # Examples
    ///
    /// ```
    /// use tls_sig_api::TlsSigApiVer2;
    /// use chrono::Duration;
    ///
    /// let mock_key = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e";
    /// let signer = TlsSigApiVer2::new(0, mock_key);
    ///
    /// let identifier = "10086";
    /// let expire = Duration::hours(2);
    /// let userbuf = "This' really a good crate!";
    ///
    /// let digest = signer.gen_sign(identifier, expire, Some(userbuf));
    /// println!("{}", digest);
    /// ```
    pub fn gen_sign(&self, identifier: &str, expire: Duration, userbuf: Option<&str>) -> String {
        // Always use current time for production sign.
        let curr_time = Utc::now();
        debug!(
            "current time: {}, timestamp_millis: {}",
            curr_time,
            curr_time.timestamp_millis()
        );

        self.gen_sign_with_time(identifier, curr_time, expire, userbuf)
    }

    fn gen_sign_with_time(
        &self,
        identifier: &str,
        dt: DateTime<Utc>,
        expire: Duration,
        userbuf: Option<&str>,
    ) -> String {
        let mut dict = json!({
            "TLS.ver": self.tls_ver,
            "TLS.identifier": identifier.to_string(),
            "TLS.sdkappid": self.sdkappid,
            "TLS.expire": expire.num_milliseconds(),
            "TLS.time": dt.timestamp_millis()
        });

        let base64_buf = userbuf.map(|buf| base64::encode_config(buf.as_bytes(), base64::STANDARD));

        if let Some(buf) = base64_buf.clone() {
            dict["TLS.userbuf"] = json!(buf);
        }

        dict["TLS.sig"] = json!(self.hmac_sha256(identifier, dt, expire, base64_buf));
        debug!("raw sig json: {}", dict);

        let sig_compressed =
            deflate_bytes_zlib_conf(dict.to_string().as_bytes(), Compression::Best);
        debug!("compressed sig: {:?}", &sig_compressed);

        b64_url_safe::encode(&sig_compressed)
    }

    fn hmac_sha256(
        &self,
        identifier: &str,
        curr_time: DateTime<Utc>,
        expire: Duration,
        base64_buf: Option<String>,
    ) -> String {
        let mut raw_content_to_be_signed = format!(
            "TLS.identifier:{}\nTLS.sdkappid:{}\nTLS.time:{}\nTLS.expire:{}\n",
            identifier,
            self.sdkappid,
            curr_time.timestamp_millis(),
            expire.num_milliseconds(),
        )
        .to_string();

        if let Some(buf) = base64_buf {
            raw_content_to_be_signed.push_str(&format!("TLS.userbuf:{}\n", buf));
        }

        debug!("raw_content_to_be_signed: {}", raw_content_to_be_signed);

        let key = hmac::Key::new(hmac::HMAC_SHA256, self.secret.as_bytes());
        let digest = hmac::sign(&key, raw_content_to_be_signed.as_bytes());

        base64::encode_config(digest.as_ref(), base64::STANDARD)
    }
}

#[cfg(test)]
mod test {
    use super::TlsSigApiVer2;
    use chrono::{Duration, TimeZone, Utc};

    const MOCK_APPID: u64 = 1400000000;
    const MOCK_KEY: &'static str =
        "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e";
    const MOCK_USERBUF: &'static str = "abc";

    fn log_init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_update_key() {
        let mut signer = TlsSigApiVer2::new(MOCK_APPID, "");
        assert_eq!(signer.secret, "".to_string());

        signer.update_key(MOCK_KEY);
        assert_eq!(signer.secret, MOCK_KEY.to_string());
    }

    #[test]
    fn test_hmac_sha256() {
        log_init();

        // the great moment of the 70th anniversary of the founding of new China!
        // timestamp_millis = 1569910200000
        let mock_curr_time = Utc.ymd(2019, 10, 1).and_hms(6, 10, 0);
        let signer = TlsSigApiVer2::new(MOCK_APPID, MOCK_KEY);
        let mock_base64_buf =
            Some(MOCK_USERBUF).map(|buf| base64::encode_config(buf.as_bytes(), base64::STANDARD));

        // mock sig generated from python version
        let mock_sig = "bEj7EPKeOGh/DZ+LevCNXjSrLtgjj+lC8Ed0uirJXYU=";
        let mock_sig_with_buf = "sWtbl2+lkv1DcoBF2Y2IWjGB44KoDgDIFxdhzwVXo2Q=";

        assert_eq!(
            &signer.hmac_sha256("0", mock_curr_time, Duration::days(180), None),
            mock_sig
        );
        assert_eq!(
            &signer.hmac_sha256("0", mock_curr_time, Duration::days(180), mock_base64_buf),
            mock_sig_with_buf
        );
    }

    // UNFINISHED TEST BECAUSE OF WRONG EXPECTED VALUES!
    #[test]
    #[ignore]
    fn test_fix_time_sign_generation_no_buf() {
        log_init();

        // the great moment of the 70th anniversary of the founding of new China!
        // timestamp_millis = 1569910200000
        let mock_curr_time = Utc.ymd(2019, 10, 1).and_hms(6, 10, 0);
        let signer = TlsSigApiVer2::new(MOCK_APPID, MOCK_KEY);

        // mock sig generated from python version
        let mock_sig = "eJyrVgrxCdYrSy1SslIy0jNQ0gHzM1NS80oy0zLBwjDB4pTsxIKCzBQlK0MTAyiAyKRWFGQWpQLFTU1NjZAlSjJzwcJmlpaGBkZIEsWZ6UCTk1yzzF0DvFP93TP0XaK0fVLLnP0isoKLfErSs7K0c5wtXFMMSjOLvCIiQ22VagHjLDB3";

        assert_eq!(
            &signer.gen_sign_with_time("0", mock_curr_time, Duration::days(180), None),
            mock_sig
        );
    }

    // This test is ignore because of the different compressing levels between
    // Rust code and Python code.
    #[test]
    #[ignore]
    fn test_fix_time_sign_generation_with_buf() {
        log_init();

        // the great moment of the 70th anniversary of the founding of new China!
        // timestamp_millis = 1569910200000
        let mock_curr_time = Utc.ymd(2019, 10, 1).and_hms(6, 10, 0);
        let signer = TlsSigApiVer2::new(MOCK_APPID, MOCK_KEY);

        // mock sig generated from python version
        // let mock_sig_with_buf = "eNqrVgrxCdYrSy1SslIy0jNQ0gHzM1NS80oy0zLBwjDB4pTsxIKCzBQlK0MTAyiAyKRWFGQWpQLFTU1NjZAlSjJzwcJmlpaGBkZIEqXFqUVJpWlA0yPDvbJgFmSmAwWKw0uScoy0c7LLDF2S853cjCKNPMOz3J1MTLzzXdJdPN0qUjKqysMi8o0CbZVqAR54Nug_";
        let mock_sig_with_buf = "eAEBwAA--3siVExTLnZlciI6IjIuMCIsIlRMUy5pZGVudGlmaWVyIjoiMCIsIlRMUy5zZGthcHBpZCI6MTQwMDAwMDAwMCwiVExTLmV4cGlyZSI6MTU1NTIwMDAwMDAsIlRMUy50aW1lIjoxNTY5OTEwMjAwMDAwLCJUTFMudXNlcmJ1ZiI6IllXSmoiLCJUTFMuc2lnIjoic1d0YmwyK2xrdjFEY29CRjJZMklXakdCNDRLb0RnRElGeGRoendWWG8yUT0ifR54Nug_";

        assert_eq!(
            &signer.gen_sign_with_time(
                "0",
                mock_curr_time,
                Duration::days(180),
                Some(MOCK_USERBUF)
            ),
            mock_sig_with_buf
        );
    }
}
