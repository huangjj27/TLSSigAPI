//! Implement Tencent Yun's customized url-safe encode.

pub(crate) fn encode(msg: &[u8]) -> String {
    base64::encode_config(&msg, base64::STANDARD)
        .replace('+', "*")
        .replace('/', "-")
        .replace('=', "_")
}
