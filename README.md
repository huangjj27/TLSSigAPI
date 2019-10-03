# Tencent Login Service Signature API (aka. TLSSigAPI)

Currently We provide only the `TLSSigAPIv2` using `HMAC-SHA256` as in describe on [TecentYun document(for server use only)](https://cloud.tencent.com/document/product/269/32688#.E6.9C.8D.E5.8A.A1.E7.AB.AF.E8.AE.A1.E7.AE.97-usersig).

Implement base on [this code](https://github.com/tencentyun/tls-sig-api-python)

## Usage

```rust
use tls_sig_api::TlsSigApiVer2;
use chrono::Duration;

let mock_key = "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e";
let signer = TlsSigApiVer2::new(0, mock_key);

let identifier = "10086";
let expire = Duration::hours(2);
let userbuf = "This' really a good crate!";

let digest = signer.gen_sign(identifier, expire, Some(userbuf));
println!("{}", digest);
```
