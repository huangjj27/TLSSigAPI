use chrono::Duration;
use dotenv::{dotenv, var};
use log::*;
use rand::prelude::*;
use reqwest::Client;
use std::collections::HashMap;
use tls_sig_api::TlsSigApiVer2;

#[test]
#[ignore]
fn get_sig_from_tim_sdk() {
    let _ = env_logger::builder().is_test(true).try_init();

    let env = dotenv().expect("Found no .dotenv file!");
    trace!("Environments loaded from {:?}.", env);

    let appid = var("TEST_APPID")
        .map(|id_str| id_str.parse::<u64>().expect("Appid ParseError: Not a Int!"))
        .expect("No test appid configured!");
    let key = var("TEST_APP_KEY").expect("No test app key configured!");
    let admin = var("TEST_APP_ADMIN").expect("No test app administrator configured!");

    trace!(
        "Test Environments got: appid: {}, appkey: {}, admin: {}.",
        appid,
        key,
        admin
    );
    let sig_api = TlsSigApiVer2::new(appid, &key);

    let admin_sig = sig_api.gen_sign(&admin, Duration::hours(10), None);
    trace!("generated admin_sig: {}", admin_sig);

    let r = random::<u32>();

    let url = format!("https://console.tim.qq.com/v4/im_open_login_svc/account_import?sdkappid={}&identifier={}&usersig={}&random={}&contenttype=json", appid, admin, admin_sig, r).to_string();
    trace!("concated url: {}", url);

    let mut map = HashMap::new();
    map.insert("Identifier", "test");

    let client = Client::new();
    let res = client
        .post(&url)
        .json(&map)
        .send()
        .expect("Sending Request failed!")
        .text()
        .expect("Reading Content failed!");
    trace!("Get respone: {}", res);

    assert!(res.contains(r#""ActionStatus":"OK""#));
}
