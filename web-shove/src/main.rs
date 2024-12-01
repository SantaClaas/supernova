use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use vapid::Vapid;

mod vapid;
fn main() {
    let vapid = Vapid::generate("example@example.com");
    let private_key = BASE64_URL_SAFE_NO_PAD.encode(vapid.private_key);
    println!("{}", private_key);
}
