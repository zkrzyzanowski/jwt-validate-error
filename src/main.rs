use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    // nbf: usize, // Optional. Not Before (as UTC timestamp)
    sub: String, // Optional. Subject (whom token refers to)
}

fn main() {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![];
    validation.insecure_disable_signature_validation();

    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY1Njc5MjY1MSwiZXhwIjoxNjU2Nzk2MjUxfQ.";
    let decoding_key = DecodingKey::from_secret("fake_key".as_ref());

    let decoded_token: Result<TokenData<Claims>, jsonwebtoken::errors::Error> =
        jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation);

    match decoded_token {
        Ok(token) => println!("{:?}", token.header),
        Err(err) => println!("{}", err),
    }
}
