use std::io::{self, BufRead};

use anyhow::{bail, Context};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{Header, RegisteredHeader, Secret};
use biscuit::{ClaimsSet, JWT};
use serde::Serialize;

use clap::{Parser, Subcommand};

/// Parse JWT tokens
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Encode,
    Decode {
        /// Parse JWT without validating
        ///
        /// Only use this for debugging tokens!
        #[arg(long)]
        no_validate: bool,
    },
}

#[derive(Serialize)]
struct Decoded {
    header: Header<biscuit::Empty>,
    payload: biscuit::ClaimsSet<serde_json::Value>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Encode => {
            let mut stdin_lock = io::stdin().lock();

            let claims: ClaimsSet<serde_json::Value> =
                serde_json::de::from_reader(&mut stdin_lock)?;

            let signing_secret = Secret::Bytes("secret".to_string().into_bytes());

            let expected_jwt = JWT::new_decoded(
                From::from(RegisteredHeader {
                    algorithm: SignatureAlgorithm::HS256,
                    ..Default::default()
                }),
                claims,
            );

            let jwt_encoded = expected_jwt
                .into_encoded(&signing_secret)
                .with_context(|| "Error signing and encoding JWT")?;
            let jwt_str = jwt_encoded.unwrap_encoded().to_string();

            println!("{}", jwt_str);

            // let mut stdout_lock = io::stdout().lock();
            // stdout_lock
            // serde_json::ser::to_writer_pretty(&mut stdout_lock, &jwt_str)?;
        }
        Commands::Decode { no_validate } => {
            if !no_validate {
                bail!("JWT validation not implemented yet. To parse without validating pass --no-validate");
            }

            let mut stdin_lock = io::stdin().lock();

            let mut token = String::new();
            stdin_lock.read_line(&mut token)?;

            let encoded_jwt = JWT::<_, biscuit::Empty>::new_encoded(&token);

            let decoded = Decoded {
                header: encoded_jwt
                    .unverified_header()
                    .with_context(|| "Error decoding header")?,
                payload: encoded_jwt
                    .unverified_payload()
                    .with_context(|| "Error decoding payload")?,
            };

            let mut stdout_lock = io::stdout().lock();
            serde_json::ser::to_writer_pretty(&mut stdout_lock, &decoded)
                .with_context(|| "Error serializing decoded JWT as json")?;
        }
    }

    Ok(())
}
