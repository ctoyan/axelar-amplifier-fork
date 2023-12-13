use std::path::Path;

use error_stack::Result;

use crate::commands::worker_pub_key;
use crate::tofnd::Config as TofndConfig;
use crate::Error;

pub async fn run(config: TofndConfig, state_path: &Path) -> Result<Option<String>, Error> {
    worker_pub_key(state_path, config)
        .await
        .and_then(|pub_key| {
            Ok(Some(
                pub_key
                    .to_bytes()
                    .iter()
                    .map(|b| format!("worker hex pubkey: {:02x}", b))
                    .collect::<Vec<String>>()
                    .join(""),
            ))
        })
}
