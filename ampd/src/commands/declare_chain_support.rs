use std::path::Path;
use std::str::FromStr;

use axelar_wasm_std::nonempty;
use connection_router::state::ChainName;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use error_stack::{Result, ResultExt};
use report::ResultCompatExt;
use service_registry::msg::ExecuteMsg;
use valuable::Valuable;

use crate::commands::{broadcast_tx, worker_pub_key};
use crate::config::Config;
use crate::{Error, PREFIX};

#[derive(clap::Args, Debug, Valuable)]
pub struct Args {
    pub service_name: nonempty::String,
    #[clap(value_delimiter = ',', num_args = 1..)]
    pub chains: Vec<String>,
}

pub async fn run(config: Config, state_path: &Path, args: Args) -> Result<Option<String>, Error> {
    let pub_key = worker_pub_key(state_path, config.tofnd_config.clone()).await?;

    let msg = serde_json::to_vec(&ExecuteMsg::DeclareChainSupport {
        service_name: args.service_name.into(),
        chains: args
            .chains
            .into_iter()
            .map(|x| ChainName::from_str(&x).change_context(Error::InvalidInput))
            .collect::<Result<Vec<ChainName>, _>>()?,
    })
    .expect("declare_chain_support msg should serialize");

    let tx = MsgExecuteContract {
        sender: pub_key.account_id(PREFIX).change_context(Error::Tofnd)?,
        contract: config.service_registry.cosmwasm_contract.as_ref().clone(),
        msg,
        funds: vec![],
    }
    .into_any()
    .expect("failed to serialize proto message");

    Ok(Some(format!(
        "successfully broadcasted declare_chains_support transaction, tx hash: {}",
        broadcast_tx(config, tx, pub_key).await?.txhash
    )))
}
