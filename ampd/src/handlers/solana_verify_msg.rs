use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::AccountId;
use error_stack::ResultExt;
use serde::Deserialize;
use solana_sdk::signature::Signature;
use sui_types::base_types::{SuiAddress, TransactionDigest};

use axelar_wasm_std::voting::{PollId, Vote};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::solana::json_rpc::EncodedConfirmedTransactionWithStatusMeta;
use crate::solana::{json_rpc::SolanaClient, verifier::verify_message};
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

// #[derive(Deserialize, Debug)]
// pub struct Message {
//     pub tx_id: TransactionDigest,
//     pub event_index: u64,
//     pub destination_address: String,
//     pub destination_chain: connection_router::state::ChainName,
//     pub source_address: SuiAddress,
//     pub payload_hash: Hash,
// }

// #[derive(Deserialize, Debug)]
// #[try_from("wasm-messages_poll_started")]
// struct PollStartedEvent {
//     #[serde(rename = "_contract_address")]
//     contract_address: TMAddress,
//     poll_id: PollId,
//     source_gateway_address: SuiAddress,
//     messages: Vec<Message>,
//     participants: Vec<TMAddress>,
// }

#[derive(Deserialize, Debug, PartialEq)]
pub struct Message {
    pub tx_id: String,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: String,
    #[serde(with = "axelar_wasm_std::hex")]
    pub payload_hash: [u8; 32],
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollId,
    source_gateway_address: String,
    messages: Vec<Message>,
    // participants: Vec<TMAddress>,
    participants: Vec<String>,
}

pub struct Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    broadcast_client: B,
}

impl<C, B> Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        broadcast_client: B,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            broadcast_client,
        }
    }
    async fn broadcast_votes(&self, poll_id: PollId, votes: Vec<Vote>) -> Result<()> {
        println!("666666666666666666666666666666666666666666");
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize");
        println!("7777777777777777777777777777777777777777777");
        let tx = MsgExecuteContract {
            // NOTE: axelar17lqysp4lka9h6cyw8enxhw20t9f855zfw3k3xg, which comes from
            // the tofnd on ampd start is funded and hardcoded as worker address
            // everywhere
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg,
            funds: vec![],
        };
        println!("8888888888888888888888888888888888888888888");

        self.broadcast_client
            .broadcast(tx)
            .await
            .change_context(Error::Broadcaster)
    }
}

#[async_trait]
impl<C, B> EventHandler for Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<()> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_gateway_address,
            messages,
            participants,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(());
            }
            event => {
                println!("DESEEEEEEEEEEEEEEEEEE {:?}", event);
                event.change_context(Error::DeserializeEvent)?
            }
        };

        println!("111111111111111111111111111");
        if self.voting_verifier != contract_address {
            println!("DONT MATCH");
            return Ok(());
        }

        println!("222222222222222222222222222");
        // if !participants.contains(&self.worker) {
        //     println!("DONT CONTAIN");
        //     return Ok(());
        // }

        // TODO: Uncomment when using fake workers
        if !participants.contains(&String::from(
            "axelar17lqysp4lka9h6cyw8enxhw20t9f855zfw3k3xg",
        )) {
            println!("KOR222222222222222222222222222");
            return Ok(());
        }

        println!("3333333333333333333333333333");
        let tx_ids_from_msg: HashSet<_> = messages.iter().map(|msg| msg.tx_id.clone()).collect();
        println!("4444444444444444444444444444");

        let mut sol_txs: Vec<EncodedConfirmedTransactionWithStatusMeta> = Vec::new();
        for msg_tx in tx_ids_from_msg {
            let result = self.rpc_client.get_transaction(msg_tx).await;
            println!("TX {:#?}", result);
            match result {
                Ok(sol_tx) => sol_txs.push(sol_tx),
                Err(err) => println!("ERR {:?}", err),
            }
        }
        println!("55555555555555555555555555555");

        let mut votes: Vec<Vote> = vec![Vote::NotFound; messages.len()];
        for msg in messages {
            votes = sol_txs
                .iter()
                .map(|tx| verify_message(&source_gateway_address, tx, &msg))
                .collect();
        }

        self.broadcast_votes(poll_id, votes).await
    }
}
