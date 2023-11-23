use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use solana_sdk::signature::Signature;
use sui_types::base_types::{SuiAddress, TransactionDigest};

use axelar_wasm_std::voting::PollID;
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
//     poll_id: PollID,
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
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollID,
    source_gateway_address: String,
    messages: Vec<Message>,
    participants: Vec<String>,
    // TODO: currently deployed with mock_address hardcoded in voting-verifier
    // participants: Vec<TMAddress>,
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
    async fn broadcast_votes(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize");
        let tx = MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg,
            funds: vec![],
        };

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
                // println!("MISMATCH {:?}", event);
                return Ok(());
            }
            event => {
                println!("EVENT {:?}", event);
                event.change_context(Error::DeserializeEvent)?
            }
        };

        if self.voting_verifier != contract_address {
            return Ok(());
        }

        // TODO: Uncomment when using real workers
        // if !participants.contains(&self.worker) {
        //     return Ok(());
        // }

        if !participants.contains(&String::from("mock_address")) {
            return Ok(());
        }

        let tx_ids_from_msg: HashSet<_> = messages.iter().map(|msg| msg.tx_id.clone()).collect();

        let mut sol_txs: Vec<EncodedConfirmedTransactionWithStatusMeta> = Vec::new();
        for msg_tx in tx_ids_from_msg {
            let result = self.rpc_client.get_transaction(msg_tx).await;
            match result {
                Ok(sol_tx) => sol_txs.push(sol_tx),
                Err(err) => println!("ERR {:?}", err),
            }
        }

        let mut votes: Vec<bool> = vec![false; messages.len()];
        for msg in messages {
            votes = sol_txs
                .iter()
                .map(|tx| verify_message(&source_gateway_address, tx, &msg))
                .collect();
        }

        println!("VOTES!!!!!!!!!!!!!!!!!!!!!!!!!!!! {:?}", votes);

        Ok(())
        // self.broadcast_votes(poll_id, votes).await
    }
}
