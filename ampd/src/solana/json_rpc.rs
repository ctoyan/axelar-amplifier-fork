use async_trait::async_trait;
use ethers::providers::{JsonRpcClient, ProviderError};
use mockall::automock;
use serde::{Deserialize, Serialize};
// use solana_sdk::transaction::Transaction;

use crate::json_rpc::Client;

type Result<T> = error_stack::Result<T, ProviderError>;

// TODO: This should come from solana-sdk crate
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub message: SolMessage,
    pub signatures: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolMessage {
    pub instructions: Vec<SolInstruction>,
    pub account_keys: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTransactionStatusMeta {
    pub log_messages: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SolInstruction {
    pub data: String,
}

// TODO: This should come from the solana-transaction-status crate
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EncodedConfirmedTransactionWithStatusMeta {
    pub transaction: Transaction,
    pub meta: UiTransactionStatusMeta,
}

#[automock]
#[async_trait]
pub trait SolanaClient {
    // async fn get_transactions(&self, digests: Vec<Transaction>) -> Result<Vec<Transaction>>;
    async fn get_transaction(
        &self,
        signature_str: String,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta>;
}

#[async_trait]
impl<P> SolanaClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn get_transaction(
        &self,
        signature_str: String,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
        self.request("getTransaction", [signature_str, String::from("json")])
            .await
    }
}