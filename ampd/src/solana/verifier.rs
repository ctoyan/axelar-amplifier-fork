use borsh::{from_slice, BorshDeserialize, BorshSerialize};

use base64;
use move_core_types::language_storage::StructTag;
use serde::Deserialize;
use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockResponse};
use sui_types::base_types::SuiAddress;

use crate::handlers::solana_verify_msg::Message;
use crate::types::Hash;

use super::json_rpc::{
    EncodedConfirmedTransactionWithStatusMeta, Transaction, UiTransactionStatusMeta,
};

// CONTRACT_CALL_EVENT is in form of <module name>::<event type>
const CONTRACT_CALL_EVENT: &str = "gateway::ContractCall";

// TODO: update after Sui gateway event finalization
#[derive(Deserialize)]
struct ContractCall {
    pub source_id: SuiAddress,
    pub destination_chain: String,
    pub destination_address: String,
    pub payload_hash: Hash,
}

// Event type is in the form of: <gateway_address>::gateway::ContractCall
fn call_contract_type(gateway_address: &SuiAddress) -> StructTag {
    format!("{}::{}", gateway_address, CONTRACT_CALL_EVENT)
        .parse()
        .expect("failed to parse struct tag")
}

impl PartialEq<&Message> for SolanaProgramData {
    fn eq(&self, msg: &&Message) -> bool {
        self.destination_contract_address == msg.destination_address
            && self.destination_chain == msg.destination_chain.to_string()
            && self.payload_hash == msg.payload_hash.to_fixed_bytes()
    }
}

fn find_event(
    transaction_block: &SuiTransactionBlockResponse,
    event_seq: u64,
) -> Option<&SuiEvent> {
    transaction_block
        .events
        .as_ref()
        .iter()
        .flat_map(|events| events.data.iter())
        .find(|event| event.id.event_seq == event_seq)
}

fn get_program_data_from_log(log_msgs: Option<&Vec<String>>) -> String {
    for msg in log_msgs.unwrap_or(&Vec::<String>::new()) {
        if let Some(pos) = msg.find("Program data:") {
            // Skip the "Program data:" part and extract the rest of the string
            let rest_of_string = &msg[pos + "Program data:".len()..].trim();

            let prog_data = rest_of_string.trim().to_string();

            return prog_data;
        }
    }

    // TODO: Should probably error?
    return String::from("");
}

#[derive(Debug, BorshDeserialize, BorshSerialize, PartialEq)]
struct SolanaProgramData {
    pub sender: [u8; 32], //TODO: Should be Pubkey from solana_sdk
    pub destination_chain: String,
    pub destination_contract_address: String,
    pub payload_hash: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug)]
enum DecodeProgDataErr {
    Base64DecodeErr(base64::DecodeError),
    BorshDeserializeErr(borsh::io::Error),
}

impl From<base64::DecodeError> for DecodeProgDataErr {
    fn from(err: base64::DecodeError) -> Self {
        DecodeProgDataErr::Base64DecodeErr(err)
    }
}

impl From<borsh::io::Error> for DecodeProgDataErr {
    fn from(err: borsh::io::Error) -> Self {
        DecodeProgDataErr::BorshDeserializeErr(err)
    }
}

fn decode_program_data(prog_data: String) -> Result<SolanaProgramData, DecodeProgDataErr> {
    let borsh_bytes = base64::decode(prog_data)?;
    let mut slice: &[u8] = &borsh_bytes[..];
    let _: [u8; 8] = {
        let mut disc = [0; 8];
        disc.copy_from_slice(&borsh_bytes[..8]);
        slice = &slice[8..];
        disc
    };
    let prog_data: SolanaProgramData = from_slice(&slice)?;

    return Ok(prog_data);
}

pub fn verify_message(
    source_gateway_address: &String, // TODO: check if sender is source_gateway_address
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    message: &Message,
) -> bool {
    let prog_data_base64_borsh = get_program_data_from_log(tx.meta.log_messages.as_ref());
    let prog_data = decode_program_data(prog_data_base64_borsh.clone()).unwrap(); // TODO: Should

    //NOTE: first signagure is always tx_id
    return prog_data == message
        && tx.transaction.signatures[0] == message.tx_id
        && tx
            .transaction
            .message
            .account_keys
            .contains(source_gateway_address);
}

#[cfg(test)]
mod tests {
    use ethers::abi::AbiEncode;
    use move_core_types::language_storage::StructTag;
    use random_string::generate;
    use sui_json_rpc_types::{SuiEvent, SuiTransactionBlockEvents, SuiTransactionBlockResponse};
    use sui_types::{
        base_types::{SuiAddress, TransactionDigest},
        event::EventID,
    };

    use connection_router::state::ChainName;

    use crate::handlers::sui_verify_msg::Message;
    use crate::sui::verifier::verify_message;
    use crate::types::{EVMAddress, Hash};

    #[test]
    fn should_not_verify_msg_if_tx_id_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.tx_id = TransactionDigest::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_event_index_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.event_index = rand::random::<u64>();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_source_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.source_address = SuiAddress::random_for_testing_only();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_chain_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.destination_chain = rand_chain_name();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_destination_address_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.destination_address = EVMAddress::random().to_string();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_not_verify_msg_if_payload_hash_does_not_match() {
        let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

        msg.payload_hash = Hash::random();
        assert!(!verify_message(&gateway_address, &tx_receipt, &msg));
    }

    #[test]
    fn should_verify_msg_if_correct() {
        let (gateway_address, tx_block, msg) = get_matching_msg_and_tx_block();
        assert!(verify_message(&gateway_address, &tx_block, &msg));
    }

    fn get_matching_msg_and_tx_block() -> (SuiAddress, SuiTransactionBlockResponse, Message) {
        let gateway_address = SuiAddress::random_for_testing_only();

        let msg = Message {
            tx_id: TransactionDigest::random(),
            event_index: rand::random::<u64>(),
            source_address: SuiAddress::random_for_testing_only(),
            destination_chain: rand_chain_name(),
            destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
            payload_hash: Hash::random(),
        };

        let json_str = format!(
            r#"{{"destination_address": "{}", "destination_chain": "{}",  "payload": "[1,2,3]",
            "payload_hash": "{}",  "source_id": "{}"}}"#,
            msg.destination_address,
            msg.destination_chain,
            msg.payload_hash.encode_hex(),
            msg.source_address
        );
        let parsed: serde_json::Value = serde_json::from_str(json_str.as_str()).unwrap();

        let event = SuiEvent {
            id: EventID {
                tx_digest: msg.tx_id,
                event_seq: msg.event_index,
            },
            package_id: gateway_address.into(),
            transaction_module: "gateway".parse().unwrap(),
            sender: msg.source_address,
            type_: StructTag {
                address: gateway_address.into(),
                module: "gateway".parse().unwrap(),
                name: "ContractCall".parse().unwrap(),
                type_params: vec![],
            },
            parsed_json: parsed,
            bcs: vec![],
            timestamp_ms: None,
        };

        let tx_block = SuiTransactionBlockResponse {
            digest: msg.tx_id,
            events: Some(SuiTransactionBlockEvents { data: vec![event] }),
            ..Default::default()
        };

        (gateway_address, tx_block, msg)
    }

    fn rand_chain_name() -> ChainName {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        generate(8, charset).parse().unwrap()
    }
}
