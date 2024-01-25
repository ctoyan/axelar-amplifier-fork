use axelar_wasm_std::voting::Vote;
use base64::Engine as _;
use borsh::{BorshDeserialize, BorshSerialize};

use base64::{self, engine::general_purpose};
use tracing::warn;

use crate::handlers::solana_verify_msg::Message;

use super::{json_rpc::EncodedConfirmedTransactionWithStatusMeta, pub_key_wrapper::PubkeyWrapper};

// Gateway program logs.
// Logged when the Gateway receives an outbound message.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize, Clone)]
#[repr(u8)]
enum GatewayEvent {
    CallContract {
        // Message sender.
        sender: PubkeyWrapper,
        destination_chain: Vec<u8>,
        destination_address: Vec<u8>,
        payload: Vec<u8>,
        payload_hash: [u8; 32],
    },
}

impl GatewayEvent {
    // Try to parse a [`CallContractEvent`] out of a Solana program log line.
    fn parse_log(log: &String) -> Option<Self> {
        let cleaned_input = log
            .trim()
            .trim_start_matches("Program data:")
            .split_whitespace()
            .flat_map(decode_base64)
            .next()?;
        borsh::from_slice(&cleaned_input).ok()
    }
}

impl PartialEq<&Message> for GatewayEvent {
    fn eq(&self, msg: &&Message) -> bool {
        match self {
            GatewayEvent::CallContract {
                sender: _,
                destination_chain,
                destination_address,
                payload: _,
                payload_hash,
            } => {
                let event_dest_addr = String::from_utf8(destination_address.to_owned());
                let event_dest_chain = String::from_utf8(destination_chain.to_owned());

                println!(
                    "IN EVENT CHECK 1 - {}",
                    event_dest_addr.clone().unwrap() == msg.destination_address
                );
                println!(
                    "IN EVENT CHECK 2 - {}",
                    event_dest_chain.clone().unwrap() == msg.destination_chain.to_string()
                );
                println!(
                    "IN EVENT CHECK 3 - {}",
                    payload_hash.to_owned() == msg.payload_hash
                );
                println!("payload 1 {:#?}", payload_hash.to_owned());
                println!("payload 2 {:#?}", msg.payload_hash);

                event_dest_addr.is_ok()
                    && event_dest_chain.is_ok()
                    && event_dest_addr.unwrap() == msg.destination_address
                    && event_dest_chain.unwrap() == msg.destination_chain.to_string()
                    && payload_hash.to_owned() == msg.payload_hash
            }
        }
    }
}

#[inline]
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    general_purpose::STANDARD.decode(input).ok()
}

pub fn verify_message(
    source_gateway_address: &String, // TODO: check if sender is source_gateway_address
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    message: &Message,
) -> Vote {
    if let None = tx.meta.log_messages {
        // TODO: Log error/warn, because this event should contain log msgs?
        return Vote::NotFound;
    }

    let program_data = tx.meta.log_messages.as_ref().unwrap();
    let gw_event_parsed: Option<GatewayEvent> = program_data
        .into_iter()
        // TODO: Will find_map work with multiple msgs in transaction?
        .find_map(|program_log| GatewayEvent::parse_log(program_log));

    // let prog_data_base64_borsh = get_program_data_from_log(tx.meta.log_messages.as_ref());
    // let prog_data = decode_program_data(prog_data_base64_borsh.clone()).unwrap(); // TODO: Should

    if gw_event_parsed.is_none() {
        // TODO: Log error/warn, because this event should be parsed
        warn!("failed to parse the event");
        return Vote::FailedOnChain;
    }

    //NOTE: first signagure is always tx_id
    let verified = gw_event_parsed.clone().unwrap() == message
        && tx.transaction.signatures[0] == message.tx_id
        && tx
            .transaction
            .message
            .account_keys
            .contains(source_gateway_address);

    println!("CHECK 1 - {}", gw_event_parsed.unwrap() == message);
    println!("CHECK 2- {}", tx.transaction.signatures[0] == message.tx_id);
    println!(
        "CHECK 3- {}",
        tx.transaction
            .message
            .account_keys
            .contains(source_gateway_address)
    );
    println!("EVENT VERIFIED - {}", verified);

    match verified {
        true => Vote::SucceededOnChain,
        false => Vote::FailedOnChain,
    }
}

// // CONTRACT_CALL_EVENT is in form of <module name>::<event type>
// const CONTRACT_CALL_EVENT: &str = "gateway::ContractCall";
//
// // TODO: update after Sui gateway event finalization
// #[derive(Deserialize)]
// struct ContractCall {
//     pub source_id: SuiAddress,
//     pub destination_chain: String,
//     pub destination_address: String,
//     pub payload_hash: Hash,
// }
//
// // Event type is in the form of: <gateway_address>::gateway::ContractCall
// fn call_contract_type(gateway_address: &SuiAddress) -> StructTag {
//     format!("{}::{}", gateway_address, CONTRACT_CALL_EVENT)
//         .parse()
//         .expect("failed to parse struct tag")
// }

// fn find_event(
//     transaction_block: &SuiTransactionBlockResponse,
//     event_seq: u64,
// ) -> Option<&SuiEvent> {
//     transaction_block
//         .events
//         .as_ref()
//         .iter()
//         .flat_map(|events| events.data.iter())
//         .find(|event| event.id.event_seq == event_seq)
// }

// fn get_program_data_from_log(log_msgs: Option<&Vec<String>>) -> String {
//     for msg in log_msgs.unwrap_or(&Vec::<String>::new()) {
//         if let Some(pos) = msg.find("Program data:") {
//             // Skip the "Program data:" part and extract the rest of the string
//             let rest_of_string = &msg[pos + "Program data:".len()..].trim();
//
//             let prog_data = rest_of_string.trim().to_string();
//
//             return prog_data;
//         }
//     }
//
//     // TODO: Should probably error?
//     return String::from("");
// }

// #[derive(Debug, BorshDeserialize, BorshSerialize, PartialEq)]
// struct SolanaProgramData {
//     pub sender: [u8; 32], //TODO: Should be Pubkey from solana_sdk
//     pub destination_chain: String,
//     pub destination_contract_address: String,
//     pub payload_hash: [u8; 32],
//     pub payload: Vec<u8>,
// }

// #[derive(Debug)]
// enum DecodeProgDataErr {
//     Base64DecodeErr(base64::DecodeError),
//     BorshDeserializeErr(borsh::io::Error),
// }
//
// impl From<base64::DecodeError> for DecodeProgDataErr {
//     fn from(err: base64::DecodeError) -> Self {
//         DecodeProgDataErr::Base64DecodeErr(err)
//     }
// }
//
// impl From<borsh::io::Error> for DecodeProgDataErr {
//     fn from(err: borsh::io::Error) -> Self {
//         DecodeProgDataErr::BorshDeserializeErr(err)
//     }
// }
//
// fn decode_program_data(prog_data: String) -> Result<SolanaProgramData, DecodeProgDataErr> {
//     let borsh_bytes = base64::decode(prog_data)?;
//     let mut slice: &[u8] = &borsh_bytes[..];
//     let _: [u8; 8] = {
//         let mut disc = [0; 8];
//         disc.copy_from_slice(&borsh_bytes[..8]);
//         slice = &slice[8..];
//         disc
//     };
//     let prog_data: SolanaProgramData = from_slice(&slice)?;
//
//     return Ok(prog_data);
// }

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
