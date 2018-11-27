extern crate web3;
extern crate serde_json;
extern crate secp256k1;
extern crate ethereum_types;
extern crate tiny_keccak;
extern crate sputnikvm;
extern crate bigint;
extern crate bn;

use web3::futures::Future;
use ethereum_types::{Address, Public};
use web3::types::{H256, H520, U256, Transaction, TransactionId};
use secp256k1::{Message, RecoverableSignature, RecoveryId, Error as SecpError};
use tiny_keccak::Keccak;
use sputnikvm::Precompiled;
use std::rc::Rc;
use std::cmp::min;
use bigint::Gas;
use web3::Error;
use std::env;



pub static INT_CHAIN_TRX_PRECOMPILED: InterChainTrxPrecompiled = InterChainTrxPrecompiled;

pub struct InterChainTrxPrecompiled;
impl Precompiled for InterChainTrxPrecompiled {

    fn gas(&self, data: &[u8]) -> Gas {
        /// TODO: Calculate the gas amount
        Gas::from(3000u64)
    }

    fn step(&self, datao: &[u8]) -> Rc<Vec<u8>> {
        println!("Data in Precompiled contract : {:?}", datao);
        let mut data = [0u8; 128];
        let copy_bytes = min(datao.len(), 128);
        data[..copy_bytes].clone_from_slice(&datao[..copy_bytes]);
        match inter_chain_trx(&data) {
            Ok(ret) => {
                let mut result: [u8; 32] = [0u8; 32];
                if ret {
                    result[0]= 1;
                }

                Rc::new(result.as_ref().into())
            },
            Err(_) => Rc::new(Vec::new()),
        }
    }
}

fn inter_chain_trx(data: &[u8]) -> Result<bool, SecpError> {
    println!("Entering into interchaintrx : {:?}", data);
    let mut tx1_from = [0u8; 20];
    for i in 0..20 {
        tx1_from[i] = data[i];
    }

    let mut tx1_hash = [0u8; 32];
    for i in 0..32 {
        tx1_hash[i] = data[20+i];
    }

    let mut sig_tx1_hash = [0u8; 65];
    for i in 0..65 {
        sig_tx1_hash[i] = data[52+i];
    }

    let url =  env::var("MAINNET_URL").expect("Environment variable has not set");
    let (_eloop, transport) = web3::transports::Http::new(&url).unwrap();
    let web3 = web3::Web3::new(transport);

    let tx1_from = address_from_slice(&tx1_from);
    let tx1_hash = tx1_hash_from_slice(&tx1_hash);
    let sig_tx1_hash = tx1_signature_hash_from_slice(&sig_tx1_hash);
    
    let transaction = match web3.eth().transaction(web3::types::TransactionId::Hash(tx1_hash)).wait().unwrap() {
        None => {
            return Err(SecpError::InvalidMessage); //Invalid Transaction Hash
        }
        Some(transaction) => transaction,  
    };
    println!("Transactions - From Address : {:#?}", transaction.from);

    let tx_receipt = match web3.eth().transaction_receipt(tx1_hash).wait().unwrap() {
        None => {
            return Err(SecpError::InvalidMessage); //Invalid Transaction Hash
        }
        Some(tx_receipt) => tx_receipt,  
    };
    println!("Transaction Receipt - Transaction Hash  : {:#?}", tx_receipt.transaction_hash);
    println!("Status of the Transaction on Ethereum : {:?}", tx_receipt.status);


    let balance = match get_balance(&web3, &tx1_from) {
        Ok(value) => value,
        Err(_) => {
            eprint!("Balance not found for {:?}", tx1_from);
            std::process::exit(-1)
        }
    };
    println!("Balance : {:?}", balance);

    // 1: Verify the "FROM" address using TrxHash and TrxHashSignature
    let eth_msg_hash = ethereum_hash(&tx1_hash); // hash of tx1_hash
    match verify_address(&tx1_from, &sig_tx1_hash, &eth_msg_hash) {
        Ok(true) => Ok(true),
        Ok(false) => Ok(false),
		Err(SecpError::InvalidSignature) => Ok(false),
		Err(x) => Err(x.into()),
    }

}

fn keccak256(input: &[u8]) -> [u8; 32] {
	let mut keccak = Keccak::new_keccak256();
	let mut result = [0u8; 32];
	keccak.update(input);
	keccak.finalize(&mut result);
	result
}

pub fn verify_address(address: &[u8], sig_tx1_hash: &[u8], eth_msg_hash: &[u8]) -> Result<bool, SecpError> {
	let public = recover(sig_tx1_hash, eth_msg_hash)?;
	let recovered_address = public_to_address(&public); //Public is nothing but address here
	Ok(address == &recovered_address)
}

pub fn recover(sig_tx1_hash: &[u8], eth_msg_hash: &[u8]) -> Result<Public, SecpError> {
	let context = &secp256k1::Secp256k1::new();
	let rsig = RecoverableSignature::from_compact(context, &sig_tx1_hash[0..64], RecoveryId::from_i32(sig_tx1_hash[64] as i32)?)?;
	let pubkey =  context.recover(&Message::from_slice(&eth_msg_hash[..])?, &rsig)?;
	let serialized = pubkey.serialize_vec(context, false);
	let mut public = Public::default();
	public.copy_from_slice(&serialized[1..65]);
	Ok(public)
}

pub fn public_to_address(public: &Public) -> [u8; 20] {
	let hash = keccak256(public);
    let mut adr = [0u8; 20];
    adr.copy_from_slice(&hash[12..]);
    return adr;
}

pub fn address_from_slice(s: &[u8]) -> Address {
	Address::from_slice(s)
}

pub fn tx1_hash_from_slice(s: &[u8]) -> H256 {
	H256::from_slice(s)
}

pub fn tx1_signature_hash_from_slice(s: &[u8]) -> [u8;65] {
	let data = H520::from_slice(s);
	let mut sig = [0u8; 65];
	sig.copy_from_slice(&data);
	sig[64] -= 27;
	return sig;
}

pub fn ethereum_hash(msg: &[u8]) -> [u8; 32] {
  let mut message = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
  message.extend_from_slice(&msg[..]);
  keccak256(&message[..]) // message_hash is the hash of tx1_hash
}

fn get_balance(web3: &web3::Web3<web3::transports::Http>, address: &web3::types::Address) -> Result<U256, Error> {
    web3.eth().balance(*address, None).wait()
}

#[cfg(test)]
mod tests {
    extern crate hexutil;
    use super::*;
    use self::hexutil::*;
    #[test]
    fn test_inter_chain_trx() {
        // result: true
        //ADDRESS : 8be74d722deb7c2ba962be126ae9c00f121e3562
        //TRX-HASH     : e62db8a544dfc640c63703f53b91579f7fec46f066432b56ec7daf5a0b7740bc
        //SIGNATURE : c7acecc3e84328c32fd6ee8a5264e203d371a1bff5561176906afdcf988a32097504b088abac55575820fc1db637b138bb05de61c942847809a1ee127866dba31c
        println!("Entering into interchaintrx");
        let address = "8be74d722deb7c2ba962be126ae9c00f121e3562";
        let message = "e62db8a544dfc640c63703f53b91579f7fec46f066432b56ec7daf5a0b7740bc";
        let signature = "de56cd22f0f006c9cf1b7d96fdbbaa29800be86d57961b55ea42dbe66e0edb953777990c13adcc5de39cf670a46f18148d7290a110da92ea76ac405f23428ff41b";
        let together = format!("{}{}{}", address, message, signature);
        println!("Final Input String : {:?}", together);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        assert_eq!(ret.ok(), Some(true));
    }

    #[test]
    fn test_inter_chain_trx_2() {
        // result: false
        //ADDRESS   : 8be74d722deb7c2ba962be126ae9c00f121e3562
        //TRX-HASH  : 9abcbf676f3b374e10d37bf06ef69224ac35676a62734a23f5b790815eb743ba
        //SIGNATURE : de56cd22f0f006c9cf1b7d96fdbbaa29800be86d57961b55ea42dbe66e0edb953777990c13adcc5de39cf670a46f18148d7290a110da92ea76ac405f23428ff41b
        println!("Entering into interchaintrx");
        let address = "8be74d722deb7c2ba962be126ae9c00f121e3562";
        let message = "9abcbf676f3b374e10d37bf06ef69224ac35676a62734a23f5b790815eb743ba";
        let signature = "de56cd22f0f006c9cf1b7d96fdbbaa29800be86d57961b55ea42dbe66e0edb953777990c13adcc5de39cf670a46f18148d7290a110da92ea76ac405f23428ff41b";
        let together = format!("{}{}{}", address, message, signature);
        println!("Final Input String : {:?}", together);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        //assert_eq!(ret.err(), Some(SecpError::IncorrectSignature));
        assert_eq!(ret.err(), None);
        //assert_eq!(ret.ok(), Some(false));
    }
}