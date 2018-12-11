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
use web3::types::{H256, H520};
use secp256k1::{Message, RecoverableSignature, RecoveryId, Error as SecpError};
use tiny_keccak::Keccak;
use sputnikvm::Precompiled;
use std::rc::Rc;
use std::cmp::min;
use bigint::Gas;
use std::env;


pub static INT_CHAIN_TRX_PRECOMPILED: InterChainTrxPrecompiled = InterChainTrxPrecompiled;

pub struct InterChainTrxPrecompiled;
impl Precompiled for InterChainTrxPrecompiled {

    fn gas(&self, _data: &[u8]) -> Gas {
        Gas::from(3000u64)
    }

    fn step(&self, datao: &[u8]) -> Rc<Vec<u8>> {
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
    let (_eloop, transport) = web3::transports::Http::new(&url).expect("unable to create Web3 HTTP provider");
    let web3 = web3::Web3::new(transport);

    let tx1_from = address_from_slice(&tx1_from);
    let tx1_hash = tx1_hash_from_slice(&tx1_hash);
    let sig_tx1_hash = tx1_signature_hash_from_slice(&sig_tx1_hash);
    
    let transaction = match web3.eth().transaction(web3::types::TransactionId::Hash(tx1_hash)).wait().unwrap() {
        None => {
            return Ok(false);
        }
        Some(transaction) => transaction,  
    };

    //Verify Transaction-1's "to" address is present on "Ethereum" network.   
    let from_trx: ethereum_types::H160 = match transaction.to {
        Some(val) => val,
        None => return Err(SecpError::InvalidMessage),
    };

    let verified: bool = verify_to_address(&from_trx, &tx1_from);

    if verified == true {
        let tx_receipt = match web3.eth().transaction_receipt(tx1_hash).wait().unwrap() {
            None => {
                return Err(SecpError::InvalidMessage); //Invalid Transaction Hash
            }
            Some(tx_receipt) => tx_receipt,  
        };

        //Verify Transaction-1's status Success/Failure
        let status = match tx_receipt.status {
            Some(val) => val,
            None => return Err(SecpError::InvalidMessage),
        };

        let verify_stat: bool = verify_status(&status);

        if verify_stat == true {
            //Check whether the transaction had happened on the "Ethereum" network.
            let eth_msg_hash = ethereum_hash(&tx1_hash);
            match verify_address(&tx1_from, &sig_tx1_hash, &eth_msg_hash) {
                Ok(true) => Ok(true),
                Ok(false) => Ok(false),
	            Err(SecpError::InvalidSignature) => Ok(false),
	            Err(x) => Err(x.into()),
            }
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
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
	let recovered_address = public_to_address(&public);
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
  keccak256(&message[..])
}

pub fn verify_to_address(trx_addr: &ethereum_types::H160, from_addr: &ethereum_types::H160) -> bool {
    if trx_addr == from_addr {
        return true;
    } else {
        return false;
    }
}

pub fn verify_status(status: &ethereum_types::U64) -> bool {
    let status_check = status.as_usize();   
    if status_check == 1 {
        return true;
    } else {
        return false;
    }
}

#[cfg(test)]
mod tests {
    extern crate hexutil;
    use super::*;
    use self::hexutil::*;
    #[test]
    fn test_inter_chain_trx_1() {
        // Result: true (Successful Transaction)
        let address = "8be74d722deb7c2ba962be126ae9c00f121e3562";
        let message = "e62db8a544dfc640c63703f53b91579f7fec46f066432b56ec7daf5a0b7740bc";
        let signature = "c7acecc3e84328c32fd6ee8a5264e203d371a1bff5561176906afdcf988a32097504b088abac55575820fc1db637b138bb05de61c942847809a1ee127866dba31c";
        let together = format!("{}{}{}", address, message, signature);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        assert_eq!(ret.ok(), Some(true));
    }

    #[test]
    fn test_inter_chain_trx_2() {
        // Result: false (Address is Wrong)
        let address = "8ce74d722deb7c2ba962be126ae9c00f121e3562";
        let message = "e62db8a544dfc640c63703f53b91579f7fec46f066432b56ec7daf5a0b7740bc";
        let signature = "c7acecc3e84328c32fd6ee8a5264e203d371a1bff5561176906afdcf988a32097504b088abac55575820fc1db637b138bb05de61c942847809a1ee127866dba31c";
        let together = format!("{}{}{}", address, message, signature);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        assert_eq!(ret.ok(), Some(false));
    }

    #[test]
    fn test_inter_chain_trx_3() {
        // Result: false (Transaction Hash is Wrong)
        let address = "8be74d722deb7c2ba962be126ae9c00f121e3562";
        let message = "e63db8a544dfc640c63703f53b91579f7fec46f066432b56ec7daf5a0b7740bc";
        let signature = "c7acecc3e84328c32fd6ee8a5264e203d371a1bff5561176906afdcf988a32097504b088abac55575820fc1db637b138bb05de61c942847809a1ee127866dba31c";
        let together = format!("{}{}{}", address, message, signature);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        assert_eq!(ret.ok(), Some(false));
    }

    #[test]
    fn test_inter_chain_trx_4() {
        // Result: false (Transaction Hash Signature is Wrong)
        let address = "8be74d722deb7c2ba962be126ae9c00f121e3562";
        let message = "e62db8a544dfc640c63703f53b91579f7fec46f066432b56ec7daf5a0b7740bc";
        let signature = "d7acecc3e84328c32fd6ee8a5264e203d371a1bff5561176906afdcf988a32097504b088abac55575820fc1db637b138bb05de61c942847809a1ee127866dba31c";
        let together = format!("{}{}{}", address, message, signature);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        assert_eq!(ret.ok(), Some(false));
    }

    #[test]
    fn test_inter_chain_trx_5() {
        // Result: false (Failed Transaction - Address, Transaction Hash)
        let address = "b4066e3f167a4e5b7b97cca2b163ee396cfd0a1d";
        let message = "a0a5e34b9b19b398c5a073513ecb461899ceb45246f51e6d470ae0cf23b39075";
        let signature = "d7acecc3e84328c32fd6ee8a5264e203d371a1bff5561176906afdcf988a32097504b088abac55575820fc1db637b138bb05de61c942847809a1ee127866dba31c";
        let together = format!("{}{}{}", address, message, signature);
        let input1 = read_hex(&together).unwrap();
        let ret = inter_chain_trx(&input1);
        assert_eq!(ret.ok(), Some(false));
    }
}