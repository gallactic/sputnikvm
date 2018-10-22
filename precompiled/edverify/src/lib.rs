extern crate bigint;
extern crate num_bigint;
extern crate sputnikvm;
extern crate bn;
extern crate crypto;
extern crate ed25519;

use std::rc::Rc;
use bigint::Gas;
use std::cmp::min;

use sputnikvm::Precompiled;
use sputnikvm::errors::RuntimeError;

pub static EDVERIFY_PRECOMPILED: EdverifyPrecompiled = EdverifyPrecompiled;

pub struct EdverifyPrecompiled;
impl Precompiled for EdverifyPrecompiled {
    fn gas(&self, _data: &[u8]) -> Gas {
        /// TODO: Calculate the gas amount
        Gas::from(100u64)
    }

    fn step(&self, datao: &[u8]) -> Rc<Vec<u8>> {

        let mut data = [0u8; 128];
        let copy_bytes = min(datao.len(), 128);
        data[..copy_bytes].clone_from_slice(&datao[..copy_bytes]);
        match edverify(&data) {
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

fn edverify(data: &[u8]) -> Result<bool, RuntimeError> {
    let mut message = [0u8; 32];
    for i in 0..32 {
        message[i] = data[i];
    }

    let mut public_key = [0u8; 32];
    for i in 0..32 {
        public_key[i] = data[32+i];
    }

    let mut signature = [0u8; 64];
    for i in 0..64 {
        signature[i] = data[64+i];
    }

    let verified = crypto::ed25519::verify(&message, &public_key, &signature);

    Ok(verified)
}

#[cfg(test)]
mod tests {
    extern crate hexutil;
    use super::*;
    use self::hexutil::*;
    #[test]
    fn test_edverify_1() {
        // result: true
        // org_msg: "Test message"
        // hash(sha256): c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b1
        // public_key:   8205d9e50973457c41eafb73b9979f44a7906e1f46ad8cffb05368b95d205e8d
        // signature:    49f43c1c0b3ec67f072fadd80821ff64ee8db1f8ad2bb55a0336d46f0e5fa4eb8d070625aeab4ce9517d4d6db3f147fe91721617db180db53316529af302ae09
        let input1 = read_hex("c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b18205d9e50973457c41eafb73b9979f44a7906e1f46ad8cffb05368b95d205e8d49f43c1c0b3ec67f072fadd80821ff64ee8db1f8ad2bb55a0336d46f0e5fa4eb8d070625aeab4ce9517d4d6db3f147fe91721617db180db53316529af302ae09").unwrap();
        assert_eq!(edverify(&input1).unwrap(), true );
    }

    #[test]
    fn test_edverify_2() {
        // result: false (wrong message)
        // message :    c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b2
        // public_key:  8205d9e50973457c41eafb73b9979f44a7906e1f46ad8cffb05368b95d205e8d
        // signature:   49f43c1c0b3ec67f072fadd80821ff64ee8db1f8ad2bb55a0336d46f0e5fa4eb8d070625aeab4ce9517d4d6db3f147fe91721617db180db53316529af302ae09
        let input2 = read_hex("c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b28205d9e50973457c41eafb73b9979f44a7906e1f46ad8cffb05368b95d205e8d49f43c1c0b3ec67f072fadd80821ff64ee8db1f8ad2bb55a0336d46f0e5fa4eb8d070625aeab4ce9517d4d6db3f147fe91721617db180db53316529af302ae09").unwrap();
        assert_eq!(edverify(&input2).unwrap(), false );
    }

    #[test]
    fn test_edverify_3() {
        // result: false (wrong public_key)
        // message:     c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b1
        // public_key:  8205d9e50973457c41eafb73b9979f44a7906e1f46ad8cffb05368b95d205e8e
        // signature:   49f43c1c0b3ec67f072fadd80821ff64ee8db1f8ad2bb55a0336d46f0e5fa4eb8d070625aeab4ce9517d4d6db3f147fe91721617db180db53316529af302ae09  
        let input3 = read_hex("c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b18205d9e50973457c41eafb73b9979f44a7906e1f46ad8cffb05368b95d205e8e49f43c1c0b3ec67f072fadd80821ff64ee8db1f8ad2bb55a0336d46f0e5fa4eb8d070625aeab4ce9517d4d6db3f147fe91721617db180db53316529af302ae09").unwrap();
        assert_eq!(edverify(&input3).unwrap(), false );
    }
}