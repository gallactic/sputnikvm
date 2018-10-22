extern crate bigint;
extern crate sputnikvm;
extern crate sputnikvm_precompiled_modexp;
extern crate sputnikvm_precompiled_bn128;
extern crate sputnikvm_precompiled_edverify;

use std::marker::PhantomData;
use bigint::{Gas, U256, H160, Address};
use sputnikvm::{Precompiled, AccountPatch, Patch,
                ID_PRECOMPILED, ECREC_PRECOMPILED, SHA256_PRECOMPILED, RIP160_PRECOMPILED};
use sputnikvm_precompiled_modexp::MODEXP_PRECOMPILED;
use sputnikvm_precompiled_bn128::{BN128_ADD_PRECOMPILED, BN128_MUL_PRECOMPILED, BN128_PAIRING_PRECOMPILED};
use sputnikvm_precompiled_edverify::{EDVERIFY_PRECOMPILED};

//Gallactic account patch
pub struct GallacticAccountPatch;
impl AccountPatch for GallacticAccountPatch {
    fn initial_nonce() -> U256 { U256::zero() }
    fn initial_create_nonce() -> U256 { Self::initial_nonce() }
    fn empty_considered_exists() -> bool { true }
}

pub static GALLACTIC_PRECOMPILEDS: [(Address, Option<&'static [u8]>, &'static Precompiled); 9] = [
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01]),
     None,
     &ECREC_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02]),
     None,
     &SHA256_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03]),
     None,
     &RIP160_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x04]),
     None,
     &ID_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x05]),
     None,
     &MODEXP_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x06]),
     None,
     &BN128_ADD_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x07]),
     None,
     &BN128_MUL_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x08]),
     None,
     &BN128_PAIRING_PRECOMPILED),
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x64]),
     None,
     &EDVERIFY_PRECOMPILED),
     /*TODO: Need to work on
    (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x65]),
     None,
     &CHK_INT_TRX_PRECOMPILED),
     (H160([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x66]),
     None,
     &CRT_NEW_BLK_PRECOMPILED),*/
];

// Gallactic Frontier patch.
pub struct FrontierPatch<A: AccountPatch>(PhantomData<A>);
pub type GallacticFrontierPatch = FrontierPatch<GallacticAccountPatch>;

impl<A: AccountPatch> Patch for FrontierPatch<A> {
    type Account = A;
    fn code_deposit_limit() -> Option<usize> { None }
    fn callstack_limit() -> usize { 1024 }
    fn gas_extcode() -> Gas { Gas::from(700usize) }
    fn gas_balance() -> Gas { Gas::from(400usize) }
    fn gas_sload() -> Gas { Gas::from(200usize) }
    fn gas_suicide() -> Gas { Gas::from(5000usize) }
    fn gas_suicide_new_account() -> Gas { Gas::from(25000usize) }
    fn gas_call() -> Gas { Gas::from(700usize) }
    fn gas_expbyte() -> Gas { Gas::from(50usize) }
    fn gas_transaction_create() -> Gas { Gas::from(32000usize) }
    fn force_code_deposit() -> bool { false }
    fn has_delegate_call() -> bool { true }
    fn has_static_call() -> bool { true }
    fn has_revert() -> bool { true }
    fn has_return_data() -> bool { true }
    fn has_bitwise_shift() -> bool { true }
    fn has_extcodehash() -> bool { true }
    fn err_on_call_with_more_gas() -> bool { false }
    fn call_create_l64_after_gas() -> bool { true }
    fn memory_limit() -> usize { usize::max_value() }
    fn precompileds() -> &'static [(Address, Option<&'static [u8]>, &'static Precompiled)] {
        &GALLACTIC_PRECOMPILEDS }
}
