//! # ed25519 Precompile
//!
//! This module implements a precompile for ed25519 curve support.
//!
//! The main purpose of this precompile is to verify ECDSA signatures that use the ed25519 elliptic
//! curve. The [`ED25519VERIFY`](crate::ed25519::ED25519VERIFY) const represents the implementation
//! of this precompile, with the address that it is currently deployed at.

use crate::addresses::ED25519VERIFY_ADDRESS;
use ed25519::Signature;
use ed25519_dalek::VerifyingKey;
use revm::{
    precompile::{u64_to_address, Precompile, PrecompileWithAddress},
    primitives::{
        Bytes, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult, B256,
    },
};
use sha2::Sha512VarCore;

/// Base gas fee for ed25519verify operation.
const ED25519VERIFY_BASE: u64 = 3_450;

/// Returns the ed25519 precompile with its address.
pub fn precompiles() -> impl Iterator<Item = PrecompileWithAddress> {
    [ED25519VERIFY].into_iter()
}

/// ed25519 precompile.
pub const ED25519VERIFY: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(ED25519VERIFY_ADDRESS),
    Precompile::Standard(ed25519_verify),
);

/// ed25519 precompile logic. It takes the input bytes sent to the precompile
/// and the gas limit. The output represents the result of verifying the
/// ed25519 signature of the input.
///
/// TODO: emphasis that this type of operation would live in a `hazmat`-style "DO NOT TOUCH THIS
/// UNLESS YOU KNOW WHAT YOU'RE DOING" crate
///
/// The input is encoded as follows:
///
/// | signed message hash |  r  |  s  | public key  |
/// | :-----------------: | :-: | :-: | :---------: |
/// |          64         | 32  | 32  |     32      |
fn ed25519_verify(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if ED25519VERIFY_BASE > gas_limit {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }
    let result = verify_impl(input).is_some();
    let out = PrecompileOutput::new(
        ED25519VERIFY_BASE,
        B256::with_last_byte(result as u8).into(),
    );
    Ok(out)
}

/// Returns `Some(())` if the signature included in the input byte slice is
/// valid, `None` otherwise.
fn verify_impl(input: &[u8]) -> Option<()> {
    if input.len() < 160 {
        return None;
    }

    // msg signed (msg is already the hash of the original message)
    let msg: &[u8; 64] = input[..64].try_into().unwrap();
    // r, s: signature
    let sig: &[u8; 64] = input[64..128].try_into().unwrap();
    // public key
    let pk: &[u8; 32] = input[128..160].try_into().unwrap();

    // Can fail only if the input is not exact length.
    let signature = Signature::from_slice(sig).unwrap();
    // Can fail if the input is not valid, so we have to propagate the error.
    let public_key = VerifyingKey::from_bytes(&pk).ok()?;

    // we do not use verify_prehashed because weak keys are bad
    // we do not use a domain separator, although it may be valid
    // TODO: dalek api doesnt support raw prehashed data unless we impl the trait
    // TODO: meter based on unbounded input
    // public_key
    //     .verify_prehashed_strict(wrapper, None, &signature)
    //     .ok()
    todo!("accept unbounded input, meter with prehashed")
}
