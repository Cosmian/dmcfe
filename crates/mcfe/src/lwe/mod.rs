use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

mod centralized;
pub mod common;
mod decentralized;
mod parameters;

pub type Setup = parameters::Setup;
pub type Parameters = parameters::Parameters;
pub type Mcfe = centralized::Mcfe;
pub type DMcfe = decentralized::DMcfe;
// size 1x(n₀+m₀)
pub type LabelVector = Vec<BigUint>;

/// Client secret Key of size m * n₀+m₀
#[derive(Serialize, Deserialize, Clone)]
pub struct SecretKey(pub Vec<Vec<BigUint>>);

/// Master secret key that holds all client keys, size nx[mx(n₀+m₀)]
pub type MasterSecretKey = Vec<SecretKey>;

/// A functional Key of  1 x (n₀+m₀)
#[derive(Serialize, Deserialize, Clone)]
pub struct FunctionalKey(pub Vec<BigUint>);
/// Encrypted client share of a functional key in the decentralized model
/// The client encrypt its share of   ∑ yᵢ.Zᵢ with i ∈ {m}
#[derive(Serialize, Deserialize, Clone)]
pub struct FunctionalKeyShare(pub Vec<BigUint>);

// A utility used for testing only that generates secret keys to
// be used in the encryption of functional keys shares and that
// sum to zero across clients
//TODO this must go in the future an be replace by a proper MPC protocol
#[allow(dead_code)]
pub fn fks_secret_keys(fks_parameters: &Parameters) -> anyhow::Result<Vec<SecretKey>> {
    decentralized::fks_secret_keys(fks_parameters)
}
