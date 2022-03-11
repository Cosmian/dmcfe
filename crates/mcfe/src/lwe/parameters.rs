use std::{cmp::Ordering, fmt::Display};

use cosmian_crypto_base::primes::closest_primes_to_power_of_2;
use num_bigint::BigUint;
use num_traits::pow::Pow;
use serde::{Deserialize, Serialize};

/// MCFE and DMCFE setup parameters.
/// Public parameters are derived from these
//
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Setup {
    /// n: Number of clients
    pub clients: usize,
    /// m: Length of the message vector (number of elements)
    pub message_length: usize,
    /// P: Message elements upper bound P i.e. x₁ ∈ {0,..., P-1}ᵐ where i∈{n}
    pub message_bound: BigUint,
    /// V: Vectors elements upper bound V i.e. yᵢ ∈ {0,..., V-1}ᵐ where i∈{n}
    pub vectors_bound: BigUint,
    /// n₀: size of key (s term)
    pub n0: usize,
}

/// Public Parameters for the Multi-Client Inner-Product Functional Encryption
/// in the Random-Oracle Model
#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    /// n: Number of clients
    pub clients: usize,
    /// m: Length of the message vector (number of elements)
    pub message_length: usize,
    /// P: Message elements upper bound P i.e. x₁ ∈ {0,..., P-1}ᵐ where i∈{n}
    pub message_bound: BigUint,
    /// V: Vectors elements upper bound V i.e. yᵢ ∈ {0,..., V-1}ᵐ where i∈{n}
    pub vectors_bound: BigUint,
    /// K: Inner Product elements upper bound i.e. ∑yᵢ.x₁ ∈ {0, K-1}ᵐ  => K =
    /// n.m.P.V
    pub k: BigUint,
    /// q the modulo of the key
    pub q: BigUint,
    /// q₀ the modulo the result is reduced to
    pub q0: BigUint,
    /// n₀: size of key (s term)
    pub n0: usize,
    /// σ=α.q the standard deviation of the tᵢ term in the key
    pub sigma: BigUint,
    /// m₀: size of t term in key
    pub m0: usize,
    /// ⌊q/K⌋ - used for encryption
    pub(crate) q_div_k: BigUint,
    /// ⌊q/2⌋ - used for rounding
    pub(crate) half_q: BigUint,
    /// ⌊q0*q/k⌋ - used for rounding in decryption
    pub(crate) q0_q_div_k: BigUint,
    /// ⌊q0*q/2k⌋ - used for rounding in decryption
    pub(crate) q0_q_div_2k: BigUint,
}

// n = 2048
// sigma = 100000000
// q = 2^127-1
// usvp: rop:  ≈2^98.4,  red:  ≈2^98.4,  δ_0: 1.006860,  β:  173,  d: 4886,  m:
// ≈2^11.5  dec: rop: ≈2^101.3,  m:  ≈2^11.6,  red: ≈2^101.3,  δ_0: 1.006745,
// β:  178,  d: 5145,  babai:  ≈2^88.5,  babai_op: ≈2^103.6,  repeat:        1,
// ε:        1 dual: rop: ≈2^101.4,  m:  ≈2^11.6,  red: ≈2^101.4,  δ_0:
// 1.006746,  β:  178,  repeat:  ≈2^40.7,  d: 5178,  c:        1

// n, alpha, q = 512, 0.00001, 65537
// usvp: rop: ≈2^102.3,  red: ≈2^102.3,  δ_0: 1.006611,  β:  184,  d:  912,  m:
// 399 dec: rop: ≈2^111.1,  m:      416,  red: ≈2^111.1,  δ_0: 1.006592,  β:
// 185,  d:  928,  babai:  ≈2^96.1,  babai_op: ≈2^111.2,  repeat:      293,  ε:
// 0.015625 dual: rop: ≈2^114.7,  m:      447,  red: ≈2^114.7,  δ_0: 1.006196,
// β:  205,  repeat:  ≈2^73.4,  d:  959,  c:        1

#[allow(clippy::many_single_char_names)]
impl Parameters {
    pub fn instantiate(setup: &Setup) -> anyhow::Result<Parameters> {
        let (n, m, p, v) = (
            setup.clients,
            setup.message_length,
            &setup.message_bound,
            &setup.vectors_bound,
        );
        anyhow::ensure!(n > 0, "There should be at least one client");
        anyhow::ensure!(m > 0, "The messages should have at least one element");

        // deactivated because of tests
        // if p < &BigUint::from(2u32) {
        //     return Err("The message bound should be at least 2".to_string());
        // }
        anyhow::ensure!(
            v >= &BigUint::from(2u32),
            "The vectors bound should be at least 2"
        );

        let k: BigUint = p * v * n * m;
        // C.3: σ = α.q > 10.n.P²
        // but we also find in the security proof that  σ = α.q > 10.n.V ?
        let mut sigma = BigUint::from(10u32) * n * m * v;
        let min_sigma = BigUint::from(100_000_u32);
        if sigma < min_sigma {
            sigma = min_sigma;
        }
        // n₀: size of key ? fix arbitrarily for now
        let n0 = setup.n0;
        // C.3: q₀ > K(nmV+1)
        let q0_lower_bound: BigUint = &k * (v * n * m + 1u32);
        let q0 = q0_lower_bound;
        //change this for optimization (e.g. power of 2)
        // No condition on q except q > q₀ and q >> K
        // There is a condition appearing where B=σ.σ', κ=ω(1) and q > q₀.n₀^ω(1).B
        // |tᵢ.eₗ| <= B when H(l) is using LWE with also q >= Ω(√n₀/α')
        let mut q = closest_next_prime_to(&q0)?;
        let min_prime = BigUint::from(65537u32);
        if q < min_prime {
            q = min_prime;
        }
        // this is used in encrypt
        let q_div_k = &q / &k;
        // C.3: m₀>= Ω(log₂(q) + 4.m.n.log₂(P)) for adaptive security
        // C.3: m₀>= Ω(log₂(q)) for selective security
        let m0 = (q.bits() + 1) as usize;
        // ⌊q/2⌋ - used for rounding
        let half_q: BigUint = &q / 2u32;
        // ⌊q0*q/k⌋ - used for rounding in decryption
        let q0_q_div_k: BigUint = &q0 * &q_div_k;
        // ⌊q0*q/2k⌋ - used for rounding in decryption
        let q0_q_div_2k: BigUint = &q0_q_div_k / 2u32;

        Ok(Parameters {
            clients: n,
            message_length: m,
            message_bound: p.clone(),
            vectors_bound: v.clone(),
            k,
            q,
            q0,
            n0,
            sigma,
            m0,
            q_div_k,
            half_q,
            q0_q_div_k,
            q0_q_div_2k,
        })
    }

    /// Return the public parameters used to encrypt functional key shares
    /// In the decentralized setting, given these encryption parameters
    /// for messages
    pub fn fks_parameters(&self) -> anyhow::Result<Parameters> {
        // The message is a ∑ skyᵢ * zᵢ which are modulo q
        // ... so the message bound is q
        // The decryption is performed by doing the scalar product with a 1 vector
        // ... so the vectors_bound is 2
        let mut fks = Parameters::instantiate(&Setup {
            clients: self.clients,
            message_length: 1,
            message_bound: self.q.clone(),
            vectors_bound: BigUint::from(2u32),
            n0: self.n0,
        })?;
        //TODO wait for David/ENS to come back with proper sigma determination
        fks.sigma = self.sigma.clone();
        Ok(fks)
    }
}

impl Display for Parameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n n: {}, m: {}, P: {}, V: {} K: {}\n q:  {} ({} bits)\n q₀: {} ({} bits)\n n₀: \
             {}, m₀: {}, σ: {}\n}}",
            self.clients,
            self.message_length,
            self.message_bound,
            self.vectors_bound,
            self.k,
            self.q,
            self.q.bits(),
            self.q0,
            self.q0.bits(),
            self.n0,
            self.m0,
            self.sigma
        )
    }
}

/// Find the closest next prime for the given `value`
///
/// This will only work for primes of size ∈ [8,400[ bits
fn closest_next_prime_to(value: &BigUint) -> anyhow::Result<BigUint> {
    let bits = value.bits() as usize;
    for n in bits + 1..bits + 3 {
        let ks = closest_primes_to_power_of_2(n)?;
        let two_pow_n = (BigUint::from(2u32)).pow(n as u64);
        for k in ks.iter().rev() {
            let prime = two_pow_n.clone() - k;
            if prime.cmp(value) == Ordering::Greater {
                return Ok(prime)
            }
        }
    }
    anyhow::bail!(
        "failed finding a prime greater than 2^{} for {}",
        bits,
        &value
    )
}
