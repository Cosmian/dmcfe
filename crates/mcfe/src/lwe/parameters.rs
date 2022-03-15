use crate::lwe::{common, FunctionalKey, FunctionalKeyShare, MasterSecretKey, SecretKey};
use anyhow::Result;
use cosmian_crypto_base::cs_prng::{Normal, Uniform};
use cosmian_crypto_base::primes::closest_primes_to_power_of_2;
use num_bigint::{BigInt, BigUint};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;

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

impl TryFrom<&Setup> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(setup: &Setup) -> Result<Self, Self::Error> {
        Ok(Parameters::instantiate(setup)?.secret_key())
    }
}

impl TryFrom<&Setup> for MasterSecretKey {
    type Error = anyhow::Error;

    fn try_from(setup: &Setup) -> Result<Self, Self::Error> {
        Ok(Parameters::instantiate(setup)?.master_secret_key())
    }
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
    /// TODO: is it useful since bit shifting allows efficient computation of
    /// this division?
    pub(crate) half_q: BigUint,
    /// ⌊q0*q/k⌋ - used for rounding in decryption
    pub(crate) q0_q_div_k: BigUint,
    /// ⌊q0*q/2k⌋ - used for rounding in decryption
    /// TODO: is it useful since bit shifting allows efficient computation of
    /// this division?
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

impl From<&Parameters> for SecretKey {
    fn from(parameters: &Parameters) -> Self {
        parameters.secret_key()
    }
}

impl From<&Parameters> for MasterSecretKey {
    fn from(parameters: &Parameters) -> Self {
        parameters.master_secret_key()
    }
}

impl Parameters {
    pub fn instantiate(setup: &Setup) -> anyhow::Result<Parameters> {
        anyhow::ensure!(setup.clients > 0, "There should be at least one client");
        anyhow::ensure!(
            setup.message_length > 0,
            "The messages should have at least one element"
        );
        anyhow::ensure!(
            setup.vectors_bound >= BigUint::from(2u32),
            "The vectors bound should be at least 2"
        );

        let k = &setup.message_bound * &setup.vectors_bound * setup.clients * setup.message_length;

        // C.3: σ = α.q > 10.n.P²
        // but we also find in the security proof that  σ = α.q > 10.n.V ?
        let sigma = BigUint::max(
            BigUint::from(10u32) * setup.clients * setup.message_length * &setup.vectors_bound,
            BigUint::from(100_000_u32),
        );

        // C.3: q₀ > K(nmV+1)
        let q0 = &k * (&setup.vectors_bound * setup.clients * setup.message_length + 1u32);

        // change this for optimization (e.g. power of 2)
        // No condition on q except q > q₀ and q >> K
        // There is a condition appearing where B=σ.σ', κ=ω(1) and q > q₀.n₀^ω(1).B
        // |tᵢ.eₗ| <= B when H(l) is using LWE with also q >= Ω(√n₀/α')
        let q = BigUint::max(closest_next_prime_to(&q0)?, BigUint::from(65537u32));
        // this is used in encrypt
        let q_div_k = &q / &k;
        // ⌊q/2⌋ - used for rounding
        let half_q: BigUint = &q / 2u32;
        // ⌊q0*q/k⌋ - used for rounding in decryption
        let q0_q_div_k: BigUint = &q0 * &q_div_k;
        // ⌊q0*q/2k⌋ - used for rounding in decryption
        let q0_q_div_2k: BigUint = &q0_q_div_k / 2u32;

        Ok(Parameters {
            clients: setup.clients,
            message_length: setup.message_length,
            message_bound: setup.message_bound.clone(),
            vectors_bound: setup.vectors_bound.clone(),
            k,
            q0,
            n0: setup.n0,
            sigma,
            // C.3: m₀>= Ω(log₂(q) + 4.m.n.log₂(P)) for adaptive security
            // C.3: m₀>= Ω(log₂(q)) for selective security
            m0: (q.bits() + 1) as usize,
            q_div_k,
            half_q,
            q0_q_div_k,
            q0_q_div_2k,
            q,
        })
    }

    /// Return the public parameters used to encrypt functional key shares
    /// In the decentralized setting, given these encryption parameters
    /// for messages
    pub fn fks_parameters(&self) -> Result<Parameters> {
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

    /// Generate a Client Secret Key
    ///
    /// Zᵢ = (sᵢ, tᵢ) ← Z¹ˣⁿ⁰ × D[ℤ¹ˣᵐ⁰,αq] for i∈{m}
    ///
    /// A Vector of all these keys constitute the Master Secret Key
    pub(crate) fn secret_key(&self) -> SecretKey {
        // TODO: see if these random number generators should not be given as argument
        // indeed, without seed, to randomly generated sequences may be identical
        let mut uniform_cs_prng = Uniform::new();
        let mut normal_cs_prng = Normal::new(&BigInt::from(0i32), &self.sigma);

        SecretKey(
            (0..self.message_length)
                .map(|_| {
                    let mut sk_mi_array = Vec::with_capacity(self.n0 + self.m0);
                    for _ in 0..self.n0 {
                        sk_mi_array.push(uniform_cs_prng.big_uint_below(&self.q))
                    }
                    for _ in 0..self.m0 {
                        sk_mi_array.push(normal_cs_prng.big_uint(&self.q));
                    }
                    sk_mi_array
                })
                .collect(),
        )
    }

    /// Generate a Master Secret Key for the centralized model
    pub(crate) fn master_secret_key(&self) -> MasterSecretKey {
        (0..self.clients).map(|_| self.secret_key()).collect()
    }

    /// Encrypt the given `message` of length `m` for the given `label` and
    /// `client`. Returns a vector of cipher texts of length `m`
    ///
    /// using: `ctᵢ_ₗ = ⌊Zᵢ.H(l) + ⌊q/K⌋.xᵢ⌉->q₀`
    /// where ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is the rounding function
    pub(crate) fn encrypt(
        &self,
        label: &[u8],
        message: &[BigUint],
        z_i: &SecretKey,
    ) -> Result<Vec<BigUint>> {
        anyhow::ensure!(
            message.len() == self.message_length,
            "The message is of length: {}, it must be of length: {}",
            message.len(),
            self.message_length,
        );

        // Zᵢ · H(l) = sₗ · aₗ + tᵢ · (Saₗ + eₗ )
        // except that we use sha3 here so we perform the dot product
        let h_l = common::create_label_vector(label, self.n0 + self.m0, &self.q);

        message
            .iter()
            .zip(z_i.0.iter())
            .map(|(u, z_ij)| {
                anyhow::ensure!(
                    u < &self.message_bound,
                    "message element: {}, is bigger than upper bound: {}",
                    u,
                    self.message_bound,
                );

                // calculate Zᵢ.H(l)
                let zi_hl: BigUint = h_l
                    .iter()
                    .zip(z_ij.iter())
                    .map(|(h_l_j, z_ijk)| h_l_j * z_ijk)
                    .sum();

                // round: modulo q and rescale to q0
                Ok(self.round_to_q0(&(zi_hl + &self.q_div_k * u)))
            })
            .collect()
    }

    /// Issue a functional key for the `vectors` from a Master Secret Key.
    /// The `vectors` has `number of clients` vectors of message length`
    ///
    /// Calculated as `sky = ∑yᵢ.Zᵢ` where `i∈{nm}`
    /// and `n` is the number of clients
    pub fn functional_key(&self, msk: &[SecretKey], y: &[Vec<BigUint>]) -> Result<FunctionalKey> {
        anyhow::ensure!(
            y.len() == self.clients,
            "The vectors number of rows: {}, must be equal to the number of clients: {}",
            y.len(),
            self.clients,
        );

        let mut sky_share: FunctionalKey =
            FunctionalKey(vec![BigUint::from(0u32); self.n0 + self.m0]);

        for (z_i, y_i) in msk.iter().zip(y.iter()) {
            let sky_i = self.clear_text_functional_key_share(z_i, y_i)?;
            for (sky_ij, sky_share_j) in sky_i.iter().zip(sky_share.0.iter_mut()) {
                *sky_share_j += sky_ij;
            }
        }

        sky_share.0.iter_mut().for_each(|sky_i| *sky_i %= &self.q);
        Ok(sky_share)
    }

    /// The client share of a functional key
    ///
    /// Calculated as `sky = ∑yᵢ.Zᵢ` where `i∈{nm}`
    /// and `n` is the number of clients
    pub fn clear_text_functional_key_share(
        &self,
        z_i: &SecretKey,
        y_i: &[BigUint],
    ) -> Result<Vec<BigUint>> {
        anyhow::ensure!(
            y_i.len() == self.message_length,
            "The vectors column size: {} must be equal that of the message: {}",
            y_i.len(),
            self.message_length,
        );

        let mut sky_share = vec![BigUint::from(0u32); self.n0 + self.m0];

        for (y_ij, z_ij) in y_i.iter().zip(z_i.0.iter()) {
            anyhow::ensure!(
                y_ij < &self.vectors_bound,
                "The vector value {} >= {}, which is not allowed",
                y_ij,
                self.vectors_bound
            );

            z_ij.iter()
                .zip(sky_share.iter_mut())
                .for_each(|(z_ijk, sky_share_k)| {
                    *sky_share_k += y_ij * z_ijk;
                });
        }

        sky_share.iter_mut().for_each(|sky_i| *sky_i %= &self.q);

        Ok(sky_share)
    }

    /// Issue an encrypted functional key share for the `vectors` as client number
    /// `client`
    ///
    /// The `share_secret_key` must have been issued with the other clients
    /// so that `∑ fks_skᵢ = 0` where `i ∈ {n}` and `n` is the number of clients.
    ///
    /// The `vectors` has `number of clients` vectors of message length`
    ///
    /// Calculated as `fksᵢ = Enc₂(fks_skᵢ, yᵢ.sk, ᵢ, H(y))` where `i` is this
    /// client number, `fks_skᵢ` is the functional key share secret key, `sk` is the
    /// secret key and `yᵢ` is the vector for that client
    /// size is m
    pub fn encrypted_functional_key_share(
        &self,
        secret_key: &SecretKey,
        fks_secret_key: &SecretKey,
        vectors: &[Vec<BigUint>],
        client: usize,
    ) -> Result<FunctionalKeyShare> {
        let n0_m0 = self.n0 + self.m0;
        anyhow::ensure!(
            client < self.clients,
            "Invalid client number: {}. There are {} clients",
            client,
            self.clients
        );

        anyhow::ensure!(
            vectors.len() == self.clients,
            "Invalid vectors length: {}. There are {} clients",
            vectors.len(),
            self.clients
        );

        anyhow::ensure!(
            vectors[0].len() == self.message_length,
            "Invalid number of vectors coefficients for client 0: {}. The message length is: {}",
            vectors[0].len(),
            self.message_length
        );

        anyhow::ensure!(
            secret_key.0.len() == self.message_length,
            "Invalid number of secret keys: {}. It should be: {}",
            secret_key.0.len(),
            self.message_length
        );

        for (mi, sk) in secret_key.0.iter().enumerate() {
            anyhow::ensure!(
                sk.len() == n0_m0,
                "Invalid secret key length: {}, for message: {}. It should be: {}",
                sk.len(),
                mi,
                n0_m0
            );
        }
        let fks_parameters = self.fks_parameters()?;
        anyhow::ensure!(
            fks_secret_key.0.len() == fks_parameters.message_length,
            "Invalid number of FKS secret keys: {}. It should be: {}",
            fks_secret_key.0.len(),
            n0_m0
        );

        for (mi, sk) in fks_secret_key.0.iter().enumerate() {
            anyhow::ensure!(
                sk.len() == fks_parameters.n0 + fks_parameters.m0,
                "Invalid FKS secret key length: {}, for message: {}. It should be: {}",
                sk.len(),
                mi,
                n0_m0
            );
        }
        // create a label for hash vector H(y)
        let h_y_label = common::create_functional_key_label(vectors);
        // encryption of all µⱼ for j ∈{n₀+m₀}
        let sky_i = self.clear_text_functional_key_share(secret_key, &vectors[client])?;
        // encrypt it
        let mut enc_fks: Vec<BigUint> = Vec::with_capacity(n0_m0);
        for (idx, sky_i_j) in sky_i.iter().enumerate() {
            // no label reuse - add counter
            let mut this_label = idx.to_be_bytes().to_vec();
            this_label.extend_from_slice(&h_y_label);
            enc_fks.push(
                fks_parameters.encrypt(&this_label, &[sky_i_j.clone()], fks_secret_key)?[0].clone(),
            );
        }
        Ok(FunctionalKeyShare(enc_fks))
    }

    /// Combine the functional key shares from the clients
    /// To recover the functional key
    ///
    /// Implemented as the scalar product of the share and the 1 vector
    /// which performs ∑skᵢ.zᵢ for i∈{n}
    pub fn recover_functional_key(
        &self,
        functional_key_shares: &[FunctionalKeyShare],
        vectors: &[Vec<BigUint>],
    ) -> Result<FunctionalKey> {
        let fks_parameters = self.fks_parameters()?;
        let fks_n0_m0 = fks_parameters.n0 + fks_parameters.m0;
        // perform the scalar products of <Enc(sk_j),1>
        // the vector to perform the n₀+m₀ scalar product over the n encrypted
        // functional key shares
        let fks_vectors = vec![vec![BigUint::from(1u32)]; self.clients];
        // the functional key is a vector of length  n₀+m₀ filled with zeroes:
        // since the functional_key_vectors is filled with 1, ∑skᵢ.yᵢ = ∑skᵢ = 0 by
        // construction
        let fks_functional_key = FunctionalKey(vec![BigUint::from(0u32); fks_n0_m0]);
        // the H(y) used is a hash of all the vectors that get into the final functional
        // computation
        let h_y_label = common::create_functional_key_label(vectors);
        // we need to perform the scalar product for the n₀+m₀ vectors
        // across the n clients
        let mut functional_key: Vec<BigUint> = Vec::with_capacity(self.n0 + self.m0);
        for j in 0..(self.n0 + self.m0) {
            // assemble all the functional key shares from all client for that j
            let mut fks_j: Vec<Vec<BigUint>> = Vec::with_capacity(self.clients);
            for fks_i in functional_key_shares {
                fks_j.push(vec![fks_i.0[j].clone()]);
            }
            // no label reuse - add counter
            let mut this_label = j.to_be_bytes().to_vec();
            this_label.extend_from_slice(&h_y_label);
            functional_key.push(
                fks_parameters.decrypt(&this_label, &fks_j, &fks_functional_key, &fks_vectors)?
                    % &self.q,
            );
        }
        Ok(FunctionalKey(functional_key))
    }

    /// Calculate and decrypt the inner product vector of `<messages , vectors>`
    /// for the given `cipher_texts`, `label` and `functional_key`.
    ///
    ///  - The `cipher_texts` vectors size must be equal to `nxm` = `number of
    ///    clients x message length`.
    ///  - The `functional_key` vectors must have size 1x(n₀+m₀) `message length`
    ///    rows.
    ///  - The `vectors` must contain `number of clients` vectors of  `message
    ///    length`.
    ///
    /// `cipher_texts` and `vectors` must have the same clients ordering
    ///
    /// Calculated as `μ = ∑yᵢ.ctᵢ_ₗ - ⌊sk.H(l)⌉->q₀ mod q₀` for each message
    /// element where `i∈{n}` and ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is the
    /// rounding function
    pub fn decrypt(
        &self,
        label: &[u8],
        cipher_texts: &[Vec<BigUint>],
        functional_key: &FunctionalKey,
        y: &[Vec<BigUint>],
    ) -> Result<BigUint> {
        anyhow::ensure!(
            cipher_texts.len() == self.clients,
            "The cipher texts vector size: {}, must be equal to the number of clients: {}",
            cipher_texts.len(),
            self.clients,
        );

        anyhow::ensure!(
            y.len() == self.clients,
            "The vector size: {}, must be equal to the number of clients: {}",
            y.len(),
            self.clients,
        );

        let sum_yc = y
            .iter()
            .zip(cipher_texts.iter())
            .map(|(y_i, c_i)| {
                y_i.iter()
                    .zip(c_i.iter())
                    .map(|(y_ij, c_ij)| y_ij * c_ij)
                    .sum::<BigUint>()
            })
            .sum::<BigUint>();

        // term to round ⌊sk.H(l)⌉->q₀
        let sk_hl = common::create_label_vector(label, self.n0 + self.m0, &self.q)
            .iter()
            .zip(functional_key.0.iter())
            .map(|(h_lj, sk_j)| sk_j * h_lj)
            .sum();

        // compute the decryption
        Ok(
            // adding an extra `self.q0` prevents underflowing
            ((((sum_yc + &self.q0 - self.round_to_q0(&sk_hl)) % &self.q0) * &self.q
                + &self.q0_q_div_2k)
                / &self.q0_q_div_k)
                % &self.k,
        )
    }

    /// Calculates ⌊(q₀/q).(x mod q)⌉ where ⌊⌉ is the rounding function performed
    /// as [(x%q)*q₀ + q/2]/q
    pub(crate) fn round_to_q0(&self, v: &BigUint) -> BigUint {
        ((v % &self.q) * &self.q0 + &self.half_q) / &self.q
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
        // TODO: bit shifting may be faster
        let two_pow_n = BigUint::from(2u32).pow(n.try_into()?);
        for k in closest_primes_to_power_of_2(n)?.iter().rev() {
            let prime = two_pow_n.clone() - k;
            if &prime >= value {
                return Ok(prime);
            }
        }
    }
    anyhow::bail!(
        "failed finding a prime greater than 2^{} for {}",
        bits,
        &value
    )
}
