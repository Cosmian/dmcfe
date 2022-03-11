use anyhow::ContextCompat as _;
use num_bigint::BigUint;

use super::{
    common::{self, decrypt, encrypt, secret_key},
    parameters::Parameters,
    FunctionalKey, FunctionalKeyShare, SecretKey,
};

/// Implementation of a Decentralized Multi-Client Inner-Product Functional
/// Encryption in the Random-Oracle Model
///
/// Michel Abdalla, Florian Bourse, Hugo Marival,
/// David Pointcheval, Azam Soleimanian, and Hendrik Waldner
pub struct DMcfe {
    pub(crate) parameters: Parameters,
    pub(crate) sk: Option<SecretKey>,
    // These are the parameters used to encrypt
    // the functional key share
    pub(crate) fks_parameters: Parameters,
}

impl DMcfe {
    /// Instantiate the Decentralized Multi Client Functional Scheme from the
    /// given public `Parameters` acting as the given `client` number
    pub fn instantiate(parameters: &Parameters) -> anyhow::Result<DMcfe> {
        Ok(DMcfe {
            parameters: parameters.clone(),
            sk: None,
            fks_parameters: parameters.fks_parameters()?,
        })
    }

    /// Return the public parameters used for message encryption
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    /// Return the public parameters used to encrypt
    // the functional key shares
    pub fn fks_parameters(&self) -> &Parameters {
        &self.fks_parameters
    }

    /// Generate a Client Secret Key and set it on the DMCFE instance
    ///
    /// Zᵢ = (sᵢ, tᵢ) ← Z¹ˣⁿ⁰ × D[ℤ¹ˣᵐ⁰,αq] for i∈{n}
    ///
    /// A Vector of all these keys constitute the Master Secret Key
    pub fn new_secret_key(&mut self) -> &SecretKey {
        self.sk = Some(secret_key(&self.parameters));
        self.sk
            .as_ref()
            .expect("This cannot happen; we just set the key on the option")
    }

    /// Retrieve a Secret Key it one has been set on the DMCFE instance
    pub fn secret_key(&self) -> &Option<SecretKey> {
        &self.sk
    }

    /// Set a Secret Key on the DMCFE instance
    pub fn set_secret_key(&mut self, sk: SecretKey) {
        self.sk = Some(sk)
    }

    /// Encrypt the given `message` of length `m` for the given `label`.
    /// Returns a vector of cipher texts of length `m`
    ///
    /// using: `ctᵢ_ₗ = ⌊Zᵢ.H(l) + ⌊q/K⌋.xᵢ⌉->q₀`
    /// where ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is the rounding function
    pub fn encrypt(&self, message: &[BigUint], label: &[u8]) -> anyhow::Result<Vec<BigUint>> {
        let secret_key = self
            .sk
            .as_ref()
            .context("The secret key must be generated or set before encrypting a value.")?;
        encrypt(&self.parameters, label, message, secret_key)
    }

    // pub(crate) fn create_functional_key_hash_vector(
    //     &self,
    //     vectors: &[Vec<BigUint>],
    // ) -> Vec<BigUint> {
    //     let mut bytes: Vec<u8> = vec![];
    //     for row in vectors {
    //         for el in row {
    //             bytes.extend_from_slice(&el.to_bytes_be());
    //         }
    //     }
    //     create_hash_vector(
    //         &bytes,
    //         self.fks_parameters.n0 + self.fks_parameters.m0,
    //         &self.fks_parameters.q,
    //     )
    // }

    /// Issue a functional key share for the `vectors` as client number `client`
    ///
    /// The `share_secret_key` must have been issued with the other clients
    /// so that `∑ fks_skᵢ = 0` where `i ∈ {n}` and `n` is the number of
    /// clients.
    ///
    /// The `vectors` has `number of clients` vectors of message length`
    ///
    /// Calculated as `fksᵢ = Enc₂(fks_skᵢ, yᵢ.sk, ᵢ, H(y))` where `i` is this
    /// client number, `fks_skᵢ` is the functional key share secret key,
    /// `sk` is the secret key and `yᵢ` is the vector for that client
    pub fn functional_key_share(
        &self,
        fks_secret_key: &SecretKey,
        vectors: &[Vec<BigUint>],
        client: usize,
    ) -> anyhow::Result<FunctionalKeyShare> {
        let secret_key = self.sk.as_ref().context(
            "The secret key must be generated or set before generating the functional key share.",
        )?;
        common::encrypted_functional_key_share(
            &self.parameters,
            &secret_key,
            fks_secret_key,
            vectors,
            client,
        )
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
    ) -> anyhow::Result<FunctionalKey> {
        common::recover_functional_key(&self.parameters, functional_key_shares, vectors)
    }

    /// Generate a secret key which can be used to perform the
    /// functional key sharing
    ///
    /// Please not that the sums of these keys across clients
    /// must be equal to zero i.e. ∑fks_skᵢ = 0 for i∈{n}
    pub fn fks_secret_key(&self) -> SecretKey {
        secret_key(&self.fks_parameters)
    }

    /// Calculate and decrypt the inner product vector of `<messages , vectors>`
    /// for the given `cipher_texts`, `label` and `functional_key`.
    ///
    ///  - The `cipher_texts` vectors size must be equal to `number of clients x
    ///    message length`.
    ///  - The `functional_key` vectors must have `message length` rows.
    ///  - The `vectors` must contain `number of clients` vectors of  `message
    ///    length`.
    ///
    /// Calculated as `μ = ∑yᵢ.ctᵢ_ₗ - ⌊sk.H(l)⌉->q₀ mod q₀` for each message
    /// element where `i∈{n}` and ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is
    /// the rounding function
    pub fn decrypt(
        &self,
        cipher_texts: &[Vec<BigUint>],
        label: &[u8],
        functional_key: &FunctionalKey,
        vectors: &[Vec<BigUint>],
    ) -> anyhow::Result<BigUint> {
        decrypt(
            &self.parameters,
            label,
            cipher_texts,
            functional_key,
            vectors,
        )
    }
}

// A utility used for testing only that generates secret keys to
// be used in the encryption of functional keys shares and that
// sum to zero across clients
pub fn fks_secret_keys(fks_parameters: &Parameters) -> anyhow::Result<Vec<SecretKey>> {
    let (m, n, fks_n0_m0, fks_q) = (
        fks_parameters.message_length, //should be 1
        fks_parameters.clients,
        fks_parameters.n0 + fks_parameters.m0,
        &fks_parameters.q,
    );
    let mut fks_sk: Vec<SecretKey> = Vec::with_capacity(n);
    for _i in 0..n - 1 {
        fks_sk.push(secret_key(fks_parameters));
    }

    let mut last_fks_sk_array: Vec<Vec<BigUint>> = Vec::with_capacity(m);
    for mi in 0..m {
        let mut last_fks_sk_array_mi: Vec<BigUint> = Vec::with_capacity(fks_n0_m0);
        for j in 0..fks_n0_m0 {
            let mut sum = BigUint::from(0u32);
            for fks_sk_i in fks_sk.iter().take(n - 1) {
                sum += &fks_sk_i.0[mi][j];
            }
            sum %= fks_q;
            last_fks_sk_array_mi.push((fks_q - sum) % fks_q);
        }
        last_fks_sk_array.push(last_fks_sk_array_mi);
    }
    fks_sk.push(SecretKey(last_fks_sk_array));
    // check that the fks keys actually sum to zero
    for mi in 0..m {
        for j in 0..fks_n0_m0 {
            let mut sum = BigUint::from(0u32);
            for fks_sk_i in &fks_sk {
                sum += &fks_sk_i.0[mi][j];
            }
            sum %= fks_q;
            assert_eq!(BigUint::from(0u32), sum);
        }
    }
    Ok(fks_sk)
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests {

    use cosmian_crypto_base::cs_prng::Uniform;
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};

    use super::{super::common::tests::paper_params, fks_secret_keys, DMcfe, Parameters};
    use crate::lwe::{
        common::{create_functional_key_label, functional_key},
        parameters::Setup,
        FunctionalKey, FunctionalKeyShare, MasterSecretKey, SecretKey,
    };

    #[test]
    fn test_h_y() {
        let params = paper_params();
        // generate test data
        let (n, m) = (params.clients, params.message_length);
        let mut label = [0u8; 32];
        thread_rng().fill(&mut label);
        let mut uniform = Uniform::new();
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for _c in 0..n {
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                vectors_c.push(uniform.big_uint_below(&params.vectors_bound));
            }
            vectors.push(vectors_c);
        }
        assert_eq!(
            create_functional_key_label(&vectors),
            create_functional_key_label(&vectors)
        );
    }

    fn test_functional_key_shares(params: &Parameters) -> anyhow::Result<()> {
        // generate test data
        let (n, m, q, n0_m0) = (
            params.clients,
            params.message_length,
            &params.q,
            params.n0 + params.m0,
        );
        let mut label = [0u8; 32];
        thread_rng().fill(&mut label);
        let mut uniform = Uniform::new();
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for _c in 0..n {
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                vectors_c.push(uniform.big_uint_below(&params.vectors_bound));
            }
            vectors.push(vectors_c);
        }
        // we need as many DMCFE as there are clients
        let mut dmcfes: Vec<DMcfe> = Vec::with_capacity(n);
        for _ in 0..n {
            let mut dmcfe = DMcfe::instantiate(&params)?;
            dmcfe.new_secret_key();
            dmcfes.push(dmcfe);
        }
        // calculate the expected functional key at the same time
        let mut expected_fk = vec![BigUint::from(0u32); n0_m0];
        for j in 0..n0_m0 {
            for i in 0..n {
                for mi in 0..m {
                    expected_fk[j] += &vectors[i][mi] * &dmcfes[i].sk.as_ref().unwrap().0[mi][j]
                }
            }
        }
        // make the fk modulo q
        for j in 0..n0_m0 {
            expected_fk[j] %= q
        }
        //
        // debug
        println!("    Parameters: {}", &params);
        println!("FKS Parameters: {}", &params.fks_parameters()?);

        //
        // Centralized
        // generate a master secret key (i.e. keys for all clients)
        let mut msk: MasterSecretKey = Vec::with_capacity(n);
        for i in 0..n {
            msk.push(dmcfes[i].sk.as_ref().unwrap().clone());
        }
        // generate the functional key in a centralized way
        let centralized_fk: FunctionalKey = functional_key(&params, &msk, &vectors)?;
        //
        // Decentralized
        // generate the functional key share secret keys fks_skᵢ s.t. ∑fks_skᵢ=0, where
        // i∈{n}
        let fks_sk: Vec<SecretKey> = fks_secret_keys(&params.fks_parameters()?)?;

        // println!("Client 0 fks_sk: {:?}", fks_sk[0]);
        // create the functional key shares
        let mut fks: Vec<FunctionalKeyShare> = Vec::with_capacity(n);
        for i in 0..n {
            fks.push(dmcfes[i].functional_key_share(&fks_sk[i], &vectors, i)?);
        }
        println!("Generated {} functional key shares", n);
        // recover the function key
        let recovered_fk: FunctionalKey =
            DMcfe::instantiate(&params)?.recover_functional_key(&fks, &vectors)?;
        println!("Recombined the functional key");
        // compare
        assert_eq!(n0_m0, recovered_fk.0.len());
        for j in 0..n0_m0 {
            assert_eq!(
                &expected_fk[j],
                &centralized_fk.0[j],
                "j: {}, expected: {} [{} bits], centralized: {} [{} bits]",
                j,
                &expected_fk[j],
                &expected_fk[j].bits(),
                &centralized_fk.0[j],
                &centralized_fk.0[j].bits(),
            );
            assert_eq!(
                &expected_fk[j],
                &recovered_fk.0[j],
                "j: {}, expected: {} [{} bits], recovered: {} [{} bits]",
                j,
                &expected_fk[j],
                &expected_fk[j].bits(),
                &recovered_fk.0[j],
                &recovered_fk.0[j].bits()
            );
            assert_eq!(
                &centralized_fk.0[j],
                &recovered_fk.0[j],
                "j: {}, centralized: {} [{} bits], recovered: {} [{} bits]",
                j,
                &centralized_fk.0[j],
                &centralized_fk.0[j].bits(),
                &recovered_fk.0[j],
                &recovered_fk.0[j].bits()
            );
        }

        Ok(())
    }

    #[test]
    fn test_functional_keys_shares() -> anyhow::Result<()> {
        // note: n0 at 256 is too low for security - this is just to test the
        // functionality
        test_functional_key_shares(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 10,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 256,
        })?)?;
        // test_functional_key_shares(&paper_params())?; // too long for CI
        test_functional_key_shares(&Parameters::instantiate(&Setup {
            clients: 10,
            message_length: 31,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 256,
        })?)?;
        test_functional_key_shares(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 31,
            message_bound: BigUint::from(2u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 256,
        })?)?;
        Ok(())
    }

    fn test_encryption_decryption(params: &Parameters) -> anyhow::Result<()> {
        println!("    Parameters: {}", &params);
        println!("FKS Parameters: {}", &params.fks_parameters()?);
        // generate test data
        let (n, m) = (params.clients, params.message_length);
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        // generate fks secret keys which sum to zero
        let fks_sks: Vec<SecretKey> = fks_secret_keys(&params.fks_parameters()?)?;
        let mut uniform = Uniform::new();
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for _i in 0..n {
            let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            // dmcfes.push(dmcfe);
            for _mi in 0..m {
                message_c.push(uniform.big_uint_below(&params.message_bound));
                vectors_c.push(uniform.big_uint_below(&params.vectors_bound));
            }
            messages.push(message_c);
            vectors.push(vectors_c);
        }
        let mut fks: Vec<FunctionalKeyShare> = Vec::with_capacity(n);
        let mut expected = BigUint::from(0u32);
        for i in 0..n {
            let mut dmcfe = DMcfe::instantiate(params)?;
            dmcfe.new_secret_key();
            fks.push(dmcfe.functional_key_share(&fks_sks[i], &vectors, i)?);
            cts.push(dmcfe.encrypt(&messages[i], &label)?);
            for mi in 0..m {
                expected += &messages[i][mi] * &vectors[i][mi];
            }
        }
        // recover functional key
        let consumer = DMcfe::instantiate(&params)?;
        let fk: FunctionalKey = consumer.recover_functional_key(&fks, &vectors)?;
        // decryption
        let result = consumer.decrypt(&cts, &label, &fk, &vectors)?;
        assert_eq!(&expected, &result);
        println!("  ==> OK\n");
        Ok(())
    }

    #[test]
    //this works but takes a VERY long time to complete if not run in release mode
    // note: n0 at 256 is too low for security - this is just to test the
    // functionality
    fn test_encryption_decryptions() -> anyhow::Result<()> {
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 10,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 256,
        })?)?;
        // test_encryption_decryption(&paper_params())?; //too long for CI
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 10,
            message_length: 31,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 256,
        })?)?;
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 31,
            message_bound: BigUint::from(2u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 256,
        })?)?;
        Ok(())
    }
}
