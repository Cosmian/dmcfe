use anyhow::ContextCompat as _;
use num_bigint::BigUint;

// use super::labels::Labels;
use super::{
    common::{decrypt, encrypt, functional_key, master_secret_key},
    parameters::{Parameters, Setup},
    FunctionalKey, MasterSecretKey,
};

/// Implementation of a (Centralized) Multi-Client Inner-Product Functional
/// Encryption in the Random-Oracle Model
///
/// Michel Abdalla, Florian Bourse, Hugo Marival,
/// David Pointcheval, Azam Soleimanian, and Hendrik Waldner
///
/// Security:
/// - selective security: messages that are fixed ahead of time, before the
///   adversary even interacts with the system
/// - adaptive security:  messages can be adaptively chosen at any point in time
pub struct Mcfe {
    pub(crate) parameters: Parameters,
    pub(crate) msk: Option<MasterSecretKey>,
    // pub(crate) labels: Labels,
}

impl Mcfe {
    pub fn new(parameters: &Parameters) -> Mcfe {
        Mcfe {
            parameters: parameters.clone(),
            msk: None,
            // labels: Labels::new(parameters.n0 + parameters.m0, &parameters.q),
        }
    }

    /// Shortcut instantiation for
    /// ```ignore
    ///     Ok(McFeRoM::new(Parameters::setup(setup)?))
    /// ```
    pub fn setup(setup: &Setup) -> anyhow::Result<Mcfe> {
        Ok(Mcfe::new(&Parameters::instantiate(setup)?))
    }

    /// Generate a Master Secret Key and set it on the MCFE instance
    pub fn new_master_secret_key(&mut self) {
        self.msk = Some(master_secret_key(&self.parameters));
    }

    /// Retrieve the Master Secret Key if one has been set on the MCFE instance
    pub fn master_secret_key(&self) -> &Option<MasterSecretKey> {
        &self.msk
    }

    /// Set a Master Secret Key on the MCFE instance
    pub fn set_master_secret_key(&mut self, msk: MasterSecretKey) {
        self.msk = Some(msk)
    }

    /// Encrypt the given `message` of length `m` for the given `label` and
    /// `client`. Returns a vector of cipher texts of length `m`
    ///
    /// using: `ctᵢ_ₗ = ⌊Zᵢ.H(l) + ⌊q/K⌋.xᵢ⌉->q₀`
    /// where ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is the rounding function
    pub fn encrypt(
        &self,
        message: &[BigUint],
        client: usize,
        label: &[u8],
    ) -> anyhow::Result<Vec<BigUint>> {
        anyhow::ensure!(
            client <= self.parameters.clients,
            "client number: {}, does not exist. Client number ∈ [0, {}[",
            client,
            self.parameters.clients,
        );

        let msk = self
            .msk
            .as_ref()
            .context("The master secret key must be generated first")?;
        let secret_key = &msk[client];
        encrypt(&self.parameters, label, message, secret_key)
    }

    /// Issue a functional key for the `vectors`.
    /// The `vectors` has `number of clients` vectors of message length`
    ///
    /// Calculated as `sky = ∑yᵢ.Zᵢ` where `i∈{n}`
    /// and `n` is the number of clients
    pub fn key_der(&self, vectors: &[Vec<BigUint>]) -> anyhow::Result<FunctionalKey> {
        let msk = self
            .msk
            .as_ref()
            .context("The master secret key must be generated first")?;
        functional_key(&self.parameters, msk, vectors)
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

#[cfg(test)]
mod tests {

    use cosmian_crypto_base::cs_prng::Uniform;
    use num_bigint::BigUint;
    use rand::Rng;

    use super::{super::common::tests::paper_params, Mcfe, Parameters};
    use crate::lwe::parameters::Setup;

    fn test_encryption_decryption(params: &Parameters) -> anyhow::Result<()> {
        println!("Parameters: {}", params);
        // generate test data
        let n = params.clients;
        let m = params.message_length;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let mut uniform = Uniform::new();
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for _c in 0..n {
            let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                message_c.push(uniform.big_uint_below(&params.message_bound));
                vectors_c.push(uniform.big_uint_below(&params.vectors_bound));
            }
            messages.push(message_c);
            vectors.push(vectors_c);
        }
        let mut expected = BigUint::from(0u32);
        #[allow(clippy::needless_range_loop)]
        for mi in 0..m {
            for i in 0..n {
                expected += &messages[i][mi] * &vectors[i][mi];
            }
        }
        //Instantiate MCFE
        let mut mcfe = Mcfe::new(params);
        // master key generation
        mcfe.new_master_secret_key();
        // derived key generation
        let sky = mcfe.key_der(&vectors)?;
        //encryption
        let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for (i, m) in messages.iter().enumerate() {
            cts.push(mcfe.encrypt(m, i, &label)?);
        }
        // decryption
        let result = mcfe.decrypt(&cts, &label, &sky, &vectors)?;
        assert_eq!(&expected, &result);
        println!("  ==> OK");
        Ok(())
    }

    #[test]
    fn test_encryption_decryptions() -> anyhow::Result<()> {
        test_encryption_decryption(&paper_params())?;
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 10,
            message_length: 31,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 31,
            message_bound: BigUint::from(2u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        Ok(())
    }
}
