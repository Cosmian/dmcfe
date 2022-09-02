use cosmian_crypto_base::distributions::Uniform;
use cosmian_mcfe::lwe::{
    fks_secret_keys, DMcfe, FunctionalKey, FunctionalKeyShare, Parameters, SecretKey, Setup,
};
use num_bigint::BigUint;
use rand::Rng;

fn main() -> anyhow::Result<()> {
    let params = Parameters::instantiate(&Setup {
        clients: 20,
        message_length: 10,
        message_bound: BigUint::from(std::u32::MAX),
        vectors_bound: BigUint::from(std::u32::MAX),
        n0: 256,
    })?;
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
        let mut dmcfe = DMcfe::instantiate(&params)?;
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
