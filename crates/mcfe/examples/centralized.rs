use cosmian_crypto_base::distributions::Uniform;
use cosmian_mcfe::lwe::{Mcfe, Parameters, Setup};
use num_bigint::BigUint;
use rand::Rng;

fn main() -> anyhow::Result<()> {
    let params = Parameters::instantiate(&Setup {
        clients: 20,
        message_length: 10_000,
        message_bound: BigUint::from(2u32),
        vectors_bound: BigUint::from(std::u32::MAX),
        n0: 1024,
    })?;

    println!("Parameters: {}", params);

    // generate test data
    let n = params.clients;
    let m = params.message_length;
    let mut label = [0u8; 32];
    rand::thread_rng().fill(&mut label);
    let mut uniform = Uniform::new();
    let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(n);
    let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
    let mut expected = BigUint::from(0u32);
    for _ in 0..n {
        let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
        let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
        for _ in 0..m {
            let m = uniform.big_uint_below(&params.message_bound);
            let v = uniform.big_uint_below(&params.vectors_bound);
            expected += &m * &v;
            message_c.push(m);
            vectors_c.push(v);
        }
        messages.push(message_c);
        vectors.push(vectors_c);
    }

    //Instantiate MCFE
    let mut mcfe = Mcfe::new(&params);
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
