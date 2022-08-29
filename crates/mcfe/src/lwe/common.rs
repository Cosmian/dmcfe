use crate::lwe::LabelVector;
use num_bigint::BigUint;
use sha3::{Digest, Sha3_256};

/// Create a label vector for label `label` of length `length` in ℤq
///
/// The n₀+m₀ terms are taken as `Sha3(hᵢ||counter)` where
/// hᵢ = sha3(hᵢ₋₁||counter) for i ∈ [1..n₀+m₀[ and h₀=label
#[inline(always)]
pub fn create_label_vector(label: &[u8], length: usize, q: &BigUint) -> LabelVector {
    let mut h = Sha3_256::new();
    h.update(label);
    let mut data = h.finalize_reset();
    (0..length)
        .map(|i| {
            h.update(&data);
            h.update(&i.to_be_bytes());
            data = h.finalize_reset();
            BigUint::from_bytes_be(&data) % q
        })
        .collect()
}

pub(crate) fn create_functional_key_label(vectors: &[Vec<BigUint>]) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    for row in vectors {
        for el in row {
            bytes.extend_from_slice(&el.to_bytes_be());
        }
    }
    bytes
}

#[cfg(test)]
pub(crate) mod tests {

    use super::{
        super::{parameters::Parameters, SecretKey},
        create_label_vector,
    };
    use crate::lwe::parameters::Setup;
    use cosmian_crypto_base::distributions::Uniform;
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use std::{thread, time::Instant};

    #[test]
    fn test_big_int() {
        let n = 1u64 << 63;
        let p = 1u64 << 32;
        let v: u64 = 1u64 << 63;
        let mut k = BigUint::from(n);
        k *= p;
        k *= v;
        assert_eq!(
            k.to_u32_digits(),
            vec![0, 0, 0, 0, 0b_0100_0000_0000_0000_0000_0000_0000_0000]
        );
    }

    #[allow(clippy::many_single_char_names)]
    pub(crate) fn paper_params() -> Parameters {
        let n = 100usize;
        let m: usize = 1usize;
        let p = BigUint::from(100u32);
        let v = BigUint::from(100u32);
        let q = BigUint::from((1u128 << 127) - 1);
        let q0 = BigUint::from(std::u32::MAX);
        let k: BigUint = &p * &v * n * m;
        let q_div_k: BigUint = &q / &k;
        let q0_q_div_k = &q0 * &q_div_k;
        // let params = Parameters::instantiate(n, p, v)?;
        Parameters {
            clients: n,
            message_length: m,
            message_bound: p,
            vectors_bound: v,
            k,
            q: q.clone(),
            q0: BigUint::from(std::u32::MAX),
            m0: 500,
            n0: 500,
            q_div_k,
            sigma: BigUint::from(1000u32),
            half_q: &q / 2u32,
            q0_q_div_k: q0_q_div_k.clone(),
            q0_q_div_2k: &q0_q_div_k / 2u32,
        }
    }

    #[test]
    fn test_round() {
        for i in 0u32..100_000 {
            let q: u32 = thread_rng().gen_range(257..std::u32::MAX);
            let q0: u32 = thread_rng().gen_range(1..q);
            let mut params = paper_params();
            params.q = BigUint::from(q);
            params.q0 = BigUint::from(q0);
            params.half_q = &params.q / 2u32;
            // perform round calculations
            let rnd = f64::round(((i % q) as f64) * (q0 as f64) / (q as f64));
            assert_eq!(
                BigUint::from(rnd as u64),
                params.round_to_q0(&BigUint::from(i)),
                "failed for q: {}, q0: {}, i: {}, rnd: {}",
                q,
                q0,
                i,
                rnd
            );
        }
    }

    #[test]
    fn test_key_gen() {
        const FACTOR: usize = 7usize;
        let mut params = paper_params();
        // push m₀ parameter up to make it statistically correct
        params.m0 = FACTOR * 100_000usize;
        // same thing for n0
        params.n0 = FACTOR * 100_000usize;
        // key generation
        let sk = params.secret_key();
        // check
        let q = params.q.clone();
        let std_dev = params.sigma.clone();
        let two_std_dev: BigUint = &std_dev * 2u32;
        let three_std_dev: BigUint = &std_dev * 3u32;
        let mut counter_1 = 0usize;
        let mut counter_2 = 0usize;
        let mut counter_3 = 0usize;
        let mut greater_than_q0 = 0;
        for zi in &sk.0 {
            assert_eq!(params.n0 + params.m0, zi.len());
            for si in zi.iter().take(params.n0) {
                assert!(si < &q);
                if si > &params.q0 {
                    greater_than_q0 += 1;
                }
            }
            for ti in zi.iter() {
                if ti < &std_dev || ti > &(&q - &std_dev) {
                    counter_1 += 1;
                    counter_2 += 1;
                    counter_3 += 1;
                } else if ti < &two_std_dev || ti > &(&q - &two_std_dev) {
                    counter_2 += 1;
                    counter_3 += 1;
                } else if ti < &three_std_dev || ti > &(&q - &three_std_dev) {
                    counter_3 += 1;
                }
            }
            assert!(greater_than_q0 > 0);
            assert!(
                counter_1 / FACTOR > 68070 && counter_1 / FACTOR < 68470,
                "{} not in ]68070, 68470[",
                counter_1 / FACTOR
            );
            assert!(
                counter_2 / FACTOR > 95250 && counter_2 / FACTOR < 95650,
                "{} not in ]92250, 96560[",
                counter_2
            );
            assert!(
                counter_3 / FACTOR > 99530 && counter_3 / FACTOR < 99930,
                "{} not in ]99530, 99930[",
                counter_3
            );
            println!("σ: [{} bits] {}", std_dev.bits(), &std_dev);
            println!(
                "<σ: {} <2σ: {} <3σ: {}",
                counter_1 / FACTOR,
                counter_2 / FACTOR,
                counter_3 / FACTOR
            );
        }
    }

    #[test]
    fn test_key_der() -> anyhow::Result<()> {
        let params = paper_params();
        let msk = params.master_secret_key();
        let mut vectors: Vec<Vec<BigUint>> =
            vec![vec![BigUint::from(0u32); params.message_length]; params.clients];
        #[allow(clippy::needless_range_loop)]
        let mut uniform = Uniform::new();
        vectors.iter_mut().for_each(|vector| {
            vector.iter_mut().for_each(|coeff| {
                *coeff = uniform.big_uint_below(&params.vectors_bound);
            });
        });
        let sky = params.functional_key(&msk, &vectors)?;
        assert_eq!(params.n0 + params.m0, sky.0.len());
        for sky_j in sky.0 {
            assert!(sky_j < params.q);
        }
        Ok(())
    }

    #[test]
    fn test_encryption() -> anyhow::Result<()> {
        let params = paper_params();
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let n0_m0 = params.n0 + params.m0;
        let h_l = create_label_vector(&label, n0_m0, &params.q);
        // encryption: `ctᵢ_ₗ = ⌊Zᵢ.H(l) + ⌊q/K⌋.xᵢ⌉->q₀`
        // if we encrypt a vector of 0, we should get a vector of the rounded version of
        // Zᵢ.H(l)
        let mu = vec![BigUint::from(0u32); params.message_length];
        let zi = params.secret_key();
        let ct_il = params.encrypt(&label, &mu, &zi)?;
        for (mi, ct_il_mi) in ct_il.iter().enumerate() {
            let mut zi_hl = BigUint::from(0u32);
            for (j, h_l_j) in h_l.iter().enumerate() {
                zi_hl += h_l_j * &zi.0[mi][j];
            }
            assert_eq!(&params.round_to_q0(&zi_hl), ct_il_mi)
        }
        // if the key is null, we should get ⌊ ⌊q/K⌋.xᵢ⌉->q₀
        let mut uniform = Uniform::new();
        let zi = SecretKey(vec![
            vec![BigUint::from(0u32); params.n0 + params.m0];
            params.message_length
        ]);
        let mut mu: Vec<BigUint> = Vec::with_capacity(params.message_length);
        for _mi in 0..params.message_length {
            mu.push(uniform.big_uint_below(&params.message_bound));
        }
        let ct_il = params.encrypt(&label, &mu, &zi)?;
        for mi in 0..params.message_length {
            assert_eq!(params.round_to_q0(&(&params.q_div_k * &mu[mi])), ct_il[mi])
        }
        Ok(())
    }

    fn bench_encryption(message_bits: (usize, u32), n0: usize) -> anyhow::Result<()> {
        let bound = BigUint::from(2u8).pow(message_bits.1);
        let parameters = Parameters::instantiate(&Setup {
            clients: 1,
            message_length: message_bits.0,
            message_bound: bound.clone(),
            vectors_bound: bound,
            n0,
        })?;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let zi = parameters.secret_key();
        let mut nanos_total = 0u128;
        let loops: usize = 25000usize;
        for _l in 0usize..loops {
            let mut uniform = Uniform::new();
            let mut mu: Vec<BigUint> = Vec::with_capacity(parameters.message_length);
            for _mi in 0..parameters.message_length {
                mu.push(uniform.big_uint_below(&parameters.message_bound));
            }
            let now = Instant::now();
            parameters.encrypt(&label, &mu, &zi)?;
            nanos_total += now.elapsed().as_nanos();
        }
        let enc_0 = parameters.encrypt(
            &label,
            &vec![&parameters.message_bound - 1u32; parameters.message_length],
            &zi,
        )?[0]
            .to_bytes_be();
        println!(
            "{:>5} | {:>4} | {:>3} | {:>3} | {:>10} | {:>11} ",
            nanos_total / 1000 / (loops as u128),
            n0,
            message_bits.0,
            message_bits.1,
            message_bits.1 as usize * message_bits.0,
            message_bits.0 * enc_0.len() * 8,
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn bench_encryptions() {
        println!("Encryption benchmarks:");
        println!("   μs |   n0 |   m |   b | Clear bits | Cipher bits ");
        println!("------|------|-----|-----|------------|-------------");
        let key_length = vec![256, 512, 1024usize];
        let message_bits: Vec<(usize, u32)> = vec![
            (1, 2),
            (1, 32),
            (1, 64),
            (1, 128),
            (2, 64),
            (4, 64),
            (8, 64),
            (16, 64),
        ];
        let mut handles = vec![];
        for n0 in key_length {
            for l in &message_bits {
                let l_c = *l;
                let handle = thread::spawn(move || {
                    bench_encryption(l_c, n0).unwrap_or_else(|_| {
                        panic!(
                            "failed for parameters: m: {}, l: {}, n0: {}",
                            l_c.0, l_c.1, n0
                        )
                    });
                });
                handles.push(handle);
            }
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    fn test_encryption_decryption(params: &Parameters) -> anyhow::Result<()> {
        let n = params.clients;
        let m = params.message_length;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut uniform = Uniform::new();
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
        let mut expected: BigUint = BigUint::from(0u32);
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            for mi in 0..m {
                expected += &messages[i][mi] * &vectors[i][mi];
            }
        }
        // master key generation
        let msk = params.master_secret_key();
        // derived key generation
        let sky = params.functional_key(&msk, &vectors)?;
        //encryption
        let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for (i, m) in messages.iter().enumerate() {
            cts.push(params.encrypt(&label, m, &msk[i])?);
        }
        // decryption
        let result = params.decrypt(&label, &cts, &sky, &vectors)?;
        assert_eq!(
            &expected, &result,
            "parameters: {}, expected: {}, result: {}",
            &params, &expected, &result
        );
        Ok(())
    }

    #[test]
    fn test_encryption_decryptions() -> anyhow::Result<()> {
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 10,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
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

    #[test]
    fn test_encryption_decryptions_of_zero() -> anyhow::Result<()> {
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 2,
            message_length: 31,
            message_bound: BigUint::from(1u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_a_lot_of_encryption_decryptions() -> anyhow::Result<()> {
        let params = Parameters::instantiate(&Setup {
            clients: 10,
            message_length: 31,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?;
        for i in 0..5000 {
            if (i + 1) % 100 == 0 {
                println!("{}", (i + 1));
            }
            test_encryption_decryption(&params)?;
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_a_lot_of_encryption_decryptions_of_zero() -> anyhow::Result<()> {
        let params = Parameters::instantiate(&Setup {
            clients: 2,
            message_length: 31,
            message_bound: BigUint::from(1u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?;
        for i in 0..5000 {
            if (i + 1) % 100 == 0 {
                println!("{}", (i + 1));
            }
            test_encryption_decryption(&params)?;
        }
        Ok(())
    }

    fn bench_decryption(
        clients: usize,
        message_bits: (usize, u32),
        n0: usize,
    ) -> anyhow::Result<()> {
        let bound = BigUint::from(2u8).pow(message_bits.1);
        let parameters = Parameters::instantiate(&Setup {
            clients,
            message_length: message_bits.0,
            message_bound: bound.clone(),
            vectors_bound: bound,
            n0,
        })?;
        let m = message_bits.0;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let mut uniform = Uniform::new();
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(clients);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(clients);
        for _c in 0..clients {
            let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                message_c.push(uniform.big_uint_below(&parameters.message_bound));
                vectors_c.push(uniform.big_uint_below(&parameters.vectors_bound));
            }
            messages.push(message_c);
            vectors.push(vectors_c);
        }
        let mut expected: Vec<BigUint> = vec![BigUint::from(0u32); m];
        for (mi, expected_mi) in expected.iter_mut().enumerate() {
            for i in 0..clients {
                *expected_mi += &messages[i][mi] * &vectors[i][mi];
            }
        }
        // master key generation
        let msk = parameters.master_secret_key();
        // derived key generation
        let sky = parameters.functional_key(&msk, &vectors)?;
        //encryption
        let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(clients);
        for (i, m) in messages.iter().enumerate() {
            cts.push(parameters.encrypt(&label, m, &msk[i])?);
        }
        let mut nanos_total = 0u128;
        let loops: usize = 50_000 / m;
        for _l in 0usize..loops {
            let now = Instant::now();
            parameters.decrypt(&label, &cts, &sky, &vectors)?;
            nanos_total += now.elapsed().as_nanos();
        }
        let dec_0 = parameters
            .decrypt(&label, &cts, &sky, &vectors)?
            .to_bytes_be();
        println!(
            "{:>5}, {:>4}, {:>4}, {:>4}, {:>4}, {:>8}",
            nanos_total / 1000 / (loops as u128),
            n0,
            clients,
            message_bits.0,
            message_bits.0 * message_bits.1 as usize,
            dec_0.len() * 8
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn bench_decryptions() {
        println!("Decryption benchmarks:");
        println!("  μs,   n0,    n,    m,    b, clear bits");
        let key_length = vec![256, 512, 1024usize];
        let message_bits: Vec<(usize, u32)> = vec![
            (1, 2),
            (1, 32),
            (1, 64),
            (1, 128),
            (2, 64),
            (4, 64),
            (8, 64),
            (16, 64),
        ];
        let clients = vec![1usize, 10, 20, 100];
        let mut handles = vec![];
        for n0 in key_length {
            for n in &clients {
                let n_c = *n;
                for l in &message_bits {
                    let l_c = *l;
                    let handle = thread::spawn(move || {
                        bench_decryption(n_c, l_c, n0).unwrap_or_else(|e| {
                            panic!(
                                "failed for parameters: n: {},m:{}, l: {}, n0: {}: {}",
                                n_c, l_c.0, l_c.1, n0, e
                            )
                        });
                    });
                    handles.push(handle);
                }
            }
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
