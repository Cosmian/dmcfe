use cosmian_bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, Criterion};
use dmcfe::{ipmcfe::*, types::Label};

fn bench_encrypt(c: &mut Criterion) {
    // number of contributions per client
    let m = 1;
    // messages
    let x = vec![Scalar::from_raw([rand::random(); 4]); m];
    // label
    let label = Label::new().unwrap();
    let ek = setup(m);
    c.bench_function("Encrypt one client, one contrib:", |b| {
        b.iter(|| encrypt(&ek, &x, &label).unwrap())
    });
}

fn bench_decrypt(c: &mut Criterion) {
    // number of clients
    let n = 10;
    // number of contributions per client
    let m = 1;
    // messages
    let x = vec![vec![Scalar::from_raw([rand::random(); 4]); m]; n];
    // decryption function
    let y = vec![vec![Scalar::from_raw([rand::random(); 4]); m]; n];
    // label
    let label = Label::new().unwrap();
    let msk: Vec<PrivateKey> = (0..n).map(|_| setup(m)).collect();
    let ctx = x
        .iter()
        .zip(msk.iter())
        .map(|(xi, eki)| encrypt(eki, xi, &label).unwrap())
        .collect::<Vec<_>>();

    // Generate the decryption key
    let dk = dkey_gen(&msk, &y).unwrap();

    c.bench_function("Decrypt 10 clients, one contrib:", |b| {
        b.iter(|| decrypt(&ctx, &dk, &label))
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
