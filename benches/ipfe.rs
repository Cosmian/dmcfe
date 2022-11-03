use cosmian_bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, Criterion};
use dmcfe::ipfe;
use rand::{rngs::ThreadRng, Rng};

fn bench_encrypt(c: &mut Criterion) {
    let mut rng = ThreadRng::default();
    // size of the problem
    let l = 100;
    let x: Vec<Scalar> = (0..l)
        .map(|_| Scalar::from_raw([rand::thread_rng().gen_range(10 ^ 6..10 ^ 5), 0, 0, 0]))
        .collect();

    // Generate IPFE keys
    let (_, mpk) = ipfe::setup(l, &mut rng);

    // Generate IPFE keys
    c.bench_function("Encrypt 100 items:", |b| {
        b.iter(|| ipfe::encrypt(&mpk, &x, &mut rng).unwrap())
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let mut rng = ThreadRng::default();
    // size of the problem
    let l = 100;
    let x: Vec<Scalar> = (0..l)
        .map(|_| Scalar::from_raw([rand::thread_rng().gen_range(0..10 ^ 6), 0, 0, 0]))
        .collect();
    let y: Vec<Scalar> = (0..l)
        .map(|_| Scalar::from_raw([rand::thread_rng().gen_range(0..10 ^ 6), 0, 0, 0]))
        .collect();

    // Generate IPFE keys
    let (msk, mpk) = ipfe::setup(l, &mut rng);
    let sky = ipfe::key_gen(&msk, &y).unwrap();

    // compute the text using the IPFE algorithm
    // stay in G1 to avoid computing the discrete logarithm
    let ct = ipfe::encrypt(&mpk, &x, &mut rng).unwrap();
    // Generate IPFE keys
    c.bench_function("Decrypt 100 items", |b| {
        b.iter(|| ipfe::decrypt(&ct, &y, &sky))
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
