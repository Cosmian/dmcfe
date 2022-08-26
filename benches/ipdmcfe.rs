use cosmian_bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, Criterion};
use dmcfe::{dsum, ipdmcfe::*, types::Label};
use rand::{rngs::ThreadRng, RngCore};

/// Generate a random scalar
fn random_scalar() -> Scalar {
    Scalar::from_raw([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}

fn bench_encrypt(c: &mut Criterion) {
    let n_clients = 10;
    let l = Label::new().unwrap();
    let x0 = random_scalar();
    // create clients dsum keys
    let (mut dsk, mut dpk) = (Vec::with_capacity(n_clients), Vec::with_capacity(n_clients));
    for _ in 0..n_clients {
        let dsum::KeyPair(dski, dpki) = dsum::client_setup();
        dsk.push(dski);
        dpk.push(dpki);
    }
    // setup for client 0
    let sk0 = setup(&dsk[0], &dpk);
    // bench encryption for client 0
    c.bench_function("Encrypt one client:", |b| {
        b.iter(|| encrypt(&x0, &sk0, &l))
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let n_clients = 10;
    let l = Label::new().unwrap();
    let mut rng = ThreadRng::default();
    let x = (0..n_clients)
        .map(|_| {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            Scalar::from_bytes_wide(&bytes)
        })
        .collect::<Vec<_>>();
    // create clients dsum keys and decryption key
    let (mut y, mut pdk) = (Vec::with_capacity(n_clients), Vec::with_capacity(n_clients));
    let (mut dsk, mut dpk) = (Vec::with_capacity(n_clients), Vec::with_capacity(n_clients));
    for _ in 0..n_clients {
        let dsum::KeyPair(dski, dpki) = dsum::client_setup();
        let mut yi = [0; 64];
        rng.fill_bytes(&mut yi);
        y.push(Scalar::from_bytes_wide(&yi));
        dsk.push(dski);
        dpk.push(dpki);
    }

    // in real life, propagate only `dpk` among clients
    let mut ctx = Vec::with_capacity(n_clients);
    for client in 0..n_clients {
        let ski = setup(&dsk[client], &dpk);
        pdk.push(dkey_gen_share(client, &ski, &y));
        ctx.push(encrypt(&x[client], &ski, &l));
    }
    let dk = key_comb(&y, &pdk);

    // bench encryption for client 0
    c.bench_function("Decrypt 10 clients:", |b| {
        b.iter(|| decrypt(&ctx, &dk, &l))
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
