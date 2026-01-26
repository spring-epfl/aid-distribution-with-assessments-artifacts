use ark_ec::pairing::*;
use ark_ff::PrimeField;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;

fn bench_recipient<F: PrimeField>(
    b: u64,
    id: u16,
    pk_enc_helper: &tink_core::keyset::Handle,
) -> (Vec<u8>, F) {
    // Secret-share F(b)
    let val = F::from(b);
    let mut rng = thread_rng();
    let share_0 = F::rand(&mut rng);
    let share_1 = val - share_0;

    let enc = tink_hybrid::new_encrypt(pk_enc_helper).unwrap();
    let id_bytes = id.to_be_bytes();
    let mut bytes = Vec::new();
    let writer = &mut bytes;
    share_0.serialize_compressed(writer).unwrap();
    let ctxt = enc.encrypt(&bytes, id_bytes.as_slice()).unwrap();

    (ctxt, share_1)
}

fn hbc_2pc_1_recipient(c: &mut Criterion) {
    type P = ark_bls12_381::Bls12_381;
    type F = <P as Pairing>::ScalarField;

    let last_period = 0u16;
    let id = 1u16;

    // PKE.KeyGen for Helper
    tink_hybrid::init();
    let sk_enc_helper = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_helper = sk_enc_helper.public().unwrap();

    c.bench_function("hbc_2pc_1_recipient", |b| {
        b.iter(|| {
            bench_recipient::<F>(black_box(1), id, black_box(&pk_enc_helper));
        })
    });
}

criterion_group! {
    name = benches_phone;
    config = Criterion::default().sample_size(10);
    targets = hbc_2pc_1_recipient
}

criterion_main!(benches_phone);
