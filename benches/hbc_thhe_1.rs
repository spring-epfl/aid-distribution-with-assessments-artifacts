use aid_distribution_with_assessments::DECRYPTION_THRESHOLD;
use aid_distribution_with_assessments::NUM_RECIPIENTS;
use aid_distribution_with_assessments::NUM_SHOW_UP;
use aid_distribution_with_assessments::thbgn::rand_invertible;
use ark_ec::Group;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_std::One;
use ark_std::Zero;
use ark_std::cfg_into_iter;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand::thread_rng;
use secret_sharing_and_dkg::common::ShareId;
use secret_sharing_and_dkg::common::lagrange_basis_at_0_for_all;
use secret_sharing_and_dkg::error::SSError;
use tink_core::keyset;

type G1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1;
type F = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;

type Ciphertext<G> = (G, G);
type SecretKeyShare<G> = (ShareId, <G as Group>::ScalarField);
type PublicKey<G> = G;
type SecretKey<G> = <G as Group>::ScalarField;
type PublicParameters<G> = G;
type PartialDecryption<G> = (ShareId, G);

fn ctxt_to_bytes<G: Group>(ctxt: &Ciphertext<G>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut bytes_1 = Vec::new();
    let writer = &mut bytes_1;
    ctxt.0.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_1);
    let mut bytes_2 = Vec::new();
    let writer = &mut bytes_2;
    ctxt.1.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_2);
    bytes
}

fn bytes_to_ctxt<G: Group>(bytes: &[u8]) -> Ciphertext<G> {
    let size = G::serialized_size(&G::zero(), ark_serialize::Compress::Yes);
    debug_assert_eq!(bytes.len(), 2 * size);
    let mut reader_1 = &bytes[0..size];
    let c1 = G::deserialize_compressed(&mut reader_1).unwrap();
    let mut reader_2 = &bytes[size..2 * size];
    let c2 = G::deserialize_compressed(&mut reader_2).unwrap();
    (c1, c2)
}

fn setup<G: Group>() -> PublicParameters<G> {
    let mut rng = thread_rng();
    G::rand(&mut rng)
}

fn keygen<G: Group>(pp: PublicParameters<G>) -> (SecretKey<G>, PublicKey<G>) {
    let s: G::ScalarField = rand_invertible();
    (s, pp * s)
}

fn encrypt<G: Group>(
    pp: PublicParameters<G>,
    pk: PublicKey<G>,
    msg: G::ScalarField,
) -> Ciphertext<G> {
    let r = rand_invertible::<G::ScalarField>();
    let g = pp;
    let h = pk;
    (g * r, G::generator() * msg + h * r)
}

fn partial_decrypt<G: Group>(ctxt: Ciphertext<G>, sk: SecretKeyShare<G>) -> PartialDecryption<G> {
    let (_c1, c2) = ctxt;
    let (id, s) = sk;
    (id, c2 * s)
}

#[allow(dead_code)]
fn decrypt<G: Group>(ctxt: Ciphertext<G>, sk: SecretKey<G>) -> G::ScalarField {
    let (c1, c2) = ctxt;
    find_dlog(G::generator(), c2 - c1 * sk, (NUM_RECIPIENTS as u64).into()).unwrap()
}

#[allow(unexpected_cfgs)]
pub fn reconstruct_secret_in_exp<G: Group>(shares: &[(ShareId, G)]) -> Result<G, SSError> {
    // let threshold = self.threshold();
    // let len = self.0.len() as ShareId;
    // if threshold > len {
    //     return Err(SSError::BelowThreshold(threshold, len));
    // }
    // let shares = &self.0[0..threshold as usize];
    let share_ids = shares.iter().map(|s| s.0).collect::<Vec<_>>();
    let basis = lagrange_basis_at_0_for_all::<G::ScalarField>(share_ids)?;
    Ok(cfg_into_iter!(basis)
        .zip(cfg_into_iter!(shares))
        .map(|(b, s)| s.1 * b)
        .sum::<G>())
}

fn final_decrypt<G: Group>(
    ctxt: Ciphertext<G>,
    pdecs: &[PartialDecryption<G>],
) -> Option<G::ScalarField> {
    let c1 = reconstruct_secret_in_exp(pdecs).unwrap();
    let c = ctxt.1 - c1;
    find_dlog(G::generator(), c, (NUM_RECIPIENTS as u64).into())
}

fn bench_helper<G: Group>(
    ctxts: &[Vec<u8>],
    id: u16,
    sk_enc_helper: &keyset::Handle,
    sk_sig_helper: &keyset::Handle,
    last_period: u16,
) -> (Ciphertext<G>, Vec<u8>) {
    // Enforce one-time property
    let id_bytes = id.to_be_bytes();
    if id <= last_period {
        panic!("Already processed this period");
    }

    // Decrypt outer ciphertexts
    let dec = tink_hybrid::new_decrypt(sk_enc_helper).unwrap();
    let inner_ctxts = ctxts
        .iter()
        .map(|ctxt| {
            let pt = dec.decrypt(ctxt, id_bytes.as_slice()).unwrap();
            bytes_to_ctxt::<G>(&pt)
        })
        .collect::<Vec<_>>();

    // Evaluate
    let res = inner_ctxts
        .into_iter()
        .fold((G::zero(), G::zero()), |acc, ctxt| {
            (acc.0 + ctxt.0, acc.1 + ctxt.1)
        });

    // Sign the resulting ciphertext
    let sig = tink_signature::new_signer(sk_sig_helper).unwrap();
    let data: Vec<u8> = ctxt_to_bytes(&res);
    let signature = sig.sign(data.as_slice()).unwrap();

    (res, signature)
}

fn bench_distribution_station<G: Group>(
    ctxt_out: Ciphertext<G>,
    pdecs: &[PartialDecryption<G>],
) -> G::ScalarField {
    // Aggregate DECRYPTION_THRESHOLD partial decryptions
    assert!(pdecs.len() == DECRYPTION_THRESHOLD);
    let out = final_decrypt(ctxt_out, pdecs);
    out.unwrap_or(G::ScalarField::zero())
}

fn bench_recipient_1<G: Group>(
    b: u64,
    pp: PublicParameters<G>,
    id: u16,
    pk: PublicKey<G>,
    pk_helper: &tink_core::keyset::Handle,
) -> Vec<u8> {
    // Encrypt a single bit with ElGamal
    let ctxt = encrypt::<G>(pp, pk, G::ScalarField::from(b));

    // Encrypt under helper's public key
    let enc = tink_hybrid::new_encrypt(pk_helper).unwrap();
    let pt = ctxt_to_bytes(&ctxt);
    let bytes = pt.as_slice();
    let ct = enc.encrypt(bytes, id.to_be_bytes().as_slice()).unwrap();

    ct
}

fn bench_recipient_2<G: Group>(
    _pp: PublicParameters<G>,
    _id: u16,
    _pk: PublicKey<G>,
    ctxt_out: Ciphertext<G>,
    ctxt_out_sig: &Vec<u8>,
    sk: SecretKeyShare<G>,
    vk: &keyset::Handle,
) -> PartialDecryption<G> {
    // Verify signature on ctxt_out
    tink_signature::init();
    let v = tink_signature::new_verifier(vk).unwrap();
    let data: Vec<u8> = ctxt_to_bytes(&ctxt_out);
    v.verify(ctxt_out_sig, data.as_slice()).unwrap();

    // Compute a partial decryption of a ciphertext
    partial_decrypt::<G>(ctxt_out, sk)
}

pub fn find_dlog<G: Group>(base: G, p: G, bound: G::ScalarField) -> Option<G::ScalarField>
where
    G::ScalarField: ark_ff::PrimeField,
{
    // Find discrete log of p in base
    // Enumerate from -Bound to Bound in F, test if base^i = p
    let mut i = G::ScalarField::zero();
    while i < bound {
        if base * i == p {
            return Some(i);
        }
        if base * i == -p {
            return Some(-i);
        }
        i += G::ScalarField::one();
    }
    None
    // panic!("Discrete log not found");
}

fn hbc_thhe_1_recipient(c: &mut Criterion) {
    let pp = setup::<G1>();

    let id = 1u16;

    // 1FE.KeyGen
    let (sk_1fe, pk_1fe) = keygen::<G1>(pp);
    let shares = (1..=DECRYPTION_THRESHOLD as u16)
        .map(|i| (i, sk_1fe * F::from(i as u64)))
        .collect::<Vec<SecretKeyShare<G1>>>();

    // SIG.KeyGen for Helper
    tink_signature::init();
    let sk_sig_helper =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let vk_sig_helper = sk_sig_helper.public().unwrap();
    let sig = tink_signature::new_signer(&sk_sig_helper).unwrap();

    // PKE.KeyGen for Helper
    tink_hybrid::init();
    let sk_enc_helper = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_helper = sk_enc_helper.public().unwrap();

    let share = shares[0];

    let ctxt_out = encrypt::<G1>(pp, pk_1fe, F::from(0u64));
    let ctxt_out_sig = sig.sign(&ctxt_to_bytes(&ctxt_out)).unwrap();
    c.bench_function("hbc_thhe_1_recipient", |b| {
        b.iter(|| {
            let _ = bench_recipient_1::<G1>(
                black_box(1),
                black_box(pp),
                id,
                black_box(pk_1fe),
                black_box(&pk_enc_helper),
            );
            let _ = bench_recipient_2(
                pp,
                id,
                pk_1fe,
                ctxt_out,
                &ctxt_out_sig,
                share,
                &vk_sig_helper,
            );
        })
    });
}

fn hbc_thhe_1(c: &mut Criterion) {
    let pp = setup::<G1>();

    let last_period = 0u16;
    let id = 1u16;

    // 1FE.KeyGen
    let (sk_1fe, pk_1fe) = keygen::<G1>(pp);
    let shares = (1..=DECRYPTION_THRESHOLD as u16)
        .map(|i| (i, sk_1fe * F::from(i as u64)))
        .collect::<Vec<SecretKeyShare<G1>>>();

    // SIG.KeyGen for Helper
    tink_signature::init();
    let sk_sig_helper =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let vk_sig_helper = sk_sig_helper.public().unwrap();

    // PKE.KeyGen for Helper
    tink_hybrid::init();
    let sk_enc_helper = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_helper = sk_enc_helper.public().unwrap();

    // Recipients encrypt
    let ctxts = (0..NUM_SHOW_UP)
        .map(|_| bench_recipient_1(1, pp, id, pk_1fe, &pk_enc_helper))
        .collect::<Vec<_>>();

    // Helper checks and processes
    let (ctxt_out, ctxt_out_sig) =
        bench_helper(&ctxts, id, &sk_enc_helper, &sk_sig_helper, last_period);

    // Recipients partially decrypt
    let pdecs = shares
        .clone()
        .into_iter()
        .map(|share| {
            bench_recipient_2(
                pp,
                id,
                pk_1fe,
                ctxt_out,
                &ctxt_out_sig,
                share,
                &vk_sig_helper,
            )
        })
        .collect::<Vec<_>>();

    c.bench_function("hbc_thhe_1_helper", |b| {
        b.iter(|| {
            bench_helper::<G1>(
                black_box(&ctxts),
                id,
                &sk_enc_helper,
                &sk_sig_helper,
                last_period,
            )
        })
    });

    c.bench_function("hbc_thhe_1_distribution", |b| {
        b.iter(|| bench_distribution_station::<G1>(black_box(ctxt_out), black_box(&pdecs)))
    });
}

// criterion_group!(benches_phone, hbc_thhe_1_recipient);
criterion_group! {
    name = benches_phone;
    config = Criterion::default().sample_size(10);
    targets = hbc_thhe_1_recipient
}
criterion_group! {
    name = benches_laptop;
    config = Criterion::default().sample_size(10);
    targets = hbc_thhe_1
}
criterion_main!(benches_phone, benches_laptop);
