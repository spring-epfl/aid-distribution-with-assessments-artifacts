use aid_distribution_with_assessments::DECRYPTION_THRESHOLD;
use aid_distribution_with_assessments::MAX_ENTITLEMENT;
use aid_distribution_with_assessments::NUM_RECIPIENTS;
use aid_distribution_with_assessments::NUM_SHOW_UP;
use aid_distribution_with_assessments::TAG_BYTELEN;
use aid_distribution_with_assessments::thbgn::rand_invertible;
use ark_ec::Group;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_std::One;
use ark_std::Zero;
use ark_std::cfg_into_iter;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand::Rng;
use rand::thread_rng;
use secret_sharing_and_dkg::common::ShareId;
use secret_sharing_and_dkg::common::lagrange_basis_at_0_for_all;
use secret_sharing_and_dkg::error::SSError;
use std::collections::HashSet;
use std::io::Write;
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
    ctxts: &Vec<Vec<Vec<u8>>>,
    id: u16,
    sig_auditor: &Vec<u8>,
    sk_enc_helper: &keyset::Handle,
    sk_sig_helper: &keyset::Handle,
    vk_sig_auditor: &keyset::Handle,
    last_period: u16,
) -> (Ciphertext<G>, Vec<u8>) {
    // Enforce one-time property
    let id_bytes = id.to_be_bytes();
    if id <= last_period {
        panic!("Already processed this period");
    }

    // Check auditor's signature on all ciphertexts
    let v_auditor = tink_signature::new_verifier(vk_sig_auditor).unwrap();
    let mut all_ctxt_bytes = Vec::new();
    for ctxt_from_recipient_i in ctxts.iter() {
        for ctxt in ctxt_from_recipient_i.iter() {
            all_ctxt_bytes.extend_from_slice(ctxt);
        }
    }
    v_auditor
        .verify(sig_auditor, all_ctxt_bytes.as_slice())
        .unwrap();

    // Decrypt outer ciphertexts
    let dec = tink_hybrid::new_decrypt(sk_enc_helper).unwrap();
    let inner_ctxts = ctxts
        .iter()
        .map(|ctxts_recipient| {
            ctxts_recipient
                .iter()
                .map(|ctxt| {
                    let pt = dec.decrypt(ctxt, id_bytes.as_slice()).unwrap();
                    bytes_to_ctxt::<G>(&pt)
                })
                .collect::<Vec<Ciphertext<G>>>()
        })
        .collect::<Vec<_>>();

    // Evaluate
    let res = inner_ctxts
        .into_iter()
        .flatten()
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
    secret_tags: &Vec<[u8; TAG_BYTELEN]>,
    pk: PublicKey<G>,
    pk_helper: &tink_core::keyset::Handle,
    pk_auditor: &tink_core::keyset::Handle,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // 1FE.Encrypt a single bit
    let ctxt = encrypt::<G>(pp, pk, G::ScalarField::from(b));

    let mut ctxts_1fe_pkehelper: Vec<Vec<u8>> = Vec::new();
    // Encrypt under helper's public key
    let enc = tink_hybrid::new_encrypt(pk_helper).unwrap();
    let pt = ctxt_to_bytes(&ctxt);
    let bytes = pt.as_slice();

    let ct_1fe_pkehelper = enc.encrypt(bytes, id.to_be_bytes().as_slice()).unwrap();

    // Encrypt 1FE ciphertext and secret_tag_{i,p,1} under auditor's public key
    let enc_auditor = tink_hybrid::new_encrypt(pk_auditor).unwrap();
    let mut bytes_auditor = Vec::new();
    bytes_auditor.extend_from_slice(&secret_tags[0]); // secret_tag{i,p,1}
    bytes_auditor.extend_from_slice(&ct_1fe_pkehelper); // 1FE ciphertext
    ctxts_1fe_pkehelper.push(ct_1fe_pkehelper);
    let ct_1fe_pkeauditor = enc_auditor.encrypt(&bytes_auditor, b"").unwrap();

    // 1FE.Encrypt dummy symbol 0 for MAX_ENTITLEMENT-1 times
    // Encrypt all dummy 1FE ciphertexts and secret_tag{i,p,k} under auditor's public key
    let mut ctxts_auditor = Vec::new();
    ctxts_auditor.push(ct_1fe_pkeauditor);
    for k in 1..MAX_ENTITLEMENT {
        let dummy_ctxt = encrypt::<G>(pp, pk, G::ScalarField::zero());
        let pt_dummy = ctxt_to_bytes(&dummy_ctxt);
        let ct_1fe_pkehelper = enc
            .encrypt(pt_dummy.as_slice(), id.to_be_bytes().as_slice())
            .unwrap();

        let mut bytes_auditor = Vec::new();
        bytes_auditor.extend_from_slice(&secret_tags[k]); // secret_tag{i,p,k}
        bytes_auditor.extend_from_slice(&ct_1fe_pkehelper); // 1FE ciphertext
        let ct_dummy = enc_auditor.encrypt(&bytes_auditor, b"").unwrap();

        ctxts_1fe_pkehelper.push(ct_1fe_pkehelper);
        ctxts_auditor.push(ct_dummy);
    }

    (ctxts_1fe_pkehelper, ctxts_auditor)
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

fn bench_auditor(
    ctxts_pke_auditor: &Vec<Vec<Vec<u8>>>,
    valid_set: &HashSet<[u8; TAG_BYTELEN]>,
    sk_enc_auditor: &keyset::Handle,
    sk_sig_auditor: &keyset::Handle,
) -> Vec<u8> {
    // Decrypt outer ciphertexts to secret tag and 1FE ciphertexts
    let dec_auditor = tink_hybrid::new_decrypt(sk_enc_auditor).unwrap();
    let mut secret_tags: Vec<Vec<[u8; TAG_BYTELEN]>> = Vec::new();
    let mut ctxts_1fe = Vec::new();
    for ctxts_recipient in ctxts_pke_auditor.iter() {
        let mut recipient_secret_tags = Vec::new();
        for ctxt in ctxts_recipient.iter() {
            let pt = dec_auditor.decrypt(ctxt, b"").unwrap();
            let secret_tag = pt[0..TAG_BYTELEN].try_into().unwrap();
            recipient_secret_tags.push(secret_tag);

            let ctxt_1fe = pt[TAG_BYTELEN..].to_vec();
            ctxts_1fe.push(ctxt_1fe);
        }
        secret_tags.push(recipient_secret_tags);
    }

    // Check that all secret tags are distinct, are part of valid_set, and that there are claimed_entitlement many secret tags
    let mut seen_tags = HashSet::new();
    for recipient_tags in secret_tags.iter() {
        for tag in recipient_tags.iter() {
            if !valid_set.contains(tag) {
                panic!("Invalid secret tag");
            }
            if seen_tags.contains(tag) {
                panic!("Duplicate secret tag");
            }
            seen_tags.insert(*tag);
        }
    }

    // Sign canonical representation of 1FE input ciphertext
    let sig = tink_signature::new_signer(&sk_sig_auditor).unwrap();
    let mut all_ctxt_bytes = Vec::new();
    for ctxt in ctxts_1fe.iter() {
        all_ctxt_bytes.extend_from_slice(&ctxt);
    }
    let signature = sig.sign(all_ctxt_bytes.as_slice()).unwrap();
    signature
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

fn mal_thhe_1_recipient(c: &mut Criterion) {
    let pp = setup::<G1>();

    let id = 1u16;

    println!("Generating keying material...");
    std::io::stdout().flush().ok();

    // 1FE.KeyGen
    let (sk_1fe, pk_1fe) = keygen::<G1>(pp);
    let shares = (1..=DECRYPTION_THRESHOLD as u16)
        .map(|i| (i, sk_1fe * F::from(i as u64)))
        .collect::<Vec<SecretKeyShare<G1>>>();

    // Signatures
    tink_signature::init();

    // SIG.KeyGen for Helper
    let sk_sig_helper =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let vk_sig_helper = sk_sig_helper.public().unwrap();
    let sig = tink_signature::new_signer(&sk_sig_helper).unwrap();

    // PKE
    tink_hybrid::init();

    // PKE.KeyGen for Helper
    let sk_enc_helper = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_helper: keyset::Handle = sk_enc_helper.public().unwrap();

    // PKE.KeyGen for Auditor
    let sk_enc_auditor = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_auditor = sk_enc_auditor.public().unwrap();

    println!("Generating inputs for recipients...");
    std::io::stdout().flush().ok();

    // Generate secret tags for recipients
    let mut tags: Vec<Vec<[u8; TAG_BYTELEN]>> = Vec::new();
    for i in 0..1 {
        tags.push(Vec::new());
        for _j in 0..(MAX_ENTITLEMENT) {
            let mut tag = [0u8; TAG_BYTELEN];
            rand::thread_rng().fill(&mut tag);
            tags[i].push(tag);
        }
    }

    let share = shares[0];
    let ctxt_out = encrypt::<G1>(pp, pk_1fe, F::from(0u64));
    let ctxt_out_sig = sig.sign(&ctxt_to_bytes(&ctxt_out)).unwrap();

    println!("Starting benchmark...");
    std::io::stdout().flush().ok();
    
    c.bench_function("mal_thhe_1_recipient", |b| {
        b.iter(|| {
            let _ = bench_recipient_1::<G1>(
                black_box(1),
                black_box(pp),
                id,
                &tags[0],
                black_box(pk_1fe),
                black_box(&pk_enc_helper),
                black_box(&pk_enc_auditor),
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

fn mal_thhe_1(c: &mut Criterion) {
    let pp = setup::<G1>();

    let last_period = 0u16;
    let id = 1u16;

    // 1FE.KeyGen
    let (sk_1fe, pk_1fe) = keygen::<G1>(pp);
    let shares = (1..=DECRYPTION_THRESHOLD as u16)
        .map(|i| (i, sk_1fe * F::from(i as u64)))
        .collect::<Vec<SecretKeyShare<G1>>>();

    // Signatures
    tink_signature::init();

    // SIG.KeyGen for Helper
    let sk_sig_helper =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let vk_sig_helper = sk_sig_helper.public().unwrap();

    // SIG.KeyGen for Auditor
    let sk_sig_auditor =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let vk_sig_auditor = sk_sig_auditor.public().unwrap();

    // PKE
    tink_hybrid::init();

    // PKE.KeyGen for Helper
    let sk_enc_helper = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_helper: keyset::Handle = sk_enc_helper.public().unwrap();

    // PKE.KeyGen for Auditor
    tink_hybrid::init();
    let sk_enc_auditor = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_auditor = sk_enc_auditor.public().unwrap();

    // Generate secret tags for recipients
    let mut valid_set: HashSet<[u8; TAG_BYTELEN]> = HashSet::new();
    let mut tags: Vec<Vec<[u8; TAG_BYTELEN]>> = Vec::new();
    for i in 0..(NUM_RECIPIENTS) {
        tags.push(Vec::new());
        for _j in 0..(MAX_ENTITLEMENT) {
            let mut tag = [0u8; TAG_BYTELEN];
            rand::thread_rng().fill(&mut tag);
            valid_set.insert(tag);
            tags[i].push(tag);
        }
    }

    // Recipients encrypt
    let ctxts = (0..NUM_SHOW_UP)
        .map(|i| bench_recipient_1(1, pp, id, &tags[i], pk_1fe, &pk_enc_helper, &pk_enc_auditor))
        .collect::<Vec<_>>();
    let ctxts_1fe_helper = ctxts.iter().map(|(ct, _)| ct.clone()).collect::<Vec<_>>();
    let ctxts_auditor = ctxts
        .iter()
        .map(|(_, ct_vec)| ct_vec.clone())
        .collect::<Vec<_>>();

    // Auditor processes
    let sig_auditor = bench_auditor(&ctxts_auditor, &valid_set, &sk_enc_auditor, &sk_sig_auditor);

    // Helper checks and processes
    let (ctxt_out, ctxt_out_sig) = bench_helper(
        &ctxts_1fe_helper,
        id,
        &sig_auditor,
        &sk_enc_helper,
        &sk_sig_helper,
        &vk_sig_auditor,
        last_period,
    );

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

    c.bench_function("mal_thhe_1_auditor", |b| {
        b.iter(|| {
            bench_auditor(&ctxts_auditor, &valid_set, &sk_enc_auditor, &sk_sig_auditor);
        })
    });

    c.bench_function("mal_thhe_1_helper", |b| {
        b.iter(|| {
            bench_helper::<G1>(
                black_box(&ctxts_1fe_helper),
                id,
                &sig_auditor,
                &sk_enc_helper,
                &sk_sig_helper,
                &vk_sig_auditor,
                last_period,
            )
        })
    });

    c.bench_function("mal_thhe_1_distribution", |b| {
        b.iter(|| bench_distribution_station::<G1>(black_box(ctxt_out), black_box(&pdecs)))
    });
}

criterion_group! {
    name = benches_phone;
    config = Criterion::default().sample_size(10);
    targets = mal_thhe_1_recipient
}
criterion_group! {
    name = benches_laptop;
    config = Criterion::default().sample_size(10);
    targets = mal_thhe_1
}

// on mobile targets, only run the phone-focused benchmark
#[cfg(any(target_os = "android", target_os = "ios"))]
criterion_main!(benches_phone);

// treat other embedded targets like mobile
#[cfg(all(
    not(any(target_os = "android", target_os = "ios")),
    any(target_arch = "arm", target_arch = "aarch64"),
    not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
))]
criterion_main!(benches_phone);

// non-mobile targets
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
criterion_main!(benches_laptop);