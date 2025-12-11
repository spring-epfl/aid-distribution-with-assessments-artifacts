use aid_distribution_with_assessments::DECRYPTION_THRESHOLD;
use aid_distribution_with_assessments::MAX_ENTITLEMENT;
use aid_distribution_with_assessments::NUM_RECIPIENTS;
use aid_distribution_with_assessments::NUM_SHOW_UP;
use aid_distribution_with_assessments::TAG_BYTELEN;
use ark_ec::pairing::*;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use rand::Rng;
use std::collections::HashSet;
use tink_core::keyset;

fn recipient<F: PrimeField>(
    b: u64,
    id: u16,
    secret_tags: &Vec<[u8; TAG_BYTELEN]>,
    pk_enc_helper: &tink_core::keyset::Handle,
    pk_enc_auditor: &tink_core::keyset::Handle,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // Secret-share F(b)
    let val = F::from(b);
    let mut rng = thread_rng();
    let share_0 = F::rand(&mut rng);
    let share_1 = val - share_0;

    let enc = tink_hybrid::new_encrypt(&pk_enc_helper).unwrap();
    let id_bytes = id.to_be_bytes();
    let mut bytes = Vec::new();
    let writer = &mut bytes;
    share_0.serialize_compressed(writer).unwrap();
    let ctxt_1fe = enc.encrypt(&bytes, id_bytes.as_slice()).unwrap();

    let mut ctxts_1fe_pkehelper: Vec<Vec<u8>> = Vec::new();

    // Encrypt 1FE ciphertext and secret_tag_{i,p,1} under auditor's public key
    let enc_auditor = tink_hybrid::new_encrypt(&pk_enc_auditor).unwrap();
    let mut bytes_auditor = Vec::new();
    bytes_auditor.extend_from_slice(&secret_tags[0]); // secret_tag{i,p,k}
    bytes_auditor.extend_from_slice(&ctxt_1fe); // 1FE ciphertext
    ctxts_1fe_pkehelper.push(ctxt_1fe);
    let ct_1fe_pkeauditor = enc_auditor.encrypt(&bytes_auditor, b"").unwrap();

    // 1FE.Encrypt dummy symbol 0 for MAX_ENTITLEMENT-1 times
    // Encrypt all dummy 1FE ciphertexts and secret_tag{i,p,k} under auditor's public key
    let mut ctxts_auditor = Vec::new();
    ctxts_auditor.push(ct_1fe_pkeauditor);
    for k in 1..MAX_ENTITLEMENT {
        let ctxt_1fe = enc.encrypt(&bytes, id_bytes.as_slice()).unwrap();

        let mut bytes_auditor = Vec::new();
        bytes_auditor.extend_from_slice(&secret_tags[k]); // secret_tag{i,p,k}
        bytes_auditor.extend_from_slice(&ctxt_1fe); // 1FE ciphertext
        ctxts_1fe_pkehelper.push(ctxt_1fe);
        let ct_1fe_pkeauditor = enc_auditor.encrypt(&bytes_auditor, b"").unwrap();

        ctxts_auditor.push(ct_1fe_pkeauditor);
    }

    (ctxts_1fe_pkehelper, ctxts_auditor)
}

fn bench_auditor(
    ctxts_pke_auditor: &Vec<Vec<Vec<u8>>>,
    valid_set: &HashSet<[u8; TAG_BYTELEN]>,
    sk_enc_auditor: &keyset::Handle,
) -> Vec<Vec<u8>> {
    // Decrypt outer ciphertexts to secret tag and 1FE ciphertexts
    let dec_auditor = tink_hybrid::new_decrypt(&sk_enc_auditor).unwrap();
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

    ctxts_1fe
}

fn hbc_2pc_2_auditor(c: &mut Criterion) {
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
    let enc = tink_hybrid::new_encrypt(&pk_enc_helper).unwrap();

    // PKE.KeyGen for Auditor
    tink_hybrid::init();
    let sk_enc_auditor = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();
    let pk_enc_auditor = sk_enc_auditor.public().unwrap();
    let enc_auditor = tink_hybrid::new_encrypt(&pk_enc_auditor).unwrap();

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
        .map(|i| recipient::<F>(1, id, &tags[i], &pk_enc_helper, &pk_enc_auditor))
        .collect::<Vec<_>>();
    let ctxts_1fe_helper = ctxts.iter().map(|(ct, _)| ct.clone()).collect::<Vec<_>>();
    let ctxts_auditor = ctxts
        .iter()
        .map(|(_, ct_vec)| ct_vec.clone())
        .collect::<Vec<_>>();

    c.bench_function("hbc_2pc_2_auditor", |b| {
        b.iter(|| bench_auditor(&ctxts_auditor, &valid_set, &sk_enc_auditor))
    });
}

criterion_group! {
    name = benches_phone;
    config = Criterion::default().sample_size(10);
    targets = hbc_2pc_2_auditor
}

criterion_main!(benches_phone);
