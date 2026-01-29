use aid_distribution_with_assessments::DECRYPTION_THRESHOLD;
use aid_distribution_with_assessments::MAX_ENTITLEMENT;
use aid_distribution_with_assessments::NUM_RECIPIENTS;
use aid_distribution_with_assessments::NUM_SHOW_UP;
use aid_distribution_with_assessments::TAG_BYTELEN;
use aid_distribution_with_assessments::thbgn::*;
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::Zero;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand::Rng;
use secret_sharing_and_dkg::common::ShareId;
use std::collections::HashSet;
use std::io::Write;
use tink_core::keyset;

const INFO_LEN: usize = 1 + 1; // 1 indicator bit, 1 data field element
const BOUND: usize = 1 << 10;

fn bytes_to_ctxts_1<P: Pairing>(bytes: &Vec<u8>) -> Vec<Ciphertext1<P>> {
    // Deserialize bytes into [Ciphertext1; INFO_LEN]
    let size = 2 * P::G1::serialized_size(&P::G1::zero(), ark_serialize::Compress::Yes)
        + 2 * P::G2::serialized_size(&P::G2::zero(), ark_serialize::Compress::Yes);
    assert_eq!(bytes.len(), INFO_LEN * size);
    let mut ctxts = Vec::new();
    for i in 0..INFO_LEN {
        let start = i * size;
        let end = start + size;
        let mut reader = &bytes[start..end];
        let c1 = P::G1::deserialize_compressed(&mut reader).unwrap();
        let c2 = P::G1::deserialize_compressed(&mut reader).unwrap();
        let c3 = P::G2::deserialize_compressed(&mut reader).unwrap();
        let c4 = P::G2::deserialize_compressed(&mut reader).unwrap();
        ctxts.push(Ciphertext1::<P>((c1, c2, c3, c4)));
    }
    ctxts
}

fn ctxt_1_to_bytes<P: Pairing>(ctxt: &Ciphertext1<P>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut bytes_1 = Vec::new();
    let writer = &mut bytes_1;
    ctxt.0.0.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_1);
    let mut bytes_2 = Vec::new();
    let writer = &mut bytes_2;
    ctxt.0.1.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_2);
    let mut bytes_3 = Vec::new();
    let writer = &mut bytes_3;
    ctxt.0.2.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_3);
    let mut bytes_4 = Vec::new();
    let writer = &mut bytes_4;
    ctxt.0.3.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_4);
    bytes
}

fn ctxt_t_to_bytes<P: Pairing>(ctxt: &CiphertextT<P>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for po in &[ctxt.0.0, ctxt.0.1, ctxt.0.2, ctxt.0.3] {
        let mut po_bytes = Vec::new();
        let writer = &mut po_bytes;
        po.serialize_compressed(writer).unwrap();
        bytes.extend_from_slice(&po_bytes);
    }
    bytes
}

#[allow(clippy::too_many_arguments)]
fn bench_helper<P: Pairing>(
    pp: PublicParameters<P>,
    ctxts: &Vec<Vec<Vec<u8>>>,
    id: u16,
    sig_auditor: &Vec<u8>,
    sk_enc_helper: &keyset::Handle,
    sk_sig_helper: &keyset::Handle,
    vk_sig_auditor: &keyset::Handle,
    last_period: u16,
) -> (Vec<Vec<CiphertextT<P>>>, Vec<u8>) {
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
                    bytes_to_ctxts_1::<P>(&pt)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // Evaluate: forall i: multiply inner_ctxts[i][0] * (inner_ctxts[i][1], ..., inner_ctxts[i][INFO_LEN-1])
    let cs_noshow = inner_ctxts[0].clone(); // Pick first recipient as the no-show for multiple periods w.l.o.g.
    // On input [[cs0,0, ..., cs0,INFO_LEN-1], [cs1,0, ..., cs1,INFO_LEN-1], ...], output [[cs0,0 * cs1,0, ..., cs0,0 * csN,0], [cs1,0 * cs1,1, ..., cs1,0 * csN,1], ...]
    let res: Vec<Vec<CiphertextT<P>>> = cs_noshow
        .into_iter()
        .map(|cs| {
            let cs_0 = cs[0];
            cs.into_iter()
                .skip(1)
                .map(|c| mul::<P>(pp, cs_0, c))
                .collect::<Vec<CiphertextT<P>>>()
        })
        .collect();

    // Sign the resulting ciphertexts
    let sig = tink_signature::new_signer(&sk_sig_helper).unwrap();
    let data: Vec<u8> = res
        .iter()
        .flat_map(|ctxts| ctxts.iter().flat_map(|ctxt| ctxt_t_to_bytes(ctxt)))
        .collect();
    let signature = sig.sign(data.as_slice()).unwrap();

    (res, signature)
}

fn bench_distribution_station_1<P: Pairing>(
    pp: PublicParameters<P>,
    pdecs: &Vec<Vec<Vec<PartialDecryption<P>>>>,
) -> Vec<Vec<IntermediateDec<P>>> {
    // Aggregate DECRYPTION_THRESHOLD partial decryptions
    assert!(pdecs.len() == DECRYPTION_THRESHOLD);
    // For each pdec_ijk in pdecs, compute intermediate decryptions idec_jk
    let mut idecs = Vec::new();
    let num_outputs = pdecs[0].len();
    let output_len_each = pdecs[0][0].len();
    for j in 0..num_outputs {
        let mut idecs_j = Vec::new();
        for k in 0..output_len_each {
            let pdecs_jk = pdecs
                .iter()
                .map(|pdec_i| pdec_i[j][k])
                .collect::<Vec<PartialDecryption<P>>>();
            let idec_jk = intermediate_dec::<P>(pp, &pdecs_jk, BOUND as u64);
            idecs_j.push(idec_jk);
        }
        idecs.push(idecs_j);
    }

    idecs
}

fn bench_distribution_station_2<P: Pairing>(
    pp: PublicParameters<P>,
    pdecs2: &Vec<Vec<Vec<PartialDecryption2<P>>>>,
) -> Vec<Vec<P::ScalarField>> {
    // Aggregate DECRYPTION_THRESHOLD partial decryptions
    assert!(pdecs2.len() == DECRYPTION_THRESHOLD);

    // For each pdec2_ijk in pdecs2, compute final decryptions out_jk
    let mut outs = Vec::new();
    let num_outputs = pdecs2[0].len();
    let output_len_each = pdecs2[0][0].len();
    for j in 0..num_outputs {
        let mut outs_j = Vec::new();
        for k in 0..output_len_each {
            let pdecs2_jk = pdecs2
                .iter()
                .map(|pdec2_i| pdec2_i[j][k])
                .collect::<Vec<PartialDecryption2<P>>>();
            let out_jk = final_decrypt::<P>(pp, &pdecs2_jk, BOUND as u64);
            outs_j.push(out_jk);
        }
        outs.push(outs_j)
    }
    outs
}

fn bench_recipient_1<P: Pairing>(
    b: u64,
    pp: PublicParameters<P>,
    id: u16,
    secret_tags: &Vec<[u8; TAG_BYTELEN]>,
    pk_1fe: PublicKey<P>,
    pk_helper: &tink_core::keyset::Handle,
    pk_auditor: &tink_core::keyset::Handle,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // Encrypt indicator bit
    let ctxt_bit = encrypt::<P>(pp, pk_1fe, P::ScalarField::from(b));

    // Encrypt recipient info
    let ctxt_data = encrypt::<P>(pp, pk_1fe, P::ScalarField::from(BOUND as u64 - 1));

    let mut ctxts_1fe_pkehelper: Vec<Vec<u8>> = Vec::new();

    // Encrypt under helper's public key
    let enc = tink_hybrid::new_encrypt(pk_helper).unwrap();
    let mut pt = Vec::new();
    pt.extend_from_slice(&ctxt_1_to_bytes(&ctxt_bit));
    pt.extend_from_slice(&ctxt_1_to_bytes(&ctxt_data));

    let ct_1fe_pkehelper = enc.encrypt(&pt, id.to_be_bytes().as_slice()).unwrap();

    // Encrypt 1FE ciphertext and secret_tag_{i,p,1} under auditor's public key
    let enc_auditor = tink_hybrid::new_encrypt(pk_auditor).unwrap();
    let mut bytes_auditor = Vec::new();
    bytes_auditor.extend_from_slice(&secret_tags[0]); // secret_tag{i,p,k}
    bytes_auditor.extend_from_slice(&ct_1fe_pkehelper); // 1FE ciphertext
    ctxts_1fe_pkehelper.push(ct_1fe_pkehelper);
    let ct_1fe_pkeauditor = enc_auditor.encrypt(&bytes_auditor, b"").unwrap();

    // 1FE.Encrypt dummy symbol 0 for MAX_ENTITLEMENT-1 times
    // Encrypt all dummy 1FE ciphertexts and secret_tag{i,p,k} under auditor's public key
    let mut ctxts_auditor = Vec::new();
    ctxts_auditor.push(ct_1fe_pkeauditor);
    for k in 1..MAX_ENTITLEMENT {
        let ctxt_bit = encrypt::<P>(pp, pk_1fe, P::ScalarField::from(0u64));
        let ctxt_data = encrypt::<P>(pp, pk_1fe, P::ScalarField::from(0u64));

        let mut pt = Vec::new();
        pt.extend_from_slice(&ctxt_1_to_bytes(&ctxt_bit));
        pt.extend_from_slice(&ctxt_1_to_bytes(&ctxt_data));
        let ct_1fe_pkehelper = enc.encrypt(&pt, id.to_be_bytes().as_slice()).unwrap();

        let mut bytes_auditor = Vec::new();
        bytes_auditor.extend_from_slice(&secret_tags[k]); // secret_tag{i,p,k}
        bytes_auditor.extend_from_slice(&ct_1fe_pkehelper); // 1FE ciphertext
        ctxts_1fe_pkehelper.push(ct_1fe_pkehelper);
        let ct_1fe_pkeauditor = enc_auditor.encrypt(&bytes_auditor, b"").unwrap();

        ctxts_auditor.push(ct_1fe_pkeauditor);
    }

    (ctxts_1fe_pkehelper, ctxts_auditor)
}

fn bench_recipient_2<P: Pairing>(
    pp: PublicParameters<P>,
    _id: u16,
    _pk: PublicKey<P>,
    ctxts_out: &Vec<Vec<CiphertextT<P>>>,
    ctxts_out_sig: &Vec<u8>,
    sk: SecretKeyShare<P>,
    vk: &keyset::Handle,
) -> Vec<Vec<PartialDecryption<P>>> {
    // Verify signature on ctxts_out
    tink_signature::init();
    let v = tink_signature::new_verifier(vk).unwrap();
    let data: Vec<u8> = ctxts_out
        .iter()
        .flat_map(|ctxts| ctxts.iter().flat_map(|ctxt| ctxt_t_to_bytes(ctxt)))
        .collect();
    v.verify(ctxts_out_sig, data.as_slice()).unwrap();

    // Partially decrypt each ciphertext
    let pdec = ctxts_out
        .iter()
        .map(|cs| {
            cs.iter()
                .map(|ctxt| partial_decrypt::<P>(pp, sk, *ctxt))
                .collect::<Vec<_>>()
        })
        .collect();

    pdec
}

fn bench_auditor(
    ctxts_pke_auditor: &Vec<Vec<Vec<u8>>>,
    valid_set: &HashSet<[u8; TAG_BYTELEN]>,
    sk_enc_auditor: &keyset::Handle,
    sk_sig_auditor: &keyset::Handle,
) -> Vec<u8> {
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
    if !secret_tags.iter().all(|tags| tags.len() == MAX_ENTITLEMENT) {
        panic!("Incorrect number of secret tags");
    }

    // Sign canonical representation of 1FE input ciphertext
    let sig = tink_signature::new_signer(sk_sig_auditor).unwrap();
    let mut all_ctxt_bytes = Vec::new();
    for ctxt in ctxts_1fe.iter() {
        all_ctxt_bytes.extend_from_slice(ctxt);
    }
    let signature = sig.sign(all_ctxt_bytes.as_slice()).unwrap();
    signature
}

fn mal_thhe_2_recipient(c: &mut Criterion) {
    type P = ark_bls12_381::Bls12_381;
    type F = <P as Pairing>::ScalarField;

    let id = 1u16;

    println!("Generating keying material...");
    std::io::stdout().flush().ok();

    // 1FE.KeyGen
    let pp = paramgen::<P>();

    let (_sk_1fe, pk_1fe) = keygen::<P>(pp);
    // let shares = share_sk::<P>(sk_1fe, NUM_RECIPIENTS / 5, NUM_RECIPIENTS);
    // Dummy share: avoid Shamir sharing in the phone micro-benchmark.
    // Any scalar values are syntactically valid for `partial_decrypt`.
    let mut rng = rand::thread_rng();
    let share: SecretKeyShare<P> = (id as ShareId, F::rand(&mut rng), F::rand(&mut rng));

    // Signatures
    tink_signature::init();

    // SIG.KeyGen for Helper
    let sk_sig_helper =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let vk_sig_helper = sk_sig_helper.public().unwrap();

    println!("Generating inputs for recipients...");
    std::io::stdout().flush().ok();

    let gt = PairingOutput::<P>::zero();
    let ctxts_out = vec![vec![CiphertextT((gt, gt, gt, gt)); INFO_LEN - 1]; MAX_ENTITLEMENT];
    let sig = tink_signature::new_signer(&sk_sig_helper).unwrap();
    let data: Vec<u8> = ctxts_out
        .iter()
        .flat_map(|ctxts| ctxts.iter().flat_map(ctxt_t_to_bytes))
        .collect();
    let ctxts_out_sig = sig.sign(data.as_slice()).unwrap();

    println!("Starting benchmark...");
    std::io::stdout().flush().ok();

    c.bench_function("mal_thhe_2_recipient", |b| {
        b.iter(|| {
            bench_recipient_2(
                pp,
                id,
                pk_1fe,
                &ctxts_out,
                &ctxts_out_sig,
                share,
                &vk_sig_helper,
            );
        })
    });
}

fn mal_thhe_2(c: &mut Criterion) {
    type P = ark_bls12_381::Bls12_381;

    let last_period = 0u16;
    let id = 1u16;

    // 1FE.KeyGen
    let pp = paramgen::<P>();

    let (sk_1fe, pk_1fe) = keygen::<P>(pp);
    let shares = share_sk::<P>(sk_1fe, NUM_RECIPIENTS / 5, NUM_RECIPIENTS);

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
        .map(|i| {
            bench_recipient_1::<P>(1, pp, id, &tags[i], pk_1fe, &pk_enc_helper, &pk_enc_auditor)
        })
        .collect::<Vec<_>>();
    let ctxts_1fe_helper = ctxts.iter().map(|(ct, _)| ct.clone()).collect::<Vec<_>>();
    let ctxts_auditor = ctxts
        .iter()
        .map(|(_, ct_vec)| ct_vec.clone())
        .collect::<Vec<_>>();

    // Auditor processes
    let sig_auditor = bench_auditor(&ctxts_auditor, &valid_set, &sk_enc_auditor, &sk_sig_auditor);

    // Helper checks and processes
    let (ctxts_out, ctxts_out_sig) = bench_helper(
        pp,
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
        .take(DECRYPTION_THRESHOLD)
        .map(|share| {
            bench_recipient_2(
                pp,
                id,
                pk_1fe,
                &ctxts_out,
                &ctxts_out_sig,
                share,
                &vk_sig_helper,
            )
        })
        .collect::<Vec<_>>();

    let idecs = bench_distribution_station_1::<P>(pp, &pdecs);
    let pdecs2 = shares
        .clone()
        .into_iter()
        .take(DECRYPTION_THRESHOLD)
        .map(|share| {
            idecs
                .iter()
                .map(|idecs_j| {
                    idecs_j
                        .iter()
                        .map(|idec_jk| partial_decrypt2::<P>(pp, share, *idec_jk))
                        .collect::<Vec<PartialDecryption2<P>>>()
                })
                .collect::<Vec<Vec<PartialDecryption2<P>>>>()
        })
        .collect::<Vec<_>>();

    c.bench_function("mal_thhe_2_auditor", |b| {
        b.iter(|| {
            bench_auditor(&ctxts_auditor, &valid_set, &sk_enc_auditor, &sk_sig_auditor);
        })
    });

    c.bench_function("mal_thhe_2_helper", |b| {
        b.iter(|| {
            bench_helper::<P>(
                pp,
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

    c.bench_function("mal_thhe_2_distribution", |b| {
        b.iter(|| {
            bench_distribution_station_1::<P>(pp, black_box(&pdecs));
            bench_distribution_station_2::<P>(pp, black_box(&pdecs2))
        })
    });
}

criterion_group! {
    name = benches_phone;
    config = Criterion::default().sample_size(10);
    targets = mal_thhe_2_recipient
}

criterion_group! {
    name = benches_laptop;
    config = Criterion::default().sample_size(10);
    targets = mal_thhe_2
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
