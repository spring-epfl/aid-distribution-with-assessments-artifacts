use aid_distribution_with_assessments::thbgn::*;
use ark_ec::pairing;
use ark_ec::pairing::*;
use ark_ec::Group;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use aid_distribution_with_assessments::thbgn::rand_invertible;
use aid_distribution_with_assessments::DECRYPTION_THRESHOLD;
use aid_distribution_with_assessments::NUM_RECIPIENTS;
use aid_distribution_with_assessments::NUM_SHOW_UP;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_std::cfg_into_iter;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;
use openssl::cipher::Cipher;
use rand::thread_rng;
use secret_sharing_and_dkg::common::lagrange_basis_at_0_for_all;
use secret_sharing_and_dkg::common::ShareId;
use secret_sharing_and_dkg::error::SSError;
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
    ctxt.0 .0.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_1);
    let mut bytes_2 = Vec::new();
    let writer = &mut bytes_2;
    ctxt.0 .1.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_2);
    let mut bytes_3 = Vec::new();
    let writer = &mut bytes_3;
    ctxt.0 .2.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_3);
    let mut bytes_4 = Vec::new();
    let writer = &mut bytes_4;
    ctxt.0 .3.serialize_compressed(writer).unwrap();
    bytes.extend_from_slice(&bytes_4);
    bytes
}

fn ctxt_t_to_bytes<P: Pairing>(ctxt: &CiphertextT<P>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for po in &[ctxt.0 .0, ctxt.0 .1, ctxt.0 .2, ctxt.0 .3] {
        let mut po_bytes = Vec::new();
        let writer = &mut po_bytes;
        po.serialize_compressed(writer).unwrap();
        bytes.extend_from_slice(&po_bytes);
    }
    bytes
}

fn bench_helper<P: Pairing>(
    pp: PublicParameters<P>,
    ctxts: &[Vec<u8>],
    id: u16,
    sk_enc_helper: &keyset::Handle,
    sk_sig_helper: &keyset::Handle,
    last_period: u16,
) -> (Vec<Vec<CiphertextT<P>>>, Vec<u8>) {
    // Enforce one-time property
    let id_bytes = id.to_be_bytes();
    if id <= last_period {
        panic!("Already processed this period");
    }

    // Decrypt outer ciphertexts
    let dec = tink_hybrid::new_decrypt(&sk_enc_helper).unwrap();
    let inner_ctxts: Vec<Vec<Ciphertext1<P>>> = ctxts
        .into_iter()
        .map(|ctxt| {
            let pt = dec.decrypt(ctxt, id_bytes.as_slice()).unwrap();
            bytes_to_ctxts_1::<P>(&pt)
        })
        .collect();

    // Evaluate: forall i: multiply inner_ctxts[i][0] * (inner_ctxts[i][1], ..., inner_ctxts[i][INFO_LEN-1])
    let cs = inner_ctxts[0].clone(); // Pick first recipient as the no-show for multiple periods w.l.o.g.
    let cs_0 = cs[0].clone();
    let res: Vec<Vec<CiphertextT<P>>> = vec![cs
        .into_iter()
        .skip(1)
        .map(|c| mul::<P>(pp, cs_0, c))
        .collect::<Vec<CiphertextT<P>>>()];

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
    pk_1fe: PublicKey<P>,
    pk_helper: &tink_core::keyset::Handle,
) -> Vec<u8> {
    // Encrypt indicator bit
    let ctxt_bit = encrypt::<P>(pp, pk_1fe, P::ScalarField::from(b));

    // Encrypt recipient info
    let ctxt_data = encrypt::<P>(pp, pk_1fe, P::ScalarField::from(BOUND as u64-1));

    // Concatenate [Ciphertext1; INFO_LEN] -> bytes
    let mut pt = Vec::new();
    pt.extend_from_slice(&ctxt_1_to_bytes(&ctxt_bit));
    pt.extend_from_slice(&ctxt_1_to_bytes(&ctxt_data));

    // Encrypt under helper's public key
    let enc = tink_hybrid::new_encrypt(&pk_helper).unwrap();
    let bytes = pt.as_slice();
    let ct = enc.encrypt(&bytes, id.to_be_bytes().as_slice()).unwrap();

    ct
}

fn bench_recipient_2<P: Pairing>(
    pp: PublicParameters<P>,
    id: u16,
    pk: PublicKey<P>,
    ctxts_out: &Vec<Vec<CiphertextT<P>>>,
    ctxt_out_sig: &Vec<u8>,
    sk: SecretKeyShare<P>,
    vk: &keyset::Handle,
) -> Vec<Vec<PartialDecryption<P>>> {
    // Verify signature on ctxts_out
    tink_signature::init();
    let v = tink_signature::new_verifier(&vk).unwrap();
    let data: Vec<u8> = ctxts_out
        .iter()
        .flat_map(|ctxts| ctxts.iter().flat_map(|ctxt| ctxt_t_to_bytes(ctxt)))
        .collect();
    v.verify(&ctxt_out_sig, data.as_slice()).unwrap();

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

fn hbc_thhe_2(c: &mut Criterion) {
    type P = ark_bls12_381::Bls12_381;
    type F = <P as Pairing>::ScalarField;

    let last_period = 0u16;
    let id = 1u16;

    // 1FE.KeyGen
    let pp = paramgen::<P>();

    let (sk_1fe, pk_1fe) = keygen::<P>(pp);
    let shares = share_sk::<P>(sk_1fe, NUM_RECIPIENTS / 5, NUM_RECIPIENTS);

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
    let enc = tink_hybrid::new_encrypt(&pk_enc_helper).unwrap();

    // Recipients encrypt
    let ctxts = (0..NUM_SHOW_UP)
        .map(|_| bench_recipient_1::<P>(1, pp, id, pk_1fe, &pk_enc_helper))
        .collect::<Vec<_>>();

    // Helper checks and processes
    let (ctxts_out, ctxts_out_sig) =
        bench_helper(pp, &ctxts, id, &sk_enc_helper, &sk_sig_helper, last_period);

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

    let share = shares[0].clone();
    c.bench_function("hbc_thhe_2_recipient", |b| {
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

    c.bench_function("hbc_thhe_2_helper", |b| {
        b.iter(|| {
            bench_helper::<P>(
                pp,
                black_box(&ctxts),
                id,
                &sk_enc_helper,
                &sk_sig_helper,
                last_period,
            )
        })
    });

    c.bench_function("hbc_thhe_2_distribution", |b| {
        b.iter(|| {
            bench_distribution_station_1::<P>(pp, black_box(&pdecs));
            bench_distribution_station_2::<P>(pp, black_box(&pdecs2))
        })
    });
}

// criterion_group!(benches, hbc_thhe_2);
criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = hbc_thhe_2
}
criterion_main!(benches);
