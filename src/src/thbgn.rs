use ark_ec::pairing;
use ark_ec::pairing::*;
use ark_std::Zero;
use ark_ff::Field;
use ark_std::UniformRand;
use bincode::de;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use secret_sharing_and_dkg::common::*;
use secret_sharing_and_dkg::error::*;
use secret_sharing_and_dkg::shamir_ss::*;

use ark_std::cfg_into_iter;
use ark_std::One;

pub type PublicParameters<P: Pairing> = (P::G1, P::G2);
pub type SecretKey<P: Pairing> = (P::ScalarField, P::ScalarField);
pub type SecretKeyShare<P: Pairing> = (ShareId, P::ScalarField, P::ScalarField);

pub type PublicKey<P: Pairing> = (P::G1, P::G2);
#[derive(Clone, Copy)]
pub struct Ciphertext1<P: Pairing>(pub (P::G1, P::G1, P::G2, P::G2));

#[derive(Clone, Copy)]
pub struct CiphertextT<P: Pairing>(
    pub (
        PairingOutput<P>,
        PairingOutput<P>,
        PairingOutput<P>,
        PairingOutput<P>,
    ),
);

pub type PartialDecryption<P: Pairing> = (
    ShareId,
    PairingOutput<P>,
    PairingOutput<P>,
    PairingOutput<P>,
    PairingOutput<P>,
);

pub type PartialDecryption2<P: Pairing> = (ShareId, PairingOutput<P>, PairingOutput<P>);
pub type IntermediateDec<P> = (PairingOutput<P>, PairingOutput<P>);

pub fn rand_invertible<F: Field>() -> F {
    let mut rng = thread_rng();
    loop {
        let candidate = F::rand(&mut rng);
        if candidate.inverse().is_some() {
            return candidate;
        }
    }
}

pub fn paramgen<P: Pairing>() -> PublicParameters<P> {
    let mut rng = thread_rng();
    (P::G1::rand(&mut rng), P::G2::rand(&mut rng))
}

pub fn keygen<P: Pairing>(pp: PublicParameters<P>) -> (SecretKey<P>, PublicKey<P>) {
    let s1: P::ScalarField = rand_invertible();
    let s2: P::ScalarField = rand_invertible();
    let (g1, g2) = pp;
    let h1 = g1 * s1;
    let h2 = g2 * s2;
    ((s1, s2), (h1, h2))
}

pub fn encrypt<P: Pairing>(
    pp: PublicParameters<P>,
    pk: PublicKey<P>,
    msg: P::ScalarField,
) -> Ciphertext1<P> {
    let mut rng = thread_rng();
    let rho = P::ScalarField::rand(&mut rng);
    let sigma = P::ScalarField::rand(&mut rng);
    let (g1, g2) = pp;
    let (h1, h2) = pk;
    Ciphertext1((
        g1 * rho,
        g1 * msg + h1 * rho,
        g2 * sigma,
        g2 * msg + h2 * sigma,
    ))
}

pub fn add<P: Pairing>(
    pp: PublicParameters<P>,
    ct1: Ciphertext1<P>,
    ct2: Ciphertext1<P>,
) -> Ciphertext1<P> {
    let (c1_1, c1_2, c1_3, c1_4) = ct1.0;
    let (c2_1, c2_2, c2_3, c2_4) = ct2.0;
    Ciphertext1((c1_1 + c2_1, c1_2 + c2_2, c1_3 + c2_3, c1_4 + c2_4))
    // TODO: rerandomize
}

pub fn mul<P: Pairing>(
    pp: PublicParameters<P>,
    ct1: Ciphertext1<P>,
    ct2: Ciphertext1<P>,
) -> CiphertextT<P> {
    let (c1_1, c1_2, c1_3, c1_4) = ct1.0;
    let (c2_1, c2_2, c2_3, c2_4) = ct2.0;
    CiphertextT((
        P::pairing(c1_1, c2_3),
        P::pairing(c1_1, c2_4),
        P::pairing(c1_2, c2_3),
        P::pairing(c1_2, c2_4),
    ))
    // TODO: rerandomize?
}

pub fn find_dlog<P: Pairing>(
    base: PairingOutput<P>,
    p: PairingOutput<P>,
    bound: P::ScalarField,
) -> P::ScalarField
where
    P::ScalarField: ark_ff::PrimeField,
{
    // Find discrete log of p in base
    // Enumerate from -Bound to Bound in F, test if base^i = p

    let mut i = P::ScalarField::zero();
    while i < bound {
        if base * i == p {
            return i;
        }
        if base * i == -p {
            return -i;
        }
        i += P::ScalarField::ONE;
    }
    panic!("Discrete log not found");
}

pub fn decrypt<P: Pairing>(
    pp: PublicParameters<P>,
    sk: SecretKey<P>,
    ct: CiphertextT<P>,
    bound: u64,
) -> P::ScalarField {
    let (s1, s2) = sk;
    let (c1, c2, c3, c4) = ct.0;
    let (g1, g2) = pp;
    let gT = P::pairing(g1, g2);
    find_dlog(
        gT,
        c1 * (s1 * s2) - c2 * s1 - c3 * s2 + c4,
        P::ScalarField::from(bound),
    )
}

pub fn share_sk<P: Pairing>(
    sk: SecretKey<P>,
    threshold: usize,
    total: usize,
) -> Vec<SecretKeyShare<P>>
where
    <P as ark_ec::pairing::Pairing>::ScalarField: ark_ff::PrimeField,
{
    let mut rng = thread_rng();

    let (shares1, poly1) =
        deal_secret(&mut rng, sk.0, threshold as ShareId, total as ShareId).unwrap();
    let (shares2, poly2) =
        deal_secret(&mut rng, sk.1, threshold as ShareId, total as ShareId).unwrap();
    debug_assert!(shares1
        .0
        .iter()
        .zip(shares2.0.iter())
        .all(|(s1, s2)| s1.id == s2.id));
    shares1
        .0
        .into_iter()
        .zip(shares2.0.into_iter())
        .map(|(s1, s2)| (s1.id, s1.share, s2.share))
        .collect()
}

pub fn partial_decrypt<P: Pairing>(
    pp: PublicParameters<P>,
    sk: SecretKeyShare<P>,
    ct: CiphertextT<P>,
) -> PartialDecryption<P> {
    let (c1, c2, c3, c4) = ct.0;
    let (id, s1, s2) = sk;
    (id, c1 * s1, c2 * s1, c3 * s2, c4)
}

pub fn intermediate_dec<P: Pairing>(
    pp: PublicParameters<P>,
    pdecs: &[PartialDecryption<P>],
    bound: u64,
) -> IntermediateDec<P> {
    let c4 = pdecs[0].4;
    debug_assert!(pdecs.into_iter().map(|pdec| pdec.4).all(|c| c == c4));
    // Reconstruct s1*c1, c2*s1, c3*s2
    let s1c1 = reconstruct_secret_in_exp(
        &pdecs
            .iter()
            .map(|pdec| (pdec.0, pdec.1))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let c1s2 = reconstruct_secret_in_exp(
        &pdecs
            .iter()
            .map(|pdec| (pdec.0, pdec.2))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let c3s2 = reconstruct_secret_in_exp(
        &pdecs
            .iter()
            .map(|pdec| (pdec.0, pdec.3))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    (s1c1, -c1s2 - c3s2 + c4)
}

pub fn partial_decrypt2<P: Pairing>(
    pp: PublicParameters<P>,
    sk: SecretKeyShare<P>,
    pdec: IntermediateDec<P>,
) -> PartialDecryption2<P> {
    let (id, s1, s2) = sk;
    let (s1c1, c) = pdec;
    (id, s1c1 * s2, c)
}

pub fn final_decrypt<P: Pairing>(
    pp: PublicParameters<P>,
    pdecs: &[PartialDecryption2<P>],
    bound: u64,
) -> P::ScalarField {
    let c = pdecs[0].2;
    debug_assert!(pdecs.into_iter().map(|pdec| pdec.2).all(|c_| c_ == c));
    let s1s2c1 = reconstruct_secret_in_exp(
        &pdecs
            .iter()
            .map(|pdec| (pdec.0, pdec.1))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    find_dlog(
        P::pairing(pp.0, pp.1),
        s1s2c1 + c,
        P::ScalarField::from(bound),
    )
}

/// Given ((i_j, s_i_j G))_{j\in[t]}, output s G where s_i_j = f(i_j) and s = f(0)
pub fn reconstruct_secret_in_exp<P: Pairing>(
    shares: &[(ShareId, PairingOutput<P>)],
) -> Result<PairingOutput<P>, SSError> {
    // let threshold = self.threshold();
    // let len = self.0.len() as ShareId;
    // if threshold > len {
    //     return Err(SSError::BelowThreshold(threshold, len));
    // }
    // let shares = &self.0[0..threshold as usize];
    let share_ids = shares.iter().map(|s| s.0).collect::<Vec<_>>();
    let basis = lagrange_basis_at_0_for_all::<P::ScalarField>(share_ids)?;
    Ok(cfg_into_iter!(basis)
        .zip(cfg_into_iter!(shares))
        .map(|(b, s)| s.1* b)
        .sum::<PairingOutput<P>>())
}

#[cfg(test)]
mod test {
    type P = ark_bls12_381::Bls12_381;
    type F = <P as Pairing>::ScalarField;
    const ptxt: u64 = 3;
    const bound: u64 = 1 << 4;

    use super::*;
    #[test]
    fn test_enc_dec() {
        let pp = paramgen::<P>();

        let (sk, pk) = keygen::<P>(pp);

        let msg = F::from(ptxt);
        debug_assert!(ptxt * ptxt <= bound);
        let ct0 = encrypt::<P>(pp, pk, msg);
        let ct1 = encrypt::<P>(pp, pk, msg);
        let ct2 = mul::<P>(pp, ct0, ct1);
        let pt = decrypt::<P>(pp, sk, ct2, bound);
        assert_eq!(msg * msg, pt);
    }

    #[test]
    fn test_enc_distributeddec() {
        let pp = paramgen::<P>();

        let (sk, pk) = keygen::<P>(pp);
        let sks = share_sk::<P>(sk, 3, 5);

        let msg = F::from(ptxt);
        debug_assert!(ptxt * ptxt <= bound);
        let ct0 = encrypt::<P>(pp, pk, msg);
        let ct1 = encrypt::<P>(pp, pk, msg);
        let ct2 = mul::<P>(pp, ct0, ct1);

        let pdecs = sks
            .iter()
            .map(|sk| partial_decrypt::<P>(pp, *sk, ct2))
            .collect::<Vec<_>>();
        let inter = intermediate_dec::<P>(pp, pdecs.as_slice(), bound);

        let pdecs2 = sks
            .iter()
            .map(|sk| partial_decrypt2::<P>(pp, *sk, inter))
            .collect::<Vec<_>>();

        let pt = final_decrypt::<P>(pp, &pdecs2, (1 << 4));
        assert_eq!(msg * msg, pt);
    }
}
