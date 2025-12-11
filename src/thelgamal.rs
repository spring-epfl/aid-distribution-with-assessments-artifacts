use ark_ec::{pairing, Group};
use ark_ec::pairing::*;
use ark_std::Zero;
// use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_std::UniformRand;
use bincode::de;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use secret_sharing_and_dkg::shamir_ss::*;
use secret_sharing_and_dkg::common::ShareId;

type PublicParameters<G: Group> = G;
type SecretKey<G: Group> = G::ScalarField;

type PublicKey<G: Group> = G;
struct Ciphertext<G: Group>(G, G);

type PartialDecryption<G: Group> = (
   G
);

pub fn rand_invertible<F: Field>() -> F {
    let mut rng = thread_rng();
    loop {
        let candidate = F::rand(&mut rng);
        if candidate.inverse().is_some() {
            return candidate;
        }
    }
}

pub fn paramgen<G: Group>() -> PublicParameters<G> {
    let mut rng = thread_rng();
    G::rand(&mut rng)
}

pub fn keygen<P: Pairing>(pp: PublicParameters<P>) -> (SecretKey<P>, PublicKey<P>) {
    let s: P::ScalarField = rand_invertible();
    (s, s * pp)
}

pub fn encrypt<P: Pairing>(
    pp: PublicParameters<P>,
    pk: PublicKey<P>,
    msg: P::ScalarField,
) -> Ciphertext1<P> {
    let mut rng = thread_rng();
    let r = P::ScalarField::rand(&mut rng);
    let g = pp;
    let h = pk;
    Ciphertext((
        g * r,
        msg + h * r,
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
}

fn find_dlog<P: Pairing>(
    base: PairingOutput<P>,
    p: PairingOutput<P>,
    bound: P::ScalarField,
) -> P::ScalarField 
where P::ScalarField: ark_ff::PrimeField
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

pub fn share_sk<P: Pairing>(sk: SecretKey<P>, threshold: usize, total: usize) -> Vec<SecretKey<P>>
where
    <P as ark_ec::pairing::Pairing>::ScalarField: ark_ff::PrimeField
{
    let mut rng = thread_rng();

    let (shares1, poly1) = deal_secret(&mut rng, sk.0, threshold as ShareId, total as ShareId).unwrap();
    let (shares2, poly2) = deal_secret(&mut rng, sk.1, threshold as ShareId, total as ShareId).unwrap();
    // let (shares1, poly1) =
    //     deal_secret::<ThreadRng, <P as ark_ec::pairing::Pairing>::ScalarField>>(&mut rng, sk.0, threshold as ShareID, total as ShareID).unwrap();
    // let (shares2, poly2) =
    //     deal_secret::<ThreadRng, <P as ark_ec::pairing::Pairing>::ScalarField>>(&mut rng, sk.1, threshold as ShareID, total as ShareID).unwrap();

    shares1.0.into_iter().zip(shares2.0.into_iter()).map(|(s1, s2)| (s1.share, s2.share)).collect()
}

pub fn partial_decrypt<P: Pairing>(
    pp: PublicParameters<P>,
    sk: SecretKey<P>,
    ct: CiphertextT<P>,
) -> PartialDecryption<P> {
    let (c1, c2, c3, c4) = ct.0;
    let (s1, s2) = sk;
    (c1 * s1, c2 * s1, c3 * s2, c4)
}

pub fn intermediate_dec<P: Pairing>(
    pp: PublicParameters<P>,
    pdecs: &[PartialDecryption<P>],
    bound: u64,
) -> PDecFinal1<P> {
    // Reconstruct s1*c1, c2*s1, c3*s2, c4
    let (s1c1, c2s2, c3s2, c4) = pdecs.iter().fold(
        (PairingOutput::<P>::zero(), PairingOutput::<P>::zero(),PairingOutput::<P>::zero(), PairingOutput::<P>::zero()),
        |acc, pdec| {
            let (c1, c2, c3, c4) = pdec;
            (acc.0 + c1, acc.1 + c2, acc.2 + c3, acc.3 + c4)
        },
    );
    (s1c1, -c2s2 - c3s2 + c4)
}

pub type PDecFinal1<P> = (PairingOutput<P>, PairingOutput<P>);

pub fn partial_decrypt2<P: Pairing>(
    pp: PublicParameters<P>,
    sk: SecretKey<P>,
    pdec: PDecFinal1<P>,
) -> PartialDecryption2<P> {
    let (s1, s2) = sk;
    let (s1c1, c) = pdec;
    (s1c1 * s2, c)
}

pub fn final_decrypt<P: Pairing>(
    pp: PublicParameters<P>,
    pdecs: &[PartialDecryption2<P>],
    bound: u64,
) -> P::ScalarField {
    let (s1s2c1, c) = pdecs.iter().fold((PairingOutput::<P>::zero(), PairingOutput::<P>::zero()), |acc, pdec| {
        let (c1, c2) = pdec;
        (acc.0 + c1, acc.1 + c2)
    });
    find_dlog(
        P::pairing(pp.0, pp.1),
        s1s2c1 + c,
        P::ScalarField::from(bound),
    )
}

// /// Given ((i_j, s_i_j G))_{j\in[t]}, output s G where s_i_j = f(i_j) and s = f(0)
// pub fn reconstruct_secret_in_exp<P:Pairing>(shares:&[(ShareId, PairingOutput<P>)]) -> Result<PairingOutput<>, SSError> {
//     // let threshold = self.threshold();
//     // let len = self.0.len() as ShareId;
//     // if threshold > len {
//     //     return Err(SSError::BelowThreshold(threshold, len));
//     // }
//     // let shares = &self.0[0..threshold as usize];
//     // let share_ids = shares.iter().map(|s| s.0).collect::<Vec<_>>();
//     // let basis = common::lagrange_basis_at_0_for_all::<F>(share_ids)?;
//     // Ok(cfg_into_iter!(basis)
//     //     .zip(cfg_into_iter!(shares))
//     //     .map(|(b, s)| b * s.1)
//     //     .sum::<PairingOutput<P>>())
//     todo!()
// }

#[cfg(test)]
mod test {
    type P = ark_bls12_381::Bls12_381;
    type F = <P as Pairing>::ScalarField;

    use super::*;
    #[test]
    fn test_enc_dec() {
        let pp = paramgen::<P>();

        let (sk, pk) = keygen::<P>(pp);

        let msg = F::from(3);
        let ct0 = encrypt::<P>(pp, pk, msg);
        let ct1 = encrypt::<P>(pp, pk, msg);
        let ct2 = mul::<P>(pp, ct0, ct1);
        let pt = decrypt::<P>(pp, sk, ct2, (1 << 4));
        assert_eq!(msg * msg, pt);
    }

    #[test]
    fn test_enc_distributeddec() {
        let pp = paramgen::<P>();

        let (sk, pk) = keygen::<P>(pp);
        let sks = share_sk::<P>(sk, 3, 5);

        let msg = F::from(3);
        let ct0 = encrypt::<P>(pp, pk, msg);
        let ct1 = encrypt::<P>(pp, pk, msg);
        let ct2 = mul::<P>(pp, ct0, ct1);

        let pdecs = sks
            .iter()
            .map(|sk| partial_decrypt::<P>(pp, *sk, ct2))
            .collect::<Vec<_>>();
        let inter = intermediate_dec::<P>(pp, pdecs.as_slice(), (1 << 4));

        let pdecs2 = sks
            .iter()
            .map(|sk| partial_decrypt2::<P>(pp, *sk, inter))
            .collect::<Vec<_>>();

        let pt = final_decrypt::<P>(pp, &pdecs2, (1 << 4));
        assert_eq!(msg * msg, pt);
    }
}
