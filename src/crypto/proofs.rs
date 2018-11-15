use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use byteorder::{ByteOrder, LittleEndian};
use curve25519::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::thread_rng;

use std::ops;

lazy_static! {
    static ref PEDERSEN_GENS: PedersenGens = PedersenGens::default();
    static ref BULLETPROOF_GENS: BulletproofGens = BulletproofGens::new(64, 1);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    inner: RistrettoPoint,
}

impl Commitment {
    /// Size of the byte representation of the commitment (i.e., a compressed Ristretto point).
    pub(crate) const BYTE_LEN: usize = 32;

    /// Creates a commitment with a randomly chosen blinding.
    ///
    /// # Return value
    ///
    /// Returns the created commitment and the blinding factor.
    pub fn new(value: u64) -> (Self, Opening) {
        let blinding = Scalar::random(&mut thread_rng());
        let opening = Opening::new(value, blinding);
        (Self::from_opening(&opening), opening)
    }

    pub fn from_opening(opening: &Opening) -> Self {
        let inner = PEDERSEN_GENS.commit(Scalar::from(opening.value), opening.blinding.clone());
        Commitment { inner }
    }

    pub fn with_no_blinding(value: u64) -> Self {
        Self::from_opening(&Opening::new(value, Scalar::zero()))
    }

    /// Attempts to deserialize a commitment from byte slice.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != Self::BYTE_LEN {
            return None;
        }

        let compressed_point = CompressedRistretto::from_slice(slice);
        compressed_point
            .decompress()
            .map(|point| Commitment { inner: point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.compress().as_bytes().to_vec()
    }

    pub fn verify(&self, opening: &Opening) -> bool {
        *self == Self::from_opening(opening)
    }
}

impl ops::Add for Commitment {
    type Output = Commitment;

    fn add(self, rhs: Self) -> Commitment {
        Commitment {
            inner: self.inner + rhs.inner,
        }
    }
}

impl ops::Sub for Commitment {
    type Output = Commitment;

    fn sub(self, rhs: Self) -> Commitment {
        Commitment {
            inner: self.inner - rhs.inner,
        }
    }
}

#[test]
fn commitment_arithmetic() {
    let (comm1, opening1) = Commitment::new(100);
    let (comm2, opening2) = Commitment::new(200);
    assert!((comm1 + comm2).verify(&(opening1 + opening2)));

    let (comm1, opening1) = Commitment::new(1234);
    let (comm2, opening2) = Commitment::new(234);
    assert!((comm1 - comm2).verify(&(opening1 - opening2)));
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub value: u64,
    blinding: Scalar,
}

impl Opening {
    const BYTE_SIZE: usize = 40;

    pub(crate) fn new(value: u64, blinding: Scalar) -> Self {
        Opening { value, blinding }
    }

    pub fn with_no_blinding(value: u64) -> Self {
        Opening::new(value, Scalar::zero())
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != Self::BYTE_SIZE {
            return None;
        }

        let mut scalar_bytes = [0_u8; 32];
        scalar_bytes.copy_from_slice(&slice[8..]);
        Some(Opening {
            value: LittleEndian::read_u64(&slice[..8]),
            blinding: Scalar::from_canonical_bytes(scalar_bytes)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0_u8; Self::BYTE_SIZE];
        LittleEndian::write_u64(&mut bytes[0..8], self.value);
        bytes[8..].copy_from_slice(&*self.blinding.as_bytes());
        bytes.to_vec()
    }
}

impl ops::Add for Opening {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Opening {
            value: self.value.checked_add(rhs.value).expect("integer overflow"),
            blinding: self.blinding + rhs.blinding,
        }
    }
}

impl ops::AddAssign for Opening {
    fn add_assign(&mut self, rhs: Self) {
        self.value = self.value.checked_add(rhs.value).expect("integer overflow");
        self.blinding += rhs.blinding;
    }
}

impl ops::Sub for Opening {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Opening {
            value: self
                .value
                .checked_sub(rhs.value)
                .expect("integer underflow"),
            blinding: self.blinding - rhs.blinding,
        }
    }
}

impl ops::SubAssign for Opening {
    fn sub_assign(&mut self, rhs: Self) {
        self.value = self
            .value
            .checked_sub(rhs.value)
            .expect("integer underflow");
        self.blinding -= rhs.blinding;
    }
}

#[derive(Debug, Clone)]
pub struct SimpleRangeProof {
    inner: RangeProof,
}

impl SimpleRangeProof {
    const BITS: usize = 64;

    pub(crate) const ELEMENTS_SIZE: usize = 9 + 2 * 6; // 6 == log2(Self::BITS)

    const DOMAIN_SEPARATOR: &'static [u8] = b"exonum.private_cryptocurrency";

    pub fn prove(opening: &Opening) -> Option<Self> {
        let mut transcript = Transcript::new(Self::DOMAIN_SEPARATOR);
        let (proof, _) = RangeProof::prove_single(
            &BULLETPROOF_GENS,
            &PEDERSEN_GENS,
            &mut transcript,
            opening.value,
            &opening.blinding,
            Self::BITS,
        ).ok()?;

        Some(SimpleRangeProof { inner: proof })
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        Some(SimpleRangeProof {
            inner: RangeProof::from_bytes(slice).ok()?,
        })
    }

    pub fn verify(&self, commitment: &Commitment) -> bool {
        let mut transcript = Transcript::new(Self::DOMAIN_SEPARATOR);
        self.inner
            .verify_single(
                &BULLETPROOF_GENS,
                &PEDERSEN_GENS,
                &mut transcript,
                &commitment.inner.compress(),
                Self::BITS,
            ).is_ok()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[test]
fn commitments_produced_by_bulletproofs_are_as_expected() {
    let proof_gens = BulletproofGens::new(64, 1);
    let secret_value = 123_u64;

    let (simple_commitment, opening) = Commitment::new(secret_value);

    let mut prover_transcript = Transcript::new(b"");
    let (_, committed_value) = RangeProof::prove_single(
        &proof_gens,
        &PEDERSEN_GENS,
        &mut prover_transcript,
        secret_value,
        &opening.blinding,
        32,
    ).expect("prove_single");

    assert_eq!(
        simple_commitment,
        Commitment::from_slice(&*committed_value.as_bytes()).expect("deserialize")
    );
}

#[test]
fn range_proof_serialized_size_is_as_expected() {
    use rand::Rng;

    let mut rng = thread_rng();
    for _ in 0..5 {
        let opening = Opening::new(rng.gen(), Scalar::random(&mut rng));
        let proof = SimpleRangeProof::prove(&opening).expect("proof");
        assert_eq!(proof.to_bytes().len(), SimpleRangeProof::ELEMENTS_SIZE * 32);
    }
}

#[test]
fn incorrect_proofs_do_not_verify() {
    let (_, opening) = Commitment::new(12345);
    let proof = SimpleRangeProof::prove(&opening).expect("prove");
    let (commitment2, _) = Commitment::new(54321);
    assert!(!proof.verify(&commitment2));
}
