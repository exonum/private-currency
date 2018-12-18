// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bulletproof-related cryptography.

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
    /// Pedersen commitment generators.
    static ref PEDERSEN_GENS: PedersenGens = PedersenGens::default();
    /// Bulletproof generators used in `SimpleRangeProof`s.
    static ref BULLETPROOF_GENS: BulletproofGens = BulletproofGens::new(SimpleRangeProof::BITS, 1);
}

/// Pedersen commitment to an integer value.
///
/// # Theory
///
/// A [Pedersen commitment] has the form (in the additive notation)
///
/// ```text
/// Comm(x; r) = xG + rH,
/// ```
///
/// where
///
/// - `G` and `H` are two generators in a prime-order group `Q`, with unknown discrete logarithm
///   relationships among them (i.e., nobody knows `k` such as `G = kH`)
/// - `x` is the committed value (it’s a residue class modulo the group order `|Q|`,
///   but we may *essentially* treat it as an integer)
/// - `r` is the blinding factor (also a residue class modulo the group order `|Q|`). Usually,
///   it’s chosen randomly from a cryptographically secure RNG.
///
/// `Q`, `G` and `H` are public parameters of the scheme shared among all commitments,
/// while `x` and `r` are private.
/// `(x, r)` is called an *opening* to the commitment; knowing the opening, it’s easy to check
/// if it corresponds to the given commitment.
///
/// Under common security assumptions, a Pedersen commitment is
///
/// - *perfectly hiding* (a party not knowing `x` and `r` cannot find them out
///   from `Comm(..)`), and
/// - *computationally binding* (a party cannot produce `(x', r') != (x, r)` such that
///   they will open to the same commitment).
///
/// # Commitment arithmetic
///
/// It is possible to add and subtract Pedersen commitments; the result is a commitment to the
/// sum / difference of corresponding values. This fact is what allows using commitments in
/// private currency.
///
/// # Implementation details
///
/// We use a [Ristretto group] built on top of Curve25519 as `Q`. Generators `G` and `H` are
/// constructed according to [the default scheme][`PedersenGens`] in the `bulletproofs`
/// implementation.
///
/// # Examples
///
/// ```
/// # use private_currency::crypto::Commitment;
/// let (mut commitment, mut opening) = Commitment::new(42);
/// assert_eq!(opening.value, 42);
/// assert_eq!(commitment, Commitment::from_opening(&opening));
///
/// let (other_commitment, other_opening) = Commitment::new(23);
/// commitment -= other_commitment;
/// opening -= other_opening;
/// assert_eq!(opening.value, 19);
/// assert_eq!(commitment, Commitment::from_opening(&opening));
/// ```
///
/// [Pedersen commitment]: https://en.wikipedia.org/wiki/Commitment_scheme
/// [Ristretto group]: https://ristretto.group/
/// [`PedersenGens`]: https://doc.dalek.rs/bulletproofs/struct.PedersenGens.html
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
    /// Returns the created commitment and the corresponding opening for it.
    pub fn new(value: u64) -> (Self, Opening) {
        let blinding = Scalar::random(&mut thread_rng());
        let opening = Opening::new(value, blinding);
        (Self::from_opening(&opening), opening)
    }

    /// Creates a commitment from the given opening.
    pub fn from_opening(opening: &Opening) -> Self {
        let inner = PEDERSEN_GENS.commit(Scalar::from(opening.value), opening.blinding);
        Commitment { inner }
    }

    /// Creates a commitment with no blinding factor.
    ///
    /// **Warning.** The commitments created in this way are not hiding. Use them only if you
    /// know what you’re doing.
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

    /// Serializes this commitment to bytes.
    ///
    /// # Implementation details
    ///
    /// The commitment is serialized as a single compressed Ristretto point (i.e., 32 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.compress().as_bytes().to_vec()
    }

    /// Verifies if this commitment corresponds to the provided opening.
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

impl<'a, 'b> ops::Add<&'b Commitment> for &'a Commitment {
    type Output = Commitment;

    fn add(self, rhs: &'b Commitment) -> Commitment {
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

impl<'a, 'b> ops::Sub<&'b Commitment> for &'a Commitment {
    type Output = Commitment;

    fn sub(self, rhs: &'b Commitment) -> Commitment {
        Commitment {
            inner: self.inner - rhs.inner,
        }
    }
}

impl ops::SubAssign for Commitment {
    fn sub_assign(&mut self, rhs: Self) {
        self.inner -= rhs.inner;
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

/// Opening for a Pedersen commitment.
///
/// # Theory
///
/// See [`Commitment`] docs for details on Pedersen commitments and their openings.
///
/// # Arithmetic
///
/// Akin to `Commitment`s, openings can be added and subtracted. If an over/underflow occurs
/// when adding or subtracting committed values, a panic is raised.
///
/// # Implementation details
///
/// Although committed value `x` is generally a scalar in the used prime-order group,
/// we restrict it to `u64`. The conversion is straightforward.
///
/// [`Commitment`]: self::Commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    /// Committed value.
    pub value: u64,
    blinding: Scalar,
}

impl Opening {
    /// Size of a serialized opening.
    const BYTE_SIZE: usize = 40;

    pub(crate) fn new(value: u64, blinding: Scalar) -> Self {
        Opening { value, blinding }
    }

    #[doc(hidden)] // useful only in tests
    pub fn with_no_blinding(value: u64) -> Self {
        Opening::new(value, Scalar::zero())
    }

    /// Attempts to deserialize an opening from a slice.
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

    /// Serializes this opening to bytes.
    ///
    /// # Implementation details
    ///
    /// Serialization consists of a committed value (8 bytes, little-endian)
    /// and a Ristretto scalar (32 bytes).
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

impl<'a, 'b> ops::Sub<&'b Opening> for &'a Opening {
    type Output = Opening;

    fn sub(self, rhs: &'b Opening) -> Opening {
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

/// Range proof for a single value in the range `[0; 1 << 64)`.
///
/// # Theory
///
/// [Bulletproofs] provide an efficient scheme for proving that a [committed] value
/// belongs to an interval. The scheme is non-interactive, succinct (i.e., the size of the data
/// and the amount of computations necessary to verify the proof are small), and zero-knowledge
/// (i.e., the verifier does not learn anything about the committed value besides the range).
///
/// # Implementation details
///
/// We use the [`bulletproofs`] crate to implement proofs. The crate allows to efficiently prove
/// several values at once, but this capability is not used as of now. Generators for proofs
/// are initialized for a single party with `Self::BITS` range capacity.
///
/// # Examples
///
/// ```
/// # use private_currency::crypto::{Commitment, SimpleRangeProof};
/// let (commitment, opening) = Commitment::new(42_000_000);
/// // We need an opening to produce the proof
/// let proof = SimpleRangeProof::prove(&opening).unwrap();
/// // ...but don’t need one to verify it
/// assert!(proof.verify(&commitment));
/// ```
///
/// [Bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
/// [`bulletproofs`]: https://doc.dalek.rs/bulletproofs/
/// [committed]: self::Commitment
#[derive(Debug, Clone)]
pub struct SimpleRangeProof {
    inner: RangeProof,
}

impl SimpleRangeProof {
    /// Number of variable bits in the committed value: `64`. The range
    /// to which the value must belong is `[0, 1 << BITS)`.
    pub const BITS: usize = 64;

    /// Number of group scalars or elements in the proof.
    // This constant is used in serialization code. We use the fact that scalars and elements
    // in the Ristretto group have the same serialized size (32 bytes).
    pub(crate) const ELEMENTS_SIZE: usize = 9 + 2 * 6; // 6 == log2(Self::BITS)

    /// Domain separator for the proof.
    const DOMAIN_SEPARATOR: &'static [u8] = b"exonum.private_cryptocurrency";

    /// Creates a proof for the specified value (which is provided together with the blinding
    /// factor as an `Opening`).
    ///
    /// # Return value
    ///
    /// This method may fail along the lines of the [underlying implementation][impl].
    /// In this case, `None` is returned.
    ///
    /// [impl]: https://doc.dalek.rs/bulletproofs/struct.RangeProof.html#method.prove_single
    pub fn prove(opening: &Opening) -> Option<Self> {
        let mut transcript = Transcript::new(Self::DOMAIN_SEPARATOR);
        let (proof, _) = RangeProof::prove_single(
            &BULLETPROOF_GENS,
            &PEDERSEN_GENS,
            &mut transcript,
            opening.value,
            &opening.blinding,
            Self::BITS,
        )
        .ok()?;

        Some(SimpleRangeProof { inner: proof })
    }

    /// Attempts to deserialize this proof from a byte slice.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        Some(SimpleRangeProof {
            inner: RangeProof::from_bytes(slice).ok()?,
        })
    }

    /// Verifies this proof with respect to the given committed value.
    pub fn verify(&self, commitment: &Commitment) -> bool {
        let mut transcript = Transcript::new(Self::DOMAIN_SEPARATOR);
        self.inner
            .verify_single(
                &BULLETPROOF_GENS,
                &PEDERSEN_GENS,
                &mut transcript,
                &commitment.inner.compress(),
                Self::BITS,
            )
            .is_ok()
    }

    /// Serializes this proof into bytes.
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
    )
    .expect("prove_single");

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
