pub use sodiumoxide::crypto::box_::{
    gen_keypair, gen_nonce, open, open_precomputed, precompute, seal, Nonce, PublicKey, SecretKey,
    PUBLICKEYBYTES,
};

use exonum::crypto::{x25519, PublicKey as VerifyingKey, SecretKey as SigningKey};

pub(crate) fn keypair_from_ed25519(pk: VerifyingKey, sk: SigningKey) -> (PublicKey, SecretKey) {
    let (pk, sk) = x25519::into_x25519_keypair(pk, sk).expect("ed25519 -> curve25519");
    (
        PublicKey::from_slice(pk.as_ref()).expect("curve25519 group element"),
        SecretKey::from_slice(sk.as_ref()).expect("curve25519 scalar"),
    )
}

pub(crate) fn pk_from_ed25519(pk: VerifyingKey) -> PublicKey {
    let pk = x25519::into_x25519_public_key(pk);
    PublicKey::from_slice(pk.as_ref()).expect("curve25519 group element")
}

#[test]
fn encryption_keys_can_be_created_from_signing_keys() {
    const MSG: &[u8] = b"Hello, world!";

    let (pk, sk) = exonum::crypto::gen_keypair();
    let (enc_pk, enc_sk) = keypair_from_ed25519(pk, sk.clone());

    // Encrypt message to self
    let nonce = gen_nonce();
    let sealed = seal(MSG, &nonce, &enc_pk, &enc_sk);
    assert_eq!(open(&sealed, &nonce, &enc_pk, &enc_sk), Ok(MSG.to_vec()));

    // Check encryption to other parties
    let (enc_pk2, enc_sk2) = gen_keypair();
    let nonce = gen_nonce();
    let sealed = seal(MSG, &nonce, &enc_pk2, &enc_sk);
    assert_eq!(open(&sealed, &nonce, &enc_pk, &enc_sk2), Ok(MSG.to_vec()));

    let (enc_pk2, enc_sk2) = gen_keypair();
    let nonce = gen_nonce();
    let sealed = seal(MSG, &nonce, &enc_pk, &enc_sk2);
    assert_eq!(open(&sealed, &nonce, &enc_pk2, &enc_sk), Ok(MSG.to_vec()));
}
