//! Supporting routines for serializing crypto types.

use exonum::encoding::{
    serialize::{
        self,
        json::{reexport::Value, ExonumJson},
        FromHex, WriteBufferWrapper,
    },
    CheckedOffset, Field, Result as CheckResult, SegmentField,
};

use std::error::Error;

use super::proofs::{Commitment, SimpleRangeProof};

impl<'a> Field<'a> for Commitment {
    fn field_size() -> u32 {
        Commitment::BYTE_LEN as u32
    }

    unsafe fn read(buffer: &'a [u8], from: u32, to: u32) -> Self {
        Commitment::from_slice(&buffer[from as usize..to as usize])
            .expect("failed to read `Commitment` from trusted source")
    }

    fn write(&self, buffer: &mut Vec<u8>, from: u32, to: u32) {
        buffer[from as usize..to as usize].copy_from_slice(&self.to_bytes());
    }

    fn check(
        buffer: &'a [u8],
        from: CheckedOffset,
        to: CheckedOffset,
        latest_segment: CheckedOffset,
    ) -> CheckResult {
        let from = from.unchecked_offset() as usize;
        let to = to.unchecked_offset() as usize;

        debug_assert_eq!((to - from) as u32, Self::field_size());
        Commitment::from_slice(&buffer[from..to])
            .map(|_| latest_segment)
            .ok_or("non-canonical `Commitment`".into())
    }
}

impl FromHex for Commitment {
    type Error = String;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = serialize::decode_hex(hex).map_err(|e| e.to_string())?;
        if bytes.len() != Self::BYTE_LEN {
            Err("invalid hex string length")?;
        }
        Commitment::from_slice(&bytes).ok_or("non-canonical `Commitment`".to_owned())
    }
}

impl ExonumJson for Commitment {
    fn deserialize_field<B: WriteBufferWrapper>(
        value: &Value,
        buffer: &mut B,
        from: u32,
        to: u32,
    ) -> Result<(), Box<dyn Error>> {
        let s = value.as_str().ok_or("expected string")?;
        let commitment = Commitment::from_hex(s)?;
        buffer.write(from, to, commitment);
        Ok(())
    }

    fn serialize_field(&self) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let hex_string = serialize::encode_hex(&self.to_bytes());
        Ok(Value::String(hex_string))
    }
}

#[test]
fn commitment_roundtrip() {
    use exonum::{encoding::serialize::json::reexport as serde_json, storage::StorageValue};

    encoding_struct! {
        struct Foo {
            bar: u32,
            baz: Commitment,
        }
    }

    let foo = Foo::new(123, Commitment::new(123).0);
    let foo_json = serde_json::to_string(&foo).expect("to_string");
    let foo_copy = serde_json::from_str(&foo_json).expect("from_str");
    assert_eq!(foo, foo_copy);

    let foo_bytes = foo.clone().into_bytes();
    let foo_copy = Foo::from_bytes(foo_bytes.into());
    assert_eq!(foo, foo_copy);
}

impl<'a> SegmentField<'a> for SimpleRangeProof {
    fn item_size() -> u32 {
        32
    }

    fn count(&self) -> u32 {
        Self::ELEMENTS_SIZE as u32
    }

    unsafe fn from_buffer(buffer: &'a [u8], from: u32, count: u32) -> Self {
        assert_eq!(count as usize, Self::ELEMENTS_SIZE);
        let slice = &buffer[from as usize..(from + Self::item_size() * count) as usize];
        SimpleRangeProof::from_slice(slice)
            .expect("failed to read `SimpleRangeProof` from trusted source")
    }

    fn extend_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.to_bytes());
    }

    fn check_data(
        buffer: &'a [u8],
        from: CheckedOffset,
        count: CheckedOffset,
        latest_segment: CheckedOffset,
    ) -> CheckResult {
        if count.unchecked_offset() != Self::ELEMENTS_SIZE as u32 {
            Err("incorrect buffer size for `SimpleRangeProof`")?;
        }

        let size: CheckedOffset = (count * Self::item_size())?;
        let to: CheckedOffset = (from + size)?;
        let slice = &buffer[from.unchecked_offset() as usize..to.unchecked_offset() as usize];
        if slice.len() != size.unchecked_offset() as usize {
            Err("undersized buffer for `SimpleRangeProof`")?;
        }

        SimpleRangeProof::from_slice(slice)
            .map(|_| latest_segment)
            .ok_or_else(|| "incorrect `SimpleRangeProof`".into())
    }
}

impl ExonumJson for SimpleRangeProof {
    fn deserialize_field<B: WriteBufferWrapper>(
        value: &Value,
        buffer: &mut B,
        from: u32,
        to: u32,
    ) -> Result<(), Box<dyn Error>> {
        let elements = value.as_array().ok_or("expected array")?;
        if elements.len() != Self::ELEMENTS_SIZE {
            Err("incorrect number of elements in proof")?;
        }

        let mut bytes = Vec::with_capacity(32 * Self::ELEMENTS_SIZE);
        for element in elements {
            let s = element.as_str().ok_or("expected hex string for element")?;
            let element_bytes = serialize::decode_hex(s)?;
            if element_bytes.len() != 32 {
                Err("invalid element byte size, 32 expected")?;
            }
            bytes.extend_from_slice(&element_bytes);
        }
        debug_assert_eq!(bytes.len(), 32 * Self::ELEMENTS_SIZE as usize);

        let proof = SimpleRangeProof::from_slice(&bytes).ok_or("invalid `SimpleRangeProof`")?;
        buffer.write(from, to, proof);
        Ok(())
    }

    fn serialize_field(&self) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let bytes = self.to_bytes();
        let element_strings: Vec<_> = bytes
            .chunks(32)
            .map(serialize::encode_hex)
            .map(Value::String)
            .collect();
        assert_eq!(element_strings.len(), Self::ELEMENTS_SIZE);
        Ok(Value::Array(element_strings))
    }
}

#[test]
fn proof_roundtrip() {
    use super::proofs::Opening;
    use exonum::{encoding::serialize::json::reexport as serde_json, storage::StorageValue};

    encoding_struct! {
        struct Foo {
            bar: u32,
            baz: SimpleRangeProof,
            qux: &str,
        }
    }

    let opening = Opening::with_no_blinding(12345);
    let proof = SimpleRangeProof::prove(&opening).expect("prove");
    let foo = Foo::new(123, proof, "qux");
    let foo_json = serde_json::to_string(&foo).expect("to_string");
    let foo_copy = serde_json::from_str(&foo_json).expect("from_str");
    assert_eq!(foo, foo_copy);

    let foo_bytes = foo.clone().into_bytes();
    let foo_copy = Foo::from_bytes(foo_bytes.into());
    assert_eq!(foo, foo_copy);
}
