//! Canonical bounded disk record. Authentication still requires the original
//! TPM and subsequent seed/public/PCP validation inside Windows.
use super::{IDENTITY_LEN, Identity, invalid};
use std::io;
use zeroize::Zeroizing;

pub const MAX_RECORD: usize = 4096;
const MAGIC: &[u8; 8] = b"ATWPQC01";
// TPMT_PUBLIC: SYMCIPHER, SHA256, fixedTPM/fixedParent/origin/userAuth/noDA/
// restricted/decrypt, empty policy, AES256-CFB, 32-byte TPM-generated unique.
const PARENT_HEADER: &[u8] = &[
    0, 0x25, 0, 11, 0, 3, 4, 0x72, 0, 0, 0, 6, 1, 0, 0, 0x43, 0, 32,
];
// TPMT_PUBLIC: KEYEDHASH, SHA256, fixedTPM/fixedParent/userAuth/noDA,
// empty policy, NULL scheme, 32-byte TPM-generated unique.
const CHILD_HEADER: &[u8] = &[0, 8, 0, 11, 0, 0, 4, 0x52, 0, 0, 0, 16, 0, 32];

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        if length > self.0.len() {
            return Err(invalid("truncated custody record"));
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn sized(&mut self) -> io::Result<&'a [u8]> {
        let size = u16::from_be_bytes(self.take(2)?.try_into().expect("checked length"));
        self.take(usize::from(size))
    }
}

fn validate_areas(parent: &[u8], private: &[u8], public: &[u8]) -> io::Result<()> {
    if parent.len() != PARENT_HEADER.len() + 32 || !parent.starts_with(PARENT_HEADER) {
        return Err(invalid("unexpected symmetric custody parent"));
    }
    if !(64..=2048).contains(&private.len()) {
        return Err(invalid("invalid sealed private area size"));
    }
    if public.len() != CHILD_HEADER.len() + 32 || !public.starts_with(CHILD_HEADER) {
        return Err(invalid("unexpected sealed child public area"));
    }
    Ok(())
}

pub struct Record {
    identity: Identity,
    parent: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}
impl Record {
    /// Blob inputs are encrypted/private and public TPM areas, never plaintext seed.
    pub fn new(
        identity: Identity,
        parent: &[u8],
        private: &[u8],
        public: &[u8],
    ) -> io::Result<Self> {
        validate_areas(parent, private, public)?;
        Ok(Self {
            identity,
            parent: parent.to_vec(),
            private: Zeroizing::new(private.to_vec()),
            public: public.to_vec(),
        })
    }

    /// The independently retained identity is mandatory. Disk contents cannot
    /// silently establish their own authority; explicit recovery sets a new one.
    pub fn parse(bytes: &[u8], expected: &Identity) -> io::Result<Self> {
        if bytes.len() > MAX_RECORD {
            return Err(invalid("oversized custody record"));
        }
        let mut cursor = Cursor(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(invalid("unknown custody record version"));
        }
        let identity = Identity::parse(cursor.take(IDENTITY_LEN)?)?;
        if &identity != expected {
            return Err(invalid("custody identity substitution rejected"));
        }
        if cursor.take(32)? != identity.commitment() {
            return Err(invalid("custody recipient commitment mismatch"));
        }
        let parent = cursor.sized()?;
        let private = cursor.sized()?;
        let public = cursor.sized()?;
        if !cursor.0.is_empty() {
            return Err(invalid("trailing custody record bytes"));
        }
        Self::new(identity, parent, private, public)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.identity.bytes());
        bytes.extend(self.identity.commitment());
        for area in [&self.parent[..], &self.private[..], &self.public[..]] {
            // Construction bounds each area below u16::MAX and their sum below4096.
            bytes.extend((area.len() as u16).to_be_bytes());
            bytes.extend(area);
        }
        bytes
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn parent(&self) -> &[u8] {
        &self.parent
    }
    pub fn private(&self) -> &[u8] {
        &self.private
    }
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Validate an already authenticated TPM response payload without copying its
    /// seed. Caller must still restore ML-KEM and match the complete public key.
    #[cfg(any(windows, test))]
    pub fn bound_seed<'a>(&self, payload: &'a [u8]) -> io::Result<&'a [u8; 64]> {
        if payload.len() != 96 || payload[64..] != self.identity.binding() {
            return Err(invalid("sealed custody binding mismatch"));
        }
        <&[u8; 64]>::try_from(&payload[..64]).map_err(|_| invalid("invalid seed length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn identity() -> Identity {
        Identity::new(
            &crate::identity::tests::public(),
            crate::identity::tests::NAME,
        )
        .unwrap()
    }
    fn record() -> Record {
        let mut parent = PARENT_HEADER.to_vec();
        parent.extend([0x11; 32]);
        let mut public = CHILD_HEADER.to_vec();
        public.extend([0x22; 32]);
        // Public stand-ins establish parser behavior only, not usable TPM blobs.
        Record::new(identity(), &parent, &[0x33; 64], &public).unwrap()
    }
    #[test]
    fn bounded_record_roundtrip_requires_the_independent_expected_identity() {
        let record = record();
        let bytes = record.encode();
        assert_eq!(&bytes[..8], b"ATWPQC01");
        assert_eq!(bytes.len(), 1506);
        // Independent Python hashlib over literal contract fields/public stand-ins.
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "fb533a818ec43483a7e033d54bfcb7517183babed89d1e3a7ebd9994af085057"
        );
        let parsed = Record::parse(&bytes, &identity()).unwrap();
        assert_eq!(parsed.encode(), bytes);
        let other = Identity::new(
            &crate::identity::tests::public(),
            "age-tpm-wsl-pq-11111111111111111111111111111111",
        )
        .unwrap();
        assert!(Record::parse(&bytes, &other).is_err());
        // No test seed hash/oracle follows the final TPM2B.
        let mut extra = bytes.clone();
        extra.extend([0; 32]);
        assert!(Record::parse(&extra, &identity()).is_err());
    }
    #[test]
    fn truncated_oversized_tampered_templates_and_commitments_are_rejected() {
        let bytes = record().encode();
        let expected = identity();
        for end in 0..bytes.len() {
            assert!(Record::parse(&bytes[..end], &expected).is_err());
        }
        assert!(Record::parse(&vec![0; MAX_RECORD + 1], &expected).is_err());
        for index in [
            0,
            8 + IDENTITY_LEN,
            8 + IDENTITY_LEN + 32,
            8 + IDENTITY_LEN + 34,
        ] {
            let mut altered = bytes.clone();
            altered[index] ^= 1;
            assert!(Record::parse(&altered, &expected).is_err());
        }
        let record = record();
        let mut rsa_parent = record.parent().to_vec();
        rsa_parent[1] = 1;
        assert!(
            Record::new(
                expected.clone(),
                &rsa_parent,
                record.private(),
                record.public()
            )
            .is_err()
        );
        let mut child = record.public().to_vec();
        child[7] ^= 2; // fixedTPM attribute
        assert!(Record::new(expected.clone(), record.parent(), record.private(), &child).is_err());
        for length in [0, 63, 2049] {
            assert!(
                Record::new(
                    expected.clone(),
                    record.parent(),
                    &vec![0; length],
                    record.public()
                )
                .is_err()
            );
        }
        let largest =
            Record::new(expected, record.parent(), &vec![0; 2048], record.public()).unwrap();
        assert!(largest.encode().len() <= MAX_RECORD);
    }
    #[test]
    fn bound_payload_is_exact_and_borrowed_with_no_seed_check_oracle() {
        let record = record();
        let mut payload = [0x55; 96];
        payload[64..].copy_from_slice(&record.identity().binding());
        let borrowed = record.bound_seed(&payload).unwrap();
        assert_eq!(borrowed.as_ptr(), payload.as_ptr());
        assert!(record.bound_seed(&payload[..95]).is_err());
        payload[95] ^= 1;
        assert!(record.bound_seed(&payload).is_err());
        let mut long = payload.to_vec();
        long.push(0);
        assert!(record.bound_seed(&long).is_err());
    }
}
