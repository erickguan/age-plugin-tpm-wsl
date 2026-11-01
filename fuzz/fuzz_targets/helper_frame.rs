#![no_main]
use age_plugin_tpm_wsl::wire::{Frame, MAX_PAYLOAD, PostQuantumRequest};
use libfuzzer_sys::fuzz_target;
use std::io::{self, Read};

struct Fragmented<'a>(&'a [u8]);
impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let length = output.len().min(self.0.len()).min(3);
        output[..length].copy_from_slice(&self.0[..length]);
        self.0 = &self.0[length..];
        Ok(length)
    }
}

fuzz_target!(|data: &[u8]| {
    let direct = Frame::read(data);
    let fragmented = Frame::read(Fragmented(data));
    assert_eq!(direct.is_ok(), fragmented.is_ok());
    if let (Ok(frame), Ok(other)) = (direct, fragmented) {
        assert!(frame.payload.len() <= MAX_PAYLOAD);
        assert!(frame.status == 0 || frame.payload.is_empty());
        assert_eq!(frame.operation, other.operation);
        assert_eq!(frame.status, other.status);
        assert_eq!(*frame.payload, *other.payload);
        if let Ok((identity, body)) = frame.unwrap_parts() {
            assert_eq!(body.len(), identity.recipient.scheme().body_len());
            let rebuilt = Frame::unwrap(&identity, body);
            assert_eq!(rebuilt.operation, frame.operation);
            assert_eq!(*rebuilt.payload, *frame.payload);
        }
        if let Ok(request) = frame.post_quantum_request() {
            let rebuilt = match request {
                PostQuantumRequest::Create { name } => Frame::post_quantum_create(name).unwrap(),
                PostQuantumRequest::Recover { name } => Frame::post_quantum_recover(name).unwrap(),
                PostQuantumRequest::Unwrap {
                    identity,
                    enc,
                    body,
                } => Frame::post_quantum_unwrap(&identity, enc, body).unwrap(),
            };
            assert_eq!(rebuilt.operation, frame.operation);
            assert_eq!(*rebuilt.payload, *frame.payload);
        }
        let mut encoded = Vec::new();
        frame.write(&mut encoded).unwrap();
        assert_eq!(encoded, data);
        encoded.push(0);
        assert!(Frame::read(encoded.as_slice()).is_err());
    }
});
