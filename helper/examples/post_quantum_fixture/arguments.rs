//! Validated fixture arguments and public authority; no filesystem or TPM I/O.
#![forbid(unsafe_code)]
use age_plugin_tpm_wsl::wire::{DELETE, Frame, INSPECT, PostQuantumRequest};
use age_tpm_wsl_post_quantum::Identity;

type Result<T> = std::result::Result<T, String>;
const ROOT_PREFIX: &str = "age-tpm-wsl-post-quantum-client-";
const ACK: &str = "isolated-disposable-only";

pub struct Namespace {
    directory: String,
    key_name: String,
}
impl Namespace {
    fn parse(value: &str) -> Result<Self> {
        let suffix = value
            .strip_prefix(ROOT_PREFIX)
            .ok_or("reserved client-validation namespace required")?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("fresh lowercase-hex namespace required".into());
        }
        Ok(Self {
            directory: value.into(),
            key_name: format!("age-tpm-wsl-pq-{suffix}"),
        })
    }
    pub fn directory(&self) -> &str {
        &self.directory
    }
    pub fn key_name(&self) -> &str {
        &self.key_name
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Serve,
    PrepareRoot,
    Absence,
    RemoveRoot,
}

pub struct Arguments {
    pub namespace: Namespace,
    pub mode: Mode,
    expected: Option<Identity>,
}
impl Arguments {
    pub fn parse(args: &[String]) -> Result<Self> {
        let [ack_flag, ack, namespace_flag, namespace, mode, rest @ ..] = args else {
            return Err("explicit fixture acknowledgment, namespace and mode required".into());
        };
        if ack_flag != "--acknowledge" || ack != ACK || namespace_flag != "--namespace" {
            return Err("explicit isolated disposable acknowledgment required".into());
        }
        let namespace = Namespace::parse(namespace)?;
        let mode = match mode.as_str() {
            "--serve" => Mode::Serve,
            "--prepare-root" => Mode::PrepareRoot,
            "--absence" => Mode::Absence,
            "--remove-root" => Mode::RemoveRoot,
            _ => return Err("unknown fixture mode".into()),
        };
        let expected = match rest {
            [] => None,
            [flag, encoded] if flag == "--expected-identity" => Some(decode(encoded)?),
            _ => return Err("unexpected fixture arguments".into()),
        };
        if expected
            .as_ref()
            .is_some_and(|identity| identity.name() != namespace.key_name())
        {
            return Err("expected identity does not belong to this namespace".into());
        }
        if mode == Mode::PrepareRoot && expected.is_some() {
            return Err("root preparation cannot reuse a retained identity".into());
        }
        if mode == Mode::RemoveRoot && expected.is_none() {
            return Err("root removal requires retained public authority".into());
        }
        Ok(Self {
            namespace,
            mode,
            expected,
        })
    }

    /// Scope checks run before the shared dispatcher can acquire storage.
    pub fn authorize(&self, request: &Frame) -> Result<()> {
        if self.mode != Mode::Serve || request.status != 0 {
            return Err("invalid fixture request mode or status".into());
        }
        if matches!(request.operation, INSPECT | DELETE) {
            let identity =
                Identity::parse(&request.payload).map_err(|_| "invalid expected identity")?;
            return self.matches(&identity);
        }
        match request
            .post_quantum_request()
            .map_err(|_| "invalid fixture request")?
        {
            PostQuantumRequest::Create { name }
                if name == self.namespace.key_name() && self.expected.is_none() =>
            {
                Ok(())
            }
            PostQuantumRequest::Recover { name }
                if name == self.namespace.key_name() && self.expected.is_some() =>
            {
                Ok(())
            }
            PostQuantumRequest::Unwrap { identity, .. } => self.matches(&identity),
            _ => Err("request outside retained fixture authority".into()),
        }
    }

    /// The fixture retains this full reference before any later operation.
    pub fn retained_identity(&self) -> Result<&Identity> {
        self.expected
            .as_ref()
            .ok_or_else(|| "retained public identity required".into())
    }

    pub fn check_identity_response(&self, payload: &[u8]) -> Result<()> {
        let identity = Identity::parse(payload).map_err(|_| "invalid public identity response")?;
        if identity.name() != self.namespace.key_name() {
            return Err("response outside fixture namespace".into());
        }
        if self.expected.is_some() {
            self.matches(&identity)?;
        }
        Ok(())
    }

    fn matches(&self, identity: &Identity) -> Result<()> {
        match &self.expected {
            Some(expected) if expected == identity => Ok(()),
            _ => Err("request differs from retained public identity".into()),
        }
    }
}

fn decode(text: &str) -> Result<Identity> {
    if text.len() != 2600
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("canonical retained public identity required".into());
    }
    let bytes = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let value = std::str::from_utf8(pair).map_err(|_| "invalid identity encoding")?;
            u8::from_str_radix(value, 16).map_err(|_| "invalid identity encoding")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Identity::parse(&bytes).map_err(|_| "invalid retained identity".into())
}

#[cfg(test)]
#[path = "arguments/tests.rs"]
mod tests;
