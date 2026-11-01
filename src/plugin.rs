use crate::{
    Identity, NAME, Recipient, Scheme, client::Helper, invalid, post_quantum, schemes, wire::Frame,
};
use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret,
};
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
};
use std::{
    collections::{HashMap, HashSet},
    io,
};

pub struct Handler;
impl PluginHandler for Handler {
    type RecipientV1 = Recipients;
    type IdentityV1 = Identities;
    fn recipient_v1(self) -> io::Result<Recipients> {
        Ok(Recipients::default())
    }
    fn identity_v1(self) -> io::Result<Identities> {
        Ok(Identities::default())
    }
}

/// A batch wraps either classical or post-quantum material, never both: the age-plugin
/// `labels` callback cannot fail, so mixtures are rejected during ingestion.
#[derive(Default)]
pub struct Recipients {
    classical: Vec<Recipient>,
    post_quantum: Vec<post_quantum::Recipient>,
}

fn check_name(name: &str) -> io::Result<()> {
    if name != NAME {
        return Err(invalid("unsupported plugin namespace"));
    }
    Ok(())
}

impl RecipientPluginV1 for Recipients {
    fn add_recipient(
        &mut self,
        index: usize,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let reject = |message: &str| recipient::Error::Recipient {
            index,
            message: message.to_string(),
        };
        if name == post_quantum::PLUGIN_NAME {
            let key = post_quantum::Recipient::parse(bytes).map_err(|e| reject(&e.to_string()))?;
            if !self.classical.is_empty() {
                return Err(reject("cannot mix classical and post-quantum recipients"));
            }
            self.post_quantum.push(key);
            return Ok(());
        }
        let key = check_name(name)
            .and_then(|_| Recipient::parse(bytes))
            .map_err(|e| reject(&e.to_string()))?;
        if !self.post_quantum.is_empty() {
            return Err(reject("cannot mix classical and post-quantum recipients"));
        }
        self.classical.push(key);
        Ok(())
    }
    fn add_identity(
        &mut self,
        index: usize,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if name != NAME {
            return Err(recipient::Error::Identity {
                index,
                message: "unsupported plugin namespace".to_string(),
            });
        }
        if bytes.first() == Some(&3) {
            let key =
                post_quantum::parse_identity(bytes).map_err(|e| recipient::Error::Identity {
                    index,
                    message: e.to_string(),
                })?;
            if !self.classical.is_empty() {
                return Err(recipient::Error::Identity {
                    index,
                    message: "cannot mix classical and post-quantum identities".to_string(),
                });
            }
            self.post_quantum
                .push(post_quantum::Recipient::parse(key.public()).map_err(|e| {
                    recipient::Error::Identity {
                        index,
                        message: e.to_string(),
                    }
                })?);
            return Ok(());
        }
        let key = Identity::parse(bytes).map_err(|e| recipient::Error::Identity {
            index,
            message: e.to_string(),
        })?;
        if !self.post_quantum.is_empty() {
            return Err(recipient::Error::Identity {
                index,
                message: "cannot mix classical and post-quantum identities".to_string(),
            });
        }
        self.classical.push(key.recipient);
        Ok(())
    }
    fn labels(&mut self) -> HashSet<String> {
        if self.post_quantum.is_empty() {
            HashSet::new()
        } else {
            HashSet::from([post_quantum::LABEL.to_string()])
        }
    }
    fn wrap_file_keys(
        &mut self,
        keys: Vec<FileKey>,
        _: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let mut files = vec![];
        for key in keys {
            let mut stanzas = vec![];
            for recipient in &self.classical {
                let body = match schemes::wrap(recipient, key.expose_secret()) {
                    Ok(body) => body,
                    Err(error) => {
                        return Ok(Err(vec![recipient::Error::Internal {
                            message: error.to_string(),
                        }]));
                    }
                };
                stanzas.push(Stanza {
                    tag: recipient.scheme().tag().into(),
                    args: vec![
                        recipient.scheme().stanza_version().into(),
                        recipient.fingerprint(),
                    ],
                    body,
                });
            }
            for recipient in &self.post_quantum {
                let stanza = recipient.stanza(key.expose_secret()).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                stanzas.push(stanza);
            }
            files.push(stanzas);
        }
        Ok(Ok(files))
    }
}

/// Identities keep the ingestion index so unwrap errors name the right one.
#[derive(Default)]
pub struct Identities {
    classical: Vec<(usize, Identity)>,
    post_quantum: Vec<(usize, age_tpm_wsl_post_quantum::Identity)>,
}
fn unwrap_file_key(request: Frame) -> io::Result<FileKey> {
    let response = Helper::configured()?.call(request)?;
    FileKey::try_init_with_mut(|out| {
        if response.payload.len() != out.len() {
            return Err(invalid("invalid file key length"));
        }
        out.copy_from_slice(&response.payload);
        Ok(())
    })
}

impl IdentityPluginV1 for Identities {
    fn add_identity(
        &mut self,
        index: usize,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        let reject = |message: String| identity::Error::Identity { index, message };
        check_name(name).map_err(|e| reject(e.to_string()))?;
        if bytes.first() == Some(&3) {
            let key = post_quantum::parse_identity(bytes).map_err(|e| reject(e.to_string()))?;
            if !self.classical.is_empty() {
                return Err(reject(
                    "cannot mix classical and post-quantum identities".into(),
                ));
            }
            self.post_quantum.push((index, key));
            return Ok(());
        }
        let key = Identity::parse(bytes).map_err(|e| reject(e.to_string()))?;
        if !self.post_quantum.is_empty() {
            return Err(reject(
                "cannot mix classical and post-quantum identities".into(),
            ));
        }
        self.classical.push((index, key));
        Ok(())
    }
    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        _: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut results = HashMap::new();
        for (file_index, stanzas) in files.into_iter().enumerate() {
            let mut errors = vec![];
            let mut key = None;
            for (stanza_index, stanza) in stanzas.iter().enumerate() {
                if stanza.tag == post_quantum::TAG {
                    let encapsulation = match post_quantum::Encapsulation::parse(stanza) {
                        Ok(value) => value,
                        Err(e) => {
                            errors.push(identity::Error::Stanza {
                                file_index,
                                stanza_index,
                                message: e.to_string(),
                            });
                            continue;
                        }
                    };
                    for (index, identity) in &self.post_quantum {
                        let routed = encapsulation.routes_to(identity).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        if !routed {
                            continue;
                        }
                        let attempt = post_quantum::unwrap_request(identity, &encapsulation)
                            .and_then(unwrap_file_key);
                        match attempt {
                            Ok(unwrapped) => {
                                key = Some(unwrapped);
                                break;
                            }
                            Err(e) => errors.push(identity::Error::Identity {
                                index: *index,
                                message: e.to_string(),
                            }),
                        }
                    }
                    if key.is_some() {
                        break;
                    }
                    continue;
                }
                let Some(scheme) = Scheme::from_tag(&stanza.tag) else {
                    continue;
                };
                let fingerprint = match validate_stanza(stanza) {
                    Ok(fp) => fp,
                    Err(e) => {
                        errors.push(identity::Error::Stanza {
                            file_index,
                            stanza_index,
                            message: e.to_string(),
                        });
                        continue;
                    }
                };
                for (index, identity) in &self.classical {
                    if scheme != identity.recipient.scheme()
                        || fingerprint != identity.recipient.fingerprint()
                    {
                        continue;
                    }
                    let attempt = unwrap_file_key(Frame::unwrap(identity, &stanza.body));
                    match attempt {
                        Ok(unwrapped) => {
                            key = Some(unwrapped);
                            break;
                        }
                        Err(e) => errors.push(identity::Error::Identity {
                            index: *index,
                            message: e.to_string(),
                        }),
                    }
                }
                if key.is_some() {
                    break;
                }
            }
            if let Some(key) = key {
                results.insert(file_index, Ok(key));
            } else if !errors.is_empty() {
                results.insert(file_index, Err(errors));
            }
        }
        Ok(results)
    }
}

pub fn validate_stanza(stanza: &Stanza) -> io::Result<&str> {
    use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
    let scheme = Scheme::from_tag(&stanza.tag).ok_or_else(|| invalid("unknown stanza tag"))?;
    if stanza.args.len() != 2
        || stanza.args[0] != scheme.stanza_version()
        || stanza.body.len() != scheme.body_len()
    {
        return Err(invalid("invalid tpm-wsl stanza version or length"));
    }
    let fingerprint = &stanza.args[1];
    let decoded = BASE64_STANDARD_NO_PAD
        .decode(fingerprint)
        .map_err(|_| invalid("invalid stanza fingerprint"))?;
    if decoded.len() != 32 || BASE64_STANDARD_NO_PAD.encode(decoded) != *fingerprint {
        return Err(invalid("noncanonical stanza fingerprint"));
    }
    Ok(fingerprint)
}
