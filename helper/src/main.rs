#[cfg(any(windows, test))]
mod key_format;

#[cfg(windows)]
mod cng;
#[cfg(any(windows, test))]
mod post_quantum;

#[cfg(windows)]
fn serve() -> std::io::Result<()> {
    use age_plugin_tpm_wsl::{
        Identity, Scheme,
        formats::P256_SUITE_ID,
        wire::{
            CREATE, CREATE_POST_QUANTUM, CREATE_SCHEME, DELETE, Frame, INSPECT, RECOVER,
            RECOVER_POST_QUANTUM, UNWRAP, UNWRAP_POST_QUANTUM, UNWRAP_SCHEME,
        },
    };
    use zeroize::Zeroizing;
    let request = Frame::read(std::io::stdin().lock())?;
    let result = (|| -> cng::Result<Zeroizing<Vec<u8>>> {
        if request.status != 0 {
            return Err(cng::INVALID);
        }
        if matches!(
            request.operation,
            CREATE_POST_QUANTUM | UNWRAP_POST_QUANTUM | RECOVER_POST_QUANTUM
        ) || (matches!(request.operation, INSPECT | DELETE)
            && request.payload.first() == Some(&3))
        {
            return post_quantum::dispatch(&request);
        }
        let provider = cng::Provider::open()?;
        match request.operation {
            CREATE | RECOVER => {
                let name = std::str::from_utf8(&request.payload).map_err(|_| cng::INVALID)?;
                let identity = if request.operation == CREATE {
                    provider.create(name, Scheme::Rsa2048)?
                } else {
                    provider.recover(name)?
                };
                Ok(Zeroizing::new(identity.bytes()))
            }
            CREATE_SCHEME => {
                if !request.payload.starts_with(&P256_SUITE_ID) {
                    return Err(cng::INVALID);
                }
                let name = std::str::from_utf8(&request.payload[P256_SUITE_ID.len()..])
                    .map_err(|_| cng::INVALID)?;
                Ok(Zeroizing::new(
                    provider.create(name, Scheme::P256Hpke)?.bytes(),
                ))
            }
            INSPECT | DELETE => {
                let identity = Identity::parse(&request.payload).map_err(|_| cng::INVALID)?;
                if request.operation == INSPECT {
                    Ok(Zeroizing::new(provider.inspect(&identity)?))
                } else {
                    provider.delete(&identity)?;
                    Ok(Zeroizing::new(vec![]))
                }
            }
            UNWRAP | UNWRAP_SCHEME => {
                let (identity, body) = request.unwrap_parts().map_err(|_| cng::INVALID)?;
                provider.unwrap(&identity, body)
            }
            _ => Err(cng::INVALID),
        }
    })();
    let response = match result {
        Ok(payload) => Frame {
            operation: request.operation,
            status: 0,
            payload,
        },
        Err(status) => Frame {
            operation: request.operation,
            status,
            payload: Zeroizing::new(vec![]),
        },
    };
    response.write(std::io::stdout().lock())
}

fn main() {
    #[cfg(windows)]
    if serve().is_err() {
        eprintln!("age-tpm-wsl-helper: invalid or interrupted protocol");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("age-tpm-wsl-helper requires Windows");
        std::process::exit(1);
    }
}
