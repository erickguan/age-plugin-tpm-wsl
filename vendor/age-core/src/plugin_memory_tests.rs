// Included inside age-core's existing private plugin::tests module.
fn memory_connection(input: &[u8]) -> Connection<std::io::Cursor<Vec<u8>>, Vec<u8>> {
    Connection {
        input: WipingReader::new(std::io::Cursor::new(input.to_vec())),
        output: Vec::new(),
        buffer: Zeroizing::new(String::new()),
        _working_dir: None,
    }
}

#[test]
fn terminal_receive_errors_clear_accumulated_protocol_input() {
    for (input, expected) in [
        (&b"-> wrap-file-key\nAAAA"[..], io::ErrorKind::UnexpectedEof),
        (&b"not a stanza\n"[..], io::ErrorKind::InvalidData),
        (&b"-> wrap-file-key\n\xff\n"[..], io::ErrorKind::InvalidData),
    ] {
        let mut connection = memory_connection(input);
        assert_eq!(connection.receive().unwrap_err().kind(), expected);
        assert!(connection.buffer.is_empty());
    }
}

#[test]
fn ordinary_receive_preserves_stanza_and_multiline_body() {
    let dummy: Vec<u8> = (0..128).collect();
    let mut encoded = Vec::new();
    cookie_factory::gen_simple(write::age_stanza("fixture", &["arg"], &dummy), &mut encoded)
        .unwrap();
    let mut connection = memory_connection(&encoded);
    let stanza = connection.receive().unwrap();
    assert_eq!(stanza.tag, "fixture");
    assert_eq!(stanza.args, ["arg"]);
    assert_eq!(stanza.body, dummy);
    assert!(connection.buffer.is_empty());
}

#[test]
fn ignored_and_done_commands_preserve_protocol_dispatch() {
    let mut connection = memory_connection(b"-> ignored\nAA\n-> known\nAQ\n-> done\nAg\n");
    let result = connection
        .unidir_receive::<_, (), (), (), (), _, _, _, _>(
            ("known", |stanza| Ok(stanza.body)),
            ("unused", |_| Ok(())),
            (None, |_| Ok(())),
            (None, |_| Ok(())),
        )
        .unwrap();
    assert_eq!(result, (Ok(vec![vec![1]]), Ok(vec![]), None, None));
    assert!(connection.buffer.is_empty());
}

struct FailingWriter {
    remaining: usize,
    fail_flush: bool,
}
impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = self.remaining.min(bytes.len());
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

fn failing_connection(remaining: usize, fail_flush: bool) -> Connection<io::Empty, FailingWriter> {
    Connection {
        input: WipingReader::new(std::io::empty()),
        output: FailingWriter {
            remaining,
            fail_flush,
        },
        buffer: Zeroizing::new(String::new()),
        _working_dir: None,
    }
}

#[test]
fn partial_writer_errors_preserve_serializer_mapping() {
    let dummy = [0u8; 128];
    for (remaining, expected) in [
        (0, io::ErrorKind::BrokenPipe),
        (5, io::ErrorKind::Other),
        (40, io::ErrorKind::Other),
    ] {
        let mut connection = failing_connection(remaining, false);
        assert_eq!(
            connection
                .send("wrap-file-key", &[] as &[&str], &dummy)
                .unwrap_err()
                .kind(),
            expected,
        );
    }
}

#[test]
fn flush_error_propagates_independently_of_partial_write_cases() {
    let mut connection = failing_connection(4096, true);
    assert_eq!(
        connection
            .send("wrap-file-key", &[] as &[&str], &[0u8; 128])
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe,
    );
}

#[test]
fn unexecuted_serializer_can_be_dropped() {
    // Source review verifies the captured guard's ownership; this does not read
    // freed allocations or claim a physical-erasure measurement.
    let dummy = [0u8; 128];
    let serializer = write::age_stanza::<Vec<u8>, &str>("wrap-file-key", &[], &dummy);
    drop(serializer);
}
