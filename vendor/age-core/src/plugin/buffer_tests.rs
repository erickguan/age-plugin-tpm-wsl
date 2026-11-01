use super::*;
use std::collections::VecDeque;
use std::io::{BufReader, Cursor, ErrorKind};

#[derive(Clone)]
enum Event {
    Bytes(Vec<u8>),
    Error(ErrorKind),
}

struct Scripted(VecDeque<Event>);
impl Read for Scripted {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front() {
            None => Ok(0),
            Some(Event::Error(kind)) => Err(io::Error::from(kind)),
            Some(Event::Bytes(bytes)) => {
                let count = bytes.len().min(out.len());
                out[..count].copy_from_slice(&bytes[..count]);
                if count < bytes.len() {
                    self.0.push_front(Event::Bytes(bytes[count..].to_vec()));
                }
                Ok(count)
            }
        }
    }
}

fn result(value: io::Result<usize>) -> Result<usize, ErrorKind> {
    value.map_err(|error| error.kind())
}

#[test]
fn line_reads_match_std_for_boundaries_utf8_eof_and_invalid_input() {
    let inputs = [
        Vec::new(),
        b"first\nsecond\nlast".to_vec(),
        "\u{03b1}\u{1f642}\n\u{03b2}".as_bytes().to_vec(),
        b"valid\ninvalid\xff\nend".to_vec(),
        [vec![b'x'; 20_000], b"\nlast\n".to_vec()].concat(),
    ];
    for capacity in [1, 2, 3, 7, 8192] {
        for input in &inputs {
            let mut standard = BufReader::with_capacity(capacity, Cursor::new(input.clone()));
            let mut guarded = WipingReader::with_capacity(capacity, Cursor::new(input.clone()));
            for _ in 0..5 {
                // Existing text and deliberately small capacity exercise guarded growth.
                let mut expected = String::from("prefix:");
                let mut actual = expected.clone();
                let expected_result = result(standard.read_line(&mut expected));
                let actual_result = result(guarded.read_line(&mut actual));
                assert_eq!(actual_result, expected_result);
                assert_eq!(actual, expected);
                if expected_result == Ok(0) {
                    break;
                }
            }
        }
    }
}

#[test]
fn short_reads_interruptions_and_errors_preserve_read_line_semantics() {
    for bytes in [b"partial".to_vec(), b"partial\xff".to_vec()] {
        for error in [ErrorKind::WouldBlock, ErrorKind::BrokenPipe] {
            let events = VecDeque::from([
                Event::Error(ErrorKind::Interrupted),
                Event::Bytes(bytes.clone()),
                Event::Error(error),
                Event::Bytes(b"after\n".to_vec()),
            ]);
            let mut standard = BufReader::with_capacity(3, Scripted(events.clone()));
            let mut guarded = WipingReader::with_capacity(3, Scripted(events));
            for _ in 0..3 {
                let mut expected = String::from("existing:");
                let mut actual = expected.clone();
                assert_eq!(
                    result(guarded.read_line(&mut actual)),
                    result(standard.read_line(&mut expected))
                );
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn read_and_read_until_preserve_bytes_and_consume_wipes_only_consumed_range() {
    let mut reader = WipingReader::with_capacity(8, Cursor::new(b"first\nnext"));
    assert_eq!(reader.fill_buf().unwrap(), b"first\nne");
    reader.consume(2);
    assert_eq!(&reader.bytes[..2], &[0; 2]);
    assert_eq!(reader.fill_buf().unwrap(), b"rst\nne");
    let mut line = Vec::new();
    assert_eq!(reader.read_until(b'\n', &mut line).unwrap(), 4);
    assert_eq!(line, b"rst\n");
    assert!(reader.bytes[..6].iter().all(|byte| *byte == 0));
    assert_eq!(reader.fill_buf().unwrap(), b"ne");
    reader.consume(usize::MAX);
    assert!(reader.bytes.iter().all(|byte| *byte == 0));
    assert_eq!(reader.fill_buf().unwrap(), b"xt");
    reader.clear();
    assert!(reader.bytes.iter().all(|byte| *byte == 0));
    assert_eq!((reader.position, reader.filled), (0, 0));
}

#[test]
fn read_matches_std_with_empty_small_and_bypassed_outputs() {
    for capacity in [1, 3, 8] {
        let bytes = b"abcdefghijklmnopqrstuvwxyz";
        let mut standard = BufReader::with_capacity(capacity, Cursor::new(bytes));
        let mut guarded = WipingReader::with_capacity(capacity, Cursor::new(bytes));
        for size in [0, 1, 2, 0, 16, 3, 32] {
            let mut expected = vec![0; size];
            let mut actual = expected.clone();
            assert_eq!(
                result(guarded.read(&mut actual)),
                result(standard.read(&mut expected))
            );
            assert_eq!(actual, expected);
            assert!(
                guarded.bytes[..guarded.position]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
}

#[test]
fn failed_underlying_read_cannot_leave_written_bytes_in_owned_storage() {
    struct WritesThenFails;
    impl Read for WritesThenFails {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            out.fill(0x42);
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
    }
    let mut reader = WipingReader::new(WritesThenFails);
    assert_eq!(reader.fill_buf().unwrap_err().kind(), ErrorKind::BrokenPipe);
    // This inspects a live allocation, never memory after drop/free.
    assert!(reader.bytes.iter().all(|byte| *byte == 0));
    assert_eq!((reader.position, reader.filled), (0, 0));
}

#[test]
fn guarded_growth_preserves_prefix_and_supports_multiple_replacements() {
    let mut bytes = Zeroizing::new(Vec::with_capacity(1));
    let mut text = String::with_capacity(1);
    for _ in 0..10 {
        append_bytes(&mut bytes, b"abc");
        append_text(&mut text, "abc");
    }
    assert_eq!(&**bytes, b"abcabcabcabcabcabcabcabcabcabc");
    assert_eq!(text, "abcabcabcabcabcabcabcabcabcabc");
    // Explicit clearing checks the live guarded allocation; Drop uses the same
    // audited Zeroizing ownership primitive rather than a freed-memory probe.
    bytes.zeroize();
    assert!(bytes.is_empty());
}
