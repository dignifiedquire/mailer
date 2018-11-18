use std::io::Read;

use circular::Buffer;
use nom::{Needed, Offset};

use errors::{Error, Result};
use packet::packet_sum::Packet;
use packet::single;

/// Parse packets, in a streaming fashion from the given reader.
pub fn parser(mut input: impl Read) -> Result<Vec<Packet>> {
    // maximum size of our buffer
    let max_capacity = 1024 * 1024 * 1024;
    // the inital capacity of our buffer
    // TODO: use a better value than a random guess
    let mut capacity = 1024;
    let mut b = Buffer::with_capacity(capacity);

    let mut packets = Vec::new();
    let mut needed: Option<Needed> = None;

    let mut second_round = false;

    loop {
        // read some data
        let sz = input.read(b.space())?;
        b.fill(sz);

        // if there's no more available data in the buffer after a write, that means we reached
        // the end of the input
        if b.available_data() == 0 {
            break;
        }

        if needed.is_some() && sz == 0 {
            if second_round {
                // Cancel if we didn't receive enough bytes from our source, the second time around.
                return Err(Error::PacketIncomplete);
            }
            second_round = true;
        }

        loop {
            let length = {
                match single::parser(b.data()) {
                    Ok((remaining, Ok(p))) => {
                        info!("-- parsed packet {:?} --", p.tag());
                        packets.push(p);
                        b.data().offset(remaining)
                    }
                    Ok((remaining, Err(err))) => {
                        warn!("parse error: {:?}", err);
                        // for now we are simply skipping invalid packets
                        b.data().offset(remaining)
                    }
                    Err(err) => match err {
                        Error::Incomplete(n) => {
                            needed = Some(n);
                            break;
                        }
                        _ => return Err(err),
                    },
                }
            };

            b.consume(length);
        }

        // if the parser returned `Incomplete`, and it needs more data than the buffer can hold, we grow the buffer.
        if let Some(Needed::Size(sz)) = needed {
            if sz > b.capacity() && capacity * 2 < max_capacity {
                capacity *= 2;
                b.grow(capacity);
            }
        }
    }

    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;
    use regex::Regex;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    use types::Tag;

    #[test]
    fn test_many_parser() {
        // use pretty_env_logger;
        // let _ = pretty_env_logger::try_init();

        let p = Path::new("./tests/sks-dump/0000.pgp");
        let file = File::open(p).unwrap();

        // list of expected tags
        // this file is built by
        // `gpg --list-packets tests/sks-dump/0000.pgp`
        let fixture = File::open("./tests/sks-dump/0000_parsed.txt").unwrap();
        let re = Regex::new(r"^#\soff=(\d+)\sctb=[[:alpha:]\d]+\stag=(\d+)\s.*").unwrap();
        let expected_tags = BufReader::new(fixture)
            .lines()
            .filter(|line| line.as_ref().unwrap().starts_with("# off"))
            .map(|line| {
                let (offset, tag) = {
                    let cap = re.captures(line.as_ref().unwrap()).unwrap();
                    (cap[1].to_string(), cap[2].to_string())
                };

                (offset, tag, line)
            })
            .filter(|(offset, _, _)| {
                // skip certain packages we are not (yet) parsing
                offset != &"1193538".to_string() && // invalid mpi
                offset != &"5053086".to_string() && // invalid mpi
                offset != &"8240010".to_string() && // unknown public key algorithm 100
                offset != &"9758352".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"9797527".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11855679".to_string() &&  // TODO: unclear why this sig fails to parse
                offset != &"11855798".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11856933".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11857023".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11857113".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"12688657".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"24798372".to_string() && // TODO: unclear why this public sub key fails to parse
                offset != &"24810682".to_string() && // bad attribute size
                offset != &"38544535".to_string() // bad attribute size
            });

        let actual_tags = parser(file).unwrap();
        for ((_offset, tag, e), packet) in expected_tags.zip(actual_tags.iter()) {
            let e = e.as_ref().unwrap();
            // println!("\n-- checking: {:?} {}", packet.tag(), e);

            let tag = Tag::from_u8(tag.parse().unwrap()).unwrap();
            assert_eq!(tag, packet.tag(), "missmatch in packet {:?} ({})", p, e);
        }
    }
}
