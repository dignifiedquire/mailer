use std::boxed::Box;

use try_from::TryInto;

use composed::message::Message;
use composed::Deserializable;
use errors::Result;
use packet::Packet;
use types::Tag;

impl Deserializable for Message {
    /// Parse a composed message.
    /// Ref: https://tools.ietf.org/html/rfc4880#section-11.3
    fn from_packets(packets: impl IntoIterator<Item = Packet>) -> Result<Vec<Message>> {
        let mut stack: Vec<Message> = Vec::new();
        // track a currently open package
        let mut cur: Option<usize> = None;
        let mut is_edata = false;

        for packet in packets.into_iter() {
            info!("{:?}: ", packet);
            let tag = packet.tag();
            match tag {
                Tag::LiteralData => match cur {
                    Some(i) => {
                        // setting the message packet if we are currently parsing a sigend message
                        match stack[i] {
                            Message::Signed {
                                ref mut message, ..
                            } => {
                                *message = Some(Box::new(Message::Literal(packet.try_into()?)));
                            }
                            _ => bail!("unexpected literal"),
                        }
                    }
                    None => {
                        // just a regular literal message
                        stack.push(Message::Literal(packet.try_into()?));
                    }
                },
                Tag::CompressedData => match cur {
                    Some(i) => {
                        // setting the message packet if we are currently parsing a signed message
                        match stack[i] {
                            Message::Signed {
                                ref mut message, ..
                            } => {
                                *message = Some(Box::new(Message::Literal(packet.try_into()?)));
                            }
                            _ => bail!("unexpected packet"),
                        }
                    }
                    None => {
                        // just a regular compressed mesage
                        stack.push(Message::Compressed(packet.try_into()?));
                    }
                },
                //    ESK :- Public-Key Encrypted Session Key Packet |
                //           Symmetric-Key Encrypted Session Key Packet.
                Tag::PublicKeyEncryptedSessionKey | Tag::SymKeyEncryptedSessionKey => {
                    ensure!(!is_edata, "edata should not be followed by esk");

                    if cur.is_none() {
                        stack.push(Message::Encrypted {
                            esk: vec![packet.try_into()?],
                            edata: Vec::new(),
                            protected: false,
                        });
                        cur = Some(stack.len() - 1);
                    } else if let Some(i) = cur {
                        if let Message::Encrypted { ref mut esk, .. } = stack[i] {
                            esk.push(packet.try_into()?);
                        } else {
                            bail!("bad esk init");
                        }
                    }
                }
                //    Encrypted Data :- Symmetrically Encrypted Data Packet |
                //          Symmetrically Encrypted Integrity Protected Data Packet
                Tag::SymEncryptedData | Tag::SymEncryptedProtectedData => {
                    is_edata = true;
                    match cur {
                        Some(_) => {
                            // Safe because cur is set.
                            let mut el = stack.pop().expect("stack in disarray");
                            stack.push(update_message(el, packet)?);
                        }
                        None => {
                            let protected = packet.tag() == Tag::SymEncryptedProtectedData;
                            stack.push(Message::Encrypted {
                                esk: Vec::new(),
                                edata: vec![packet.try_into()?],
                                protected,
                            });
                            cur = Some(stack.len() - 1);
                        }
                    }
                }
                Tag::Signature => match cur {
                    Some(i) => match stack[i] {
                        Message::Signed {
                            ref mut signature, ..
                        } => {
                            *signature = Some(packet.try_into()?);
                            cur = None;
                        }
                        _ => bail!("unexpected signature"),
                    },
                    None => {
                        stack.push(Message::Signed {
                            message: None,
                            one_pass_signature: None,
                            signature: Some(packet.try_into()?),
                        });
                    }
                },
                Tag::OnePassSignature => {
                    stack.push(Message::Signed {
                        message: None,
                        one_pass_signature: Some(packet.try_into()?),
                        signature: None,
                    });
                    cur = Some(stack.len() - 1);
                }
                Tag::Marker => {
                    // Marker Packets are ignored
                    // see https://tools.ietf.org/html/rfc4880#section-5.8
                }
                _ => bail!("unexpected packet {:?}", packet.tag()),
            }
        }

        Ok(stack)
    }
}

fn update_message(el: Message, packet: Packet) -> Result<Message> {
    match el {
        Message::Encrypted { .. } => update_encrypted(el, packet),
        Message::Signed { .. } => update_signed(el, packet),
        _ => bail!("bad edata init"),
    }
}
fn update_encrypted(mut el: Message, packet: Packet) -> Result<Message> {
    if let Message::Encrypted {
        ref mut edata,
        ref mut protected,
        ..
    } = el
    {
        *protected = packet.tag() == Tag::SymEncryptedProtectedData;
        edata.push(packet.try_into()?);
    }

    Ok(el)
}

fn update_signed(el: Message, packet: Packet) -> Result<Message> {
    if let Message::Signed {
        message,
        signature,
        one_pass_signature,
    } = el
    {
        let new_message = match message {
            Some(msg) => {
                if let Message::Encrypted { .. } = *msg {
                    let res = update_encrypted((*msg).clone(), packet)?;

                    Some(Box::new(res))
                } else {
                    bail!("bad edata init in signed message");
                }
            }
            None => {
                let protected = packet.tag() == Tag::SymEncryptedProtectedData;
                Some(Box::new(Message::Encrypted {
                    esk: Vec::new(),
                    edata: vec![packet.try_into()?],
                    protected,
                }))
            }
        };

        Ok(Message::Signed {
            message: new_message,
            signature,
            one_pass_signature,
        })
    } else {
        unreachable!()
    }
}
