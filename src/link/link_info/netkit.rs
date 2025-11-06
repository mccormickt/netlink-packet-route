// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u16, parse_u16, parse_u8, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use super::super::{LinkMessage, LinkMessageBuffer};

const NETKIT_MODE_L2: u8 = 0;
const NETKIT_MODE_L3: u8 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum NetkitMode {
    L2,
    L3,
    Other(u8),
}

impl From<NetkitMode> for u8 {
    fn from(mode: NetkitMode) -> Self {
        match mode {
            NetkitMode::L2 => NETKIT_MODE_L2,
            NetkitMode::L3 => NETKIT_MODE_L3,
            NetkitMode::Other(value) => value,
        }
    }
}

impl From<u8> for NetkitMode {
    fn from(value: u8) -> Self {
        match value {
            NETKIT_MODE_L2 => NetkitMode::L2,
            NETKIT_MODE_L3 => NetkitMode::L3,
            _ => NetkitMode::Other(value),
        }
    }
}

const NETKIT_POLICY_PASS: u8 = 0;
const NETKIT_POLICY_DROP: u8 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum NetkitPolicy {
    Pass,
    Drop,
    Other(u8),
}

impl From<NetkitPolicy> for u8 {
    fn from(policy: NetkitPolicy) -> Self {
        match policy {
            NetkitPolicy::Pass => NETKIT_POLICY_PASS,
            NetkitPolicy::Drop => NETKIT_POLICY_DROP,
            NetkitPolicy::Other(value) => value,
        }
    }
}

impl From<u8> for NetkitPolicy {
    fn from(value: u8) -> Self {
        match value {
            NETKIT_POLICY_PASS => NetkitPolicy::Pass,
            NETKIT_POLICY_DROP => NetkitPolicy::Drop,
            _ => NetkitPolicy::Other(value),
        }
    }
}

const IFLA_NETKIT_PEER_INFO: u16 = 1;
const IFLA_NETKIT_PRIMARY: u16 = 2;
const IFLA_NETKIT_POLICY: u16 = 3;
const IFLA_NETKIT_PEER_POLICY: u16 = 4;
const IFLA_NETKIT_MODE: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoNetkit {
    Peer(LinkMessage),
    Primary(u16),
    Policy(NetkitPolicy),
    PeerPolicy(NetkitPolicy),
    Mode(NetkitMode),
    Other(DefaultNla),
}

impl Nla for InfoNetkit {
    fn value_len(&self) -> usize {
        match *self {
            Self::Peer(ref message) => message.buffer_len(),
            Self::Primary(primary) => primary.to_ne_bytes().len(),
            Self::Policy(policy) | Self::PeerPolicy(policy) => {
                u8::from(policy).to_ne_bytes().len()
            }
            Self::Mode(mode) => u8::from(mode).to_ne_bytes().len(),
            Self::Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Peer(ref message) => message.emit(buffer),
            Self::Primary(value) => emit_u16(buffer, value).unwrap(),
            Self::Policy(value) | Self::PeerPolicy(value) => {
                buffer[0] = value.into();
            }
            Self::Mode(value) => {
                buffer[0] = value.into();
            }
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Peer(_) => IFLA_NETKIT_PEER_INFO,
            Self::Primary(_) => IFLA_NETKIT_PRIMARY,
            Self::Policy(_) => IFLA_NETKIT_POLICY,
            Self::PeerPolicy(_) => IFLA_NETKIT_PEER_POLICY,
            Self::Mode(_) => IFLA_NETKIT_MODE,
            Self::Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoNetkit {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_NETKIT_PEER_INFO => {
                let err = "failed to parse netkit peer info";
                let buffer =
                    LinkMessageBuffer::new_checked(&payload).context(err)?;
                Self::Peer(LinkMessage::parse(&buffer).context(err)?)
            }
            IFLA_NETKIT_PRIMARY => Self::Primary(parse_u16(payload)?),
            IFLA_NETKIT_POLICY => Self::Policy(parse_u8(payload)?.into()),
            IFLA_NETKIT_PEER_POLICY => {
                Self::PeerPolicy(parse_u8(payload)?.into())
            }
            IFLA_NETKIT_MODE => Self::Mode(parse_u8(payload)?.into()),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind} for netkit"))?,
            ),
        })
    }
}
