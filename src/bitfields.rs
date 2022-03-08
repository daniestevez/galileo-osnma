use core::fmt;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct NmaHeader<'a>(pub &'a [u8; 1]);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum NmaStatus {
    Reserved,
    Test,
    Operational,
    DontUse,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainAndPubkeyStatus {
    Reserved,
    Nominal,
    EndOfChain,
    ChainRevoked,
    NewPublicKey,
    PublicKeyRevoked,
}

impl<'a> NmaHeader<'a> {
    pub fn nma_status(&self) -> NmaStatus {
        match self.value() >> 6 {
            0 => NmaStatus::Reserved,
            1 => NmaStatus::Test,
            2 => NmaStatus::Operational,
            3 => NmaStatus::DontUse,
            _ => unreachable!(),
        }
    }

    pub fn chain_id(&self) -> u8 {
        (self.value() >> 4) & 0x3
    }

    pub fn chain_and_pubkey_status(&self) -> ChainAndPubkeyStatus {
        match (self.value() >> 1) & 0x7 {
            0 | 6 | 7 => ChainAndPubkeyStatus::Reserved,
            1 => ChainAndPubkeyStatus::Nominal,
            2 => ChainAndPubkeyStatus::EndOfChain,
            3 => ChainAndPubkeyStatus::ChainRevoked,
            4 => ChainAndPubkeyStatus::NewPublicKey,
            5 => ChainAndPubkeyStatus::PublicKeyRevoked,
            _ => unreachable!(),
        }
    }

    fn value(&self) -> u8 {
        self.0[0]
    }
}

impl fmt::Debug for NmaHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NmaHeader")
            .field("nma_status", &self.nma_status())
            .field("chain_id", &self.chain_id())
            .field("chain_and_pubkey_status", &self.chain_and_pubkey_status())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nma_header() {
        let header = [0x52]; // NMA header broadcast on 2022-03-07
        let nma_header = NmaHeader(&header);
        assert_eq!(nma_header.nma_status(), NmaStatus::Test);
        assert_eq!(nma_header.chain_id(), 1);
        assert_eq!(
            nma_header.chain_and_pubkey_status(),
            ChainAndPubkeyStatus::Nominal
        );
    }
}
