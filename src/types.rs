use core::convert::{From, Into, TryFrom};
use embedded_hal::blocking::delay::DelayMs;

// SE050 T1 mandates a single-byte LEN field, so IFS is strictly limited
pub const MAX_IFSC: usize = 255;

// T1 frame is NAD+PCB+LEN, IFS (up to IFSC), CRC16 (2)
pub const MAX_T1_FRAME_SIZE: usize = 3 + MAX_IFSC + 2;

// 8 TLV payload objects should be enough for every request?
pub const MAX_TLVS: usize = 8;

pub struct DelayWrapper {
    pub inner: &'static mut dyn DelayMs<u32>,
}
impl<T> From<&'static mut T> for DelayWrapper
where
    T: DelayMs<u32>,
{
    fn from(delay: &'static mut T) -> Self {
        Self { inner: delay }
    }
}

//////////////////////////////////////////////////////////////////////////////

pub enum Iso7816Error {
    ValueError,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
#[repr(u8)]
pub enum ApduClass {
    StandardPlain = 0b0000_0000,
    ProprietaryPlain = 0b1000_0000,
    ProprietarySecure = 0b1000_0100,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
#[repr(u8)]
pub enum ApduStandardInstruction {
    EraseBinary = 0x0e,
    Verify = 0x20,
    ManageChannel = 0x70,
    ExternalAuthenticate = 0x82,
    GetChallenge = 0x84,
    InternalAuthenticate = 0x88,
    SelectFile = 0xa4,
    ReadBinary = 0xb0,
    ReadRecords = 0xb2,
    GetResponse = 0xc0,
    Envelope = 0xc2,
    GetData = 0xca,
    WriteBinary = 0xd0,
    WriteRecord = 0xd2,
    UpdateBinary = 0xd6,
    PutData = 0xda,
    UpdateData = 0xdc,
    AppendRecord = 0xe2,
}

//////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct SimpleTlv<'a> {
    tag: u8,
    header: heapless::Vec<u8, 3>,
    data: &'a [u8],
}

impl<'a> SimpleTlv<'a> {
    pub fn new(tag: u8, data: &'a [u8]) -> Self {
        let header = if data.len() < 128 {
            heapless::Vec::from_slice(&[tag, data.len() as u8]).unwrap()
        } else { 
            heapless::Vec::from_slice(&[tag, 0x82, (data.len() >> 8) as u8, data.len() as u8]).unwrap()
        };
        Self { tag, header, data }
    }

    pub fn total_len(&self) -> usize {
        self.header.len() + self.data.len()
    }

    pub fn get_header(&self) -> &heapless::Vec<u8, 3> {
        &self.header
    }

    pub fn get_data(&self) -> &'a [u8] {
        &self.data
    }
}

//////////////////////////////////////////////////////////////////////////////

pub struct RawRApdu<'a> {
    pub data: &'a [u8],
    pub sw: u16,
}

pub struct RApdu<'a> {
    pub tlvs: heapless::Vec<SimpleTlv<'a>, MAX_TLVS>,
    pub sw: u16,
}

impl<'a> RApdu<'a> {
    pub fn get_tlv(&self, tag: u8) -> Option<&SimpleTlv<'a>> {
        for tlv in self.tlvs.iter() {
            if tlv.tag == tag {
                return Some(&tlv);
            }
        }
        None
    }
}

//////////////////////////////////////////////////////////////////////////////

pub struct CApdu<'a> {
    pub cla: ApduClass,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    tlvs: heapless::Vec<SimpleTlv<'a>, MAX_TLVS>,
    payload_len: usize,
    pub le: Option<usize>,
}

pub struct CApduByteIterator<'a> {
    capdu: &'a CApdu<'a>,
    extended: bool,
    capdu_header: heapless::Vec<u8, 7>,
    capdu_trailer: heapless::Vec<u8, 3>,
    section: usize,
    off: usize,
}

impl<'a> CApduByteIterator<'a> {
    fn new(capdu: &'a CApdu<'a>) -> Self {
        let is_extended = capdu.payload_len > 255 || capdu.le.map_or(false, |le| le > 255);
        let mut header = heapless::Vec::from_slice(&[capdu.cla.into(), capdu.ins, capdu.p1, capdu.p2]).unwrap();
        let mut trailer = heapless::Vec::new();
        if capdu.payload_len > 0 {
            if is_extended {
                header.extend_from_slice(&[0x00, (capdu.payload_len >> 8) as u8, capdu.payload_len as u8]).unwrap();
            } else {
                header.push(capdu.payload_len as u8).unwrap();
            }
        }
        if let Some(le) = capdu.le {
            if is_extended {
                trailer.extend_from_slice(&[0x00, (le >> 8) as u8, le as u8]).unwrap();
            } else {
                trailer.push(le as u8).unwrap();
            }
        }

        Self { capdu: capdu, extended: is_extended, capdu_header: header, capdu_trailer: trailer, section: 0, off: 0 }
    }

    fn current_slice(&self) -> Option<&[u8]> {
        match self.section {
        0 => { Some(&self.capdu_header) },
        i if i <= 2*self.capdu.tlvs.len() && i % 2 == 1 => { Some(&self.capdu.tlvs[i>>1].header) },
        i if i <= 2*self.capdu.tlvs.len() => { Some(&self.capdu.tlvs[(i-1)>>1].data) },
        i if i == 2*MAX_TLVS+1 => { Some(&self.capdu_trailer) },
        _ => { None },
        }
    }
}

impl<'a> Iterator for CApduByteIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let slice = self.current_slice();
        if slice.is_none() { return None; }
        let ret = slice.unwrap()[self.off];

        self.off += 1;
        loop {
            if let Some(slice) = self.current_slice() {
                if self.off < slice.len() { break; }
            }
            self.off = 0;
            self.section += 1;
            if self.section > 2*MAX_TLVS+1 { break; }
        }
        Some(ret)
    }
}

impl<'a> CApdu<'a> {
    pub fn new(cla: ApduClass, ins: u8, p1: u8, p2: u8, le: Option<usize>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            tlvs: heapless::Vec::new(),
            payload_len: 0,
            le,
        }
    }

    pub fn push(&mut self, tlv: SimpleTlv<'a>) {
        self.payload_len += tlv.total_len();
        self.tlvs.push(tlv).unwrap();
    }

    pub fn byte_iter(&self) -> CApduByteIterator<'_> {
        CApduByteIterator::new(self)
    }
}

//////////////////////////////////////////////////////////////////////////////

pub const T1_S_REQUEST_CODE: u8 = 0b1100_0000;
pub const T1_S_RESPONSE_CODE: u8 = 0b1110_0000;

pub const T1_R_CODE_MASK: u8 = 0b1110_1100;
pub const T1_R_CODE: u8 = 0b1000_0000;

pub struct T1Header {
    pub nad: u8,
    pub pcb: T1PCB,
    pub len: u8,
    pub crc: u16,
}

#[derive(PartialEq)]
pub enum T1PCB {
    I(u8, bool),		// seq, multi
    S(T1SCode, bool),		// code, response?
    R(u8, u8),			// seq, err
}

impl core::convert::TryFrom<u8> for T1PCB {
    type Error = Iso7816Error;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        if (val & T1_R_CODE_MASK) == T1_R_CODE {
            return Ok(T1PCB::R((val & 0x10) >> 4, val & 0x3));
        } else if (val & T1_S_REQUEST_CODE) == T1_S_REQUEST_CODE {
            let s_code = T1SCode::try_from(val & !T1_S_RESPONSE_CODE)?;
            return Ok(T1PCB::S(s_code, (val & 0x20) != 0));
        } else if (val & 0b1001_1111u8) == 0 {
            return Ok(T1PCB::I((val & 0x40) >> 6, (val & 0x20) != 0));
        } else {
            return Err(Iso7816Error::ValueError);
        }
    }
}

impl core::convert::Into<u8> for T1PCB {
    fn into(self) -> u8 {
        match self {
        T1PCB::I(seq, multi) => (seq << 6) | { if multi { 0x20 } else { 0 }},
        T1PCB::R(seq, err) => T1_R_CODE | (seq << 5) | err,
        T1PCB::S(code, false) => T1_S_REQUEST_CODE | <T1SCode as Into<u8>>::into(code),
        T1PCB::S(code, true) => T1_S_RESPONSE_CODE | <T1SCode as Into<u8>>::into(code),
        }
    }
}

#[derive(PartialEq)]
pub enum T1SCode {
    Resync = 0,
    IFS = 1,
    Abort = 2,
    WTX = 3,
    EndApduSession = 5,
    ChipReset = 6,
    GetATR = 7,
    InterfaceSoftReset = 15,
}

#[derive(Debug)]
pub enum T1Error {
    TransmitError,
    ReceiveError,
    BufferOverrunError(usize),
    ChecksumError,
    ProtocolError,
    RCodeReceived(u8),
    TlvParseError,
}

pub trait T1Proto {
    fn send_apdu(&mut self, apdu: &CApdu, delay: &mut DelayWrapper) -> Result<(), T1Error>;
    fn receive_apdu_raw<'a>(
        &mut self,
        buf: &'a mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<RawRApdu<'a>, T1Error>;
    fn receive_apdu<'a>(
        &mut self,
        buf: &'a mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<RApdu<'a>, T1Error>;
    fn interface_soft_reset(&mut self, delay: &mut DelayWrapper) -> Result<AnswerToReset, T1Error>;
}

//////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct AnswerToReset {
    pub protocol_version: u8,
    pub vendor_id: [u8; 5],
    // Data Link Layer Parameters
    pub dllp: DataLinkLayerParameters,
    // Physical Layer Parameters
    pub plp: PhysicalLayerParameters,
    // Historical Bytes (truncated to save memory)
    pub historical_bytes: [u8; 15],
}

#[derive(Debug)]
pub struct DataLinkLayerParameters {
    pub bwt_ms: u16,
    pub ifsc: u16,
}

#[derive(Debug)]
pub enum PhysicalLayerParameters {
    I2C(I2CParameters),
}

#[derive(Debug)]
pub struct I2CParameters {
    pub mcf: u16,
    pub configuration: u8,
    pub mpot_ms: u8,
    pub rfu: [u8; 3],
    pub segt_us: u16,
    pub wut_us: u16,
}

//////////////////////////////////////////////////////////////////////////////

pub type Se050CRC = crc16::State<crc16::X_25>;

//////////////////////////////////////////////////////////////////////////////

include!("types_convs.rs");
