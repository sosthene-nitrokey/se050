use crate::types::*;

#[test]
fn test_capdu2() {
    let mut c = CApdu::new(ApduClass::ProprietaryPlain, 0x20, 0x40, 0x60, Some(0));
    let t1 = SimpleTlv::new(0x41, &[0,1,2,3,0,1,2,3,0,1,2,3]);
    c.push(t1);
    let v: heapless::Vec<u8, 256> = c.byte_iter().collect();
    // APDU header, Lc (1B), TLV (1B size), Le (1B)
    assert_eq!(v.len(), 4+1+(1+1+12)+1);
    assert_eq!(v.as_slice(), &[0x80,0x20,0x40,0x60,0x0e,
                               0x41,0x0c,0,1,2,3,0,1,2,3,0,1,2,3,
                               0x00]);
}

#[test]
fn test_crc16_ccitt() {
    assert_eq!(0x78a1, Se050CRC::calculate(&[0,48,95,111,242]));
}
