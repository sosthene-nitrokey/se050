#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input<'a> {
    class: u8,
    instruction: u8,
    p1: u8,
    p2: u8,
    le: u16,
    data: &'a [u8],
}

fuzz_target!(|data: Input| {
    let Input {
        class,
        instruction,
        p1,
        p2,
        le,
        data,
    } = data;
    if class == 0b11101111 {
        // pathological class that can't be chained because it makes it a 0xFF
        return;
    }
    let Ok(iso_class) = class.try_into() else {
        return;
    };
    let iso_ins = instruction.into();

    let Ok(se_class) = class.try_into() else {
        return;
    };
    let Ok(se_ins) = instruction.try_into() else {
        return;
    };
    let se_le = if le == 256 && data.len() <= 255 {
        Some(0)
    } else if le == 0 {
        None
    } else {
        Some(le as _)
    };

    let iso_command = iso7816::command::CommandBuilder::new(iso_class, iso_ins, p1, p2, data, le);

    let se_command = &se050::RawCApdu::new(se_class, se_ins, p1, p2, data, se_le);

    let iso_command_serialized = iso_command.serialize_to_vec();
    let se_command_serialized: Vec<u8> = se_command.byte_iter().collect();
    assert_eq!(se_command_serialized, iso_command_serialized, "\nserialized by SE: {se_command_serialized:02x?}\nserialized by iso: {iso_command_serialized:02x?}");
});
