
pub fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 { return Vec::new(); }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..];
    if list.len() < list_len { return Vec::new(); }
    list[..list_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

pub fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() { return Vec::new(); }
    let list_len = data[0] as usize;
    let list = &data[1..];
    if list.len() < list_len { return Vec::new(); }
    list[..list_len].to_vec()
}

pub fn join_u16(items: &[u16]) -> String {
    items.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-")
}

pub fn join_u8(items: &[u8]) -> String {
    items.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-")
}
