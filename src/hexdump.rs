pub fn hex_dump(start: u32, bytes: &[u8]) {
    println!();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = start.wrapping_add((i * 16) as u32);
        print!("  0x{:08X}  ", addr);
        for j in 0..16 {
            if j < chunk.len() {
                print!("{:02X} ", chunk[j]);
            } else {
                print!("   ");
            }
        }
        print!(" |");
        for &b in chunk {
            if (0x20..0x7F).contains(&b) {
                print!("{}", b as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    println!();
}

/// Печатает несколько диапазонов, разделяя их маркерами недоступных участков.
pub fn hex_dump_chunks(chunks: &[(u32, Vec<u8>)]) {
    if chunks.is_empty() {
        println!("  (no readable data)");
        return;
    }
    let mut prev_end: Option<u32> = None;
    for (addr, bytes) in chunks {
        if let Some(pe) = prev_end {
            if *addr > pe {
                println!("  --- unmapped/inaccessible: 0x{:08X}..0x{:08X} ({} bytes) ---",
                         pe, addr, addr.wrapping_sub(pe));
            }
        }
        hex_dump(*addr, bytes);
        prev_end = Some(addr.wrapping_add(bytes.len() as u32));
    }
}