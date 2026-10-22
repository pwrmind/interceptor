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