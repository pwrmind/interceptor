use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::HANDLE;

use crate::debugger::{read_memory, read_u32};

pub struct ExportInfo {
    pub name: String,
    pub address: u32,
}

fn read_u16(process: HANDLE, addr: u32) -> Result<u16> {
    let buf = read_memory(process, addr, 2)?;
    if buf.len() < 2 {
        bail!("short read");
    }
    Ok(u16::from_le_bytes([buf[0], buf[1]]))
}

fn read_cstr(process: HANDLE, addr: u32, max: usize) -> Result<String> {
    let buf = read_memory(process, addr, max)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).to_string())
}

pub fn parse_exports_from_memory(process: HANDLE, base: u32) -> Result<Vec<ExportInfo>> {
    let e_lfanew = read_u32(process, base.wrapping_add(0x3C))?;
    let nt = base.wrapping_add(e_lfanew);

    let sig = read_u32(process, nt)?;
    if sig != 0x0000_4550 {
        bail!("invalid PE signature at 0x{:08X}", nt);
    }

    let _opt_size = read_u16(process, nt + 4 + 16)?;
    let opt = nt + 4 + 20;

    let magic = read_u16(process, opt)?;
    let is_pe32_plus = magic == 0x20B;

    let export_dir_offset: u32 = if is_pe32_plus { 112 } else { 96 };
    let export_rva = read_u32(process, opt + export_dir_offset)?;
    let export_size = read_u32(process, opt + export_dir_offset + 4)?;
    if export_rva == 0 || export_size == 0 {
        return Ok(Vec::new());
    }

    let exp = base.wrapping_add(export_rva);

    let num_functions = read_u32(process, exp + 0x14)?;
    let num_names = read_u32(process, exp + 0x18)?;
    let addr_of_functions = read_u32(process, exp + 0x1C)?;
    let addr_of_names = read_u32(process, exp + 0x20)?;
    let addr_of_ordinals = read_u32(process, exp + 0x24)?;

    let export_dir_end = base
        .wrapping_add(export_rva)
        .wrapping_add(export_size);
    let mut out = Vec::new();

    for i in 0..num_names {
        let name_rva = match read_u32(
            process,
            base.wrapping_add(addr_of_names).wrapping_add(i * 4),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = match read_cstr(process, base.wrapping_add(name_rva), 256) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ord = match read_u16(
            process,
            base.wrapping_add(addr_of_ordinals).wrapping_add(i * 2),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if (ord as u32) >= num_functions {
            continue;
        }
        let func_rva = match read_u32(
            process,
            base.wrapping_add(addr_of_functions)
                .wrapping_add((ord as u32) * 4),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let func_addr = base.wrapping_add(func_rva);

        if func_addr >= base.wrapping_add(export_rva) && func_addr < export_dir_end {
            continue;
        }

        out.push(ExportInfo {
            name,
            address: func_addr,
        });
    }

    Ok(out)
}