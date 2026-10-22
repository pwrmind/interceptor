mod debugger;
mod hexdump;
mod pe_parser;

use anyhow::Result;
use debugger::Debugger;
use std::io::{self, Write};

fn parse_hex_u32(s: &str) -> Option<u32> {
    let t = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(t, 16).ok()
}

fn parse_size(s: &str) -> Option<usize> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(h, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut dbg = if args.len() >= 3 && (args[1] == "-p" || args[1] == "--attach") {
        let pid: u32 = args[2].parse().expect("invalid pid");
        println!("[+] Attaching to PID {}", pid);
        Debugger::attach(pid)?
    } else if args.len() >= 2 {
        println!("[+] Launching: {}", args[1]);
        Debugger::launch(&args[1])?
    } else {
        eprintln!("Usage:");
        eprintln!("  {} <target.exe>", args[0]);
        eprintln!("  {} -p <pid>", args[0]);
        std::process::exit(1);
    };

    println!("[+] Ready. Commands:");
    println!("      find <pattern>              - search exported functions");
    println!("      break <func> [enter|exit]   - set breakpoint (repeatable)");
    println!("      break <func> exit <spec>    - exit BP with dump spec");
    println!("      run | continue              - resume execution");
    println!("      step | s                    - single step");
    println!("      regs | reg                  - dump registers");
    println!("      bt                          - backtrace (EBP chain)");
    println!("      dump <hexaddr> [size]       - hex dump (size: dec or 0x...)");
    println!("      disas <hexaddr> [count]     - disassemble");
    println!("      info modules                - list loaded modules");
    println!("      info exports <module>       - list exports of module");
    println!("      hwbreak <hexaddr> <kind>    - HW BP (kind: exec|write|read)");
    println!("      hwlist | hwclear            - manage HW BPs");
    println!("      quit                        - exit");
    println!();
    println!("  Dump spec syntax:");
    println!("      <addr>:<len>                - one spec, use ',' for multiple");
    println!("      <addr> = [esp+N] | eax | ebx | ecx | edx | esi | edi");
    println!("      <len>  = [esp+N] | [[esp+N]] | eax..edi | <N> | str | wstr | auto");
    println!("      Examples:");
    println!("        break CryptDecrypt exit [esp+20]:[[esp+24]]");
    println!("        break Send exit [esp+8]:[esp+12]");
    println!("        break recv exit [esp+8]:eax");
    println!("        break MessageBoxW exit [esp+8]:wstr");

    loop {
        print!("dbg> ");
        io::stdout().flush()?;

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            break;
        }
        let tokens: Vec<&str> = input.trim().split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let result: Result<()> = match tokens[0].to_lowercase().as_str() {
            "find" | "f" => {
                if tokens.len() < 2 {
                    println!("Usage: find <pattern>");
                } else {
                    dbg.find(tokens[1]);
                }
                Ok(())
            }
            "break" | "b" => {
                if tokens.len() < 2 {
                    println!("Usage: break <func> [enter|exit] [spec]");
                    Ok(())
                } else {
                    let mode = if tokens.len() > 2 { tokens[2] } else { "enter" };
                    let spec = if tokens.len() > 3 { tokens[3..].join(" ") } else { String::new() };
                    dbg.set_breakpoint(tokens[1], mode, &spec)
                }
            }
            "dump" | "d" => {
                if tokens.len() < 2 {
                    println!("Usage: dump <hexaddr> [size]");
                    Ok(())
                } else {
                    match parse_hex_u32(tokens[1]) {
                        Some(addr) => {
                            let size = if tokens.len() > 2 {
                                parse_size(tokens[2]).unwrap_or(64)
                            } else {
                                64
                            };
                            dbg.dump(addr, size);
                            Ok(())
                        }
                        None => {
                            println!("[!] Invalid hex address");
                            Ok(())
                        }
                    }
                }
            }
            "run" | "r" | "continue" | "c" => dbg.run(),
            "step" | "s" => dbg.step(),
            "regs" | "reg" => {
                dbg.regs();
                Ok(())
            }
            "bt" => {
                dbg.backtrace();
                Ok(())
            }
            "disas" | "u" => {
                if tokens.len() < 2 {
                    println!("Usage: disas <hexaddr> [count]");
                    Ok(())
                } else {
                    match parse_hex_u32(tokens[1]) {
                        Some(addr) => {
                            let count = if tokens.len() > 2 {
                                tokens[2].parse().unwrap_or(8)
                            } else {
                                8
                            };
                            dbg.disassemble(addr, count);
                            Ok(())
                        }
                        None => {
                            println!("[!] Invalid hex address");
                            Ok(())
                        }
                    }
                }
            }
            "info" | "i" => {
                if tokens.len() < 2 {
                    println!("Usage: info modules | info exports <module>");
                    Ok(())
                } else {
                    match tokens[1].to_lowercase().as_str() {
                        "modules" | "mod" | "m" => {
                            dbg.info_modules();
                            Ok(())
                        }
                        "exports" | "exp" | "e" => {
                            if tokens.len() < 3 {
                                println!("Usage: info exports <module>");
                            } else {
                                dbg.info_exports(tokens[2]);
                            }
                            Ok(())
                        }
                        _ => {
                            println!("Unknown info subcommand: {}", tokens[1]);
                            Ok(())
                        }
                    }
                }
            }
            "hwbreak" | "hb" => {
                if tokens.len() < 3 {
                    println!("Usage: hwbreak <hexaddr> <exec|write|read>");
                    Ok(())
                } else {
                    match parse_hex_u32(tokens[1]) {
                        Some(addr) => dbg.add_hw_breakpoint(addr, tokens[2]),
                        None => {
                            println!("[!] Invalid hex address");
                            Ok(())
                        }
                    }
                }
            }
            "hwclear" | "hwc" => dbg.clear_hw_breakpoints(),
            "hwlist" | "hwl" => {
                dbg.list_hw_breakpoints();
                Ok(())
            }
            "quit" | "q" | "exit" => {
                println!("[+] Exiting.");
                break;
            }
            _ => {
                println!("Unknown command: {}", tokens[0]);
                Ok(())
            }
        };

        if let Err(e) = result {
            println!("[!] {}", e);
        }
    }

    Ok(())
}