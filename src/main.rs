mod debugger;
mod hexdump;
mod pe_parser;

use anyhow::Result;
use debugger::Debugger;
use std::io::{self, Write};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <target.exe>", args[0]);
        std::process::exit(1);
    }

    println!("[+] Launching: {}", args[1]);
    let mut dbg = Debugger::launch(&args[1])?;

    println!("[+] Ready. Commands:");
    println!("      find <pattern>            - search exported functions");
    println!("      break <func> [enter|exit] - set breakpoint");
    println!("      dump <hexaddr> [size]     - hex dump memory");
    println!("      run | continue            - resume execution");
    println!("      quit                      - exit");

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
                    println!("Usage: break <func> [enter|exit]");
                    Ok(())
                } else {
                    let mode = if tokens.len() > 2 { tokens[2] } else { "enter" };
                    dbg.set_breakpoint(tokens[1], mode)
                }
            }
            "dump" | "d" => {
                if tokens.len() < 2 {
                    println!("Usage: dump <hexaddr> [size]");
                    Ok(())
                } else {
                    match u32::from_str_radix(tokens[1].trim_start_matches("0x"), 16) {
                        Ok(addr) => {
                            let size = if tokens.len() > 2 {
                                tokens[2].parse().unwrap_or(64)
                            } else {
                                64
                            };
                            dbg.dump(addr, size);
                            Ok(())
                        }
                        Err(_) => {
                            println!("[!] Invalid hex address");
                            Ok(())
                        }
                    }
                }
            }
            "run" | "r" | "continue" | "c" => dbg.run(),
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