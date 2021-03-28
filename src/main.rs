/*mod confighandler;
mod client;
mod memory;

fn main() {
    client::sendpacket("Hello");
    let scan = memory::modules("snes9x-x64.exe");
}*/

use memflow::connector::{ConnectorInventory, ConnectorArgs};
use memflow::error::*;
use memflow::mem::virt_mem::VirtualMemory;
use memflow::types::Address;

use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::{Error, Result};

use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};

use std::convert::TryInto;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Instant;
use std::env;

pub mod value_scanner;
use value_scanner::ValueScanner;

pub mod pointer_map;
use pointer_map::PointerMap;

pub mod disasm;
use disasm::Disasm;

pub mod sigmaker;
use sigmaker::Sigmaker;

use memflow::ConnectorInstance;

pub mod pbar;

#[macro_use]
extern crate scan_fmt;

pub const MAX_PRINT: usize = 32;

fn get_connector() -> ConnectorInstance {
    TermLogger::init(LevelFilter::Trace, Config::default(), TerminalMode::Mixed);

    let inventory = unsafe {
        ConnectorInventory::scan()
    };

    let args: Vec<String> = vec![String::from("device"), String::from("FPGA"), String::from("memmap"), String::from("memmap.toml")];
    let conn_args = if args.len() > 1 {
        ConnectorArgs::parse(&args[1]).expect("unable to parse arguments")
    } else {
        ConnectorArgs::new()
    };

    let connector = unsafe {
        inventory.create_connector("pcileech", &conn_args)
    }.unwrap();

    return connector
}

fn main() -> Result<()> {
    TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Mixed).unwrap();

    let args: Vec<String> = env::args().collect();
    let program = &args[1];

    let connector= get_connector();

    let mut kernel = Kernel::builder(connector).build_default_caches().build()?;

    let process_info = kernel.process_info(program)?;

    let mut process = Win32Process::with_kernel(kernel, process_info);

    let modules = process.module_list()?;

    let process_mod = modules
        .into_iter()
        .find(|m| m.name == program.to_string())
        .ok_or(Error::Other("Could not find the module"))?;

    println!("{:#?}", process_mod);

    let mut value_scanner = ValueScanner::default();
    let mut typename: Option<String> = None;
    let mut buf_len = 0;

    let mut disasm = Disasm::default();
    let mut pointer_map = PointerMap::default();

    while let Ok(line) = get_line() {
        let line = line.trim();

        let mut toks = line.splitn(2, ' ');
        let (cmd, args) = (toks.next().unwrap_or(""), toks.next().unwrap_or(""));

        match cmd {
            "quit" | "q" => break,
            "reset" | "r" => {
                value_scanner.reset();
                disasm.reset();
                pointer_map.reset();
                typename = None;
            }
            "print" | "p" => {
                if let Some(t) = &typename {
                    print_matches(&value_scanner, &mut process.virt_mem, buf_len, t)?
                } else {
                    println!("Perform a scan first!");
                }
            }
            "pointer_map" | "pm" => {
                pointer_map.reset();
                pointer_map.create_map(
                    &mut process.virt_mem,
                    process.proc_info.proc_arch.size_addr(),
                )?;
            }
            "globals" | "g" => {
                disasm.reset();
                disasm.collect_globals(&mut process)?;
                println!("Global variable references found: {:x}", disasm.map().len());
            }
            "sigmaker" | "s" => {
                if let Some(addr) = scan_fmt_some!(args, "{x}", [hex u64]) {
                    match Sigmaker::find_sigs(&mut process, &disasm, addr.into()) {
                        Ok(sigs) => {
                            println!("Found signatures:");
                            for sig in sigs {
                                println!("{}", sig);
                            }
                        }
                        Err(e) => println!("sigmaker error {}", e),
                    }
                } else {
                    println!("Usage: s {{addr}}");
                }
            }
            "offset_scan" | "os" => {
                if let (Some(use_di), Some(lrange), Some(urange), Some(max_depth), filter_addr) =
                    scan_fmt_some!(args, "{} {} {} {} {x}", String, usize, usize, usize, [hex u64])
                {
                    if pointer_map.map().is_empty() {
                        pointer_map.create_map(
                            &mut process.virt_mem,
                            process.proc_info.proc_arch.size_addr(),
                        )?;
                    }

                    let start = Instant::now();

                    let matches = if use_di == "y" {
                        if disasm.map().is_empty() {
                            disasm.collect_globals(&mut process)?;
                        }
                        pointer_map.find_matches_addrs(
                            (lrange, urange),
                            max_depth,
                            value_scanner.matches(),
                            disasm.globals(),
                        )
                    } else {
                        pointer_map.find_matches(
                            (lrange, urange),
                            max_depth,
                            value_scanner.matches(),
                        )
                    };

                    println!(
                        "Matches found: {} in {:.2}ms",
                        matches.len(),
                        start.elapsed().as_secs_f64() * 1000.0
                    );

                    if matches.len() > MAX_PRINT {
                        println!("Printing first {} matches", MAX_PRINT);
                    }
                    for (m, offsets) in matches
                        .into_iter()
                        .filter(|(_, v)| {
                            if let Some(a) = filter_addr {
                                if let Some((s, _)) = v.first() {
                                    s.as_u64() == a
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        })
                        .take(MAX_PRINT)
                    {
                        for (start, off) in offsets.into_iter() {
                            print!("{:x} + ({}) => ", start, off);
                        }
                        println!("{:x}", m);
                    }
                } else {
                    println!(
                        "usage: os {{y/[n]}} {{lower range}} {{upper range}} {{max
                            depth}} ({{filter}})"
                    );
                }
            }
            "write" | "wr" => {
                if let Err(e) = write_value(
                    args,
                    &typename,
                    value_scanner.matches(),
                    &mut process.virt_mem,
                ) {
                    println!("Error: {}", e);
                }
            }
            _ => {
                if let Some((buf, t)) = parse_input(line, &typename) {
                    buf_len = buf.len();
                    value_scanner.scan_for(&mut process.virt_mem, &buf)?;
                    print_matches(&value_scanner, &mut process.virt_mem, buf_len, &t)?;
                    typename = Some(t);
                } else {
                    println!("Invalid input!\n\nUsage:\nScan:\t\t\t<type> <value>\nPrint:\t\t\tprint\nPointer Scan:\t\tpointer_map\nGlobal Variables:\tglobals\nFind signature:\t\tsigmaker\nOffset scan:\t\toffset_scan\nWrite:\t\t\twrite");
                }
            }
        }
    }

    Ok(())
}

pub fn print_matches<V: VirtualMemory>(
    value_scanner: &ValueScanner,
    virt_mem: &mut V,
    buf_len: usize,
    typename: &str,
) -> Result<()> {
    println!("Matches found: {}", value_scanner.matches().len());

    for &m in value_scanner.matches() {
        let mut buf = vec![0; buf_len];
        virt_mem.virt_read_raw_into(m, &mut buf).data_part()?;
        println!(
            "{:x}: {}",
            m,
            print_value(&buf, typename).ok_or(Error::Other("Failed to parse type"))?
        );
    }

    Ok(())
}

pub fn get_line() -> std::io::Result<String> {
    let mut output = String::new();
    std::io::stdin().read_line(&mut output).map(|_| output)
}

pub fn async_get_line() -> Receiver<std::io::Result<String>> {
    let (tx, rx) = channel();
    thread::spawn(move || tx.send(get_line()).unwrap());
    rx
}

pub fn write_value(
    args: &str,
    typename: &Option<String>,
    matches: &[Address],
    mut virt_mem: impl VirtualMemory,
) -> Result<()> {
    if matches.is_empty() {
        return Err(Error::Other("no matches found!"));
    }

    let usage = Error::Other("usage: wr {{idx/*}} {{o/c}} {{value}}");
    let mut words = args.splitn(3, " ");
    let (idx, mode, value) = (
        words.next().ok_or(usage)?,
        words.next().ok_or(usage)?,
        words.next().ok_or(usage)?,
    );

    let (skip, take) = if idx == "*" {
        (0, matches.len())
    } else {
        (
            idx.parse::<usize>()
                .map_err(|_| Error::Other("failed to parse index!"))?,
            1,
        )
    };

    let gl = match mode {
        "o" => Ok(None),
        "c" => Ok(Some(async_get_line())),
        _ => Err(Error::Other("failed to parse mode!")),
    }?;

    let (v, _) = parse_input(value, typename).ok_or(Error::Other("failed to parse value!"))?;

    println!("Write to matches {}-{}", skip, skip + take - 1);

    loop {
        for &m in matches.iter().skip(skip).take(take) {
            virt_mem.virt_write_raw(m, v.as_ref()).data_part()?;
        }

        if let Some(try_get_line) = &gl {
            if let Ok(ret) = try_get_line.try_recv() {
                if let Err(e) = ret {
                    println!("Error reading line: {}", e.to_string());
                }
                break;
            }
        } else {
            break;
        }
    }

    println!("Write done");

    Ok(())
}

pub fn print_value(buf: &[u8], typename: &str) -> Option<String> {
    match typename {
        "str" => Some(String::from_utf8_lossy(buf).to_string()),
        "str_utf16" => {
            let mut vec = vec![];
            for w in buf.chunks_exact(2) {
                let s = u16::from_ne_bytes(w.try_into().unwrap());
                vec.push(s);
            }
            Some(format!("{}", String::from_utf16_lossy(&vec)))
        }
        "i128" => Some(format!("{}", i128::from_ne_bytes(buf.try_into().ok()?))),
        "i64" => Some(format!("{}", i64::from_ne_bytes(buf.try_into().ok()?))),
        "i32" => Some(format!("{}", i32::from_ne_bytes(buf.try_into().ok()?))),
        "i16" => Some(format!("{}", i16::from_ne_bytes(buf.try_into().ok()?))),
        "i8" => Some(format!("{}", i8::from_ne_bytes(buf.try_into().ok()?))),
        "u128" => Some(format!("{}", u128::from_ne_bytes(buf.try_into().ok()?))),
        "u64" => Some(format!("{}", u64::from_ne_bytes(buf.try_into().ok()?))),
        "u32" => Some(format!("{}", u32::from_ne_bytes(buf.try_into().ok()?))),
        "u16" => Some(format!("{}", u16::from_ne_bytes(buf.try_into().ok()?))),
        "u8" => Some(format!("{}", u8::from_ne_bytes(buf.try_into().ok()?))),
        "f64" => Some(format!("{}", f64::from_ne_bytes(buf.try_into().ok()?))),
        "f32" => Some(format!("{}", f32::from_ne_bytes(buf.try_into().ok()?))),
        _ => None,
    }
}

pub fn parse_input(input: &str, opt_typename: &Option<String>) -> Option<(Box<[u8]>, String)> {
    let (typename, value) = if let Some(t) = opt_typename {
        (t.as_str(), input)
    } else {
        let mut words = input.splitn(2, " ");
        (words.next()?, words.next()?)
    };

    let b = match typename {
        "str" => Some(Box::from(value.as_bytes())),
        "str_utf16" => {
            let mut out = vec![];
            for v in value.encode_utf16() {
                out.extend(v.to_ne_bytes().iter().copied());
            }
            Some(out.into_boxed_slice())
        }
        "i128" => Some(Box::from(value.parse::<i128>().ok()?.to_ne_bytes())),
        "i64" => Some(Box::from(value.parse::<i64>().ok()?.to_ne_bytes())),
        "i32" => Some(Box::from(value.parse::<i32>().ok()?.to_ne_bytes())),
        "i16" => Some(Box::from(value.parse::<i16>().ok()?.to_ne_bytes())),
        "i8" => Some(Box::from(value.parse::<i8>().ok()?.to_ne_bytes())),
        "u128" => Some(Box::from(value.parse::<u128>().ok()?.to_ne_bytes())),
        "u64" => Some(Box::from(value.parse::<u64>().ok()?.to_ne_bytes())),
        "u32" => Some(Box::from(value.parse::<u32>().ok()?.to_ne_bytes())),
        "u16" => Some(Box::from(value.parse::<u16>().ok()?.to_ne_bytes())),
        "u8" => Some(Box::from(value.parse::<u8>().ok()?.to_ne_bytes())),
        "f64" => Some(Box::from(value.parse::<f64>().ok()?.to_ne_bytes())),
        "f32" => Some(Box::from(value.parse::<f32>().ok()?.to_ne_bytes())),
        _ => None,
    }?;
    Some((b, typename.to_string()))
}