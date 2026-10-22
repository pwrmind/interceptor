use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, FlushInstructionCache,
    GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory,
    CONTEXT, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread,
    CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS, PROCESS_ALL_ACCESS, PROCESS_INFORMATION,
    STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

use crate::hexdump::{hex_dump, hex_dump_chunks};
use crate::pe_parser::{self, ExportInfo};

const INFINITE: u32 = 0xFFFF_FFFF;

const DBG_CONTINUE: i32 = 0x0001_0002;
const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001u32 as i32;

const EXCEPTION_DEBUG_EVENT: u32 = 1;
const EXCEPTION_BREAKPOINT: i32 = 0x8000_0003u32 as i32;
const EXCEPTION_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;

const CONTEXT_I386: u32 = 0x0001_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_I386 | 0x0000_0001;
const CONTEXT_INTEGER: u32 = CONTEXT_I386 | 0x0000_0002;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_I386 | 0x0000_0010;

const THREAD_SUSPEND_RESUME: u32 = 0x0002;

const EFLAGS_TF: u32 = 0x100;

const SAVED_STACK_DWORDS: usize = 16;

const SCAN_MAX_RESULTS: usize = 100;
const SCAN_MAX_HITS_PER_REGION: usize = 32;
const SCAN_CHUNK: u32 = 64 * 1024;

// ---------------------------------------------------------------------------
// Dump spec types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DumpSpec {
    addr: AddrSource,
    len: LenSource,
}

#[derive(Clone, Debug)]
enum AddrSource {
    Stack(u32),
    Register(Reg),
}

#[derive(Clone, Debug)]
enum LenSource {
    StackDirect(u32),
    StackPtr(u32),
    Register(Reg),
    Fixed(u32),
    CString,
    WString,
    Auto,
}

#[derive(Clone, Copy, Debug)]
enum Reg {
    Eax,
    Ebx,
    Ecx,
    Edx,
    Esi,
    Edi,
    Ebp,
    Esp,
}

impl Reg {
    fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "eax" => Some(Reg::Eax),
            "ebx" => Some(Reg::Ebx),
            "ecx" => Some(Reg::Ecx),
            "edx" => Some(Reg::Edx),
            "esi" => Some(Reg::Esi),
            "edi" => Some(Reg::Edi),
            "ebp" => Some(Reg::Ebp),
            "esp" => Some(Reg::Esp),
            _ => None,
        }
    }
    fn value(self, ctx: &CONTEXT) -> u32 {
        match self {
            Reg::Eax => ctx.Eax,
            Reg::Ebx => ctx.Ebx,
            Reg::Ecx => ctx.Ecx,
            Reg::Edx => ctx.Edx,
            Reg::Esi => ctx.Esi,
            Reg::Edi => ctx.Edi,
            Reg::Ebp => ctx.Ebp,
            Reg::Esp => ctx.Esp,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Reg::Eax => "eax",
            Reg::Ebx => "ebx",
            Reg::Ecx => "ecx",
            Reg::Edx => "edx",
            Reg::Esi => "esi",
            Reg::Edi => "edi",
            Reg::Ebp => "ebp",
            Reg::Esp => "esp",
        }
    }
}

fn parse_u32_any(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

fn parse_addr_source(s: &str) -> Result<AddrSource> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Some(rest) = inner.strip_prefix("esp+") {
            if let Some(n) = parse_u32_any(rest) {
                return Ok(AddrSource::Stack(n));
            }
        }
        bail!("Unsupported address expression: {}", s);
    }
    if let Some(r) = Reg::from_name(s) {
        return Ok(AddrSource::Register(r));
    }
    bail!("Unsupported address expression: {}", s);
}

fn parse_len_source(s: &str) -> Result<LenSource> {
    let s = s.trim();
    if s == "str" {
        return Ok(LenSource::CString);
    }
    if s == "wstr" {
        return Ok(LenSource::WString);
    }
    if s == "auto" || s.is_empty() {
        return Ok(LenSource::Auto);
    }
    if let Some(inner) = s.strip_prefix("[[").and_then(|x| x.strip_suffix("]]")) {
        if let Some(rest) = inner.strip_prefix("esp+") {
            if let Some(n) = parse_u32_any(rest) {
                return Ok(LenSource::StackPtr(n));
            }
        }
        bail!("Unsupported length expression: {}", s);
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Some(rest) = inner.strip_prefix("esp+") {
            if let Some(n) = parse_u32_any(rest) {
                return Ok(LenSource::StackDirect(n));
            }
        }
        bail!("Unsupported length expression: {}", s);
    }
    if let Some(n) = parse_u32_any(s) {
        return Ok(LenSource::Fixed(n));
    }
    if let Some(r) = Reg::from_name(s) {
        return Ok(LenSource::Register(r));
    }
    bail!("Unsupported length expression: {}", s);
}

fn parse_dump_spec(s: &str) -> Result<DumpSpec> {
    let mut depth = 0;
    let mut split_pos = None;
    for (i, ch) in s.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            ':' if depth == 0 => {
                split_pos = Some(i);
                break;
            }
            _ => {}
        }
    }
    let (addr_s, len_s) = match split_pos {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    let addr = parse_addr_source(addr_s)?;
    let len = parse_len_source(len_s)?;
    Ok(DumpSpec { addr, len })
}

fn parse_dump_specs(s: &str) -> Result<Vec<DumpSpec>> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|p| parse_dump_spec(p.trim()))
        .collect()
}

impl DumpSpec {
    fn label(&self) -> String {
        let a = match &self.addr {
            AddrSource::Stack(off) => format!("[esp+{}]", off),
            AddrSource::Register(r) => r.name().to_string(),
        };
        let l = match &self.len {
            LenSource::StackDirect(off) => format!("[esp+{}]", off),
            LenSource::StackPtr(off) => format!("[[esp+{}]]", off),
            LenSource::Register(r) => r.name().to_string(),
            LenSource::Fixed(n) => format!("{}", n),
            LenSource::CString => "str".to_string(),
            LenSource::WString => "wstr".to_string(),
            LenSource::Auto => "auto".to_string(),
        };
        format!("{}:{}", a, l)
    }
}

// ---------------------------------------------------------------------------
// Debugger state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BpType {
    Enter,
    Exit,
}

#[derive(Clone, Copy)]
enum HwKind {
    Execute,
    Write,
    ReadWrite,
}

struct HwBreakpoint {
    addr: u32,
    kind: HwKind,
    index: u8,
}

struct Breakpoint {
    original_byte: u8,
    bp_type: BpType,
    function_name: String,
    armed: bool,
    exit_specs: Vec<DumpSpec>,
}

struct TempBreakpoint {
    original_byte: u8,
    exit_ctx: ExitContext,
}

struct ExitContext {
    function_name: String,
    entry_addr: u32,
    saved_stack: Vec<u32>,
    specs: Vec<DumpSpec>,
}

struct ModuleInfo {
    base: u32,
    size: u32,
}

struct FunctionInfo {
    name: String,
    address: u32,
    module: String,
}

enum Flow {
    Continue,
    ContinueNotHandled,
    Stop,
    ProcessExited,
}

struct Paused {
    event: DEBUG_EVENT,
    resume: ResumeAction,
}

enum ResumeAction {
    Continue,
    StepAndRearm(Vec<u32>),
}

enum StepKind {
    InternalRearm(Vec<u32>),
    UserStep(Vec<u32>),
}

pub struct Debugger {
    process_handle: HANDLE,
    process_id: u32,
    breakpoints: HashMap<u32, Breakpoint>,
    temp_breakpoints: HashMap<u32, TempBreakpoint>,
    pending_breakpoints: Vec<(String, BpType, Vec<DumpSpec>)>,
    modules: HashMap<String, ModuleInfo>,
    cached_functions: HashMap<String, FunctionInfo>,
    hw_breakpoints: Vec<HwBreakpoint>,
    paused: Option<Paused>,
    pending_step: Option<StepKind>,
    exited: bool,
    attached: bool,
}

// ---------------------------------------------------------------------------
// Public helpers for pe_parser
// ---------------------------------------------------------------------------

pub fn read_memory(process: HANDLE, addr: u32, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut read,
        )
    };
    if ok == 0 {
        bail!(
            "ReadProcessMemory(0x{:08X}, {}) failed: {}",
            addr,
            size,
            std::io::Error::last_os_error()
        );
    }
    buf.truncate(read);
    Ok(buf)
}

pub fn read_u32(process: HANDLE, addr: u32) -> Result<u32> {
    let buf = read_memory(process, addr, 4)?;
    if buf.len() < 4 {
        bail!("short read at 0x{:08X}", addr);
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn write_memory(process: HANDLE, addr: u32, data: &[u8]) -> Result<()> {
    let size = data.len();
    let mut old_prot: u32 = 0;
    unsafe {
        VirtualProtectEx(
            process,
            addr as *const _,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        );
    }
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            addr as *const _,
            data.as_ptr() as *const _,
            size,
            &mut written,
        )
    };
    if ok == 0 {
        bail!(
            "WriteProcessMemory(0x{:08X}) failed: {}",
            addr,
            std::io::Error::last_os_error()
        );
    }
    unsafe {
        VirtualProtectEx(process, addr as *const _, size, old_prot, &mut old_prot);
        FlushInstructionCache(process, addr as *const _, size);
    }
    Ok(())
}

fn get_module_basename(file: HANDLE) -> Option<String> {
    if file.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetFinalPathNameByHandleW(file, buf.as_mut_ptr(), buf.len() as u32, 0) };
    if len == 0 || (len as usize) >= buf.len() {
        return None;
    }
    buf.truncate(len as usize);
    let s = String::from_utf16(&buf).ok()?;
    let s = s.trim_start_matches(r"\\?\");
    s.rsplit('\\').next().map(|x| x.to_string())
}

fn enable_debug_privilege() -> Result<()> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            bail!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut luid: LUID = std::mem::zeroed();
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            bail!(
                "LookupPrivilegeValueW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0] = LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        };
        if AdjustTokenPrivileges(
            token,
            0,
            &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            CloseHandle(token);
            bail!(
                "AdjustTokenPrivileges failed: {}",
                std::io::Error::last_os_error()
            );
        }
        CloseHandle(token);
    }
    Ok(())
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '-')
        .collect();
    let s = cleaned.as_str();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() % 2 != 0 {
        bail!("hex string must have even length (got {})", s.len());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)?;
        out.push(byte);
    }
    Ok(out)
}

impl Debugger {
    pub fn launch(target: &str) -> Result<Self> {
        let mut cmdline: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        if ok == 0 {
            bail!(
                "CreateProcessW failed: {}",
                std::io::Error::last_os_error()
            );
        }

        if !pi.hThread.is_null() {
            unsafe { CloseHandle(pi.hThread) };
        }

        let mut dbg = Self {
            process_handle: pi.hProcess,
            process_id: pi.dwProcessId,
            breakpoints: HashMap::new(),
            temp_breakpoints: HashMap::new(),
            pending_breakpoints: Vec::new(),
            modules: HashMap::new(),
            cached_functions: HashMap::new(),
            hw_breakpoints: Vec::new(),
            paused: None,
            pending_step: None,
            exited: false,
            attached: false,
        };

        println!("[+] PID = {}", dbg.process_id);
        dbg.initialize()?;
        Ok(dbg)
    }

    pub fn attach(pid: u32) -> Result<Self> {
        enable_debug_privilege()?;

        let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        if process_handle.is_null() {
            bail!(
                "OpenProcess({}) failed: {}",
                pid,
                std::io::Error::last_os_error()
            );
        }

        if unsafe { DebugActiveProcess(pid) } == 0 {
            unsafe { CloseHandle(process_handle) };
            bail!(
                "DebugActiveProcess({}) failed: {}",
                pid,
                std::io::Error::last_os_error()
            );
        }

        let mut dbg = Self {
            process_handle,
            process_id: pid,
            breakpoints: HashMap::new(),
            temp_breakpoints: HashMap::new(),
            pending_breakpoints: Vec::new(),
            modules: HashMap::new(),
            cached_functions: HashMap::new(),
            hw_breakpoints: Vec::new(),
            paused: None,
            pending_step: None,
            exited: false,
            attached: true,
        };

        println!("[+] Attached to PID {}", pid);
        dbg.initialize()?;
        Ok(dbg)
    }

    fn initialize(&mut self) -> Result<()> {
        loop {
            let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut ev, INFINITE) } == 0 {
                bail!(
                    "WaitForDebugEvent failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let flow = self.handle_event(ev, true)?;
            match flow {
                Flow::Continue => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                },
                Flow::ContinueNotHandled => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                },
                Flow::Stop => return Ok(()),
                Flow::ProcessExited => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    self.exited = true;
                    return Ok(());
                },
            }
        }
    }

    pub fn run(&mut self) -> Result<()> {
        if self.exited {
            println!("[!] Process has exited.");
            return Ok(());
        }
        if let Some(paused) = self.paused.take() {
            self.resume_from_paused(paused)?;
        }
        self.run_loop()
    }

    pub fn step(&mut self) -> Result<()> {
        if self.exited {
            println!("[!] Process has exited.");
            return Ok(());
        }
        let paused = match self.paused.take() {
            Some(p) => p,
            None => {
                println!("[!] Not stopped. Use 'run' first.");
                return Ok(());
            }
        };
        let rearm = match paused.resume {
            ResumeAction::Continue => Vec::new(),
            ResumeAction::StepAndRearm(addrs) => addrs,
        };
        self.set_trap_flag(paused.event.dwThreadId)?;
        self.pending_step = Some(StepKind::UserStep(rearm));
        unsafe {
            ContinueDebugEvent(
                paused.event.dwProcessId,
                paused.event.dwThreadId,
                DBG_CONTINUE,
            );
        }
        self.run_loop()
    }

    fn resume_from_paused(&mut self, paused: Paused) -> Result<()> {
        match paused.resume {
            ResumeAction::Continue => unsafe {
                ContinueDebugEvent(
                    paused.event.dwProcessId,
                    paused.event.dwThreadId,
                    DBG_CONTINUE,
                );
            },
            ResumeAction::StepAndRearm(addrs) => {
                self.set_trap_flag(paused.event.dwThreadId)?;
                self.pending_step = Some(StepKind::InternalRearm(addrs));
                unsafe {
                    ContinueDebugEvent(
                        paused.event.dwProcessId,
                        paused.event.dwThreadId,
                        DBG_CONTINUE,
                    );
                }
            }
        }
        Ok(())
    }

    fn run_loop(&mut self) -> Result<()> {
        loop {
            let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut ev, INFINITE) } == 0 {
                bail!(
                    "WaitForDebugEvent failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let flow = self.handle_event(ev, false)?;
            match flow {
                Flow::Continue => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                },
                Flow::ContinueNotHandled => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                },
                Flow::Stop => return Ok(()),
                Flow::ProcessExited => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    self.exited = true;
                    return Ok(());
                },
            }
        }
    }

    fn set_trap_flag(&self, tid: u32) -> Result<()> {
        let mut ctx = self.get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER)?;
        ctx.EFlags |= EFLAGS_TF;
        self.set_context(tid, &ctx)
    }

    fn clear_trap_flag(&self, tid: u32) -> Result<()> {
        let mut ctx = self.get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER)?;
        ctx.EFlags &= !EFLAGS_TF;
        self.set_context(tid, &ctx)
    }

    pub fn find(&self, pattern: &str) {
        let pat = pattern.to_lowercase();
        let mut count = 0usize;
        for (key, fi) in &self.cached_functions {
            if key.contains(&pat) {
                println!("  0x{:08X}  {}  [{}]", fi.address, fi.name, fi.module);
                count += 1;
            }
        }
        if count == 0 {
            println!("  (no matches)");
        } else {
            println!("  {} match(es)", count);
        }
    }

    // -----------------------------------------------------------------------
    // Memory scan
    // -----------------------------------------------------------------------

    pub fn scan(&mut self, args: &[&str]) -> Result<()> {
        if self.exited {
            println!("[!] Process has exited.");
            return Ok(());
        }

        let mut wide_only = false;
        let mut hex_mode = false;
        let mut case_insensitive = false;
        let mut all_types = false;
        let mut pattern_parts: Vec<&str> = Vec::new();

        for a in args {
            match *a {
                "-w" | "--wide" => wide_only = true,
                "-x" | "--hex" => hex_mode = true,
                "-i" | "--icase" => case_insensitive = true,
                "-a" | "--all" => all_types = true,
                "-h" | "--help" => {
                    println!("Usage: scan [-a|-w|-x] [-i] <pattern>");
                    println!("  -a  ASCII + UTF-16LE");
                    println!("  -w  UTF-16LE only");
                    println!("  -x  hex bytes ('70 61 73 73' or '0x70,0x61')");
                    println!("  -i  case-insensitive (ASCII only)");
                    return Ok(());
                }
                s if s.starts_with('-') && s.len() > 1 => {
                    println!("[!] Unknown flag: {}", s);
                    return Ok(());
                }
                _ => pattern_parts.push(*a),
            }
        }

        let pattern = pattern_parts.join(" ");
        if pattern.is_empty() {
            println!("Usage: scan [-a|-w|-x] [-i] <pattern>");
            return Ok(());
        }

        let mut needles: Vec<(Vec<u8>, &'static str)> = Vec::new();
        if hex_mode {
            match parse_hex_bytes(&pattern) {
                Ok(b) if !b.is_empty() => needles.push((b, "hex")),
                Ok(_) => {
                    println!("[!] Empty hex pattern");
                    return Ok(());
                }
                Err(e) => {
                    println!("[!] Bad hex: {}", e);
                    return Ok(());
                }
            }
        } else if wide_only {
            needles.push((utf16le(&pattern), "wide"));
        } else if all_types {
            needles.push((pattern.as_bytes().to_vec(), "ascii"));
            needles.push((utf16le(&pattern), "wide"));
        } else {
            needles.push((pattern.as_bytes().to_vec(), "ascii"));
        }

        let max_needle = needles.iter().map(|(n, _)| n.len()).max().unwrap_or(1);
        let overlap = (max_needle.saturating_sub(1)) as u32;

        let regions = self.enumerate_regions()?;
        let total_bytes: u64 = regions.iter().map(|(_, s)| *s as u64).sum();
        println!(
            "[+] Scanning {} region(s), {:.1} MB",
            regions.len(),
            total_bytes as f64 / 1_048_576.0
        );

        let mut count = 0usize;
        let mut regions_scanned = 0usize;

        'outer: for (base, size) in regions {
            if size == 0 {
                continue;
            }
            regions_scanned += 1;
            let mut addr = base;
            let end = base.wrapping_add(size);

            'region: while addr < end {
                let to_read = ((end - addr).min(SCAN_CHUNK)) as usize;
                let buf = match read_memory(self.process_handle, addr, to_read) {
                    Ok(b) if !b.is_empty() => b,
                    _ => {
                        addr = addr.wrapping_add(SCAN_CHUNK);
                        continue;
                    }
                };

                let mut hits_here = 0usize;
                for (needle, label) in &needles {
                    if needle.len() > buf.len() {
                        continue;
                    }
                    let mut pos = 0usize;
                    let end_pos = buf.len() - needle.len();
                    while pos <= end_pos {
                        let matched = if case_insensitive && *label == "ascii" {
                            buf[pos..pos + needle.len()]
                                .iter()
                                .zip(needle.iter())
                                .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
                        } else {
                            &buf[pos..pos + needle.len()] == needle.as_slice()
                        };
                        if matched {
                            let hit_addr = addr.wrapping_add(pos as u32);
                            let module = self.annotate_module(hit_addr);
                            match module {
                                Some(m) => println!(
                                    "\n  [{}] 0x{:08X}  ({})",
                                    label, hit_addr, m
                                ),
                                None => println!("\n  [{}] 0x{:08X}", label, hit_addr),
                            }
                            let ctx_start = hit_addr.saturating_sub(16) & !0xFu32;
                            let ctx_len = 80usize;
                            if let Ok(ctx) = read_memory(self.process_handle, ctx_start, ctx_len) {
                                hex_dump(ctx_start, &ctx);
                            }
                            count += 1;
                            hits_here += 1;
                            if count >= SCAN_MAX_RESULTS {
                                println!(
                                    "[!] Reached {} results; stopping.",
                                    SCAN_MAX_RESULTS
                                );
                                break 'outer;
                            }
                            if hits_here >= SCAN_MAX_HITS_PER_REGION {
                                println!("  [!] Too many hits in this region, skipping rest.");
                                break 'region;
                            }
                            pos += needle.len().max(1);
                        } else {
                            pos += 1;
                        }
                    }
                }

                let step = (SCAN_CHUNK - overlap).max(1);
                addr = addr.wrapping_add(step);
            }
        }

        if count == 0 {
            println!("  (no matches)");
        } else {
            println!(
                "\n[+] {} match(es) in {} region(s) scanned",
                count, regions_scanned
            );
        }
        Ok(())
    }

    fn enumerate_regions(&self) -> Result<Vec<(u32, u32)>> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    addr as *const _,
                    &mut mbi,
                    mbi_size,
                )
            };
            if ret == 0 {
                break;
            }
            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            if region_size == 0 {
                break;
            }
            if mbi.State == MEM_COMMIT
                && (mbi.Protect & PAGE_GUARD) == 0
                && (mbi.Protect & PAGE_NOACCESS) == 0
            {
                regions.push((region_base as u32, region_size as u32));
            }
            let next = region_base.saturating_add(region_size);
            if next <= addr {
                break;
            }
            addr = next;
            if addr >= 0x8000_0000 {
                break;
            }
        }
        Ok(regions)
    }

    fn annotate_module(&self, addr: u32) -> Option<String> {
        for (name, m) in &self.modules {
            if addr >= m.base && addr < m.base.wrapping_add(m.size) {
                return Some(name.clone());
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Breakpoints
    // -----------------------------------------------------------------------

    pub fn set_breakpoint(&mut self, name: &str, mode: &str, spec_str: &str) -> Result<()> {
        let bp_type = if mode.eq_ignore_ascii_case("exit") {
            BpType::Exit
        } else {
            BpType::Enter
        };
        let specs = if bp_type == BpType::Exit {
            parse_dump_specs(spec_str)?
        } else {
            if !spec_str.trim().is_empty() {
                println!("[!] Spec is only applicable to 'exit' mode; ignored.");
            }
            Vec::new()
        };

        let key = name.to_lowercase();
        if let Some(fi) = self.cached_functions.get(&key) {
            let fname = fi.name.clone();
            let addr = fi.address;
            let module = fi.module.clone();
            self.install_bp(&fname, addr, bp_type, &module, specs)
        } else {
            println!(
                "[*] '{}' not loaded yet; queued as pending breakpoint.",
                name
            );
            self.pending_breakpoints.push((name.to_string(), bp_type, specs));
            Ok(())
        }
    }

    fn install_bp(
        &mut self,
        name: &str,
        addr: u32,
        bp_type: BpType,
        module: &str,
        exit_specs: Vec<DumpSpec>,
    ) -> Result<()> {
        if let Some(bp) = self.breakpoints.get_mut(&addr) {
            if bp.armed {
                println!("[!] Breakpoint already installed at 0x{:08X}", addr);
                return Ok(());
            }
            write_memory(self.process_handle, addr, &[0xCC])?;
            bp.armed = true;
            bp.bp_type = bp_type;
            bp.exit_specs = exit_specs;
            println!(
                "[+] Re-armed BP at 0x{:08X} [{}]",
                addr,
                match bp_type {
                    BpType::Enter => "enter",
                    BpType::Exit => "exit",
                }
            );
            return Ok(());
        }
        let orig = read_memory(self.process_handle, addr, 1)?[0];
        write_memory(self.process_handle, addr, &[0xCC])?;

        let spec_label = if exit_specs.is_empty() {
            String::new()
        } else {
            format!(
                " spec={}",
                exit_specs
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };

        self.breakpoints.insert(
            addr,
            Breakpoint {
                original_byte: orig,
                bp_type,
                function_name: name.to_string(),
                armed: true,
                exit_specs,
            },
        );

        println!(
            "[+] Breakpoint: {} (0x{:08X}) [{}{}] in {}",
            name,
            addr,
            match bp_type {
                BpType::Enter => "enter",
                BpType::Exit => "exit",
            },
            spec_label,
            module
        );
        if bp_type == BpType::Exit
            && self
                .breakpoints
                .get(&addr)
                .map_or(false, |b| b.exit_specs.is_empty())
        {
            println!("[*] No dump spec — will show raw args + tip on return.");
        }
        Ok(())
    }

    pub fn dump(&self, addr: u32, size: usize) {
        let page = 4096u32;
        let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut cur = addr;
        let end = addr.wrapping_add(size as u32);

        while cur < end {
            let page_start = cur & !(page - 1);
            let page_end = page_start.wrapping_add(page);
            let chunk_end = if end < page_end { end } else { page_end };
            let chunk_size = chunk_end - cur;
            if let Ok(bytes) = read_memory(self.process_handle, cur, chunk_size as usize) {
                if !bytes.is_empty() {
                    chunks.push((cur, bytes));
                }
            }
            cur = chunk_end;
        }

        hex_dump_chunks(&chunks);
    }

    pub fn disassemble(&self, addr: u32, count: usize) {
        let want = (count.max(1) * 15) as usize;
        let code = match read_memory(self.process_handle, addr, want) {
            Ok(b) => b,
            Err(e) => {
                println!("[!] {}", e);
                return;
            }
        };
        let mut decoder = Decoder::with_ip(32, &code, addr as u64, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut output = String::new();
        let mut instr = Instruction::default();
        for _ in 0..count {
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut instr);
            output.clear();
            formatter.format(&instr, &mut output);
            let ip = instr.ip() as u32;
            let start = (ip - addr) as usize;
            let end = start + instr.len();
            let bytes_hex: String = code[start..end]
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  0x{:08X}  {:24}  {}", ip, bytes_hex, output);
        }
    }

    pub fn info_modules(&self) {
        if self.modules.is_empty() {
            println!("  (no modules registered)");
            return;
        }
        let mut entries: Vec<_> = self.modules.iter().collect();
        entries.sort_by_key(|(_, m)| m.base);
        for (name, m) in entries {
            println!(
                "  {:24} base=0x{:08X}  size=0x{:08X}",
                name, m.base, m.size
            );
        }
    }

    pub fn info_exports(&self, module: &str) {
        let module_lc = module.to_lowercase();
        let mut matches: Vec<_> = self
            .cached_functions
            .values()
            .filter(|fi| fi.module.to_lowercase() == module_lc)
            .collect();
        matches.sort_by_key(|fi| fi.address);
        for fi in &matches {
            println!("  0x{:08X}  {}", fi.address, fi.name);
        }
        println!("  {} export(s)", matches.len());
    }

    pub fn regs(&self) {
        let tid = match &self.paused {
            Some(p) => p.event.dwThreadId,
            None => {
                println!("[!] Not stopped. Use 'run' to reach a breakpoint.");
                return;
            }
        };
        match self.get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER) {
            Ok(ctx) => print_regs(&ctx),
            Err(e) => println!("[!] {}", e),
        }
    }

    pub fn backtrace(&self) {
        let tid = match &self.paused {
            Some(p) => p.event.dwThreadId,
            None => {
                println!("[!] Not stopped.");
                return;
            }
        };
        let ctx = match self.get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER) {
            Ok(c) => c,
            Err(e) => {
                println!("[!] {}", e);
                return;
            }
        };
        println!("  #0  0x{:08X}  (EIP, current)", ctx.Eip);
        let mut ebp = ctx.Ebp;
        for i in 1..64 {
            if ebp == 0 || ebp < 0x10000 {
                break;
            }
            let next_ebp = match read_u32(self.process_handle, ebp) {
                Ok(v) => v,
                Err(_) => break,
            };
            let ret_addr = match read_u32(self.process_handle, ebp.wrapping_add(4)) {
                Ok(v) => v,
                Err(_) => break,
            };
            if ret_addr == 0 {
                break;
            }
            println!("  #{}  0x{:08X}  (EBP=0x{:08X})", i, ret_addr, ebp);
            if next_ebp <= ebp {
                break;
            }
            ebp = next_ebp;
        }
    }

    pub fn add_hw_breakpoint(&mut self, addr: u32, kind: &str) -> Result<()> {
        let hw_kind = match kind.to_lowercase().as_str() {
            "exec" | "execute" | "x" => HwKind::Execute,
            "write" | "w" => HwKind::Write,
            "read" | "rw" | "r" | "access" => HwKind::ReadWrite,
            _ => bail!("Unknown kind: {} (use exec|write|read)", kind),
        };
        let index = match self.find_free_hw_index() {
            Some(i) => i,
            None => bail!("No free HW BP slots (max 4)"),
        };
        self.hw_breakpoints.push(HwBreakpoint {
            addr,
            kind: hw_kind,
            index,
        });
        if let Some(paused) = &self.paused {
            self.apply_hw_breakpoints_to_thread(paused.event.dwThreadId)?;
        } else {
            println!("[!] Not stopped — HW BP will be applied on next pause.");
        }
        println!("[+] HW BP #{} @ 0x{:08X} [{}]", index, addr, kind);
        Ok(())
    }

    pub fn list_hw_breakpoints(&self) {
        if self.hw_breakpoints.is_empty() {
            println!("  (no HW breakpoints)");
            return;
        }
        for hb in &self.hw_breakpoints {
            let kind = match hb.kind {
                HwKind::Execute => "exec",
                HwKind::Write => "write",
                HwKind::ReadWrite => "r/w",
            };
            println!("  DR{}  0x{:08X}  {}", hb.index, hb.addr, kind);
        }
    }

    pub fn clear_hw_breakpoints(&mut self) -> Result<()> {
        self.hw_breakpoints.clear();
        if let Some(paused) = &self.paused {
            self.apply_hw_breakpoints_to_thread(paused.event.dwThreadId)?;
        }
        println!("[+] All HW breakpoints cleared.");
        Ok(())
    }

    fn find_free_hw_index(&self) -> Option<u8> {
        for i in 0..4u8 {
            if !self.hw_breakpoints.iter().any(|hb| hb.index == i) {
                return Some(i);
            }
        }
        None
    }

    fn apply_hw_breakpoints_to_thread(&self, tid: u32) -> Result<()> {
        let mut ctx = self.get_context(
            tid,
            CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS,
        )?;

        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        let mut dr7: u32 = 0;

        for hb in &self.hw_breakpoints {
            let i = hb.index as usize;
            match i {
                0 => ctx.Dr0 = hb.addr,
                1 => ctx.Dr1 = hb.addr,
                2 => ctx.Dr2 = hb.addr,
                3 => ctx.Dr3 = hb.addr,
                _ => continue,
            }
            dr7 |= 1u32 << (i * 2);
            let (rw, len) = match hb.kind {
                HwKind::Execute => (0u32, 0u32),
                HwKind::Write => (1u32, 3u32),
                HwKind::ReadWrite => (3u32, 3u32),
            };
            dr7 |= rw << (16 + i * 4);
            dr7 |= len << (18 + i * 4);
        }
        ctx.Dr7 = dr7;

        self.set_context(tid, &ctx)
    }

    fn handle_event(&mut self, ev: DEBUG_EVENT, init_phase: bool) -> Result<Flow> {
        if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let exc = unsafe { &ev.u.Exception };
            let code = exc.ExceptionRecord.ExceptionCode;

            if code == EXCEPTION_SINGLE_STEP {
                if let Some(pending) = self.pending_step.take() {
                    let (addrs, stop) = match pending {
                        StepKind::InternalRearm(a) => (a, false),
                        StepKind::UserStep(a) => (a, true),
                    };
                    for a in addrs {
                        if let Some(bp) = self.breakpoints.get_mut(&a) {
                            if !bp.armed {
                                write_memory(self.process_handle, a, &[0xCC])?;
                                bp.armed = true;
                            }
                        }
                    }
                    self.clear_trap_flag(ev.dwThreadId)?;
                    if stop {
                        println!(
                            "\n[+] step done. EIP=0x{:08X}",
                            self.eip(ev.dwThreadId)?
                        );
                        self.paused = Some(Paused {
                            event: ev,
                            resume: ResumeAction::Continue,
                        });
                        return Ok(Flow::Stop);
                    }
                    return Ok(Flow::Continue);
                } else {
                    let tid = ev.dwThreadId;
                    let ctx = self.get_context(
                        tid,
                        CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS,
                    )?;
                    let dr6 = ctx.Dr6;
                    if dr6 & 0xF != 0 {
                        let which = (dr6 & 0xF).trailing_zeros() as u8;
                        let hb = self.hw_breakpoints.iter().find(|hb| hb.index == which);
                        println!("\n[+] HW BP #{} fired on thread {}", which, tid);
                        if let Some(hb) = hb {
                            let kind = match hb.kind {
                                HwKind::Execute => "exec",
                                HwKind::Write => "write",
                                HwKind::ReadWrite => "r/w",
                            };
                            println!("    addr=0x{:08X} kind={}", hb.addr, kind);
                        }
                        println!("    EIP=0x{:08X}", ctx.Eip);
                        self.paused = Some(Paused {
                            event: ev,
                            resume: ResumeAction::Continue,
                        });
                        return Ok(Flow::Stop);
                    } else {
                        return Ok(Flow::ContinueNotHandled);
                    }
                }
            }
        }

        match ev.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { &ev.u.CreateProcessInfo };
                let base = info.lpBaseOfImage as u32;
                if let Ok(exports) =
                    pe_parser::parse_exports_from_memory(self.process_handle, base)
                {
                    self.register_exports("target.exe", base, &exports);
                }
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
                Ok(Flow::Continue)
            }

            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { &ev.u.LoadDll };
                let base = info.lpBaseOfDll as u32;
                let name = get_module_basename(info.hFile)
                    .unwrap_or_else(|| format!("module_0x{:08X}", base));
                if let Ok(exports) =
                    pe_parser::parse_exports_from_memory(self.process_handle, base)
                {
                    self.register_exports(&name, base, &exports);
                }
                if !info.hFile.is_null() {
                    unsafe { CloseHandle(info.hFile) };
                }
                self.try_resolve_pending();
                Ok(Flow::Continue)
            }

            CREATE_THREAD_DEBUG_EVENT => {
                let tid = ev.dwThreadId;
                if !self.hw_breakpoints.is_empty() {
                    if let Err(e) = self.apply_hw_breakpoints_to_thread(tid) {
                        println!("[!] HW BP apply to thread {} failed: {}", tid, e);
                    }
                }
                Ok(Flow::Continue)
            }

            EXCEPTION_DEBUG_EVENT => {
                if init_phase {
                    let exc = unsafe { &ev.u.Exception };
                    if exc.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT {
                        self.paused = Some(Paused {
                            event: ev,
                            resume: ResumeAction::Continue,
                        });
                        Ok(Flow::Stop)
                    } else {
                        Ok(Flow::ContinueNotHandled)
                    }
                } else {
                    self.handle_breakpoint(ev)
                }
            }

            EXIT_PROCESS_DEBUG_EVENT => {
                println!("[+] Process exited.");
                Ok(Flow::ProcessExited)
            }

            _ => Ok(Flow::Continue),
        }
    }

    fn eip(&self, tid: u32) -> Result<u32> {
        let ctx = self.get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER)?;
        Ok(ctx.Eip)
    }

    fn register_exports(&mut self, module: &str, base: u32, exports: &[ExportInfo]) {
        let size = self.read_size_of_image(base).unwrap_or(0);
        self.modules
            .insert(module.to_lowercase(), ModuleInfo { base, size });
        for e in exports {
            self.cached_functions.insert(
                e.name.to_lowercase(),
                FunctionInfo {
                    name: e.name.clone(),
                    address: e.address,
                    module: module.to_string(),
                },
            );
        }
    }

    fn try_resolve_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending_breakpoints);
        for (name, bt, specs) in pending {
            let key = name.to_lowercase();
            if let Some(fi) = self.cached_functions.get(&key) {
                let fname = fi.name.clone();
                let addr = fi.address;
                let module = fi.module.clone();
                if let Err(e) = self.install_bp(&fname, addr, bt, &module, specs) {
                    println!("[!] Failed to install pending bp {}: {}", fname, e);
                }
            } else {
                self.pending_breakpoints.push((name, bt, specs));
            }
        }
    }

    fn read_size_of_image(&self, base: u32) -> Result<u32> {
        let e_lfanew = read_u32(self.process_handle, base.wrapping_add(0x3C))?;
        let nt = base.wrapping_add(e_lfanew);
        read_u32(self.process_handle, nt.wrapping_add(0x50))
    }

    fn handle_breakpoint(&mut self, ev: DEBUG_EVENT) -> Result<Flow> {
        let exc = unsafe { &ev.u.Exception };
        if exc.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT {
            return Ok(Flow::ContinueNotHandled);
        }

        let tid = ev.dwThreadId;
        let mut ctx = self.get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER)?;
        let bp_addr = ctx.Eip.wrapping_sub(1);

        if self.breakpoints.contains_key(&bp_addr) {
            let bt = self.breakpoints[&bp_addr].bp_type;
            match bt {
                BpType::Enter => self.handle_enter(ev, bp_addr, tid, &mut ctx)?,
                BpType::Exit => self.handle_exit_entry(ev, bp_addr, tid, &mut ctx)?,
            }
            return Ok(Flow::Stop);
        }

        if self.temp_breakpoints.contains_key(&bp_addr) {
            self.handle_exit_return(ev, bp_addr, tid, &mut ctx)?;
            return Ok(Flow::Stop);
        }

        Ok(Flow::Continue)
    }

    fn handle_enter(
        &mut self,
        ev: DEBUG_EVENT,
        bp_addr: u32,
        tid: u32,
        ctx: &mut CONTEXT,
    ) -> Result<()> {
        let (orig_byte, fname) = {
            let bp = self.breakpoints.get_mut(&bp_addr).unwrap();
            bp.armed = false;
            (bp.original_byte, bp.function_name.clone())
        };
        write_memory(self.process_handle, bp_addr, &[orig_byte])?;
        ctx.Eip = bp_addr;
        self.set_context(tid, ctx)?;

        println!("\n[+] HIT (enter): {} at 0x{:08X}", fname, bp_addr);
        print_regs(ctx);
        println!("   (repeatable; type 'continue' to proceed or 'step' to single-step)");
        println!("   --- disassembly @ 0x{:08X} ---", bp_addr);
        self.disassemble(bp_addr, 8);

        self.paused = Some(Paused {
            event: ev,
            resume: ResumeAction::StepAndRearm(vec![bp_addr]),
        });
        Ok(())
    }

    fn handle_exit_entry(
        &mut self,
        ev: DEBUG_EVENT,
        bp_addr: u32,
        tid: u32,
        ctx: &mut CONTEXT,
    ) -> Result<()> {
        let (orig_byte, fname, specs) = {
            let bp = self.breakpoints.get_mut(&bp_addr).unwrap();
            bp.armed = false;
            (
                bp.original_byte,
                bp.function_name.clone(),
                bp.exit_specs.clone(),
            )
        };

        let esp = ctx.Esp;

        let ret_addr = read_u32(self.process_handle, esp)?;
        let mut saved_stack: Vec<u32> = Vec::with_capacity(SAVED_STACK_DWORDS);
        saved_stack.push(ret_addr);
        for i in 1..SAVED_STACK_DWORDS {
            let v = read_u32(self.process_handle, esp.wrapping_add((i * 4) as u32))
                .unwrap_or(0);
            saved_stack.push(v);
        }

        let ret_orig = read_memory(self.process_handle, ret_addr, 1)?[0];
        write_memory(self.process_handle, ret_addr, &[0xCC])?;
        self.temp_breakpoints.insert(
            ret_addr,
            TempBreakpoint {
                original_byte: ret_orig,
                exit_ctx: ExitContext {
                    function_name: fname.clone(),
                    entry_addr: bp_addr,
                    saved_stack: saved_stack.clone(),
                    specs: specs.clone(),
                },
            },
        );

        write_memory(self.process_handle, bp_addr, &[orig_byte])?;
        ctx.Eip = bp_addr;
        self.set_context(tid, ctx)?;

        println!(
            "\n[+] HIT (enter→arming exit): {} at 0x{:08X}",
            fname, bp_addr
        );
        println!("    return addr : 0x{:08X}", ret_addr);
        println!("    entry ESP   : 0x{:08X}", esp);
        println!("    --- args ---");
        for i in 0..8 {
            let idx = i + 1;
            if let Some(&v) = saved_stack.get(idx) {
                println!("    arg[{}] [esp+{}] = 0x{:08X}", i, 4 + i * 4, v);
            }
        }
        if specs.is_empty() {
            println!("    (no dump spec; will show args + tip on return)");
            println!("    tip: 'break <func> exit [esp+20]:[[esp+24]]' etc.");
        } else {
            println!("    --- planned dumps ---");
            for spec in &specs {
                match &spec.addr {
                    AddrSource::Stack(off) => {
                        let idx = (*off / 4) as usize;
                        match saved_stack.get(idx) {
                            Some(&a) => println!("    {}: addr=0x{:08X}", spec.label(), a),
                            None => {
                                println!("    {}: (stack offset out of range)", spec.label())
                            }
                        }
                    }
                    AddrSource::Register(r) => {
                        println!("    {}: (addr from {} at exit)", spec.label(), r.name())
                    }
                }
            }
        }
        println!("    (type 'continue' to run to function return)");
        self.disassemble(bp_addr, 8);

        self.paused = Some(Paused {
            event: ev,
            resume: ResumeAction::StepAndRearm(vec![bp_addr]),
        });
        Ok(())
    }

    fn handle_exit_return(
        &mut self,
        ev: DEBUG_EVENT,
        bp_addr: u32,
        tid: u32,
        ctx: &mut CONTEXT,
    ) -> Result<()> {
        let tb = self.temp_breakpoints.remove(&bp_addr).unwrap();
        let ret_val = ctx.Eax;

        write_memory(self.process_handle, bp_addr, &[tb.original_byte])?;
        ctx.Eip = bp_addr;
        self.set_context(tid, ctx)?;

        if let Some(entry_bp) = self.breakpoints.get_mut(&tb.exit_ctx.entry_addr) {
            if !entry_bp.armed {
                write_memory(self.process_handle, tb.exit_ctx.entry_addr, &[0xCC])?;
                entry_bp.armed = true;
            }
        }

        println!(
            "\n[+] HIT (return): {} back to 0x{:08X}",
            tb.exit_ctx.function_name, bp_addr
        );
        println!("    EAX = 0x{:08X} ({})", ret_val, ret_val as i32);

        if tb.exit_ctx.specs.is_empty() {
            self.dump_default_return(&tb.exit_ctx);
        } else {
            for spec in &tb.exit_ctx.specs {
                if let Err(e) = self.dump_with_spec(&tb.exit_ctx, spec, ctx) {
                    println!("    [!] dump spec {} failed: {}", spec.label(), e);
                }
            }
        }

        println!("   (type 'continue' to resume target)");
        self.paused = Some(Paused {
            event: ev,
            resume: ResumeAction::Continue,
        });
        Ok(())
    }

    fn dump_default_return(&self, ec: &ExitContext) {
        println!("    --- args ---");
        for i in 0..8 {
            let idx = i + 1;
            if let Some(&v) = ec.saved_stack.get(idx) {
                println!("    arg[{}] = 0x{:08X}", i, v);
            }
        }
        println!(
            "    tip: use 'break <func> exit [esp+N]:[[esp+M]]' to dump a specific buffer"
        );
    }

    fn dump_with_spec(
        &self,
        ec: &ExitContext,
        spec: &DumpSpec,
        ctx: &CONTEXT,
    ) -> Result<()> {
        let addr = match &spec.addr {
            AddrSource::Stack(off) => {
                let idx = (*off / 4) as usize;
                ec.saved_stack
                    .get(idx)
                    .copied()
                    .ok_or_else(|| anyhow!("stack offset 0x{:X} out of captured range", off))?
            }
            AddrSource::Register(r) => r.value(ctx),
        };

        println!("    --- dump {} @ 0x{:08X} ---", spec.label(), addr);

        match &spec.len {
            LenSource::Fixed(n) => {
                let n = (*n).min(1 << 20) as usize;
                if n == 0 {
                    println!("    (len=0)");
                    return Ok(());
                }
                let data = read_memory(self.process_handle, addr, n)?;
                hex_dump(addr, &data);
            }
            LenSource::StackDirect(off) => {
                let idx = (*off / 4) as usize;
                let n = ec
                    .saved_stack
                    .get(idx)
                    .copied()
                    .ok_or_else(|| anyhow!("stack offset 0x{:X} out of captured range", off))?;
                let n = n.min(1 << 20) as usize;
                if n == 0 {
                    println!("    (len=0)");
                    return Ok(());
                }
                let data = read_memory(self.process_handle, addr, n)?;
                hex_dump(addr, &data);
            }
            LenSource::StackPtr(off) => {
                let idx = (*off / 4) as usize;
                let ptr = ec
                    .saved_stack
                    .get(idx)
                    .copied()
                    .ok_or_else(|| anyhow!("stack offset 0x{:X} out of captured range", off))?;
                let n = read_u32(self.process_handle, ptr)?;
                let n = n.min(1 << 20) as usize;
                if n == 0 {
                    println!("    (len=0)");
                    return Ok(());
                }
                let data = read_memory(self.process_handle, addr, n)?;
                hex_dump(addr, &data);
            }
            LenSource::Register(r) => {
                let n = r.value(ctx).min(1 << 20) as usize;
                if n == 0 {
                    println!("    (len=0)");
                    return Ok(());
                }
                let data = read_memory(self.process_handle, addr, n)?;
                hex_dump(addr, &data);
            }
            LenSource::CString => {
                let data = self.read_cstring(addr, 4096)?;
                hex_dump(addr, &data);
            }
            LenSource::WString => {
                let data = self.read_wstring(addr, 4096)?;
                hex_dump(addr, &data);
            }
            LenSource::Auto => {
                if let Ok(data) = self.read_cstring(addr, 256) {
                    if !data.is_empty() {
                        hex_dump(addr, &data);
                        return Ok(());
                    }
                }
                match read_memory(self.process_handle, addr, 64) {
                    Ok(data) => hex_dump(addr, &data),
                    Err(e) => println!("    [!] read failed: {}", e),
                }
            }
        }
        Ok(())
    }

    fn read_cstring(&self, addr: u32, max: usize) -> Result<Vec<u8>> {
        let data = read_memory(self.process_handle, addr, max)?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        Ok(data[..end].to_vec())
    }

    fn read_wstring(&self, addr: u32, max: usize) -> Result<Vec<u8>> {
        let data = read_memory(self.process_handle, addr, max * 2)?;
        let mut end = data.len();
        for i in (0..data.len().saturating_sub(1)).step_by(2) {
            if data[i] == 0 && data[i + 1] == 0 {
                end = i + 2;
                break;
            }
        }
        Ok(data[..end].to_vec())
    }

    fn get_context(&self, tid: u32, flags: u32) -> Result<CONTEXT> {
        let h = self.open_thread(tid)?;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.ContextFlags = flags;
        let ok = unsafe { GetThreadContext(h, &mut ctx) };
        unsafe { CloseHandle(h) };
        if ok == 0 {
            bail!(
                "GetThreadContext failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(ctx)
    }

    fn set_context(&self, tid: u32, ctx: &CONTEXT) -> Result<()> {
        let h = self.open_thread(tid)?;
        let ok = unsafe { SetThreadContext(h, ctx) };
        unsafe { CloseHandle(h) };
        if ok == 0 {
            bail!(
                "SetThreadContext failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    fn open_thread(&self, tid: u32) -> Result<HANDLE> {
        let h = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE,
                tid,
            )
        };
        if h.is_null() {
            bail!(
                "OpenThread({}) failed: {}",
                tid,
                std::io::Error::last_os_error()
            );
        }
        Ok(h)
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        if self.attached && !self.exited {
            unsafe { DebugActiveProcessStop(self.process_id) };
        }
        if !self.process_handle.is_null() {
            unsafe { CloseHandle(self.process_handle) };
        }
    }
}

fn print_regs(ctx: &CONTEXT) {
    println!(
        "    EIP=0x{:08X}  ESP=0x{:08X}  EBP=0x{:08X}",
        ctx.Eip, ctx.Esp, ctx.Ebp
    );
    println!(
        "    EAX=0x{:08X}  EBX=0x{:08X}  ECX=0x{:08X}  EDX=0x{:08X}",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx
    );
    println!(
        "    ESI=0x{:08X}  EDI=0x{:08X}  EFL=0x{:08X}",
        ctx.Esi, ctx.Edi, ctx.EFlags
    );
}