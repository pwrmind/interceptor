use anyhow::{bail, Result};
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
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
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

// EXCEPTION_DEBUG_EVENT is defined locally (windows-sys import omitted to avoid name clash)
const EXCEPTION_DEBUG_EVENT: u32 = 1;

const EXCEPTION_BREAKPOINT: i32 = 0x8000_0003u32 as i32;
const EXCEPTION_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;

const CONTEXT_I386: u32 = 0x0001_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_I386 | 0x0000_0001;
const CONTEXT_INTEGER: u32 = CONTEXT_I386 | 0x0000_0002;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_I386 | 0x0000_0010;

const THREAD_SUSPEND_RESUME: u32 = 0x0002;

const EFLAGS_TF: u32 = 0x100;

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
}

struct TempBreakpoint {
    original_byte: u8,
    exit_ctx: ExitContext,
}

struct ExitContext {
    function_name: String,
    pb_data_addr: u32,
    pdw_data_len_addr: u32,
    entry_addr: u32,
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
    pending_breakpoints: Vec<(String, BpType)>,
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
            bail!("CreateProcessW failed: {}", std::io::Error::last_os_error());
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

    // -----------------------------------------------------------------------
    // User commands — resume / step
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Trap flag helpers
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // find / break / dump / disas / info
    // -----------------------------------------------------------------------

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

    pub fn set_breakpoint(&mut self, name: &str, mode: &str) -> Result<()> {
        let bp_type = if mode.eq_ignore_ascii_case("exit") {
            BpType::Exit
        } else {
            BpType::Enter
        };
        let key = name.to_lowercase();
        if let Some(fi) = self.cached_functions.get(&key) {
            let fname = fi.name.clone();
            let addr = fi.address;
            let module = fi.module.clone();
            self.install_bp(&fname, addr, bp_type, &module)
        } else {
            println!(
                "[*] '{}' not loaded yet; queued as pending breakpoint.",
                name
            );
            self.pending_breakpoints.push((name.to_string(), bp_type));
            Ok(())
        }
    }

    fn install_bp(&mut self, name: &str, addr: u32, bp_type: BpType, module: &str) -> Result<()> {
        if let Some(bp) = self.breakpoints.get_mut(&addr) {
            if bp.armed {
                println!("[!] Breakpoint already installed at 0x{:08X}", addr);
                return Ok(());
            }
            write_memory(self.process_handle, addr, &[0xCC])?;
            bp.armed = true;
            bp.bp_type = bp_type;
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
        self.breakpoints.insert(
            addr,
            Breakpoint {
                original_byte: orig,
                bp_type,
                function_name: name.to_string(),
                armed: true,
            },
        );
        println!(
            "[+] Breakpoint: {} (0x{:08X}) [{}] in {}",
            name,
            addr,
            match bp_type {
                BpType::Enter => "enter",
                BpType::Exit => "exit",
            },
            module
        );
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

    // -----------------------------------------------------------------------
    // Registers / backtrace
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Hardware breakpoints
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Event handling
    // -----------------------------------------------------------------------

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
                        println!("\n[+] step done. EIP=0x{:08X}", self.eip(ev.dwThreadId)?);
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
                // CREATE_THREAD_DEBUG_INFO has no dwThreadId; use ev.dwThreadId.
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
        for (name, bt) in pending {
            let key = name.to_lowercase();
            if let Some(fi) = self.cached_functions.get(&key) {
                let fname = fi.name.clone();
                let addr = fi.address;
                let module = fi.module.clone();
                if let Err(e) = self.install_bp(&fname, addr, bt, &module) {
                    println!("[!] Failed to install pending bp {}: {}", fname, e);
                }
            } else {
                self.pending_breakpoints.push((name, bt));
            }
        }
    }

    fn read_size_of_image(&self, base: u32) -> Result<u32> {
        let e_lfanew = read_u32(self.process_handle, base.wrapping_add(0x3C))?;
        let nt = base.wrapping_add(e_lfanew);
        read_u32(self.process_handle, nt.wrapping_add(0x50))
    }

    // -----------------------------------------------------------------------
    // Breakpoint handling
    // -----------------------------------------------------------------------

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
        let (orig_byte, fname) = {
            let bp = self.breakpoints.get_mut(&bp_addr).unwrap();
            bp.armed = false;
            (bp.original_byte, bp.function_name.clone())
        };

        let esp = ctx.Esp;
        let ret_addr = read_u32(self.process_handle, esp)?;
        let pb_data_addr = read_u32(self.process_handle, esp.wrapping_add(20))?;
        let pdw_data_len_addr = read_u32(self.process_handle, esp.wrapping_add(24))?;

        let ret_orig = read_memory(self.process_handle, ret_addr, 1)?[0];
        write_memory(self.process_handle, ret_addr, &[0xCC])?;
        self.temp_breakpoints.insert(
            ret_addr,
            TempBreakpoint {
                original_byte: ret_orig,
                exit_ctx: ExitContext {
                    function_name: fname.clone(),
                    pb_data_addr,
                    pdw_data_len_addr,
                    entry_addr: bp_addr,
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
        println!("    pbData      : 0x{:08X}", pb_data_addr);
        println!("    pdwDataLen  : 0x{:08X}", pdw_data_len_addr);
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

        if ret_val != 0 {
            let len = read_u32(self.process_handle, tb.exit_ctx.pdw_data_len_addr)?;
            println!("    decrypted length: {} bytes", len);
            if len > 0 && (len as usize) <= (1usize << 20) {
                match read_memory(self.process_handle, tb.exit_ctx.pb_data_addr, len as usize) {
                    Ok(data) => {
                        println!(
                            "    decrypted bytes at 0x{:08X}:",
                            tb.exit_ctx.pb_data_addr
                        );
                        hex_dump(tb.exit_ctx.pb_data_addr, &data);
                    }
                    Err(e) => println!("[!] reading decrypted buffer failed: {}", e),
                }
            }
        } else {
            println!("    function returned FALSE (0)");
        }
        println!("   (type 'continue' to resume target)");

        self.paused = Some(Paused {
            event: ev,
            resume: ResumeAction::Continue,
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Thread context helpers
    // -----------------------------------------------------------------------

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