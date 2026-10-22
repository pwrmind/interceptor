use anyhow::{bail, Result};
use std::collections::HashMap;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, FlushInstructionCache, GetThreadContext, ReadProcessMemory,
    SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT,
    CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, OpenThread, CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS,
    PROCESS_INFORMATION, STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

use crate::hexdump::hex_dump;
use crate::pe_parser::{self, ExportInfo};

const INFINITE: u32 = 0xFFFF_FFFF;

// NTSTATUS-значения — i32, как того требует ContinueDebugEvent.
const DBG_CONTINUE: i32 = 0x0001_0002;
const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001u32 as i32;

const EXCEPTION_DEBUG_EVENT: u32 = 1;
const EXCEPTION_BREAKPOINT: i32 = 0x8000_0003u32 as i32;

// Константы CONTEXT для x86 отсутствуют в windows-sys 0.59, задаём вручную.
const CONTEXT_I386: u32 = 0x0001_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_I386 | 0x0000_0001;
const CONTEXT_INTEGER: u32 = CONTEXT_I386 | 0x0000_0002;

const THREAD_SUSPEND_RESUME: u32 = 0x0002;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BpType {
    Enter,
    Exit,
}

struct Breakpoint {
    original_byte: u8,
    bp_type: BpType,
    function_name: String,
}

struct TempBreakpoint {
    original_byte: u8,
    exit_ctx: ExitContext,
}

struct ExitContext {
    function_name: String,
    pb_data_addr: u32,
    pdw_data_len_addr: u32,
}

struct ModuleInfo {
    #[allow(dead_code)]
    base: u32,
    #[allow(dead_code)]
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

pub struct Debugger {
    process_handle: HANDLE,
    process_id: u32,
    breakpoints: HashMap<u32, Breakpoint>,
    temp_breakpoints: HashMap<u32, TempBreakpoint>,
    pending_breakpoints: Vec<(String, BpType)>,
    modules: HashMap<String, ModuleInfo>,
    cached_functions: HashMap<String, FunctionInfo>,
    pending_event: Option<DEBUG_EVENT>,
    exited: bool,
}

// ---------------------------------------------------------------------------
// Публичные хелперы для pe_parser
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
            pending_event: None,
            exited: false,
        };

        println!("[+] PID = {}", dbg.process_id);
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
            let flow = self.handle_event(&ev, true)?;
            match flow {
                Flow::Continue => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                },
                Flow::ContinueNotHandled => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                },
                Flow::Stop => {
                    self.pending_event = Some(ev);
                    return Ok(());
                }
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
        if let Some(ev) = self.pending_event.take() {
            unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
        }

        loop {
            let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut ev, INFINITE) } == 0 {
                bail!(
                    "WaitForDebugEvent failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let flow = self.handle_event(&ev, false)?;
            match flow {
                Flow::Continue => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                },
                Flow::ContinueNotHandled => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                },
                Flow::Stop => {
                    self.pending_event = Some(ev);
                    return Ok(());
                }
                Flow::ProcessExited => unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    self.exited = true;
                    return Ok(());
                },
            }
        }
    }

    // -----------------------------------------------------------------------
    // Поиск / установка брейкпоинтов / дамп
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
        if self.breakpoints.contains_key(&addr) {
            println!("[!] Breakpoint already installed at 0x{:08X}", addr);
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
        match read_memory(self.process_handle, addr, size) {
            Ok(data) => hex_dump(addr, &data),
            Err(e) => println!("[!] Dump failed: {}", e),
        }
    }

    // -----------------------------------------------------------------------
    // Обработка событий
    // -----------------------------------------------------------------------

    fn handle_event(&mut self, ev: &DEBUG_EVENT, init_phase: bool) -> Result<Flow> {
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

            EXCEPTION_DEBUG_EVENT => {
                if init_phase {
                    let exc = unsafe { &ev.u.Exception };
                    if exc.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT {
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

    fn handle_breakpoint(&mut self, ev: &DEBUG_EVENT) -> Result<Flow> {
        let exc = unsafe { &ev.u.Exception };
        if exc.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT {
            return Ok(Flow::ContinueNotHandled);
        }

        let tid = ev.dwThreadId;
        let mut ctx = self.get_context(tid)?;
        let bp_addr = ctx.Eip.wrapping_sub(1);

        if self.breakpoints.contains_key(&bp_addr) {
            let bt = self.breakpoints[&bp_addr].bp_type;
            match bt {
                BpType::Enter => self.handle_enter(bp_addr, tid, &mut ctx)?,
                BpType::Exit => self.handle_exit_entry(bp_addr, tid, &mut ctx)?,
            }
            return Ok(Flow::Stop);
        }

        if self.temp_breakpoints.contains_key(&bp_addr) {
            self.handle_exit_return(bp_addr, tid, &mut ctx)?;
            return Ok(Flow::Stop);
        }

        Ok(Flow::Continue)
    }

    fn handle_enter(&mut self, bp_addr: u32, tid: u32, ctx: &mut CONTEXT) -> Result<()> {
        let bp = self.breakpoints.remove(&bp_addr).unwrap();
        write_memory(self.process_handle, bp_addr, &[bp.original_byte])?;
        ctx.Eip = bp_addr;
        self.set_context(tid, ctx)?;

        println!(
            "\n[+] HIT (enter): {} at 0x{:08X}",
            bp.function_name, bp_addr
        );
        print_regs(ctx);
        println!("   (one-shot bp removed; type 'continue' to proceed)");
        Ok(())
    }

    fn handle_exit_entry(&mut self, bp_addr: u32, tid: u32, ctx: &mut CONTEXT) -> Result<()> {
        let bp = self.breakpoints.remove(&bp_addr).unwrap();

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
                    function_name: bp.function_name.clone(),
                    pb_data_addr,
                    pdw_data_len_addr,
                },
            },
        );

        write_memory(self.process_handle, bp_addr, &[bp.original_byte])?;
        ctx.Eip = bp_addr;
        self.set_context(tid, ctx)?;

        println!(
            "\n[+] HIT (enter→arming exit): {} at 0x{:08X}",
            bp.function_name, bp_addr
        );
        println!("    return addr : 0x{:08X}", ret_addr);
        println!("    pbData      : 0x{:08X}", pb_data_addr);
        println!("    pdwDataLen  : 0x{:08X}", pdw_data_len_addr);
        println!("    (type 'continue' to run to function return)");
        Ok(())
    }

    fn handle_exit_return(&mut self, bp_addr: u32, tid: u32, ctx: &mut CONTEXT) -> Result<()> {
        let tb = self.temp_breakpoints.remove(&bp_addr).unwrap();
        let ret_val = ctx.Eax;

        write_memory(self.process_handle, bp_addr, &[tb.original_byte])?;
        ctx.Eip = bp_addr;
        self.set_context(tid, ctx)?;

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
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Thread context helpers
    // -----------------------------------------------------------------------

    fn get_context(&self, tid: u32) -> Result<CONTEXT> {
        let h = self.open_thread(tid)?;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
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