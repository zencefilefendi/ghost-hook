use aya::{Bpf, BpfLoader};
use aya::programs::TracePoint;
use aya::maps::{RingBuf, HashMap};
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::sleep;
use serde::Deserialize;
use rand::Rng;
use nix::sys::mman::{memfd_create, MemFdCreateFlag};
use nix::unistd::write;
use libc::{prctl, PR_SET_NAME};
use std::ffi::CString;
use tokio::signal;

#[derive(Deserialize, Debug)]
struct AnomalousBehavior {
    pid: u32,
    threat_level: u8,
    description: String,
}

const MOCK_JSON_PAYLOAD: &str = r#"
[
    { "pid": 1337, "threat_level": 1, "description": "Suspicious /etc/shadow read with unusual parent" },
    { "pid": 6666, "threat_level": 1, "description": "Known Malicious process signature" }
]
"#;

// --- 1. Process Name Obfuscation ---
fn obfuscate_process_name() {
    // Yaygın bir system kernel thread'i veya daemon ismine bürünüyoruz.
    // 'ps aux' veya 'top' çıktısında sıradan bir worker gibi görünür.
    let fake_name = CString::new("[kworker/u4:2]").unwrap();
    unsafe {
        // PR_SET_NAME syscall'u process comm değerini değiştirir (max 15 karakter).
        prctl(PR_SET_NAME, fake_name.as_ptr() as std::os::raw::c_ulong, 0, 0, 0);
    }
}

// --- 2. In-Memory Execution (Diskless Reflective Loader Simülasyonu) ---
// Gerçek dünyada loader kendisini memfd_create ile kopyalayıp execveat(..., AT_EMPTY_PATH) ile yeniden başlatır.
// Burada konsepti ve /proc/self/exe bağlantısını koparma mantığını sembolize ediyoruz.
fn diskless_execution_setup() -> Result<(), anyhow::Error> {
    // Memory'de anonim bir dosya oluşturuyoruz (Diskte fiziksel karşılığı yok).
    let mfd = memfd_create(
        c"ghost_memory_space", 
        MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING
    )?;
    
    // Aslında self-binary okunup buraya yazılır ve oradan exec yapılır.
    let dummy_payload: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46]; // Fake ELF magic
    write(mfd, &dummy_payload)?;

    // /proc/self/exe linki diskten RAM'e (memfd) yönlenmiş olur. (Anti-Forensics)
    Ok(())
}

fn parse_and_apply_rules(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let rules: Vec<AnomalousBehavior> = serde_json::from_str(MOCK_JSON_PAYLOAD)?;
    let mut live_threats: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("live_threats").unwrap())?;

    for rule in rules {
        live_threats.insert(rule.pid, rule.threat_level, 0)?;
    }
    Ok(())
}

fn weave_polymorphic_bytecode(raw_elf: &mut [u8]) {
    let pattern: [u8; 8] = [0xbf, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // r9 = r9
    let mut rng = rand::thread_rng();

    for i in 0..raw_elf.len() - 8 {
        if &raw_elf[i..i+8] == &pattern {
            let junk_reg = rng.gen_range(6..=8) as u8;
            let reg_byte = (junk_reg << 4) | junk_reg; 
            let new_inst = [0xbf, reg_byte, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            raw_elf[i..i+8].copy_from_slice(&new_inst);
        }
    }
}

// --- 3. Secure Memory Wiping (Slab Cleanup) ---
fn secure_wipe_before_exit(bpf: &mut Bpf) {
    // 1. Kernel tarafındaki Kprobe wipe kancasını tetikliyoruz.
    unsafe {
        // sys_prctl (0xDEADBEEF argümanı ile eBPF kancamıza sinyal göndeririz)
        // Kernel'daki BPF map değerlerini 0x00 (Zero) ile overwrite eder.
        prctl(libc::PR_SET_SECCOMP, 0xDEADBEEF, 0, 0, 0);
    }
    
    // 2. User-space (Rust) memory scrubbing (Değişkenleri ve map referanslarını RAM'den silme)
    if let Ok(mut live_threats) = HashMap::try_from(bpf.map_mut("live_threats").unwrap()) {
        // Örnek bir key'i (1337) map'ten tamamen kaldırma (Tombstone atma).
        let _ = live_threats.remove(&1337);
    }
}


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Stealth Boot Sequence
    obfuscate_process_name();
    let _ = diskless_execution_setup();

    let mut elf_bytes = include_bytes!("../bpf/target/bpfel-unknown-none/release/ghost_hook").to_vec();
    weave_polymorphic_bytecode(&mut elf_bytes);

    let mut bpf = BpfLoader::new().load(&elf_bytes)?;

    let program: &mut TracePoint = bpf.program_mut("ghost_block_ptrace").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_ptrace")?;
    
    parse_and_apply_rules(&mut bpf)?;

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("event_ringbuf").unwrap())?;
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // 4. Final Kill-Switch (Sinyal ile veya Timeout ile tetiklenir)
    tokio::spawn(async move {
        // Timeout
        sleep(Duration::from_millis(100)).await;
        r.store(false, Ordering::Release); 
    });

    // SIGINT (Ctrl+C) veya özel bir Kill Sinyali (SIGUSR1 vb.) yakalama
    let r_sig = running.clone();
    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        r_sig.store(false, Ordering::Release);
    });

    while running.load(Ordering::Acquire) {
        if let Some(_item) = ring_buf.next() {
            // Sessiz müdahale, log yok (Dmesg Silence).
        }
        tokio::task::yield_now().await;
    }

    // --- EFEMERİK İMHA (Zero-Persistence & Anti-Forensics) ---
    // Kernel bellek alanlarını ve map'leri (Slab) sıfırlarla overwrite et (Wipe).
    secure_wipe_before_exit(&mut bpf);
    
    // Kancaları kaldır ve eBPF programını sök.
    drop(bpf);
    
    // İşletim sistemine process'in temizce bittiğini bildirir (Sessiz Çıkış).
    std::process::exit(0);
}
