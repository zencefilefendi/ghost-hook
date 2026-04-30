#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} live_threats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} event_ringbuf SEC(".maps");

struct attack_event {
    u32 pid;
    u64 ts;
};

#define JUNK_CODE_SLED \
    asm volatile( \
        "r9 = r9;\n" \
        "r9 = r9;\n" \
        "r9 = r9;\n" \
        : : : "r9" \
    )

// Entropy Zero: Kernel Log Scrubbing (Dmesg Silence)
// BPF_PRINTK veya benzeri hiçbir loglama (tracing) kullanılmaz.
// Memory Scrubbing: User-space, eBPF'i temizlemeden önce bu fonksiyonu tetikleyecek.
// Amaç: BPF map'lerinin içerisindeki threat verilerini rastgele (junk) byte'larla ezmek.
SEC("tracepoint/syscalls/sys_enter_prctl")
int ghost_memory_wipe(struct trace_event_raw_sys_enter *ctx) {
    // tracepoint'te argümanlar array (args) olarak gelir. 
    // prctl(option, arg2, arg3, arg4, arg5)
    int option = (int)ctx->args[0];
    long arg2 = ctx->args[1];
    
    // Sadece özel sihirli argüman (magic number) ile tetiklenir
    // 0xDEADBEEF olarak arg2 üzerinden bekliyoruz. option ise 22 (PR_SET_SECCOMP).
    if (option == 22 && arg2 == 0xDEADBEEF) {
        JUNK_CODE_SLED;
        // Map Overwrite (Secure Wiping): 
        // Döngüler eBPF'de katı kurallara (verifier) tabidir, bu yüzden limitli/statik unrolled bir wipe yapıyoruz.
        
        // Örnek bir kritik PID map elementini junk byte'la ezme
        u32 target_pid = 1337;
        u8 junk_value = 0x00; // Zeroing out
        bpf_map_update_elem(&live_threats, &target_pid, &junk_value, BPF_ANY);

        // Bu kanca çalıştıktan sonra geriye bir iz bırakmaz.
        JUNK_CODE_SLED;
    }
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_ptrace")
int ghost_block_ptrace(struct trace_event_raw_sys_enter *ctx) {
    JUNK_CODE_SLED;

    // Anti-Debugging: Self-Awareness
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned int ptrace_flag = BPF_CORE_READ(task, ptrace);
    
    if (ptrace_flag != 0) {
        return 0; 
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    long request = ctx->args[0];

    u8 *threat_level = bpf_map_lookup_elem(&live_threats, &pid);
    
    if ((threat_level && *threat_level == 1) || (request == 16 || request == 4)) {
        bpf_send_signal(9);

        struct attack_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
        if (e) {
            e->pid = pid;
            e->ts = bpf_ktime_get_ns();
            bpf_ringbuf_submit(e, 0);
        }
    }
    
    JUNK_CODE_SLED;
    return 0;
}
