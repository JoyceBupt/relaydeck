//! Kernel cgroup bind guards, independent of systemd's optional BPF framework.
#[cfg(target_os = "linux")]
mod linux {
    use crate::executor::RuntimePlan;
    use anyhow::{Context, ensure};
    use std::{
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::OpenOptionsExt,
        },
        path::Path,
    };

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Insn {
        code: u8,
        registers: u8,
        offset: i16,
        immediate: i32,
    }
    #[repr(C)]
    struct Load {
        kind: u32,
        count: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log: u64,
        kernel: u32,
        flags: u32,
        name: [u8; 16],
        ifindex: u32,
        attach: u32,
    }
    #[repr(C)]
    struct Attach {
        target: u32,
        program: u32,
        kind: u32,
        flags: u32,
        replace: u32,
    }
    #[repr(C)]
    struct Info {
        fd: u32,
        length: u32,
        value: u64,
    }
    #[repr(C)]
    struct Query {
        target: u32,
        kind: u32,
        flags: u32,
        attach_flags: u32,
        ids: u64,
        count: u32,
        padding: u32,
    }
    pub struct BindGuard {
        programs: [OwnedFd; 2],
        ids: [u32; 2],
    }

    fn syscall<T>(command: u32, attrs: &mut T) -> std::io::Result<i32> {
        // repr(C) attributes use the stable Linux bpf syscall ABI. All pointed-to
        // instruction/log/query buffers stay alive for this synchronous call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                command,
                attrs as *mut T,
                std::mem::size_of::<T>(),
            )
        };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as i32)
        }
    }

    fn instructions(plan: &RuntimePlan) -> Vec<Insn> {
        let mut code = vec![
            Insn {
                code: 0x61,
                registers: 0x12,
                offset: 24,
                immediate: 0,
            }, // ctx.user_port (network order)
            Insn {
                code: 0x15,
                registers: 2,
                offset: 0,
                immediate: 0,
            }, // automatic upstream bind
            Insn {
                code: 0x61,
                registers: 0x13,
                offset: 36,
                immediate: 0,
            }, // ctx.protocol
        ];
        let mut allowed = vec![1];
        for rule in plan.rules() {
            for (protocol, enabled) in [
                (libc::IPPROTO_TCP, rule.protocol.tcp()),
                (libc::IPPROTO_UDP, rule.protocol.udp()),
            ] {
                if !enabled {
                    continue;
                }
                code.push(Insn {
                    code: 0x55,
                    registers: 3,
                    offset: 1,
                    immediate: protocol,
                });
                allowed.push(code.len());
                code.push(Insn {
                    code: 0x15,
                    registers: 2,
                    offset: 0,
                    immediate: i32::from(rule.listen_port.to_be()),
                });
            }
        }
        code.extend([
            Insn {
                code: 0xb7,
                registers: 0,
                offset: 0,
                immediate: 0,
            },
            Insn {
                code: 0x95,
                registers: 0,
                offset: 0,
                immediate: 0,
            },
        ]);
        let accept = code.len();
        code.extend([
            Insn {
                code: 0xb7,
                registers: 0,
                offset: 0,
                immediate: 1,
            },
            Insn {
                code: 0x95,
                registers: 0,
                offset: 0,
                immediate: 0,
            },
        ]);
        for jump in allowed {
            code[jump].offset = (accept - jump - 1) as i16;
        }
        code
    }

    fn program(plan: &RuntimePlan, attach: u32) -> anyhow::Result<(OwnedFd, u32)> {
        let code = instructions(plan);
        ensure!(code.len() < 256, "bind program exceeds instruction budget");
        let mut log = vec![0_u8; 16384];
        let mut attrs = Load {
            kind: 18,
            count: code.len() as u32,
            insns: code.as_ptr() as u64,
            license: c"GPL".as_ptr() as u64,
            log_level: 1,
            log_size: log.len() as u32,
            log: log.as_mut_ptr() as u64,
            kernel: 0,
            flags: 0,
            name: [0; 16],
            ifindex: 0,
            attach,
        };
        let fd = syscall(5, &mut attrs).map_err(|error| {
            anyhow::anyhow!(
                "load bind guard: {error}; {}",
                String::from_utf8_lossy(&log)
                    .trim_matches('\0')
                    .chars()
                    .take(600)
                    .collect::<String>()
            )
        })?;
        // A successful BPF_PROG_LOAD returns a new, uniquely owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut details = [0_u32; 2];
        syscall(
            15,
            &mut Info {
                fd: fd.as_raw_fd() as u32,
                length: 8,
                value: details.as_mut_ptr() as u64,
            },
        )
        .context("inspect bind program identity")?;
        ensure!(
            details[0] == 18 && details[1] > 0,
            "unexpected bind program identity"
        );
        Ok((fd, details[1]))
    }

    fn cgroup(path: &Path) -> anyhow::Result<File> {
        crate::linux::secure_root_path(path, true)?;
        Ok(std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?)
    }

    impl BindGuard {
        pub fn attach(plan: &RuntimePlan, path: &Path) -> anyhow::Result<Self> {
            let group = cgroup(path)?;
            let (four, id4) = program(plan, 8)?;
            let (six, id6) = program(plan, 9)?;
            for (program, kind) in [(&four, 8), (&six, 9)] {
                syscall(
                    8,
                    &mut Attach {
                        target: group.as_raw_fd() as u32,
                        program: program.as_raw_fd() as u32,
                        kind,
                        flags: 2,
                        replace: 0,
                    },
                )
                .context("attach cgroup bind guard")?;
            }
            let guard = Self {
                programs: [four, six],
                ids: [id4, id6],
            };
            guard.verify(path)?;
            Ok(guard)
        }

        pub fn verify(&self, path: &Path) -> anyhow::Result<()> {
            let group = cgroup(path)?;
            for (index, kind) in [8, 9].into_iter().enumerate() {
                let mut ids = [0_u32; 64];
                let mut attrs = Query {
                    target: group.as_raw_fd() as u32,
                    kind,
                    flags: 0,
                    attach_flags: 0,
                    ids: ids.as_mut_ptr() as u64,
                    count: 64,
                    padding: 0,
                };
                syscall(16, &mut attrs).context("query cgroup bind guard")?;
                ensure!(
                    attrs.count <= 64 && ids[..attrs.count as usize].contains(&self.ids[index]),
                    "bind guard was detached or replaced"
                );
                ensure!(
                    self.programs[index].as_raw_fd() >= 0,
                    "bind guard descriptor lost"
                );
            }
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::BindGuard;
