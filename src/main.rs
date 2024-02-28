use core::panic;
use std::{default, error::Error, fs::File, io::{stdout, Write}, os::fd::{AsFd, AsRawFd}};
use nix::{libc::ioctl};
use nix::libc;
use std::os::raw::c_void;

const _IOC_NONE: u32 = 0;
const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;
const _IOC_NRSHIFT: u32 = 0;
const _IOC_NRBITS: u32 = 8;
const _IOC_TYPEBITS: u32 = 8;
const _IOC_SIZEBITS: u32 = 14;
const _IOC_TYPESHIFT: u32 = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: u32 = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: u32 = _IOC_SIZESHIFT + _IOC_SIZEBITS;

// convert kvm api to ioctl argument value macro

macro_rules! _IO {
    ($type:expr, $nr:expr) => {
        _IOC!(_IOC_NONE, $type, $nr, 0)
    };
}
macro_rules! _IOC {
    ($dir:expr, $type:expr, $nr:expr, $size:expr) => {
        (($dir as u32) << _IOC_DIRSHIFT) |
        (($type as u32) << _IOC_TYPESHIFT) |
        (($nr as u32) << _IOC_NRSHIFT) |
        (($size as u32) << _IOC_SIZESHIFT)
    };
}

macro_rules! _IOC_TYPECHECK {
    ($t:ty) => {
        std::mem::size_of::<$t>()
    };
}

macro_rules! _IOR {
    ($type:expr, $nr:expr, $size:ty) => {
        _IOC!(_IOC_READ, $type, $nr, _IOC_TYPECHECK!($size))
    };
}

macro_rules! _IOW {
    ($type:expr, $nr:expr, $size:ty) => {
        _IOC!(_IOC_WRITE, $type, $nr, _IOC_TYPECHECK!($size))
    };
}

#[repr(C)]
struct kvm_userspace_memory_region {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct kvm_exit_io {
    direction: u8,
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
}

#[repr(C)]
union kvm_exit {
    io: kvm_exit_io,
}

#[repr(C)]
struct kvm_run {
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [u8; 6],
    exit_reason: u32,
    padding2: [u8; 4],
    padding3: [u64; 2],
    kvm_exit: kvm_exit,
    kvm_valid_regs: u64,
    kvm_dirty_regs: u64,
}

#[repr(C)]
struct kvm_segment {
    base: u64,
    limit: u32,
    selector: u16,
    type_: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
}

#[repr(C)]
struct kvm_dtable {
    base: u64,
    limit: u16,
    padding: [u16; 3],
}

#[repr(C)]
struct kvm_sregs {
    cs: kvm_segment,
    ds: kvm_segment, 
    es: kvm_segment, 
    fs: kvm_segment, 
    gs: kvm_segment, 
    ss: kvm_segment, 
    tr: kvm_segment,
    ldt: kvm_segment,
    gdt: kvm_dtable,
    idt: kvm_dtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; KVM_NR_INTERRUPTS / 64],
}

impl Default for kvm_sregs {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

const KVMIO: u32 = 0xAE;

#[repr(u32)]
enum KVM_API {
    KVM_CREATE_VM  = _IO!(KVMIO, 0x01),
    KVM_CREATE_VCPU = _IO!(KVMIO, 0x41),
    KVM_GET_VCPU_MMAP_SIZE = _IO!(KVMIO, 0x04),
    KVM_SET_USER_MEMORY_REGION = _IOW!(KVMIO, 0x46, kvm_userspace_memory_region),
    KVM_RUN = _IO!(KVMIO, 0x80),
    KVM_GET_REGS = _IOR!(KVMIO,  0x81, kvm_regs),
    KVM_SET_REGS = _IOW!(KVMIO,  0x82, kvm_regs),
    KVM_GET_SREGS = _IOR!(KVMIO, 0x83, kvm_sregs),
    KVM_SET_SREGS = _IOW!(KVMIO, 0x84, kvm_sregs),
}

const KVM_EXIT_IO_IN: u8 = 0;
const KVM_EXIT_IO_OUT: u8 = 1;

#[repr(C)]
struct kvm_regs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

const KVM_NR_INTERRUPTS:usize = 256;

fn main() {
    let kvmfd = init_kvm().expect("Failed to open /dev/kvm");

    println!("KVMfd is {:?}", kvmfd.as_raw_fd());

    let vmfd = create_vm(&kvmfd).expect("Failed to create VM");
    let binary = File::open("binary/a.out").expect("Failed to open binary");
    let rom = load_binary(&binary).expect("Failed to load binary");

    //print loaded binary
    println!("==== Loaded VM binary data =====");
    unsafe {
        let p = rom as *const u8;
        for i in 0..binary.metadata().unwrap().len() as usize {
            print!("{:02x} ", *p.offset(i as isize));
            if i % 16 == 15 {
                println!();
            }
        }
    }
    println!("==== loaded VM binary data =====");

    println!("VM binary addresss is 0x{:x}", rom as u64);

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        flags: 0,
        guest_phys_addr: 0x0,
        memory_size: 0x1000,
        userspace_addr: rom as u64,
    };

    unsafe {
        let err = ioctl(vmfd, KVM_API::KVM_SET_USER_MEMORY_REGION as u64, &mem_region);
        if err < 0 {
            panic!("Failed to set user memory region");
        }
    }

    let vcpufd = create_vcpu(vmfd).expect("Failed to create VCPU");
    let mmap_size = get_vcpu_mmap_size(&kvmfd).expect("Failed to get VCPU mmap size");

    println!("mmap_size is {}", mmap_size);
    let vcpu_run = unsafe {(
        libc::mmap(
            std::ptr::null_mut(),
            mmap_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            vcpufd,
            0,
        ) as *mut kvm_run).as_ref()}.unwrap();

    let mut sregs: kvm_sregs = Default::default();

    // let sregs_ptr = &mut sregs as *mut kvm_sregs;

    unsafe {
        println!("vcpufd is {:?}", vcpufd);
        let res = ioctl(vcpufd, KVM_API::KVM_GET_SREGS as u64, &sregs);
        if res < 0 {
            panic!("Failed to get sregs");
        }
    }

    sregs.cs.base = 0;
    sregs.cs.selector = 0;

    unsafe {
        let res = ioctl(vcpufd, KVM_API::KVM_SET_SREGS as u64, &sregs);
        if res < 0 {
            panic!("Failed to set sregs");
        }
    }

    let regs = kvm_regs {
        rax: 0x0,
        rbx: 0x0,
        rcx: 0x0,
        rdx: 0x0,
        rsi: 0x0,
        rdi: 0x0,
        rsp: 0x0,
        rbp: 0x0,
        r8: 0x0,
        r9: 0x0,
        r10: 0x0,
        r11: 0x0,
        r12: 0x0,
        r13: 0x0,
        r14: 0x0,
        r15: 0x0,
        rip: 0x0,
        rflags: 0x2,
    };

    unsafe {
        let res = ioctl(vcpufd, KVM_API::KVM_SET_REGS as u64, &regs);
        if res < 0 {
            panic!("Failed to set regs");
        }
    }


    println!("↓↓↓ Start VM ↓↓↓");
    loop {
        unsafe {
            ioctl(vcpufd, KVM_API::KVM_RUN as u64, 0);
        }
        // println!("VCPU exited");
        // println!("Exit reason: {}", vcpu_run.exit_reason);

        match vcpu_run.exit_reason {
            0 => {
                // println!("KVM_EXIT_UNKNOWN");
                // break;
            }
            1 => {
                // println!("KVM_EXIT_EXCEPTION");
                // break;
            }
            2 => {
                // println!("KVM_EXIT_IO");
                unsafe {
                    if (vcpu_run.kvm_exit.io.port == 0x01 && vcpu_run.kvm_exit.io.direction == KVM_EXIT_IO_OUT) {
                        let offset = vcpu_run.kvm_exit.io.data_offset;
                        let base_addr = vcpu_run as *const kvm_run as *const u8;
                        let data_addr = base_addr.offset(offset as isize);
                        let char = (data_addr as *const char).as_ref().unwrap();
                        print!("{}", char);
                        stdout().flush().unwrap();
                    } else {
                        // println!("KVM_EXIT_IO_IN");
                    }
                }
            }
            3 => {
                // println!("KVM_EXIT_HYPERCALL");
                break;
            }
            4 => {
                // println!("KVM_EXIT_DEBUG");
                // break;
            }
            5 => {
                // println!("KVM_EXIT_HLT");
                // break;
            }
            6 => {
                // println!("KVM_EXIT_MMIO");
                // break;
            }
            7 => {
                // println!("KVM_EXIT_IRQ_WINDOW_OPEN");
                // break;
            }
            8 => {
                // println!("KVM_EXIT_SHUTDOWN");
                // break;
            }
            9 => {
                // println!("KVM_EXIT_FAIL_ENTRY");
                // break;
            }
            10 => {
                // println!("KVM_EXIT_INTR");
                // break;
            }
            11 => {
                // println!("KVM_EXIT_SET_TPR");
                // break;
            }
            12 => {
                // println!("KVM_EXIT_TPR_ACCESS");
                // break;
            }
            13 => {
                // println!("KVM_EXIT_S390_SIEIC");
                // break;
            }
            14 => {
                // println!("KVM_EXIT_S390_RESET");
                // break;
            }
            15 => {
                // println!("KVM_EXIT_DCR");
                // break;
            }
            16 => {
                // // println!("KVM_EXIT_NMI");
            }
            17 => {
                // // println!("KVM_EXIT_INTERNAL_ERROR");
                // break;
            }
            18 => {
                // println!("KVM_EXIT_OSI");
                // break;
            }
            19 => {
                // println!("KVM_EXIT_PAPR_HCALL");
                // break;
            }
            21 => {
                // println!("KVM_EXIT_WATCHDOG");
                // break;
            }
            23 => {
                // // println!("KVM_EXIT_EPR");
                // break;
            }
            24 => {
                // // println!("KVM_EXIT_SYSTEM_EVENT");
                // break;
            }
            default => {
                println!("Unknown exit reason");
                panic!();
            }
        }
    }

}

fn get_vcpu_mmap_size(kvmfd: &File) -> Result<i32, i32> {
    unsafe {
        let mmap_size = ioctl(kvmfd.as_raw_fd(), KVM_API::KVM_GET_VCPU_MMAP_SIZE as u64, 0);
        if mmap_size < 0 {
            return Err(mmap_size);
        } 
        return Ok(mmap_size);
    }
}

// create kvm vcpu
fn create_vcpu(vmfd: i32) -> Result<i32, i32> {
    unsafe {
        let vcpufd = ioctl(vmfd, KVM_API::KVM_CREATE_VCPU as u64, 0);
        if vcpufd < 0 {
            return Err(vcpufd);
        }
        return Ok(vcpufd);
    }
}

fn init_kvm() -> Result<File, std::io::Error> {
    let fd = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm")?;
    return Ok(fd);
}

fn create_vm(kvmfd: &File) -> Result<i32, i32> {
    unsafe {
        let vmfd = ioctl(kvmfd.as_raw_fd(), KVM_API::KVM_CREATE_VM as u64, 0);
        if vmfd < 0 {
            return Err(vmfd);
        }
        return Ok(vmfd);
    }
}

// Copy binary to memory mapped region
fn load_binary(binary: &File) -> Result<*mut c_void, Box<dyn Error>> {
    let mmap = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };

    if mmap == libc::MAP_FAILED {
        return Err("Failed to mmap binary".into());
    }

    // Copy binary to memory mapped region
    let binary_data = std::fs::read("binary/a.out")?;
    println!("Binary size is {}", binary.metadata()?.len() as usize);
    unsafe {
        libc::memcpy(
            mmap as *mut libc::c_void,
            binary_data.as_ptr() as *const libc::c_void,
            binary.metadata()?.len() as usize,
        );
    }

    // Unmap memory
    // unsafe {
    //     libc::munmap(mmap, binary.metadata()?.len() as usize);
    // }

    Ok(mmap)
}
