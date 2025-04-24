use unicorn_engine::RegisterARM64;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

// https://shell-storm.org/online/Online-Assembler-and-Disassembler/
const CODE: [u8; 8] = [
    0x64, 0x1f, 0x00, 0x51, // sub w4, w27, #0x7
    0x9f, 0x04, 0x00, 0x71, // cmp w4, #0x1
];
const CODE_SIZE: u64 = CODE.len() as u64;

const MEM_BASE: u64 = 0x1000;
const MEM_SIZE: usize = 0x4000;

const TIMEOUT: u64 = 10 * SECOND_SCALE;
const MAX_INSTRUCTIONS: usize = 1000;

fn main() {
    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    emu.mem_map(MEM_BASE, MEM_SIZE, Permission::ALL)
        .expect("failed to map code page");
    emu.mem_write(MEM_BASE, &CODE)
        .expect("failed to write instructions");

    emu.reg_write(RegisterARM64::W27, 0x3)
        .expect("failed write W27");

    emu.emu_start(MEM_BASE, MEM_BASE + CODE_SIZE, TIMEOUT, MAX_INSTRUCTIONS)
        .unwrap();

    // flags are stored in the highest 4 bits
    // https://developer.arm.com/documentation/ddi0601/2025-03/AArch64-Registers/NZCV--Condition-Flags
    let r = emu.reg_read(RegisterARM64::NZCV).unwrap() >> 28;

    // The result determines conditional branch behavior.
    // E.g., C = 1 and Z = 0 will branch on B.HI (unsigned greater than).
    // https://devblogs.microsoft.com/oldnewthing/20220815-00/?p=106975
    println!("NZCV: {r:04b}"); // 1010

    let r = emu.reg_read(RegisterARM64::W4).unwrap();
    println!("W4:   {r:08x}");

    let r = emu.reg_read(RegisterARM64::W27).unwrap();
    println!("W27:  {r:08x}");
}
