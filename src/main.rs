use unicorn_engine::RegisterARM64;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

// https://shell-storm.org/online/Online-Assembler-and-Disassembler/
//                    add x0, x1, w0, uxtb #2
const CODE: [u8; 4] = [0x20, 0x08, 0x20, 0x8b];

fn main() {
    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    emu.mem_map(0x1000, 0x4000, Permission::ALL)
        .expect("failed to map code page");
    emu.mem_write(0x1000, &CODE)
        .expect("failed to write instructions");

    emu.reg_write(RegisterARM64::X0, 0x11)
        .expect("failed write X0");
    emu.reg_write(RegisterARM64::X1, 0xfdcc83c8)
        .expect("failed write X1");

    emu.emu_start(
        0x1000,
        (0x1000 + CODE.len()) as u64,
        10 * SECOND_SCALE,
        1000,
    )
    .unwrap();

    let res = emu.reg_read(RegisterARM64::X0).unwrap();

    println!("{res:08x}");
}
