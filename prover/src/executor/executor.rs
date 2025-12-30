use common::file;
use elf::{endian::AnyEndian, ElfBytes};
use num::ToPrimitive;
use zkm_emulator::state::{InstrumentedState, State};
use zkm_emulator::utils::get_block_path;

#[derive(Default)]
pub struct Executor {}

use crate::executor::SplitContext;

impl Executor {
    pub fn split(&self, ctx: &SplitContext) -> Result<(u64, u32), String> {
        // 1. split ELF into segs
        let elf_path = ctx.elf_path.as_str();
        let block_no = ctx.block_no.unwrap_or(0);
        let seg_path = ctx.seg_path.as_str();
        let seg_size = ctx.seg_size.to_usize().expect("u32->usize failed");
        let mut args: Vec<&str> = ctx.args.split_whitespace().collect();
        if args.len() > 2 {
            args.truncate(2);
        }

        log::info!("split {} load elf file", elf_path);
        let data = file::new(elf_path).read();
        let mut block_path = get_block_path(&ctx.base_dir, &block_no.to_string(), "");
        let input_path = if block_path.ends_with('/') {
            format!("{}input", block_path)
        } else {
            format!("{}/input", block_path)
        };

        if let Result::Ok(data) = data {
            let file_result = ElfBytes::<AnyEndian>::minimal_parse(data.as_slice());
            match file_result {
                Result::Ok(file) => {
                    let mut state = State::load_elf(&file);
                    state.patch_elf(&file);
                    // state.patch_stack(args);
                    state.patch_stack(vec![]);
                    // public_input_stream
                    if !ctx.public_input_path.is_empty() {
                        let data = file::new(&ctx.public_input_path)
                            .read()
                            .expect("read public_input_stream failed");
                        let len = data.len();
                        state.input_stream.push(data);
                        log::info!("split set public_input data {}", len);
                    }

                    // private_input_stream
                    // FIXME: only one private input is allowed. need to support many.
                    if !ctx.private_input_path.is_empty() {
                        let data = file::new(&ctx.private_input_path)
                            .read()
                            .expect("read private_input_stream failed");
                        let len = data.len();
                        state.input_stream.push(data);
                        log::info!("split set private_input data {}", len);
                    }

                    if !ctx.receipt_inputs_path.is_empty() {
                        let data = file::new(&ctx.receipt_inputs_path)
                            .read()
                            .expect("read receipt_inputs_stream failed");
                        let receipt_inputs = bincode::deserialize::<Vec<Vec<u8>>>(&data)
                            .expect("deserialize receipt_inputs_stream failed");
                        for receipt_input in receipt_inputs {
                            state.input_stream.push(receipt_input);
                            log::info!("split set receipt_inputs data {}", data.len());
                        }
                    }

                    if block_no > 0 {
                        log::info!("split set input data {}", input_path);
                        let input_data = file::new(&input_path).read().unwrap();
                        state
                            .memory
                            .set_memory_range(0x30000000, Box::new(input_data.as_slice()))
                            .expect("set memory range failed");
                    } else {
                        block_path = "".to_string();
                    }

                    let mut instrumented_state = InstrumentedState::new(state, block_path);
                    file::new(seg_path).create_dir_all().unwrap();
                    let new_write = |_: &str| -> Option<std::fs::File> { None };
                    instrumented_state.split_segment(false, seg_path, new_write);

                    let new_write =
                        |name: &str| -> Option<Box<dyn std::io::Write>> { Some(file::new(name)) };
                    let mut loop_index = 0;
                    loop {
                        if instrumented_state.state.exited {
                            break;
                        }
                        let cycles = instrumented_state.step();
                        let split_seg_size = if loop_index < 8 {
                            seg_size as u64 >> 2
                        } else {
                            seg_size as u64
                        };
                        if cycles >= split_seg_size {
                            instrumented_state.split_segment(true, seg_path, new_write);
                            loop_index += 1;
                        }
                    }
                    instrumented_state.split_segment(true, seg_path, new_write);
                    log::info!(
                        "Split done {} : {}",
                        instrumented_state.state.total_step,
                        instrumented_state.state.total_cycle
                    );
                    instrumented_state.dump_memory();
                    // write public_values_stream
                    let _ = file::new(&ctx.output_path)
                        .write(&instrumented_state.state.public_values_stream)
                        .unwrap();
                    return Ok((
                        instrumented_state.state.total_step,
                        instrumented_state.pre_segment_id,
                    ));
                }
                Err(e) => {
                    log::error!("split minimal_parse error {:?}", e.to_string());
                    return Err(e.to_string());
                }
            }
        }
        Ok((0, 0))
    }
}
