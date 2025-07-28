#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]
#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_main)]
#![allow(clippy::unwrap_used)]

extern crate alloc;

mod builtins;
mod imports;
mod utils;

use {
    crate::{
        builtins::register_builtins,
        utils::{JamContextObject, JamParameters},
    },
    alloc::{sync::Arc, vec::Vec},
    jam_pvm_common::{info, Service},
    jam_types::*,
    solana_sbpf::{
        aligned_memory::AlignedMemory, elf::Executable, memory_region::MemoryRegion,
        program::BuiltinProgram, vm::Config,
    },
};

struct MyService;
jam_pvm_common::declare_service!(MyService);

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
fn main() {}

impl Service for MyService {
    fn refine(
        _id: ServiceId,
        payload: WorkPayload,
        _package_hash: WorkPackageHash,
        _context: RefineContext,
        _auth_code_hash: CodeHash,
    ) -> WorkOutput {
        info!(target = "counter_service", "refine is called!");
        [&b"Hello "[..], payload.take().as_slice()].concat().into()
    }
    fn accumulate(slot: Slot, id: ServiceId, items: Vec<AccumulateItem>) -> Option<Hash> {
        info!(
            "accumulate is called. slot: {slot:x}, service id: {id:x}, items' size: {}",
            items.len()
        );
        for param_bytes in items.into_iter().filter_map(|x| x.result.ok()) {
            let jam_params = JamParameters::decode(&mut param_bytes.0.as_slice());
            let jam_params = match jam_params {
                Ok(v) => v,
                Err(err) => {
                    info!(target = "sbpf-jam", "decode param_bytes fail: {}", err);
                    return None;
                }
            };

            let (elf, new_parameter_bytes, regions) = read_params(&jam_params);
            let mut loader = BuiltinProgram::new_loader(Config::default());
            loader.register_function("log", builtins::Log::vm).unwrap();
            register_builtins(&mut loader);
            let loader = Arc::new(loader);
            let executable = Executable::<JamContextObject>::load_with_backup(elf, loader, false);
            if executable.is_err() {
                let err = executable.err().unwrap();
                info!(target = "sbpf-jam", "loading elf error: {}", err);
                return None;
            }
            let executable = executable.unwrap();
            let mut ctx_obj = JamContextObject::new(100000, jam_params.invoke_context_ptr);
            let mut stack = AlignedMemory::zero_filled(jam_params.stack_size as usize);
            let mut heap = AlignedMemory::zero_filled(jam_params.heap_size as usize);
            create_vm!(vm, &executable, &mut ctx_obj, stack, heap, regions, None);
            let regions = vm.memory_mapping.get_regions();
            unsafe {
                imports::export_memory_regions(regions.as_ptr() as u64, regions.len() as u64);
            }
            let (instr_cnt, result) = vm.execute_program(&executable, true);
            unsafe {
                imports::export_parameter_bytes(
                    new_parameter_bytes.as_slice().as_ptr() as u64,
                    new_parameter_bytes.as_slice().len() as u64,
                );
                imports::export_program_result((&result) as *const _ as u64, instr_cnt);
            }
            if result.is_err() {
                info!(
                    target = "sbpf-jam",
                    "program execute fail: {}",
                    result.unwrap_err()
                );
            } else {
                info!(
                    target = "sbpf-jam",
                    "program execution result: instruction_count: {instr_cnt}, program_result: {}",
                    result.unwrap()
                );
            }
            return Some([23; 32]);
        }
        None
    }
    fn on_transfer(_slot: Slot, _id: ServiceId, _items: Vec<TransferRecord>) {
        info!(target = "counter_service", "on_transfer is called!");
    }
}

fn read_slice<'a, T>(ptr: u32, len: u32) -> &'a [T] {
    unsafe { core::slice::from_raw_parts(ptr as *const T, len as usize) }
}

/// The parameter_bytes need to be writable, but host cannot write the bytes to
/// rw_data region due to the bytes' huge size.
fn read_params(
    jam_params: &JamParameters,
) -> (&'static [u8], AlignedMemory<16>, Vec<MemoryRegion>) {
    let elf = read_slice::<'_, u8>(jam_params.elf_ptr, jam_params.elf_len);
    let params = read_slice::<'_, u8>(jam_params.params_ptr, jam_params.params_len);
    let regions = read_slice::<'_, MemoryRegion>(jam_params.regions_ptr, jam_params.regions_len);

    let new_params = AlignedMemory::<16>::from_slice(params);
    let new_regions = regions.to_vec();
    let old_base = jam_params.params_ptr as u64;
    let new_base = new_params.as_slice().as_ptr() as u64;
    for region in new_regions.iter() {
        let new_addr = region.host_addr.get() - old_base + new_base;
        region.host_addr.set(new_addr);
    }
    (elf, new_params, new_regions)
}
