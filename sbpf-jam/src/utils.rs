use {
    alloc::{vec, vec::Vec},
    jam_codec::{Decode, Encode},
    jam_pvm_common::info,
    solana_sbpf::{
        aligned_memory::AlignedMemory,
        ebpf::{self, HOST_ALIGN},
        elf::Executable,
        error::EbpfError,
        memory_region::{MemoryCowCallback, MemoryMapping, MemoryRegion},
        vm::ContextObject,
    },
};

pub fn create_memory_mapping<'a, C: ContextObject>(
    executable: &'a Executable<C>,
    stack: &'a mut AlignedMemory<{ HOST_ALIGN }>,
    heap: &'a mut AlignedMemory<{ HOST_ALIGN }>,
    additional_regions: Vec<MemoryRegion>,
    cow_cb: Option<MemoryCowCallback>,
) -> Result<MemoryMapping<'a>, EbpfError> {
    let config = executable.get_config();
    let sbpf_version = executable.get_sbpf_version();
    let regions: Vec<MemoryRegion> = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
    ]
    .into_iter()
    .chain(additional_regions.into_iter())
    .collect();

    Ok(if let Some(cow_cb) = cow_cb {
        MemoryMapping::new_with_cow(regions, config, sbpf_version, cow_cb)?
    } else {
        MemoryMapping::new(regions, config, sbpf_version)?
    })
}

#[macro_export]
macro_rules! create_vm {
    ($vm_name:ident, $verified_executable:expr, $context_object:expr, $stack:ident, $heap:ident, $additional_regions:expr, $cow_cb:expr) => {
        let stack_len = $stack.len();
        let memory_mapping = $crate::utils::create_memory_mapping(
            $verified_executable,
            &mut $stack,
            &mut $heap,
            $additional_regions,
            $cow_cb,
        )
        .unwrap();
        let mut $vm_name = solana_sbpf::vm::EbpfVm::new(
            $verified_executable.get_loader().clone(),
            $verified_executable.get_sbpf_version(),
            $context_object,
            memory_mapping,
            stack_len,
        );
    };
}

#[derive(Decode, Encode)]
pub struct JamParameters {
    pub elf_ptr: u32, // polkavm aux data addr
    pub elf_len: u32,
    pub params_ptr: u32, // polkavm aux data addr
    pub params_len: u32,
    pub regions_ptr: u32, // polkavm aux data addr
    pub regions_len: u32,
    pub invoke_context_ptr: u64, // host addr
    pub stack_size: u32,
    pub heap_size: u32,
}

pub struct JamContextObject {
    remaining: u64,
    pub invoke_context_ptr: u64,
}

impl JamContextObject {
    pub fn new(remaining: u64, invoke_context_ptr: u64) -> Self {
        Self {
            remaining,
            invoke_context_ptr,
        }
    }
}

impl ContextObject for JamContextObject {
    fn trace(&mut self, _state: [u64; 12]) {}

    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}
