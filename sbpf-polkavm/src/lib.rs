mod cpi;
mod imports;

use {
    anyhow::bail,
    jam_codec::Decode,
    jam_types::{
        AccumulateItem, AuthTrace, AuthorizerHash, Encode, PayloadHash, SegmentTreeRoot, ServiceId,
        Slot, WorkOutput, WorkPackageHash,
    },
    polkavm::{Config, Engine, Instance, Linker, Module, ModuleConfig, ProgramBlob},
    solana_program_runtime::invoke_context::InvokeContext,
    solana_sbpf::{
        error::{EbpfError, ProgramResult, StableResult},
        memory_region::{AccessType, MemoryRegion},
    },
    std::{
        alloc::{Layout, alloc},
        cell::UnsafeCell,
        fs::File,
        io::Read,
        mem,
        ops::{Deref, DerefMut},
        rc::Rc,
        slice::from_raw_parts_mut,
        u64,
    },
};

extern crate alloc;
use {crate::imports::define_all_typed, jam_codec::Output};

pub fn read_memory(
    handler: &InstanceHandler,
    vm_addr: u32,
    size: usize,
    align: usize,
) -> anyhow::Result<*mut u8> {
    let layout = Layout::from_size_align(size, align)?;
    let ptr = unsafe {
        let ptr = alloc(layout);
        if ptr.is_null() {
            bail!("Memory allocation failed");
        }
        let slice = from_raw_parts_mut(ptr, size);
        handler.read_memory_into(vm_addr, slice)?;
        ptr
    };
    Ok(ptr)
}

pub fn read_object<T: Sized>(handler: &InstanceHandler, vm_addr: u32) -> anyhow::Result<T> {
    let ptr = read_memory(handler, vm_addr, mem::size_of::<T>(), mem::align_of::<T>())?;
    unsafe {
        let b = Box::from_raw(ptr as *mut T);
        Ok(*b)
    }
}

pub fn map_and_read_object<T: Sized>(
    handler: &InstanceHandler,
    sbpf_addr: u64,
) -> anyhow::Result<T> {
    let polkavm_addr = handler.map(sbpf_addr, size_of::<T>() as u64).unwrap();
    read_object(handler, polkavm_addr as u32)
}

pub fn read_objects<T: Sized>(
    handler: &InstanceHandler,
    vm_addr: u32,
    len: usize,
) -> anyhow::Result<Vec<T>> {
    if len == 0 {
        return Ok(vec![]);
    }
    let ptr = read_memory(
        handler,
        vm_addr,
        mem::size_of::<T>() * len,
        mem::align_of::<T>(),
    )?;
    unsafe { Ok(Vec::<T>::from_raw_parts(ptr as *mut T, len, len)) }
}

pub fn map_and_read_objects<T: Sized>(
    handler: &InstanceHandler,
    sbpf_addr: u64,
    len: usize,
) -> anyhow::Result<Vec<T>> {
    let polkavm_addr = handler.map(sbpf_addr, size_of::<T>() as u64).unwrap();
    read_objects(handler, polkavm_addr as u32, len)
}

pub fn read_string(handler: &InstanceHandler, vm_addr: u32, len: usize) -> anyhow::Result<String> {
    let ptr = read_memory(handler, vm_addr, len, mem::align_of::<u8>())?;
    unsafe { Ok(String::from_raw_parts(ptr, len, len)) }
}

pub fn map_and_read_string(
    handler: &InstanceHandler,
    sbpf_addr: u64,
    len: usize,
) -> anyhow::Result<String> {
    let polkavm_addr = handler.map(sbpf_addr, len as u64).unwrap();
    read_string(handler, polkavm_addr as u32, len)
}

pub struct SbpfPolkaVm {
    handler: InstanceHandler,
    guest_data_addr: u32,
}

impl SbpfPolkaVm {
    pub fn new() -> Self {
        let mut raw_blob = vec![];
        let mut file = File::open("target/sbpf.polkavm").unwrap();
        file.read_to_end(&mut raw_blob).unwrap();
        // let raw_blob = include_bytes!("../../target/sbpf.polkavm");
        let blob = ProgramBlob::parse(raw_blob[..].into()).unwrap();

        let mut config = Config::from_env().unwrap();
        // config.set_allow_dynamic_paging(true);
        config.set_backend(Some(polkavm::BackendKind::Interpreter));
        let engine = Engine::new(&config).unwrap();
        let mut module_cfg = ModuleConfig::new();
        module_cfg.set_aux_data_size(1 * 1024 * 1024);
        let module = Module::from_blob(&engine, &module_cfg, blob).unwrap();
        let handler = InstanceHandler::new();
        // High-level API.
        let mut linker: Linker = Linker::new();

        // Define a host function.
        define_all_typed(&mut linker, &handler).unwrap();

        // Link the host functions with the module.
        let instance_pre = linker.instantiate_pre(&module).unwrap();

        // Instantiate the module.
        let instance = instance_pre.instantiate().unwrap();
        handler.init(instance);
        let guest_data_addr = handler.module().memory_map().aux_data_address();
        Self {
            handler,
            guest_data_addr,
        }
    }

    pub fn guest_data_addr(&self) -> u64 {
        self.guest_data_addr as u64
    }

    pub fn execute_program<'a, 'b: 'a>(
        &mut self,
        elf: &[u8],
        params: &mut [u8],
        regions: &[MemoryRegion],
        stack_size: usize,
        invoke_context: &'a InvokeContext<'b>,
    ) -> (u64, StableResult<u64, EbpfError>) {
        let jam_params = self.write_parameters(elf, params, regions, stack_size, invoke_context);
        let acc_params = Self::jam_acc_parameters(&jam_params);

        let size = acc_params.encoded_size();
        let mut buf = vec![0u8; size];
        acc_params.encode_to(&mut BufferOutput(&mut buf, 0));
        let addr = self.write(&buf);
        let _result: u64 = self
            .handler
            .call_typed_and_get_result(&mut (), "accumulate_ext", (addr, size as u32))
            .unwrap();
        let new_parameter_bytes = self.handler.context_mut().take_parameter_bytes();
        params.copy_from_slice(&new_parameter_bytes);
        self.handler.context_mut().take_program_result()
    }

    fn write_parameters<'a, 'b: 'a>(
        &mut self,
        elf: &[u8],
        params: &[u8],
        regions: &[MemoryRegion],
        stack_size: usize,
        invoke_context: &'a InvokeContext<'b>,
    ) -> JamParameters {
        let elf_ptr = self.write(elf);
        let elf_len = elf.len() as u32;
        let params_ptr = self.write(params);
        let params_len = params.len() as u32;
        let n_bytes = std::mem::size_of_val(regions);
        let new_regions = Self::convert_regions(params, params_ptr, regions);
        let regions_bytes =
            unsafe { std::slice::from_raw_parts(new_regions.as_ptr() as *const u8, n_bytes) };
        let regions_ptr = self.write(regions_bytes);
        let regions_len = new_regions.len() as u32;
        let invoke_context_ptr = invoke_context as *const InvokeContext as u64;

        JamParameters {
            elf_ptr,
            elf_len,
            params_ptr,
            params_len,
            regions_ptr,
            regions_len,
            invoke_context_ptr,
            stack_size: stack_size as u32,
            heap_size: invoke_context.get_compute_budget().heap_size,
        }
    }

    fn jam_acc_parameters(jam_param: &JamParameters) -> jam_types::AccumulateParams {
        let size = jam_param.encoded_size();
        let mut buf = vec![0u8; size];
        jam_param.encode_to(&mut BufferOutput(&mut buf, 0));
        let slot = Slot::from_le_bytes(0xdeadbeefu32.to_le_bytes());
        let id = ServiceId::from_le_bytes(0xbeefdeadu32.to_le_bytes());

        let items = vec![AccumulateItem {
            package: WorkPackageHash([0; 32]),
            exports_root: SegmentTreeRoot([0; 32]),
            authorizer_hash: AuthorizerHash([0; 32]),
            auth_output: AuthTrace(vec![0]),
            payload: PayloadHash([0; 32]),
            gas_limit: 10000,
            result: Ok(WorkOutput(buf)),
        }];
        jam_types::AccumulateParams {
            slot,
            id,
            results: items,
        }
    }

    fn convert_regions(
        params: &[u8],
        new_params_ptr: u32,
        regions: &[MemoryRegion],
    ) -> Vec<MemoryRegion> {
        let old_base = params.as_ptr() as u64;
        let new_base = new_params_ptr as u64;
        let mut result = vec![];
        for region in regions {
            let new_region = region.clone();
            let new_host_addr = region.host_addr.get() - old_base + new_base;
            new_region.host_addr.set(new_host_addr);
            result.push(new_region);
        }
        result
    }

    fn write(&mut self, data: &[u8]) -> u32 {
        let addr = self.guest_data_addr() as u32;
        self.handler.write_memory(addr, data).unwrap();
        self.guest_data_addr += data.len() as u32;
        addr
    }
}

#[derive(Decode, Encode)]
struct JamParameters {
    elf_ptr: u32, // polkavm aux data addr
    elf_len: u32,
    params_ptr: u32, // polkavm aux data addr
    params_len: u32,
    regions_ptr: u32, // polkavm aux data addr
    regions_len: u32,
    invoke_context_ptr: u64, // host addr
    stack_size: u32,
    heap_size: u32,
}

pub struct BufferOutput<'a>(&'a mut [u8], usize);
impl Output for BufferOutput<'_> {
    /// Write to the output.
    fn write(&mut self, bytes: &[u8]) {
        let (_, rest) = self.0.split_at_mut(self.1);
        let len = bytes.len().min(rest.len());
        rest[..len].copy_from_slice(&bytes[..len]);
        self.1 += len;
    }
}

pub struct Context {
    instance: Option<Instance>,
    sbpf_memory_regions: Option<Vec<MemoryRegion>>,
    program_result: Option<(u64, solana_sbpf::error::ProgramResult)>,
    parameter_bytes: Option<Vec<u8>>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            instance: None,
            sbpf_memory_regions: None,
            program_result: None,
            parameter_bytes: None,
        }
    }
}

impl Context {
    pub fn set_instance(&mut self, instance: Instance) {
        self.instance = Some(instance);
    }

    pub fn instance(&self) -> &Instance {
        self.instance.as_ref().unwrap()
    }

    pub fn set_regions(&mut self, regions: Vec<MemoryRegion>) {
        self.sbpf_memory_regions = Some(regions);
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        self.sbpf_memory_regions.as_ref().unwrap()
    }

    pub fn set_parameter_bytes(&mut self, bytes: Vec<u8>) {
        self.parameter_bytes = Some(bytes);
    }

    pub fn take_parameter_bytes(&mut self) -> Vec<u8> {
        self.parameter_bytes.take().unwrap()
    }

    pub fn set_program_result(&mut self, program_result: (u64, ProgramResult)) {
        self.program_result = Some(program_result);
    }

    pub fn take_program_result(&mut self) -> (u64, ProgramResult) {
        self.program_result.take().unwrap()
    }
}

#[derive(Clone)]
pub struct InstanceHandler(pub Rc<UnsafeCell<Context>>);

impl InstanceHandler {
    pub fn new() -> Self {
        Self(Rc::new(UnsafeCell::new(Context::default())))
    }

    pub fn init(&self, inst: Instance) {
        unsafe { (&mut *self.0.get()).instance.replace(inst) };
    }

    pub fn is_null(&self) -> bool {
        unsafe { (&*self.0.get()).instance.is_none() }
    }

    pub fn context(&self) -> &Context {
        unsafe { &*self.0.get() }
    }

    pub fn context_mut(&mut self) -> &mut Context {
        unsafe { &mut *self.0.get() }
    }

    pub fn map(&self, sbpf_addr: u64, len: u64) -> ProgramResult {
        let regions = self.context().regions();
        let index = sbpf_addr
            .checked_shr(solana_sbpf::ebpf::VIRTUAL_ADDRESS_BITS as u32)
            .unwrap_or(0) as usize;
        if (1..regions.len()).contains(&index) {
            let region = &regions[index as usize];
            if let Some(polkavm_addr) = region.vm_to_host(sbpf_addr, len) {
                return ProgramResult::Ok(polkavm_addr);
            }
        }
        ProgramResult::Err(EbpfError::AccessViolation(
            AccessType::Load,
            sbpf_addr,
            len,
            "map error",
        ))
    }

    pub fn map_and_write_memory(
        &mut self,
        sbpf_addr: u64,
        data: &[u8],
    ) -> Result<(), polkavm::MemoryAccessError> {
        let polkavm_addr = match self.map(sbpf_addr, data.len() as u64) {
            ProgramResult::Ok(v) => v,
            ProgramResult::Err(e) => {
                return Err(polkavm::MemoryAccessError::Error(polkavm::Error::from(
                    e.to_string(),
                )));
            }
        };
        self.write_memory(polkavm_addr as u32, data)
    }
}

impl Deref for InstanceHandler {
    type Target = Instance;

    fn deref(&self) -> &Self::Target {
        unsafe { (&*self.0.get()).instance() }
    }
}

impl DerefMut for InstanceHandler {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { (&mut *self.0.get()).instance.as_mut().unwrap() }
    }
}

unsafe impl Sync for InstanceHandler {}
unsafe impl Send for InstanceHandler {}
