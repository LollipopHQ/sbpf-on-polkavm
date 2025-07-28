use {
    crate::{
        InstanceHandler, cpi::SolInvokeSignedRust, map_and_read_objects, read_object, read_objects,
        read_string,
    },
    anyhow::bail,
    polkavm::{Error, Linker},
    solana_cpi::MAX_RETURN_DATA,
    solana_hash::Hash,
    solana_program_runtime::{
        execution_budget::{SVMTransactionExecutionBudget, SVMTransactionExecutionCost},
        invoke_context::InvokeContext,
        stable_log,
    },
    solana_pubkey::{MAX_SEED_LEN, Pubkey},
    solana_rent::Rent,
    solana_sbpf::{error::ProgramResult, memory_region::MemoryRegion},
    solana_sha256_hasher::Hasher,
    solana_sysvar_id::SysvarId,
    std::{marker::PhantomData, mem, u64},
};

#[macro_export]
macro_rules! declare_polkavm_builtin {
    ($(#[$attr:meta])* $name:ident $(<$($generic_ident:tt : $generic_type:tt),+>)?, fn rust(
        $vm:ident : InstanceHandler,
        $($arg_name: ident : $arg_ty:ty),*$(,)?
    ) -> $Result:ty { $($rust:tt)* }) => {
        $(#[$attr])*
        pub struct $name {}
        impl $name {
            /// Rust interface
            pub fn rust $(<$($generic_ident : $generic_type),+>)? (
                $vm: InstanceHandler,
                $($arg_name: $arg_ty),*
            ) -> $Result {
                $($rust)*
            }

            pub fn register<'a, 'b, $($generic_ident : $generic_type),*> (
                linker: &'a mut polkavm::Linker,
                handler: &'b $crate::InstanceHandler,
                name: &'static str,
            ) -> Result<&'a mut Linker, polkavm::Error> {
                linker.define_typed::<($($arg_ty),*), $Result>(name,
                    {
                        let h = handler.clone();
                        move |$($arg_name: $arg_ty),*| -> $Result {
                            let h1 = h.clone();
                            $name::rust$(::<$($generic_ident),+>)?(h1, $($arg_name),*);
                        }
                    }
                )
            }
        }
    }
}

#[macro_export]
macro_rules! declare_sbpf_builtin {
    ($(#[$attr:meta])* $name:ident $(<$($generic_ident:tt : $generic_type:tt),+>)?, fn rust(
        $vm:ident : InstanceHandler,
        $invoke_context:ident : &mut InvokeContext,
        $($arg_name: ident : $arg_ty:ty),*$(,)?
    ) -> $Result:ty { $($rust:tt)* }) => {
        $(#[$attr])*
        pub struct $name {}
        impl $name {
            /// Rust interface
            pub fn rust $(<$($generic_ident : $generic_type),+>)? (
                $vm: InstanceHandler,
                $invoke_context: &mut InvokeContext,
                $($arg_name: $arg_ty),*
            ) -> $Result {
                $($rust)*
            }

            pub fn register<'a, 'b, $($($generic_ident : $generic_type),+)?> (
                linker: &'a mut polkavm::Linker,
                handler: &'b $crate::InstanceHandler,
                name: &'static str,
            ) -> Result<&'a mut Linker, polkavm::Error> {
                linker.define_typed::<(u64, $($arg_ty),*), $Result>(name,
                {
                    let h = handler.clone();
                    move |invoke_context_ptr: u64, $($arg_name: $arg_ty),*| -> $Result {
                        let invoke_context = unsafe {
                            &mut *(invoke_context_ptr as *mut InvokeContext)
                        };
                        let h1 = h.clone();
                        $name::rust$(::<$($generic_ident),+>)?(h1, invoke_context, $($arg_name),*)
                    }
                }
                )
            }
        }
    }
}

pub fn define_all_typed<'a, 'b>(
    linker: &'a mut Linker,
    handler: &'b InstanceHandler,
) -> Result<&'a mut Linker, Error> {
    Log::register(linker, handler, "log")?;
    ExportMemoryRegions::register(linker, handler, "export_memory_regions")?;
    ExportProgramResult::register(linker, handler, "export_program_result")?;
    ExportParameterBytes::register(linker, handler, "export_parameter_bytes")?;
    SolAbort::register(linker, handler, "abort")?;
    SolLog::register(linker, handler, "sol_log_")?;
    SolLogPubkey::register(linker, handler, "sol_log_pubkey")?;
    SolTryFindProgramAddress::register(linker, handler, "sol_try_find_program_address")?;
    SolSetReturnData::register(linker, handler, "sol_set_return_data")?;
    SolInvokeSignedRust::register(linker, handler, "sol_invoke_signed_rust")?;
    SolMemcpy::register(linker, handler, "sol_memcpy_")?;
    SolMemset::register(linker, handler, "sol_memset_")?;
    SolHash::register::<Sha256Hasher>(linker, handler, "sol_sha256")?;
    SolGetRentSysvar::register(linker, handler, "sol_get_rent_sysvar")
}

declare_polkavm_builtin!(
    Log,
    fn rust(
        handler: InstanceHandler,
        level: u64,
        target_ptr: u64,
        target_len: u64,
        text_ptr: u64,
        text_len: u64,
    ) -> () {
        if handler.is_null() {
            panic!("handler is null");
        }
        let target = if target_ptr != 0 {
            read_string(&handler, target_ptr as u32, target_len as usize).unwrap()
        } else {
            "".to_string()
        };
        let text = if text_ptr != 0 {
            read_string(&handler, text_ptr as u32, text_len as usize).unwrap()
        } else {
            "".to_string()
        };
        println!("[level={level}][{target}]{text}");
    }
);

declare_polkavm_builtin! {
    ExportMemoryRegions,
    fn rust(handler: InstanceHandler, regions_ptr: u64, len: u64) -> () {
        let regions: Vec<MemoryRegion> = read_objects(&handler, regions_ptr as u32, len as usize).unwrap();
        let mut handler = handler;
        handler.context_mut().set_regions(regions);
    }
}

declare_polkavm_builtin! {
    ExportProgramResult,
    fn rust(handler: InstanceHandler, result_ptr: u64, instr_cnt: u64) -> () {
        let result: ProgramResult = read_object(&handler, result_ptr as u32).unwrap();
        let mut handler = handler;
        handler.context_mut().set_program_result((instr_cnt, result));
    }
}

declare_polkavm_builtin! {
    ExportParameterBytes,
    fn rust(handler: InstanceHandler, bytes_ptr: u64, len: u64) -> () {
        let bytes = read_objects::<u8>(&handler, bytes_ptr as u32, len as usize).unwrap();
        let mut handler = handler;
        handler.context_mut().set_parameter_bytes(bytes);
    }
}

declare_sbpf_builtin! {
    SolAbort,
    fn rust(
        _handler: InstanceHandler,
        _invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> () {

    }
}

declare_sbpf_builtin! {
    SolLog,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        sbpf_addr: u64,
        len: u64,
    ) -> () {
        let cost = invoke_context
            .get_execution_cost()
            .syscall_base_cost
            .max(len);
        invoke_context.consume_checked(cost).unwrap();

        let polkavm_addr = handler.map(sbpf_addr, len).unwrap();
        let s = read_string(&handler, polkavm_addr as u32, len as usize).unwrap();
        println!("sol_log_: {s}");
        stable_log::program_log(&invoke_context.get_log_collector(), &s);
    }
}

declare_sbpf_builtin! {
    SolLogPubkey,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        pubkey_ptr: u64
    ) -> () {
        let cost = invoke_context.get_execution_cost().log_pubkey_units;
        invoke_context.consume_checked(cost).unwrap();
        let polkavm_addr = handler.map(pubkey_ptr, mem::size_of::<solana_pubkey::Pubkey>() as u64).unwrap();
        let pubkey = read_object::<solana_pubkey::Pubkey>(&handler, polkavm_addr as u32).unwrap();
        stable_log::program_log(&invoke_context.get_log_collector(), &pubkey.to_string());
    }
}

declare_sbpf_builtin! {
    SolGetRentSysvar,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        var_addr: u64,
    ) -> () {
        let cost = invoke_context
            .get_execution_cost()
            .syscall_base_cost
            .saturating_add(size_of::<Rent>() as u64);
        invoke_context.consume_checked(cost).unwrap();
        let polkavm_var_addr = handler.map(var_addr, size_of::<Rent>() as u64).unwrap();
        let buffer = invoke_context
            .get_sysvar_cache()
            .sysvar_id_to_buffer(&Rent::id())
            .as_ref()
            .unwrap();
        let mut handler = handler;
        handler.write_memory(polkavm_var_addr as u32, &buffer).unwrap();
    }
}

declare_sbpf_builtin! {
    SolTryFindProgramAddress,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        bump_seed_addr: u64,
    ) -> () {
        let cost = invoke_context
            .get_execution_cost()
            .create_program_address_units;
        invoke_context.consume_checked(cost).unwrap();
        let (seeds, program_id) = translate_and_check_program_address_inputs(
            seeds_addr,
            seeds_len,
            program_id_addr,
            &handler).unwrap();
        let seed_slices = seeds
            .iter()
            .map(|v| v.as_slice())
            .collect::<Vec<_>>();
        let polka_address_addr = handler.map(address_addr, size_of::<Pubkey>() as u64).unwrap();
        let polka_bump_seed_addr = handler.map(bump_seed_addr, 1).unwrap();
        let mut handler = handler;
        let mut bump_seed = u8::MAX;
        for _ in 0..u8::MAX {
            {
                let bump_seed = [bump_seed];
                let mut seed_slices = seed_slices.clone();
                seed_slices.push(&bump_seed);
                if let Ok(new_address) =
                    Pubkey::create_program_address(&seed_slices, &program_id)
                {
                    handler.write_memory(polka_address_addr as u32, &new_address.as_ref()).unwrap();
                    handler.write_memory(polka_bump_seed_addr as u32, &bump_seed).unwrap();
                    return;
                }
            }
            bump_seed = bump_seed.saturating_sub(1);
            invoke_context.consume_checked(cost).unwrap();
        }
    }
}

declare_sbpf_builtin! {
    SolSetReturnData,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        addr: u64,
        len: u64,
    ) -> () {
        let exe_cost = invoke_context.get_execution_cost();

        let cost = len
            .checked_div(exe_cost.cpi_bytes_per_unit)
            .unwrap_or(u64::MAX)
            .saturating_add(exe_cost.syscall_base_cost);
        invoke_context.consume_checked(cost).unwrap();
        if len > MAX_RETURN_DATA as u64 {
            panic!("SyscallError::ReturnDataTooLarge({len}, {MAX_RETURN_DATA})");
        }
        let polka_addr = handler.map(addr, len).unwrap();
        let return_data = if len == 0 {
            Vec::new()
        } else {
            read_objects::<u8>(&handler, polka_addr as u32, len as usize).unwrap()
        };
        let transaction_context = &mut invoke_context.transaction_context;
        let program_id = *transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                instruction_context.get_last_program_key(transaction_context)
            }).unwrap();

        transaction_context.set_return_data(program_id, return_data).unwrap();
    }
}

declare_sbpf_builtin! {
    SolMemcpy,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        dst_ptr: u64,
        src_ptr: u64,
        n: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> () {
        // 1. 计算消耗的计算单元
        let cost = invoke_context
            .get_execution_cost()
            .mem_op_base_cost
            .saturating_add(n);
        invoke_context.consume_checked(cost).unwrap();

        // 2. 映射地址到polkavm地址空间
        let polka_dst = handler.map(dst_ptr, n).unwrap() as u32;
        let polka_src = handler.map(src_ptr, n).unwrap() as u32;

        // 3. 执行内存拷贝
        let mut handler = handler;
        let src_data = handler.read_memory(polka_src, (n as usize).try_into().unwrap()).unwrap();
        handler.write_memory(polka_dst, &src_data).unwrap();
    }
}

declare_sbpf_builtin! {
    SolMemset,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        dst_ptr: u64,
        value: u64,  // 注意：虽然传的是u64，但实际只使用最低字节
        n: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> () {
        // 1. 计算消耗的计算单元
        let cost = invoke_context
            .get_execution_cost()
            .mem_op_base_cost
            .saturating_add(n);
        invoke_context.consume_checked(cost).unwrap();

        // 2. 映射地址到polkavm地址空间
        let polka_dst = handler.map(dst_ptr, n).unwrap() as u32;

        // 3. 准备填充数据（取value的最低字节）
        let fill_byte = value as u8;
        let fill_data = vec![fill_byte; n as usize];

        // 4. 执行内存设置
        let mut handler = handler;
        handler.write_memory(polka_dst, &fill_data).unwrap();
    }
}

pub trait HasherImpl {
    const NAME: &'static str;
    type Output: AsRef<[u8]>;

    fn create_hasher() -> Self;
    fn hash(&mut self, val: &[u8]);
    fn result(self) -> Self::Output;
    fn get_base_cost(compute_cost: &SVMTransactionExecutionCost) -> u64;
    fn get_byte_cost(compute_cost: &SVMTransactionExecutionCost) -> u64;
    fn get_max_slices(compute_budget: &SVMTransactionExecutionBudget) -> u64;
}

struct Sha256Hasher(Hasher);

impl HasherImpl for Sha256Hasher {
    const NAME: &'static str = "Sha256";
    type Output = Hash;

    fn create_hasher() -> Self {
        Sha256Hasher(Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_cost: &SVMTransactionExecutionCost) -> u64 {
        compute_cost.sha256_base_cost
    }
    fn get_byte_cost(compute_cost: &SVMTransactionExecutionCost) -> u64 {
        compute_cost.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &SVMTransactionExecutionBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

declare_sbpf_builtin! {
    SolHash<H: HasherImpl>,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> () {
        let compute_budget = invoke_context.get_compute_budget();
        let compute_cost = invoke_context.get_execution_cost();
        let hash_base_cost = H::get_base_cost(compute_cost);
        let hash_byte_cost = H::get_byte_cost(compute_cost);
        let hash_max_slices = H::get_max_slices(compute_budget);
        if hash_max_slices < vals_len {
            panic!(
                "SyscallError::TooManySlices. {} Hashing {} sequences in one syscall is over the limit {}",
                H::NAME,
                vals_len,
                hash_max_slices,
            );
        }
        let mut hasher = H::create_hasher();
        if vals_len > 0 {
            let vals = map_and_read_objects::<VmSlice<u8>>(
                &handler,
                vals_addr,
                vals_len as usize,
            ).unwrap();

            for val in vals.iter() {
                let bytes = val.translate(&handler).unwrap();
                let cost = compute_cost.mem_op_base_cost.max(
                    hash_byte_cost.saturating_mul(
                        val.len
                            .checked_div(2)
                            .expect("div by non-zero literal"),
                    ),
                );
                invoke_context.consume_checked(cost).unwrap();
                hasher.hash(&bytes);
            }
        }
        let polkavm_addr = handler.map(result_addr, std::mem::size_of::<H::Output>() as u64).unwrap();
        let mut handler = handler;
        handler.write_memory(polkavm_addr as u32, hasher.result().as_ref()).unwrap();

        invoke_context.consume_checked(hash_base_cost).unwrap();
    }
}

#[repr(C)]
pub struct VmSlice<T> {
    pub ptr: u64,
    pub len: u64,
    resource_type: PhantomData<T>,
}

impl<T> VmSlice<T> {
    pub fn translate(&self, handler: &InstanceHandler) -> anyhow::Result<Vec<T>> {
        map_and_read_objects(handler, self.ptr, self.len as usize)
    }
}

fn translate_and_check_program_address_inputs(
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    handler: &InstanceHandler,
) -> anyhow::Result<(Vec<Vec<u8>>, Pubkey)> {
    let polkavm_seed_addr = handler.map(seeds_addr, seeds_len).unwrap();
    let untranslated_seeds =
        read_objects::<VmSlice<u8>>(handler, polkavm_seed_addr as u32, seeds_len as usize)?;
    let seeds = untranslated_seeds
        .iter()
        .map(|seed| {
            if seed.len > MAX_SEED_LEN as u64 {
                bail!("seed exceeded.");
            }
            let polkavm_ptr = handler.map(seed.ptr, seed.len).unwrap();
            read_objects::<u8>(handler, polkavm_ptr as u32, seed.len as usize)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let polkavm_id_addr = handler
        .map(program_id_addr, size_of::<Pubkey>() as u64)
        .unwrap();
    let program_id = read_object::<Pubkey>(handler, polkavm_id_addr as u32)?;
    Ok((seeds, program_id))
}
