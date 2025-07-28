use {
    crate::{imports, utils::JamContextObject},
    alloc::{boxed::Box, string::ToString},
    core::error::Error,
    solana_sbpf::{
        declare_builtin_function,
        error::ProgramResult,
        memory_region::{AccessType, MemoryMapping},
        program::BuiltinProgram,
    },
};

const LOG_TARGET: &'static [u8] = b"sbpf-jam::builtins";

declare_builtin_function!(
    Log,
    fn rust(
        _invoke_ctx: &mut JamContextObject, //ptr
        text_ptr: u64,
        text_len: u64,
        _1: u64,
        _2: u64,
        _3: u64,
        vm_mm: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn Error>> {
        let text_ptr: Result<u64, Box<dyn Error>> = vm_mm
            .map(AccessType::Load, text_ptr, text_len)
            .map_err(|err| {
                let e: Box<dyn Error> = err.to_string().into();
                e
            })
            .into();
        let text_ptr = text_ptr?;
        unsafe {
            imports::log(
                2,
                LOG_TARGET.as_ptr(),
                LOG_TARGET.len() as u64,
                text_ptr as *const u8,
                text_len,
            );
        }
        Ok(0)
    }
);

pub struct Builtins;

macro_rules! declare_sbpf_builtin {
    ($name:ident, $index: literal) => {
        #[polkavm_derive::polkavm_import]
        extern "C" {
            #[polkavm_import(index = $index)]
            fn $name(
                invoke_context_ptr: u64,
                arg_a: u64,
                arg_b: u64,
                arg_c: u64,
                arg_d: u64,
                arg_e: u64,
            );
        }
        impl Builtins {
            pub fn $name(
                vm: *mut solana_sbpf::vm::EbpfVm<$crate::JamContextObject>,
                arg_a: u64,
                arg_b: u64,
                arg_c: u64,
                arg_d: u64,
                arg_e: u64,
            ) {
                let vm = unsafe {
                    &mut *(vm
                        .cast::<u64>()
                        .offset(-(solana_sbpf::vm::get_runtime_environment_key() as isize))
                        .cast::<solana_sbpf::vm::EbpfVm<JamContextObject>>())
                };
                let invoke_context_ptr = vm.context_object_pointer.invoke_context_ptr;
                unsafe {
                    $name(invoke_context_ptr, arg_a, arg_b, arg_c, arg_d, arg_e);
                }
            }
        }
    };
}

pub fn register_builtins(loader: &mut BuiltinProgram<JamContextObject>) {
    loader
        .register_function("abort", Builtins::abort_mock)
        .unwrap();
    loader
        .register_function("sol_panic_", Builtins::sol_panic_)
        .unwrap();
    loader
        .register_function("sol_log_", Builtins::sol_log_)
        .unwrap();
    loader
        .register_function("sol_log_64_", Builtins::sol_log_64_)
        .unwrap();
    loader
        .register_function("sol_log_pubkey", Builtins::sol_log_pubkey)
        .unwrap();
    loader
        .register_function("sol_log_compute_units_", Builtins::sol_log_compute_units_)
        .unwrap();
    loader
        .register_function(
            "sol_create_program_address",
            Builtins::sol_create_program_address,
        )
        .unwrap();
    loader
        .register_function(
            "sol_try_find_program_address",
            Builtins::sol_try_find_program_address,
        )
        .unwrap();
    loader
        .register_function("sol_sha256", Builtins::sol_sha256)
        .unwrap();
    loader
        .register_function("sol_keccak256", Builtins::sol_keccak256)
        .unwrap();
    loader
        .register_function("sol_secp256k1_recover", Builtins::sol_secp256k1_recover)
        .unwrap();
    loader
        .register_function("sol_blake3", Builtins::sol_blake3)
        .unwrap();
    loader
        .register_function(
            "sol_curve_validate_point",
            Builtins::sol_curve_validate_point,
        )
        .unwrap();
    loader
        .register_function("sol_curve_group_op", Builtins::sol_curve_group_op)
        .unwrap();
    loader
        .register_function(
            "sol_curve_multiscalar_mul",
            Builtins::sol_curve_multiscalar_mul,
        )
        .unwrap();
    loader
        .register_function("sol_get_clock_sysvar", Builtins::sol_get_clock_sysvar)
        .unwrap();
    loader
        .register_function(
            "sol_get_epoch_schedule_sysvar",
            Builtins::sol_get_epoch_schedule_sysvar,
        )
        .unwrap();
    loader
        .register_function("sol_get_fees_sysvar", Builtins::sol_get_fees_sysvar)
        .unwrap();
    loader
        .register_function("sol_get_rent_sysvar", Builtins::sol_get_rent_sysvar)
        .unwrap();
    loader
        .register_function(
            "sol_get_last_restart_slot",
            Builtins::sol_get_last_restart_slot,
        )
        .unwrap();
    loader
        .register_function(
            "sol_get_epoch_rewards_sysvar",
            Builtins::sol_get_epoch_rewards_sysvar,
        )
        .unwrap();
    loader
        .register_function("sol_memcpy_", Builtins::sol_memcpy_)
        .unwrap();
    loader
        .register_function("sol_memmove_", Builtins::sol_memmove_)
        .unwrap();
    loader
        .register_function("sol_memset_", Builtins::sol_memset_)
        .unwrap();
    loader
        .register_function("sol_memcmp_", Builtins::sol_memcmp_)
        .unwrap();
    loader
        .register_function(
            "sol_get_processed_sibling_instruction",
            Builtins::sol_get_processed_sibling_instruction,
        )
        .unwrap();
    loader
        .register_function("sol_get_stack_height", Builtins::sol_get_stack_height)
        .unwrap();
    loader
        .register_function("sol_set_return_data", Builtins::sol_set_return_data)
        .unwrap();
    loader
        .register_function("sol_get_return_data", Builtins::sol_get_return_data)
        .unwrap();
    loader
        .register_function("sol_invoke_signed_c", Builtins::sol_invoke_signed_c)
        .unwrap();
    loader
        .register_function("sol_invoke_signed_rust", Builtins::sol_invoke_signed_rust)
        .unwrap();
    loader
        .register_function("sol_alloc_free_", Builtins::sol_alloc_free_)
        .unwrap();
    loader
        .register_function("sol_alt_bn128_group_op", Builtins::sol_alt_bn128_group_op)
        .unwrap();
    loader
        .register_function("sol_big_mod_exp", Builtins::sol_big_mod_exp)
        .unwrap();
    loader
        .register_function("sol_poseidon", Builtins::sol_poseidon)
        .unwrap();
    loader
        .register_function(
            "sol_remaining_compute_units",
            Builtins::sol_remaining_compute_units,
        )
        .unwrap();
    loader
        .register_function(
            "sol_alt_bn128_compression",
            Builtins::sol_alt_bn128_compression,
        )
        .unwrap();
    loader
        .register_function("sol_get_sysvar", Builtins::sol_get_sysvar)
        .unwrap();
    loader
        .register_function("sol_get_epoch_stake", Builtins::sol_get_epoch_stake)
        .unwrap();
    loader
        .register_function("sol_log_data", Builtins::sol_log_data)
        .unwrap();
}

impl Builtins {
    pub fn abort_mock(
        vm: *mut solana_sbpf::vm::EbpfVm<crate::JamContextObject>,
        _arg_a: u64,
        _arg_b: u64,
        _arg_c: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) {
        jam_pvm_common::info!(target = "jam-builtin", "Builtin abort_mock is called.");
        let vm = unsafe {
            &mut *(vm
                .cast::<u64>()
                .offset(-(solana_sbpf::vm::get_runtime_environment_key() as isize))
                .cast::<solana_sbpf::vm::EbpfVm<JamContextObject>>())
        };
        vm.program_result = ProgramResult::Err(solana_sbpf::error::EbpfError::SyscallError(
            "abort is called".into(),
        ));

        jam_pvm_common::info!(target = "jam-builtin", "Builtin abort_mock is returned.");
    }
}

declare_sbpf_builtin!(abort, 50);
declare_sbpf_builtin!(sol_panic_, 51);
declare_sbpf_builtin!(sol_log_, 52);
declare_sbpf_builtin!(sol_log_64_, 53);
declare_sbpf_builtin!(sol_log_pubkey, 54);
declare_sbpf_builtin!(sol_log_compute_units_, 55);
declare_sbpf_builtin!(sol_create_program_address, 56);
declare_sbpf_builtin!(sol_try_find_program_address, 57);
declare_sbpf_builtin!(sol_sha256, 58);
declare_sbpf_builtin!(sol_keccak256, 59);
declare_sbpf_builtin!(sol_secp256k1_recover, 60);
declare_sbpf_builtin!(sol_blake3, 61);
declare_sbpf_builtin!(sol_curve_validate_point, 62);
declare_sbpf_builtin!(sol_curve_group_op, 63);
declare_sbpf_builtin!(sol_curve_multiscalar_mul, 64);
declare_sbpf_builtin!(sol_get_clock_sysvar, 65);
declare_sbpf_builtin!(sol_get_epoch_schedule_sysvar, 66);
declare_sbpf_builtin!(sol_get_fees_sysvar, 67);
declare_sbpf_builtin!(sol_get_rent_sysvar, 68);
declare_sbpf_builtin!(sol_get_last_restart_slot, 69);
declare_sbpf_builtin!(sol_get_epoch_rewards_sysvar, 70);
declare_sbpf_builtin!(sol_memcpy_, 71);
declare_sbpf_builtin!(sol_memmove_, 72);
declare_sbpf_builtin!(sol_memset_, 73);
declare_sbpf_builtin!(sol_memcmp_, 74);
declare_sbpf_builtin!(sol_get_processed_sibling_instruction, 75);
declare_sbpf_builtin!(sol_get_stack_height, 76);
declare_sbpf_builtin!(sol_set_return_data, 77);
declare_sbpf_builtin!(sol_get_return_data, 78);
declare_sbpf_builtin!(sol_invoke_signed_c, 79);
declare_sbpf_builtin!(sol_invoke_signed_rust, 80);
declare_sbpf_builtin!(sol_alloc_free_, 81);
declare_sbpf_builtin!(sol_alt_bn128_group_op, 82);
declare_sbpf_builtin!(sol_big_mod_exp, 83);
declare_sbpf_builtin!(sol_poseidon, 84);
declare_sbpf_builtin!(sol_remaining_compute_units, 85);
declare_sbpf_builtin!(sol_alt_bn128_compression, 86);
declare_sbpf_builtin!(sol_get_sysvar, 87);
declare_sbpf_builtin!(sol_get_epoch_stake, 88);
declare_sbpf_builtin!(sol_log_data, 89);
