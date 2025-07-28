use {
    crate::{
        InstanceHandler, Linker, declare_sbpf_builtin, imports::VmSlice, map_and_read_object,
        map_and_read_objects,
    },
    anyhow::anyhow,
    solana_account_info::{AccountInfo, MAX_PERMITTED_DATA_INCREASE},
    solana_instruction::AccountMeta,
    solana_loader_v3_interface::instruction as bpf_loader_upgradeable,
    solana_measure::measure::Measure,
    solana_program_entrypoint::SUCCESS,
    solana_program_runtime::invoke_context::{InvokeContext, SerializedAccountMetadata},
    solana_pubkey::{MAX_SEEDS, Pubkey},
    solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, native_loader},
    solana_stable_layout::stable_instruction::StableInstruction,
    solana_timings::ExecuteTimings,
    solana_transaction_context::{BorrowedAccount, IndexOfAccount, InstructionAccount},
    std::{mem, u64},
};

const MAX_CPI_INSTRUCTION_DATA_LEN: u64 = 10 * 1024;
const MAX_CPI_INSTRUCTION_ACCOUNTS: u8 = u8::MAX;
const MAX_CPI_ACCOUNT_INFOS: usize = 128;
/// Maximum signers
const MAX_SIGNERS: usize = 16;

/// Host side representation of AccountInfo or SolAccountInfo passed to the CPI syscall.
///
/// At the start of a CPI, this can be different from the data stored in the
/// corresponding BorrowedAccount, and needs to be synched.
struct CallerAccount {
    lamports: u64,
    lamports_addr: u64,
    owner: Pubkey,
    owner_addr: u64,
    // The original data length of the account at the start of the current
    // instruction. We use this to determine wether an account was shrunk or
    // grown before or after CPI, and to derive the vm address of the realloc
    // region.
    original_data_len: usize,
    // This points to the data section for this account, as serialized and
    // mapped inside the vm (see serialize_parameters() in
    // BpfExecutor::execute).
    //
    // This is only set when direct mapping is off (see the relevant comment in
    // CallerAccount::from_account_info).
    serialized_data: Vec<u8>,
    // Given the corresponding input AccountInfo::data, vm_data_addr points to
    // the pointer field and ref_to_len_in_vm points to the length field.
    vm_data_addr: u64,
    vm_len_addr: u64,
}

impl CallerAccount {
    // Create a CallerAccount given an AccountInfo.
    fn from_account_info(
        invoke_context: &InvokeContext,
        handler: &InstanceHandler,
        _vm_addr: u64,
        account_info: &AccountInfo,
        account_metadata: &SerializedAccountMetadata,
    ) -> anyhow::Result<CallerAccount> {
        let (lamports, lamports_addr) = {
            let ptr = map_and_read_object::<u64>(handler, account_info.lamports.as_ptr() as u64)?;
            (map_and_read_object::<u64>(handler, ptr)?, ptr)
        };
        let owner_addr = account_info.owner as *const _ as u64;
        let owner = map_and_read_object::<Pubkey>(handler, owner_addr)?;

        let data =
            map_and_read_object::<&[u8]>(handler, account_info.data.as_ptr() as *const _ as u64)
                .unwrap();
        invoke_context
            .consume_checked(
                (data.len() as u64)
                    .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX),
            )
            .unwrap();
        let vm_len_addr =
            (account_info.data.as_ptr() as *const _ as u64).saturating_add(size_of::<u64>() as u64);
        let len = map_and_read_object::<u64>(handler, vm_len_addr)?;
        let vm_data_addr = data.as_ptr() as u64;
        let serialized_data = map_and_read_objects::<u8>(handler, vm_data_addr, len as usize)?;
        Ok(Self {
            lamports,
            lamports_addr,
            owner,
            owner_addr,
            original_data_len: account_metadata.original_data_len,
            serialized_data,
            vm_data_addr,
            vm_len_addr,
        })
    }
}

type TranslatedAccounts = Vec<(IndexOfAccount, Option<CallerAccount>)>;

/// Implemented by language specific data structure translators
trait SyscallInvokeSigned {
    fn translate_instruction(
        addr: u64,
        handler: &InstanceHandler,
        invoke_context: &mut InvokeContext,
    ) -> anyhow::Result<StableInstruction>;
    fn translate_accounts(
        instruction_accounts: &[InstructionAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        handler: &InstanceHandler,
        invoke_context: &mut InvokeContext,
    ) -> anyhow::Result<TranslatedAccounts>;
    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        handler: &InstanceHandler,
        invoke_context: &InvokeContext,
    ) -> anyhow::Result<Vec<Pubkey>>;
}

declare_sbpf_builtin! {
    SolInvokeSignedRust,
    fn rust(
        handler: InstanceHandler,
        invoke_context: &mut InvokeContext,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
    ) -> () {
        cpi_common::<Self>(
            invoke_context,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
            handler).unwrap();
    }
}

impl SyscallInvokeSigned for SolInvokeSignedRust {
    fn translate_instruction(
        addr: u64,
        handler: &InstanceHandler,
        invoke_context: &mut InvokeContext,
    ) -> anyhow::Result<StableInstruction> {
        let ix: StableInstruction = map_and_read_object::<StableInstruction>(handler, addr)?;
        let account_metas = map_and_read_objects::<AccountMeta>(
            handler,
            ix.accounts.as_vaddr(),
            ix.accounts.len() as usize,
        )?;

        let data = map_and_read_objects::<u8>(handler, ix.data.as_vaddr(), ix.data.len() as usize)?;

        check_instruction_size(account_metas.len(), data.len(), invoke_context)?;

        if invoke_context.get_feature_set().loosen_cpi_size_restriction {
            invoke_context
                .consume_checked(
                    (data.len() as u64)
                        .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
                        .unwrap_or(u64::MAX),
                )
                .unwrap();
        }
        let result = StableInstruction {
            accounts: account_metas.into(),
            data: data.into(),
            program_id: ix.program_id,
        };
        {
            let _metas = mem::ManuallyDrop::new(ix.accounts);
            let _data = mem::ManuallyDrop::new(ix.data);
        }
        Ok(result)
    }

    fn translate_accounts(
        instruction_accounts: &[InstructionAccount],
        account_infos_addr: u64,
        account_infos_len: u64,
        is_loader_deprecated: bool,
        handler: &InstanceHandler,
        invoke_context: &mut InvokeContext,
    ) -> anyhow::Result<TranslatedAccounts> {
        let (account_infos, account_info_keys) = translate_account_infos(
            account_infos_addr,
            account_infos_len,
            |info: &AccountInfo| info.key as *const _ as u64,
            handler,
            invoke_context,
        )?;
        let result = translate_and_update_accounts(
            instruction_accounts,
            &account_info_keys,
            &account_infos,
            account_infos_addr,
            is_loader_deprecated,
            invoke_context,
            handler,
            CallerAccount::from_account_info,
        );
        {
            for info in account_infos {
                let _info = mem::ManuallyDrop::new(info);
            }
        }
        result
    }

    fn translate_signers(
        program_id: &Pubkey,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
        handler: &InstanceHandler,
        _invoke_context: &InvokeContext,
    ) -> anyhow::Result<Vec<Pubkey>> {
        let mut signers = Vec::new();
        if signers_seeds_len > 0 {
            let signers_seeds = map_and_read_objects::<VmSlice<VmSlice<u8>>>(
                handler,
                signers_seeds_addr,
                signers_seeds_len as usize,
            )?;
            if signers_seeds.len() > MAX_SIGNERS {
                return Err(anyhow!("SyscallError::TooManySigners"));
            }
            for signer_seeds in signers_seeds.iter() {
                let untranslated_seeds = map_and_read_objects::<VmSlice<u8>>(
                    handler,
                    signer_seeds.ptr,
                    signer_seeds.len as usize,
                )?;
                if untranslated_seeds.len() > MAX_SEEDS {
                    return Err(anyhow!("InstructionError::MaxSeedLengthExceeded"));
                }
                let seeds = untranslated_seeds
                    .iter()
                    .map(|untranslated_seed| untranslated_seed.translate(handler))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let seed_slices = seeds.iter().map(|v| v.as_slice()).collect::<Vec<_>>();
                let signer = Pubkey::create_program_address(&seed_slices, program_id)
                    .map_err(|e| anyhow!("SyscallError::BadSeeds: {}", e))?;
                signers.push(signer);
            }
            Ok(signers)
        } else {
            Ok(vec![])
        }
    }
}

fn check_authorized_program(
    program_id: &Pubkey,
    instruction_data: &[u8],
    invoke_context: &InvokeContext,
) -> anyhow::Result<()> {
    if native_loader::check_id(program_id)
        || bpf_loader::check_id(program_id)
        || bpf_loader_deprecated::check_id(program_id)
        || (solana_sdk_ids::bpf_loader_upgradeable::check_id(program_id)
            && !(bpf_loader_upgradeable::is_upgrade_instruction(instruction_data)
                || bpf_loader_upgradeable::is_set_authority_instruction(instruction_data)
                || (invoke_context
                    .get_feature_set()
                    .enable_bpf_loader_set_authority_checked_ix
                    && bpf_loader_upgradeable::is_set_authority_checked_instruction(
                        instruction_data,
                    ))
                || (invoke_context
                    .get_feature_set()
                    .enable_extend_program_checked
                    && bpf_loader_upgradeable::is_extend_program_checked_instruction(
                        instruction_data,
                    ))
                || bpf_loader_upgradeable::is_close_instruction(instruction_data)))
        || invoke_context.is_precompile(program_id)
    {
        return Err(anyhow!("SyscallError::ProgramNotSupported({program_id})"));
    }
    Ok(())
}

/// Call process instruction, common to both Rust and C
fn cpi_common<S: SyscallInvokeSigned>(
    invoke_context: &mut InvokeContext,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    mut handler: InstanceHandler,
) -> anyhow::Result<u64> {
    // CPI entry.
    //
    // Translate the inputs to the syscall and synchronize the caller's account
    // changes so the callee can see them.
    invoke_context
        .consume_checked(invoke_context.get_execution_cost().invoke_units)
        .unwrap();
    if let Some(execute_time) = invoke_context.execute_time.as_mut() {
        execute_time.stop();
        invoke_context.timings.execute_us += execute_time.as_us();
    }
    let instruction = S::translate_instruction(instruction_addr, &handler, invoke_context);
    let instruction = instruction?;
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let caller_program_id = instruction_context.get_last_program_key(transaction_context)?;
    let signers = S::translate_signers(
        caller_program_id,
        signers_seeds_addr,
        signers_seeds_len,
        &handler,
        invoke_context,
    )?;
    let is_loader_deprecated = *instruction_context
        .try_borrow_last_program_account(transaction_context)?
        .get_owner()
        == bpf_loader_deprecated::id();
    let (instruction_accounts, program_indices) =
        invoke_context.prepare_instruction(&instruction, &signers)?;
    check_authorized_program(&instruction.program_id, &instruction.data, invoke_context)?;

    let mut accounts = S::translate_accounts(
        &instruction_accounts,
        account_infos_addr,
        account_infos_len,
        is_loader_deprecated,
        &handler,
        invoke_context,
    )?;

    // Process the callee instruction
    let mut compute_units_consumed = 0;
    invoke_context.process_instruction(
        &instruction.data,
        &instruction_accounts,
        &program_indices,
        &mut compute_units_consumed,
        &mut ExecuteTimings::default(),
    )?;

    // re-bind to please the borrow checker
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    for (index_in_caller, caller_account) in accounts.iter_mut() {
        if let Some(caller_account) = caller_account {
            let mut callee_account = instruction_context
                .try_borrow_instruction_account(transaction_context, *index_in_caller)?;
            update_caller_account(&mut handler, caller_account, &mut callee_account)?;
        }
    }

    invoke_context.execute_time = Some(Measure::start("execute"));
    Ok(SUCCESS)
}

fn translate_account_infos<T, F>(
    account_infos_addr: u64,
    account_infos_len: u64,
    key_addr: F,
    handler: &InstanceHandler,
    invoke_context: &mut InvokeContext,
) -> anyhow::Result<(Vec<T>, Vec<Pubkey>)>
where
    F: Fn(&T) -> u64,
{
    let account_infos =
        map_and_read_objects::<T>(handler, account_infos_addr, account_infos_len as usize)?;
    check_account_infos(account_infos.len(), invoke_context)?;
    let mut account_info_keys = Vec::with_capacity(account_infos_len as usize);
    #[allow(clippy::needless_range_loop)]
    for account_index in 0..account_infos_len as usize {
        #[allow(clippy::indexing_slicing)]
        let account_info = &account_infos[account_index];
        account_info_keys.push(map_and_read_object::<Pubkey>(
            handler,
            key_addr(account_info),
        )?);
    }
    Ok((account_infos, account_info_keys))
}

fn check_instruction_size(
    num_accounts: usize,
    data_len: usize,
    invoke_context: &mut InvokeContext,
) -> anyhow::Result<()> {
    if invoke_context.get_feature_set().loosen_cpi_size_restriction {
        let data_len = data_len as u64;
        let max_data_len = MAX_CPI_INSTRUCTION_DATA_LEN;
        if data_len > max_data_len {
            return Err(anyhow!(
                "SyscallError::MaxInstructionDataLenExceeded data_len {}, max_data_len {}",
                data_len,
                max_data_len
            ));
        }

        let num_accounts = num_accounts as u64;
        let max_accounts = MAX_CPI_INSTRUCTION_ACCOUNTS as u64;
        if num_accounts > max_accounts {
            return Err(anyhow!(
                "SyscallError::MaxInstructionAccountsExceeded num_accounts: {}, max_accounts: {}",
                num_accounts,
                max_accounts
            ));
        }
    } else {
        let max_size = invoke_context.get_compute_budget().max_cpi_instruction_size;
        let size = num_accounts
            .saturating_mul(size_of::<AccountMeta>())
            .saturating_add(data_len);
        if size > max_size {
            return Err(anyhow!(
                "SyscallError::InstructionTooLarge size: {}, max_size: {}",
                size,
                max_size
            ));
        }
    }
    Ok(())
}

fn check_account_infos(
    num_account_infos: usize,
    invoke_context: &mut InvokeContext,
) -> anyhow::Result<()> {
    if invoke_context.get_feature_set().loosen_cpi_size_restriction {
        let max_cpi_account_infos = if invoke_context
            .get_feature_set()
            .increase_tx_account_lock_limit
        {
            MAX_CPI_ACCOUNT_INFOS
        } else {
            64
        };
        let num_account_infos = num_account_infos as u64;
        let max_account_infos = max_cpi_account_infos as u64;
        if num_account_infos > max_account_infos {
            return Err(anyhow!(
                "SyscallError::MaxInstructionAccountInfosExceeded num_account_infos: {},max_account_infos: {}",
                num_account_infos,
                max_account_infos
            ));
        }
    } else {
        let adjusted_len = num_account_infos.saturating_mul(size_of::<Pubkey>());

        if adjusted_len > invoke_context.get_compute_budget().max_cpi_instruction_size {
            // Cap the number of account_infos a caller can pass to approximate
            // maximum that accounts that could be passed in an instruction
            return Err(anyhow!("SyscallError::TooManyAccounts"));
        };
    }
    Ok(())
}

// Finish translating accounts, build CallerAccount values and update callee
// accounts in preparation of executing the callee.
fn translate_and_update_accounts<T, F>(
    instruction_accounts: &[InstructionAccount],
    account_info_keys: &[Pubkey],
    account_infos: &[T],
    account_infos_addr: u64,
    _is_loader_deprecated: bool,
    invoke_context: &mut InvokeContext,
    handler: &InstanceHandler,
    do_translate: F,
) -> anyhow::Result<TranslatedAccounts>
where
    F: Fn(
        &InvokeContext,
        &InstanceHandler,
        u64,
        &T,
        &SerializedAccountMetadata,
    ) -> anyhow::Result<CallerAccount>,
{
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut accounts = Vec::with_capacity(instruction_accounts.len());

    // unwrapping here is fine: we're in a syscall and the method below fails
    // only outside syscalls
    let accounts_metadata = &invoke_context
        .get_syscall_context()
        .unwrap()
        .accounts_metadata;

    for (instruction_account_index, instruction_account) in instruction_accounts.iter().enumerate()
    {
        if instruction_account_index as IndexOfAccount != instruction_account.index_in_callee {
            continue; // Skip duplicate account
        }

        let callee_account = instruction_context.try_borrow_instruction_account(
            transaction_context,
            instruction_account.index_in_caller,
        )?;
        let account_key = invoke_context
            .transaction_context
            .get_key_of_account_at_index(instruction_account.index_in_transaction)?;

        #[allow(deprecated)]
        if callee_account.is_executable() {
            // Use the known account
            invoke_context
                .consume_checked(
                    (callee_account.get_data().len() as u64)
                        .checked_div(invoke_context.get_execution_cost().cpi_bytes_per_unit)
                        .unwrap_or(u64::MAX),
                )
                .unwrap();
        } else if let Some(caller_account_index) =
            account_info_keys.iter().position(|key| key == account_key)
        {
            let serialized_metadata = accounts_metadata
                .get(instruction_account.index_in_caller as usize)
                .ok_or_else(|| {
                    anyhow!(
                        "InstructionError::MissingAccount. Internal error: index mismatch for account {}",
                        account_key
                    )
                })?;

            // build the CallerAccount corresponding to this account.
            if caller_account_index >= account_infos.len() {
                return Err(anyhow!("SyscallError::InvalidLength"));
            }
            #[allow(clippy::indexing_slicing)]
            let caller_account =
                do_translate(
                    invoke_context,
                    handler,
                    account_infos_addr.saturating_add(
                        caller_account_index.saturating_mul(mem::size_of::<T>()) as u64,
                    ),
                    &account_infos[caller_account_index],
                    serialized_metadata,
                )?;

            // before initiating CPI, the caller may have modified the
            // account (caller_account). We need to update the corresponding
            // BorrowedAccount (callee_account) so the callee can see the
            // changes.
            let update_caller = update_callee_account(&caller_account, callee_account)?;

            let caller_account = if instruction_account.is_writable || update_caller {
                Some(caller_account)
            } else {
                None
            };
            accounts.push((instruction_account.index_in_caller, caller_account));
        } else {
            return Err(anyhow!(
                "InstructionError::MissingAccount. Instruction references an unknown account {}",
                account_key
            ));
        }
    }

    Ok(accounts)
}

// Update the given account before executing CPI.
//
// caller_account and callee_account describe the same account. At CPI entry
// caller_account might include changes the caller has made to the account
// before executing CPI.
//
// This method updates callee_account so the CPI callee can see the caller's
// changes.
//
// When true is returned, the caller account must be updated after CPI. This
// is only set for direct mapping when the pointer may have changed.
fn update_callee_account(
    caller_account: &CallerAccount,
    mut callee_account: BorrowedAccount<'_>,
) -> anyhow::Result<bool> {
    let must_update_caller = false;

    if callee_account.get_lamports() != caller_account.lamports {
        callee_account.set_lamports(caller_account.lamports)?;
    }

    // The redundant check helps to avoid the expensive data comparison if we can
    match callee_account.can_data_be_resized(caller_account.serialized_data.len()) {
        Ok(()) => callee_account.set_data_from_slice(&caller_account.serialized_data)?,
        Err(err) if callee_account.get_data() != caller_account.serialized_data => {
            return Err(anyhow!(err));
        }
        _ => {}
    }

    // Change the owner at the end so that we are allowed to change the lamports and data before
    if callee_account.get_owner() != &caller_account.owner {
        callee_account.set_owner(caller_account.owner.as_ref())?;
    }

    Ok(must_update_caller)
}

// Update the given account after executing CPI.
//
// caller_account and callee_account describe to the same account. At CPI exit
// callee_account might include changes the callee has made to the account
// after executing.
//
// This method updates caller_account so the CPI caller can see the callee's
// changes.
fn update_caller_account(
    handler: &mut InstanceHandler,
    caller_account: &mut CallerAccount,
    callee_account: &mut BorrowedAccount<'_>,
) -> anyhow::Result<()> {
    caller_account.lamports = callee_account.get_lamports();
    caller_account.owner = *callee_account.get_owner();
    handler
        .map_and_write_memory(
            caller_account.lamports_addr,
            &caller_account.lamports.to_le_bytes(),
        )
        .unwrap();
    handler
        .map_and_write_memory(caller_account.owner_addr, caller_account.owner.as_ref())
        .unwrap();

    let prev_len = caller_account.serialized_data.len();
    let post_len = callee_account.get_data().len();
    if prev_len != post_len {
        let max_increase = MAX_PERMITTED_DATA_INCREASE;
        let data_overflow = post_len
            > caller_account
                .original_data_len
                .saturating_add(max_increase);
        if data_overflow {
            return Err(anyhow!(
                "InstructionError::InvalidRealloc. Account data size realloc limited to {max_increase} in inner instructions",
            ));
        }

        // If the account has been shrunk, we're going to zero the unused memory
        // *that was previously used*.
        if post_len < prev_len {
            caller_account
                .serialized_data
                .get_mut(post_len..)
                .ok_or_else(|| anyhow!("InstructionError::AccountDataTooSmall"))?
                .fill(0);
        }

        // when direct mapping is enabled we don't cache the serialized data in
        // caller_account.serialized_data. See CallerAccount::from_account_info.

        caller_account.serialized_data =
            map_and_read_objects::<u8>(handler, caller_account.vm_data_addr, post_len)?;
        handler
            .map_and_write_memory(caller_account.vm_len_addr, &post_len.to_le_bytes())
            .unwrap();
        handler
            .map_and_write_memory(
                caller_account
                    .vm_data_addr
                    .saturating_sub(mem::size_of::<u64>() as u64),
                &post_len.to_le_bytes(),
            )
            .unwrap();
    }

    let to_slice = &mut caller_account.serialized_data;
    let from_slice = callee_account
        .get_data()
        .get(0..post_len)
        .ok_or(anyhow!("SyscallError::InvalidLength"))?;
    if to_slice.len() != from_slice.len() {
        return Err(anyhow!("InstructionError::AccountDataTooSmall"));
    }
    // to_slice.copy_from_slice(from_slice);
    let polkavm_addr = handler
        .map(caller_account.vm_data_addr, from_slice.len() as u64)
        .unwrap();
    handler
        .clone()
        .write_memory(polkavm_addr as u32, from_slice)
        .unwrap();
    // shared_data.set_data_from_slice(from_slice);

    Ok(())
}
