use {
    anchor_lang::{AnchorDeserialize, Discriminator, InstructionData, Space, ToAccountMetas},
    anyhow::Result,
    counter::{Counter, accounts, instruction},
    litesvm::LiteSVM,
    litesvm_loader::deploy_upgradeable_program,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_sdk::{account::ReadableAccount, instruction::Instruction},
    solana_signer::Signer,
    solana_transaction::Transaction,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let payer = Keypair::new();
    let payer_key = payer.pubkey();
    #[allow(deprecated)]
    let program_keypair = Keypair::from_bytes(&[
        24, 99, 243, 156, 143, 51, 133, 177, 219, 44, 219, 97, 115, 142, 115, 130, 6, 150, 221, 98,
        110, 159, 243, 128, 174, 106, 159, 102, 184, 85, 56, 185, 205, 18, 209, 250, 156, 37, 11,
        48, 102, 63, 227, 126, 129, 231, 158, 184, 197, 154, 154, 209, 241, 53, 76, 147, 41, 11,
        212, 80, 120, 234, 207, 254,
    ])
    .unwrap();
    dbg!(program_keypair.pubkey());
    let mut svm = LiteSVM::default()
        .with_builtins()
        .with_lamports(1_000_000_000_000_000)
        .with_sysvars();
    svm.airdrop(&payer_key, 999999999995000).unwrap();

    let program_data = include_bytes!(
        "../../solana-programs/counter/target/sbf-solana-solana/release/counter.so"
    );
    deploy_upgradeable_program(&mut svm, &payer, &program_keypair, program_data).unwrap();

    let (counter_pda, _bump) =
        Pubkey::find_program_address(&[b"counter", payer_key.as_ref()], &program_keypair.pubkey());
    println!("counter_pda {counter_pda}");
    println!("Calling counter Initialize instruction...");
    let init_ix = Instruction {
        program_id: program_keypair.pubkey(),
        accounts: accounts::Initialize {
            payer: payer_key.clone(),
            counter: counter_pda.clone(),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: instruction::Initialize {}.data(),
    };
    let mut init_tx = Transaction::new_with_payer(&[init_ix], Some(&payer_key));
    init_tx.sign(&[&payer], svm.latest_blockhash());
    svm.send_transaction(init_tx).unwrap();
    print_counter(&svm, &counter_pda);

    println!("Calling counter inc instruction...");
    let inc_ix = Instruction {
        program_id: program_keypair.pubkey(),
        accounts: accounts::Inc {
            payer: payer_key.clone(),
            counter: counter_pda.clone(),
            system_program: solana_system_interface::program::ID,
        }
        .to_account_metas(None),
        data: instruction::Inc {}.data(),
    };
    let mut inc_tx = Transaction::new_with_payer(&[inc_ix], Some(&payer_key));
    inc_tx.sign(&[&payer], svm.latest_blockhash());
    svm.send_transaction(inc_tx).unwrap();
    print_counter(&svm, &counter_pda);
    println!("Counter init space: {}", Counter::INIT_SPACE);
    Ok(())
}

fn print_counter(svm: &LiteSVM, counter_pda: &Pubkey) {
    let counter_acc = svm.get_account(&counter_pda).unwrap();
    let data = counter_acc.data();
    let mut data = &data[Counter::DISCRIMINATOR.len()..];
    let counter = <Counter as AnchorDeserialize>::deserialize(&mut data).unwrap();
    println!("Counter: {counter:?} len: {:?}", counter_acc.data());
}
