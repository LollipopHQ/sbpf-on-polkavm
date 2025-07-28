import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Counter } from "../target/types/counter";
import { assert } from "chai";

describe("counter", () => {
  // 使用本地网络的提供者
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // 加载程序
  const program = anchor.workspace.Counter as Program<Counter>;

  it("Initializes and modifies counter", async () => {
    // 生成一个新的付款人密钥对
    const payer = anchor.web3.Keypair.generate();

    // 给付款人账户空投一些 SOL
    const airdropSignature = await provider.connection.requestAirdrop(
      payer.publicKey,
      anchor.web3.LAMPORTS_PER_SOL * 5 // 空投 1 SOL
    );

    const latestBlockHash = await provider.connection.getLatestBlockhash();

    await provider.connection.confirmTransaction({
      blockhash: latestBlockHash.blockhash,
      lastValidBlockHeight: latestBlockHash.lastValidBlockHeight,
      signature: airdropSignature,
    });

    // 获取计数器 PDA
    const [counterPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("counter"), payer.publicKey.toBuffer()],
      program.programId
    );

    // 初始化计数器
    await program.methods
     .initialize()
     .accounts({
        payer: payer.publicKey,
        counter: counterPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
     .signers([payer])
     .rpc();

    // 增加计数器
    await program.methods
     .inc()
     .accounts({
        payer: payer.publicKey,
        counter: counterPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
     .signers([payer])
     .rpc();

    // 获取计数器账户
    const counterAccount = await program.account.counter.fetch(counterPda);
    assert.strictEqual(counterAccount.cnt, 1);

    // 减少计数器
    await program.methods
     .dec()
     .accounts({
        payer: payer.publicKey,
        counter: counterPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
     .signers([payer])
     .rpc();

    // 再次获取计数器账户
    const updatedCounterAccount = await program.account.counter.fetch(counterPda);
    assert.strictEqual(updatedCounterAccount.cnt, 0);
  });
}); 
