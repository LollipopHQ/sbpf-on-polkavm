#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("EoXDvKpyju8yYcV5MP7BAULnffvKoRfXGxVriDg7MCJy");

#[program]
pub mod counter {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("initialize: {:?}", ctx.program_id);
        ctx.accounts.counter.cnt = 0;
        Ok(())
    }

    pub fn inc(ctx: Context<Inc>) -> Result<i32> {
        msg!("Inc: {:?}", ctx.program_id);
        ctx.accounts.counter.cnt += 1;
        Ok(ctx.accounts.counter.cnt)
    }

    pub fn dec(ctx: Context<Dec>) -> Result<i32> {
        msg!("initialize: {:?}", ctx.program_id);
        ctx.accounts.counter.cnt -= 1;
        Ok(ctx.accounts.counter.cnt)
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        space = 8 + Counter::INIT_SPACE,
        payer = payer,
        seeds = [b"counter", payer.key().as_ref()],
        bump
    )]
    pub counter: Account<'info, Counter>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Inc<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"counter", payer.key().as_ref()],
        bump
    )]
    pub counter: Account<'info, Counter>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Dec<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"counter", payer.key().as_ref()],
        bump
    )]
    pub counter: Account<'info, Counter>,

    pub system_program: Program<'info, System>,
}

#[account]
#[derive(Debug, InitSpace)]
pub struct Counter {
    cnt: i32,
}