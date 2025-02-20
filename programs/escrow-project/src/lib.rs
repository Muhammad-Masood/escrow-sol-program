use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
use anchor_lang::solana_program::sysvar::clock::Clock;

declare_id!("HPFKvGvdtChrFrfqzAYzbNZJ3sRKw9HDHMKWgtZg1oNs");

#[program]
mod escrow_project {
    use super::*;
    
    pub fn start_subscription(
        ctx: Context<StartSubscription>,
        query_size: u64,
        number_of_blocks: u64,
        x: u64,
        // g: [u8; 48],
        // v: [u8; 48],
        // u: [u8; 96],
        g: u64,
        v: u64,
        u: u64,
    ) -> Result<Pubkey> {
        let escrow = &mut ctx.accounts.escrow;
        escrow.buyer = *ctx.accounts.buyer.key;
        escrow.query_size = query_size;
        escrow.number_of_blocks = number_of_blocks;
        escrow.x = x;
        escrow.g = g;
        escrow.v = v;
        escrow.u = u;
        escrow.balance = 0;
        escrow.bump = ctx.bumps.escrow;
        Ok(escrow.key())
    }

    pub fn extend_subscription(ctx: Context<ExtendSubscription>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let buyer = &ctx.accounts.buyer;
        let system_program = &ctx.accounts.system_program;
        
        // Transfer 1 SOL to escrow
        let escrow_signer_seeds: &[&[u8]] = &[b"escrow", &escrow.buyer.to_bytes(), &[escrow.bump]]; 
        invoke_signed(
            &system_instruction::transfer(
                &buyer.key(),
                &escrow.key(),
                1_000_000_000, // 1 SOL in lamports
            ),
            &[buyer.to_account_info(), escrow.to_account_info(), system_program.to_account_info()],
            &[escrow_signer_seeds],
        )?;
        escrow.balance += 1;
        
        // Generate query tuples
        let clock = Clock::get()?.unix_timestamp as u64;
        escrow.queries.clear();
        let num_blocks = escrow.number_of_blocks;
        for i in 0..escrow.query_size.min(10) {
            escrow.queries.push(((clock + i) % num_blocks, (clock + i * 7) % 100));
        }
        Ok(())
    }
    
    pub fn get_query_values(ctx: Context<GetQueryValues>) -> Result<Vec<(u64, u64)>> {
        let escrow = &ctx.accounts.escrow;
        Ok(escrow.queries.clone())
    }

    pub fn prove(ctx: Context<Prove>, sigma: u64, mu: u64) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let seller = &ctx.accounts.seller;
        let buyer = &ctx.accounts.buyer;
        
        // Perform field operations & validation (pseudo-validation for now)
        let valid = sigma % mu == 0;
        
        if valid {
            if escrow.balance >= 5 {
                **seller.to_account_info().try_borrow_mut_lamports()? += 1_000_000_000;
                **escrow.to_account_info().try_borrow_mut_lamports()? -= 1_000_000_000;
                escrow.balance -= 1;
            }
        } else {
            **buyer.to_account_info().try_borrow_mut_lamports()? += escrow.to_account_info().lamports();
            **escrow.to_account_info().try_borrow_mut_lamports()? = 0;
            escrow.balance = 0;
        }
        Ok(())
    }

    pub fn end_subscription_by_buyer(ctx: Context<EndSubscriptionByBuyer>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let seller = &ctx.accounts.seller;
        **seller.to_account_info().try_borrow_mut_lamports()? += escrow.to_account_info().lamports();
        **escrow.to_account_info().try_borrow_mut_lamports()? = 0;
        escrow.balance = 0;
        Ok(())
    }

    pub fn end_subscription_by_server(ctx: Context<EndSubscriptionByServer>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let buyer = &ctx.accounts.buyer;
        **buyer.to_account_info().try_borrow_mut_lamports()? += escrow.to_account_info().lamports();
        **escrow.to_account_info().try_borrow_mut_lamports()? = 0;
        escrow.balance = 0;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct StartSubscription<'info> {
    #[account(init, seeds = [b"escrow", buyer.key().as_ref()], bump, payer = buyer, space = 4096)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExtendSubscription<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct EndSubscriptionByBuyer<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    /// CHECK: This is safe because buyer is verified through the escrow contract logic
    #[account(mut)]
    pub seller: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct EndSubscriptionByServer<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
}

#[derive(Accounts)]
pub struct GetQueryValues<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
}

#[derive(Accounts)]
pub struct Prove<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub seller: Signer<'info>,
    /// CHECK: This is safe because buyer is verified through the escrow contract logic
    #[account(mut)]
    pub buyer: AccountInfo<'info>,
}

#[account]
pub struct Escrow {
    pub buyer: Pubkey,
    pub balance: u64,
    pub query_size: u64,
    pub number_of_blocks: u64,
    pub x: u64,
    // pub g: [u8; 48],  
    // pub v: [u8; 48], 
    // pub u: [u8; 96],
    pub g: u64,
    pub v: u64,
    pub u: u64,
    pub queries: Vec<(u64, u64)>,
    pub bump: u8,
}
