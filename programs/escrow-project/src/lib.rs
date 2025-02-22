use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
use solana_program::program::invoke;
use anchor_lang::solana_program::sysvar::clock::Clock;
use anchor_lang::solana_program::keccak;
use std::ops::{Add, Mul};
// use bls12_381::{pairing, G1Affine, G2Affine, G1Projective, Scalar};
use bls12_381_plus::{pairing, G1Affine, G2Affine, G1Projective, Scalar};
use sha2::{Digest, Sha256};
// use bls12_381_plus::hash_to_curve::HashToCurve;
use bls12_381_plus::ExpandMsgXmd;

declare_id!("CFvp4pXkyqaEDqgZ6sXy4TP8aVjvxr1ztAZWyG8h1CW");

#[program]
mod escrow_project {
    use super::*;
    
    pub fn start_subscription(
        ctx: Context<StartSubscription>,
        query_size: u64,
        number_of_blocks: u64,
        u: [u8; 48],
        g: [u8; 96],
        v: [u8; 96],
        validate_every: i64, // Timestamp interval
    ) -> Result<Pubkey> {
        let escrow = &mut ctx.accounts.escrow;
        escrow.buyer_pubkey = *ctx.accounts.buyer.key;
        escrow.seller_pubkey = *ctx.accounts.seller.key;
        escrow.query_size = query_size;
        escrow.number_of_blocks = number_of_blocks;
        escrow.validate_every = validate_every;
        escrow.u = u;
        escrow.g = g;
        escrow.v = v;
        escrow.balance = 0;
        escrow.subscription_duration = 0;
        escrow.bump = ctx.bumps.escrow;
        Ok(escrow.key())
    }

    // This was `extend_subscription` previously
    /**
      Added a new parameter `amount`
    **/
    pub fn add_funds_to_subscription(ctx: Context<ExtendSubscription>, amount: u64) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let buyer = &ctx.accounts.buyer;
        let system_program = &ctx.accounts.system_program;
        
        // // Transfer Amount to escrow
        // let escrow_signer_seeds: &[&[u8]] = &[b"escrow", &escrow.buyer.to_bytes(), &[escrow.bump]]; 
        // invoke_signed(
        invoke(
            &system_instruction::transfer(
                &buyer.key(),
                &escrow.key(),
                amount
            ),
            &[buyer.to_account_info(), escrow.to_account_info(), system_program.to_account_info()],
            // &[escrow_signer_seeds],
        )?;
        escrow.balance += amount;
        
        // // Generate query tuples
        // let clock = Clock::get()?.unix_timestamp as u64;
        // escrow.queries.clear();
        // let num_blocks = escrow.number_of_blocks;
        // for i in 0..escrow.query_size.min(10) {
        //     escrow.queries.push(((clock + i) % num_blocks, (clock + i * 7) % 100));
        // }  
        Ok(())
    }

    pub fn generate_queries(ctx: Context<GenerateQueries>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
    
        // Get the current timestamp
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;
    
        // Generate queries
        let queries: Vec<(u128, [u8; 32])> = (0..escrow.query_size)
            .map(|i| {
                let block_index = (current_time + i as i64) % escrow.number_of_blocks as i64;
                let v_i = keccak::hash(&block_index.to_le_bytes()).0; // Generate 32-byte hash
                (block_index as u128, v_i)
            })
            .collect();
    
        escrow.queries = queries;
        escrow.queries_generation_time = current_time;
    
        Ok(())
    }
    
    pub fn get_query_values(ctx: Context<GetQueryValues>) -> Result<Vec<(u128, [u8; 32])>> {
        let escrow = &ctx.accounts.escrow;
        Ok(escrow.queries.clone())
    }

    pub fn prove_subscription(ctx: Context<ProveSubscription>, sigma: [u8; 48], mu: u128) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let seller = &ctx.accounts.seller;
        // let system_program = &ctx.accounts.system_program;
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;
        
        if now < escrow.last_prove_date + escrow.validate_every {
            return Err(ErrorCode::NoValidationNeeded.into());
        }
        // 30*60 = 1800
        if now > escrow.queries_generation_time + 1800 {
            return Err(ErrorCode::GenerateAnotherQuery.into());
        }

        let multiplication_sum = calculate_multiplication(&escrow.queries, escrow.u, mu);
        let g_affine = G2Affine::from_compressed(&escrow.g).unwrap();
        let sigma_affine = G1Affine::from_compressed(&sigma).unwrap();
        let v_affine = G2Affine::from_compressed(&escrow.v).unwrap();
        let multiplication_sum_affine = G1Affine::from(multiplication_sum);
        
        let left_pairing = pairing(&sigma_affine, &g_affine);
        let right_pairing = pairing(&multiplication_sum_affine, &v_affine);
    
        if left_pairing == right_pairing {
            escrow.subscription_duration += 1;
            if escrow.subscription_duration > 5 {
                let transfer_amount = (1.0 + 0.05 * escrow.query_size as f64) as u64;
                **seller.to_account_info().try_borrow_mut_lamports()? += transfer_amount;
                **escrow.to_account_info().try_borrow_mut_lamports()? -= transfer_amount;
                escrow.balance -= transfer_amount;
            }
            escrow.last_prove_date = now;
            Ok(())
        } else {
            Err(ErrorCode::Unauthorized.into())
        }
    }

    pub fn end_subscription_by_buyer(ctx: Context<EndSubscriptionByBuyer>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let buyer = &ctx.accounts.buyer;
        require!(escrow.buyer_pubkey == buyer.key(), ErrorCode::Unauthorized);
        escrow.is_subscription_ended_by_buyer = true;
        Ok(())
    }

    pub fn end_subscription_by_seller(ctx: Context<EndSubscriptionBySeller>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let seller = &ctx.accounts.seller;
        require!(escrow.seller_pubkey == seller.key(), ErrorCode::Unauthorized);
        escrow.is_subscription_ended_by_seller = true;
        Ok(())
    }

    pub fn request_fund(ctx: Context<RequestFund>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let user = &ctx.accounts.user;
        let system_program = &ctx.accounts.system_program;
    
        let now = Clock::get()?.unix_timestamp as u64;
    
        // If the buyer is requesting funds
        if user.key() == escrow.buyer_pubkey {
            require!(
                escrow.is_subscription_ended_by_seller || now > (escrow.last_prove_date + 3 * 86400).try_into().unwrap(),
                ErrorCode::Unauthorized
            );
    
            let transfer_amount = escrow.balance * 1_000_000_000;
            let escrow_signer_seeds: &[&[u8]] = &[b"escrow", &escrow.buyer_pubkey.to_bytes(), &[escrow.bump]];
    
            invoke_signed(
                &system_instruction::transfer(&escrow.key(), &user.key(), transfer_amount),
                &[escrow.to_account_info(), user.to_account_info(), system_program.to_account_info()],
                &[escrow_signer_seeds],
            )?;
    
            escrow.balance = 0;
            return Ok(());
        }
    
        // If the seller is requesting funds
        if user.key() == escrow.seller_pubkey {
            require!(escrow.is_subscription_ended_by_buyer, ErrorCode::Unauthorized);
    
            let transfer_amount = escrow.balance * 1_000_000_000;
            let escrow_signer_seeds: &[&[u8]] = &[b"escrow", &escrow.buyer_pubkey.to_bytes(), &[escrow.bump]];
    
            invoke_signed(
                &system_instruction::transfer(&escrow.key(), &user.key(), transfer_amount),
                &[escrow.to_account_info(), user.to_account_info(), system_program.to_account_info()],
                &[escrow_signer_seeds],
            )?;
    
            escrow.balance = 0;
            return Ok(());
        }
    
        // If none of the conditions are met
        Err(ErrorCode::Unauthorized.into())
    }
    
}


// pub fn perform_hash_to_curve(i: u128) -> G1Affine {
//     let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";
//     let msg = i.to_be_bytes();
//     let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&msg, dst);
//     G1Affine::from(&g)
// }

fn perform_hash_to_curve(i: u128) -> G1Affine {
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let msg = i.to_be_bytes();
    
    // Perform SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(&msg);
    let hash_result = hasher.finalize();
    
    // Convert hash to a valid field element
    let mut field_bytes = [0u8; 48]; 
    field_bytes[..32].copy_from_slice(&hash_result[..32]);
    let hash = Sha256::digest(field_bytes); // 32-byte hash
    let scalar = Scalar::from_bytes(&hash.try_into().unwrap()).unwrap();  // Convert hash to scalar

    // Multiply base point by scalar
    let base_point = G1Affine::generator();
    let g1_projective = base_point.mul(scalar);
    
    G1Affine::from(&g1_projective)
}

fn hex_str_to_scalar(hex_str: &str) -> Scalar {
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    let bytes_array: [u8; 32] = bytes.try_into().expect("Hex string should be 32 bytes long");
    Scalar::from_bytes(&bytes_array).unwrap()
}

pub fn calculate_multiplication(queries: &Vec<(u128, [u8; 32])>, u_compressed: [u8; 48], mu: u128) -> G1Affine {
    let mut multiplication_sum = G1Projective::identity();

    for &(block_index, ref v_i_bytes) in queries {
        let h_i = perform_hash_to_curve(block_index);
        let v_i_scalar = Scalar::from_bytes(v_i_bytes).unwrap();
        multiplication_sum = multiplication_sum.add(h_i.mul(v_i_scalar));
    }

    let u = G1Affine::from_compressed(&u_compressed).unwrap();
    // let u_mul_mu = u.mul(Scalar::from(mu as u64));
    let mu_bytes = mu.to_le_bytes();
    let mu_scalar = Scalar::from_bytes(&mu_bytes[..32].try_into().unwrap()).unwrap();
    let u_mul_mu = u.mul(mu_scalar);

    G1Affine::from(multiplication_sum.add(u_mul_mu)) 
}

#[derive(Accounts)]
pub struct StartSubscription<'info> {
    #[account(init, seeds = [b"escrow", buyer.key().as_ref()], bump, payer = buyer, space = 4096)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    /// CHECK: This is safe.
    #[account(mut)]
    pub seller: AccountInfo<'info>,
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
}

#[derive(Accounts)]
pub struct EndSubscriptionBySeller<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub seller: Signer<'info>,
}

#[derive(Accounts)]
pub struct RequestFund<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub user: Signer<'info>, // Can be buyer or seller
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetQueryValues<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
}

#[derive(Accounts)]
pub struct ProveSubscription<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub seller: Signer<'info>,
}

#[derive(Accounts)]
pub struct GenerateQueries<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Escrow {
    pub buyer_pubkey: Pubkey,
    pub seller_pubkey: Pubkey,
    pub query_size: u64,
    pub number_of_blocks: u64,
    pub u: [u8; 48], 
    pub g: [u8; 96], 
    pub v: [u8; 96],
    pub subscription_duration: u64,
    pub validate_every: i64,
    // pub queries: Vec<(u64, u64)>,
    pub queries: Vec<(u128, [u8; 32])>,
    pub queries_generation_time: i64,
    pub balance: u64,
    pub last_prove_date: i64,
    pub is_subscription_ended_by_buyer: bool,
    pub is_subscription_ended_by_seller: bool,
    pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("No validation needed at this time")]
    NoValidationNeeded,

    #[msg("Generate another query before proving")]
    GenerateAnotherQuery,

    #[msg("Unauthorized operation.")]
    Unauthorized,
}