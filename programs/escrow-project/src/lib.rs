use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke_signed, system_instruction};
use solana_program::program::invoke;
use anchor_lang::solana_program::sysvar::clock::Clock;
use anchor_lang::solana_program::keccak;
use std::ops::{Add, Mul};
use bls12_381_plus::{pairing, G1Affine, G2Affine, G1Projective, Scalar};
use sha2::{Digest, Sha256};
use bls12_381_plus::ExpandMsgXmd;
// use bls12_381::{pairing, G1Affine, G2Affine, G1Projective, Scalar, G2Projective};
// use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
use solana_program::sysvar::slot_hashes;

declare_id!("GXSHqMQ9t85xXt2F7HBFC4h2r5qdg7NezrXb6GxwQk9p");

#[program]
mod escrow_project {
    use super::*;
    
    pub fn start_subscription(
        ctx: Context<StartSubscription>,
        subscription_id: u64,
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
        escrow.subscription_id = subscription_id;
        escrow.bump = ctx.bumps.escrow;
        Ok(escrow.key())
    }

    // This was `extend_subscription` previously
    /**
      Added a new parameter `amount`
    **/
    pub fn add_funds_to_subscription(ctx: Context<AddFundsToSubscription>, amount: u64) -> Result<()> {
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
        Ok(())
    }

    pub fn generate_queries(ctx: Context<GenerateQueries>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;

        let slot_hashes = &ctx.accounts.slot_hashes;

        // Get the current timestamp
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;

        require!(
            *slot_hashes.to_account_info().key == slot_hashes::id(),
            ErrorCode::InvalidSlotHashSysvar
        );
        let binding = slot_hashes.to_account_info();
        let data = binding.try_borrow_data()?;
        let num_slot_hashes = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let mut pos = 8;

        // Generate queries
        // let queries: Vec<(u128, [u8; 32])> = (0..escrow.query_size)
        //     .map(|i| {
        //         let block_index = (current_time + i as i64) % escrow.number_of_blocks as i64;
        //         let v_i = keccak::hash(&block_index.to_le_bytes()).0; // Generate 32-byte hash
        //         (block_index as u128, v_i)
        //     })
        //     .collect();

        let mut queries = Vec::new();

        for i in 0..escrow.query_size.min(num_slot_hashes) {
            let slot = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let hash = &data[pos..pos + 32]; // Slot hash (32 bytes)
            pos += 32;
    
            // Use slot as block index and hash as v_i
            queries.push((slot as u128, hash.try_into().unwrap()));
        }

        escrow.queries = queries;
        escrow.queries_generation_time = current_time;
    
        Ok(())
    }
    
    pub fn get_query_values(ctx: Context<GetQueryValues>) -> Result<Vec<(u128, [u8; 32])>> {
        let escrow = &ctx.accounts.escrow;
        Ok(escrow.queries.clone())
    }

    pub fn prove_subscription(ctx: Context<ProveSubscription>, sigma: [u8; 48], mu: [u8; 32]) -> Result<()> {
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

        // let multiplication_sum = calculate_multiplication(&escrow.queries, escrow.u, mu);
        // let g_affine = G2Affine::from_compressed(&escrow.g).unwrap();
        // let sigma_affine = G1Affine::from_compressed(&sigma).unwrap();
        // let v_affine = G2Affine::from_compressed(&escrow.v).unwrap();
        // let multiplication_sum_affine = G1Affine::from(multiplication_sum);
        
        // let left_pairing = pairing(&sigma_affine, &g_affine);
        // let right_pairing = pairing(&multiplication_sum_affine, &v_affine);
    
        // if left_pairing == right_pairing {
        //     escrow.subscription_duration += 1;
        //     if escrow.subscription_duration > 5 {
        //         let transfer_amount = (1.0 + 0.05 * escrow.query_size as f64) as u64;
        //         **seller.to_account_info().try_borrow_mut_lamports()? += transfer_amount;
        //         **escrow.to_account_info().try_borrow_mut_lamports()? -= transfer_amount;
        //         escrow.balance -= transfer_amount;
        //     }

        let g_norm = G2Affine::from_compressed(&escrow.g).unwrap();
        let v_norm = G2Affine::from_compressed(&escrow.v).unwrap();
        let u = G1Affine::from_compressed(&escrow.u).unwrap();

        let mu_scalar = Scalar::from_bytes(&mu).unwrap();
        let sigma_affine = G1Affine::from_compressed(&sigma).unwrap();

        let all_h_i_multiply_vi = compute_h_i_multiply_vi(&escrow.queries);
        let u_multiply_mu = u.mul(mu_scalar);
        
        let multiplication_sum = all_h_i_multiply_vi.add(&u_multiply_mu);
        let multiplication_sum_affine = G1Affine::from(multiplication_sum);
        
        let left_pairing = pairing(&sigma_affine, &g_norm);
        let right_pairing = pairing(&multiplication_sum_affine, &v_norm);
        
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
        let escrow = &ctx.accounts.escrow;
        let user = &ctx.accounts.user;
        let system_program = &ctx.accounts.system_program;
    
        let now = Clock::get()?.unix_timestamp as u64;
        
        msg!("Subscription Id from program {}", escrow.subscription_id);

        // If the buyer is requesting funds
        if user.key() == escrow.buyer_pubkey {
            require!(
                escrow.is_subscription_ended_by_seller || now > (escrow.last_prove_date + 3 * 86400).try_into().unwrap(),
                // escrow.is_subscription_ended_by_seller || now > (escrow.last_prove_date + 180).try_into().unwrap(), // 3 mins for testing
                ErrorCode::Unauthorized
            );
    
            let transfer_amount = escrow.balance;

            **ctx.accounts.user.try_borrow_mut_lamports()? = ctx
                .accounts
                .user
                .lamports()
                .checked_add(transfer_amount)
                .ok_or(ErrorCode::AmountOverflow)?;
            
            **ctx
                .accounts
                .escrow
                .to_account_info()
                .try_borrow_mut_lamports()? = ctx
                .accounts
                .escrow
                .to_account_info()
                .lamports()
                .checked_sub(transfer_amount)
                .ok_or(ErrorCode::InsufficientFunds)?;

            // escrow.balance = 0;
            return Ok(());
        }
    
        // If the seller is requesting funds
        if user.key() == escrow.seller_pubkey {
            require!(escrow.is_subscription_ended_by_buyer, ErrorCode::Unauthorized);
    
            // let transfer_amount = escrow.balance * 1_000_000_000;
            let transfer_amount = escrow.balance;

            **ctx.accounts.user.try_borrow_mut_lamports()? = ctx
                .accounts
                .user
                .lamports()
                .checked_add(transfer_amount)
                .ok_or(ErrorCode::AmountOverflow)?;
            
            **ctx
                .accounts
                .escrow
                .to_account_info()
                .try_borrow_mut_lamports()? = ctx
                .accounts
                .escrow
                .to_account_info()
                .lamports()
                .checked_sub(transfer_amount)
                .ok_or(ErrorCode::InsufficientFunds)?;
    
            // escrow.balance = 0;

            return Ok(());
        }
    
        // If none of the conditions are met
        Err(ErrorCode::Unauthorized.into())
    }
    
}

// fn convert_u128_to_32_bytes(i: u128) -> [u8; 32] {
//     let mut bytes = [0u8; 32];  // Create a 32-byte array, initially all zeros
//     // Convert the u128 into bytes (16 bytes) and place it in the last 16 bytes of the array
//     bytes[16..32].copy_from_slice(&i.to_be_bytes());  // Using big-endian format

//     bytes
// }

// fn perform_hash_to_curve(i: u128) -> G1Affine {
//     let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";
//     let msg = convert_u128_to_32_bytes(i);
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

// pub fn calculate_multiplication(queries: &Vec<(u128, [u8; 32])>, u_compressed: [u8; 48], mu: u128) -> G1Affine {
//     let mut multiplication_sum = G1Projective::identity();

//     for &(block_index, ref v_i_bytes) in queries {
//         let h_i = perform_hash_to_curve(block_index);
//         let v_i_scalar = Scalar::from_bytes(v_i_bytes).unwrap();
//         multiplication_sum = multiplication_sum.add(h_i.mul(v_i_scalar));
//     }

//     let u = G1Affine::from_compressed(&u_compressed).unwrap();
//     // let u_mul_mu = u.mul(Scalar::from(mu as u64));
//     let mu_bytes = mu.to_le_bytes();
//     let mu_scalar = Scalar::from_bytes(&mu_bytes[..32].try_into().unwrap()).unwrap();
//     let u_mul_mu = u.mul(mu_scalar);

//     G1Affine::from(multiplication_sum.add(u_mul_mu)) 
// }

fn reverse_endianness(input: [u8; 32]) -> [u8; 32] {
    let mut reversed = input;
    reversed.reverse();
    reversed
}

pub fn compute_h_i_multiply_vi(queries: &Vec<(u128, [u8; 32])>) -> G1Projective {
    let mut all_h_i_multiply_vi = G1Projective::identity();

    for (i, v_i_bytes) in queries {
        let h_i = perform_hash_to_curve(*i); // Compute H(i)
        let v_i_scalar = Scalar::from_bytes(&reverse_endianness(*v_i_bytes)).unwrap(); // Convert v_i to Scalar
        let h_i_multiply_v_i = h_i.mul(v_i_scalar); // Compute H(i)^(v_i)

        all_h_i_multiply_vi = all_h_i_multiply_vi.add(&h_i_multiply_v_i);
    }

    all_h_i_multiply_vi
}


#[derive(Accounts)]
pub struct AddFundsToSubscription<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(subscription_id: u64)]
pub struct StartSubscription<'info> {
    #[account(init, seeds = [b"escrow", buyer.key().as_ref(), seller.key().as_ref(), &subscription_id.to_le_bytes()], bump, payer = buyer, space = 4096)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    /// CHECK: This is safe.
    #[account(mut)]
    pub seller: AccountInfo<'info>,
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
    #[account(mut, seeds = [
        b"escrow",
        // user.key().as_ref(),
        escrow.buyer_pubkey.as_ref(),
        escrow.seller_pubkey.as_ref(),
        &escrow.subscription_id.to_le_bytes(),
    ],
    bump,
    close = user,
    )]
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
    /// CHECK: This is the SlotHashes sysvar, used for retrieving recent slot hashes.
    #[account(address = slot_hashes::id())]
    pub slot_hashes: AccountInfo<'info>,
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
    pub subscription_id: u64,
    pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds")]
    InsufficientFunds,

    #[msg("Amount overflow")]
    AmountOverflow,
    
    #[msg("Payment count overflow")]
    PaymentCountOverflow,

    #[msg("No validation needed at this time")]
    NoValidationNeeded,

    #[msg("Generate another query before proving")]
    GenerateAnotherQuery,

    #[msg("Unauthorized operation.")]
    Unauthorized,

    #[msg("Invalid SlotHashes sysvar provided.")]
    InvalidSlotHashSysvar,
}