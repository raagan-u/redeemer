use bitcoin::{
    consensus,
    key::{Keypair, Secp256k1},
    secp256k1::{Message, SecretKey},
    Address, Network, Sequence, TapSighashType, XOnlyPublicKey,
};
use eyre::{bail, Result};
use garden::bitcoin::{
    get_htlc_address, get_redeem_witness,
    htlc::{
        hash::TapScriptSpendSigHashGenerator,
        htlc::get_htlc_leaf_script,
        tx::{build_tx, create_previous_outputs, sort_utxos},
    },
    BitcoinIndexerClient, HTLCLeaf, HTLCParams, Indexer,
};
use sha2::{Digest, Sha256};
use std::str::FromStr;

// ── Hardcoded HTLC parameters ──────────────────────────────────────────────
// TODO: Replace these with your actual values
const INITIATOR_PUBKEY: &str =
    "a5c458c9fa587a6b3ac179079d459209f2f8047f25c8d57b5607358a9847db98";
const REDEEMER_PUBKEY: &str =
    "03c15ad9d33d21a1a7ff75276dd530717988003b977525c726f72b7ccf4dc610";
const SECRET_HASH: &str =
    "3329f2c07954a8723bdc5d59b6381536e8590d01c5bfa5cf1ea3c061e25e5d01";
const SECRET: &str =
    "9e42539f432d695dfc599174b27c2f8549a798d7357e8f30d0fc6d6d4c6a2bf8";
const TIMELOCK: u64 = 144;
const AMOUNT_SATS: u64 = 20_000_000;

// ── Network & Indexer config ───────────────────────────────────────────────
const NETWORK: Network = Network::Bitcoin;
const INDEXER_URL: &str = "https://mempool.space/api";

// ── Fee (fixed, in sats) ──────────────────────────────────────────────────
const FEE_SATS: u64 = 650;

// ── Recipient address (where redeemed funds go) ────────────────────────────
// TODO: Replace with your actual recipient address
const RECIPIENT_ADDRESS: &str = "bc1q4x62ey7lss2v6xyaws2fkvatr0kxrfxnqthzna";

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== BTC HTLC Redeemer Script ===\n");

    // 1. Load private key from env
    let private_key_hex = std::env::var("REDEEMER_PRIVATE_KEY")
        .expect("REDEEMER_PRIVATE_KEY env var not set");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(&private_key_hex)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.x_only_public_key().0;
    println!("Our pubkey: {}", our_pubkey);

    // 2. Build HTLC params
    let initiator_pubkey = XOnlyPublicKey::from_str(INITIATOR_PUBKEY)?;
    let redeemer_pubkey = XOnlyPublicKey::from_str(REDEEMER_PUBKEY)?;

    let secret_hash_bytes: [u8; 32] = hex::decode(SECRET_HASH)?
        .try_into()
        .map_err(|_| eyre::eyre!("Secret hash must be 32 bytes"))?;

    let htlc_params = HTLCParams {
        initiator_pubkey,
        redeemer_pubkey,
        amount: AMOUNT_SATS,
        secret_hash: secret_hash_bytes,
        timelock: TIMELOCK,
    };

    // 3. Validate secret matches secret_hash
    let secret_bytes = hex::decode(SECRET)?;
    let computed_hash = Sha256::digest(&secret_bytes);
    if computed_hash.as_slice() != secret_hash_bytes {
        bail!(
            "Secret hash mismatch!\n  expected: {}\n  computed: {}",
            SECRET_HASH,
            hex::encode(computed_hash)
        );
    }
    println!("Secret hash verified OK");

    // 4. Derive HTLC address
    let htlc_address = get_htlc_address(&htlc_params, NETWORK)?;
    println!("HTLC address: {}", htlc_address);

    // 5. Query UTXOs at the HTLC address
    let indexer = BitcoinIndexerClient::new(INDEXER_URL.to_string(), Some(30))?;
    let utxos = indexer.get_utxos(&htlc_address).await?;

    if utxos.is_empty() {
        bail!("No UTXOs found at HTLC address {}", htlc_address);
    }

    println!("Found {} UTXO(s):", utxos.len());
    for utxo in &utxos {
        println!("  txid: {} vout: {} value: {} sats", utxo.txid, utxo.vout, utxo.value);
    }

    // 6. Parse recipient address
    let recipient = Address::from_str(RECIPIENT_ADDRESS)?
        .require_network(NETWORK)?;

    // 7. Build redeem witness (with signature placeholder)
    let witness = get_redeem_witness(&htlc_params, &secret_bytes)?;

    // 8. Get the redeem leaf script (for sighash computation)
    let redeem_script = get_htlc_leaf_script(&htlc_params, HTLCLeaf::Redeem);

    // 9. Sort UTXOs for deterministic tx construction
    let sorted_utxos = sort_utxos(&utxos);

    // 10. Build the unsigned transaction
    let sighash_type = TapSighashType::SinglePlusAnyoneCanPay;
    let mut tx = build_tx(
        &sorted_utxos,
        &recipient,
        &witness,
        Sequence::MAX,
        sighash_type,
        Some(FEE_SATS),
    )?;

    println!("\nUnsigned tx built with {} input(s) and {} output(s)", tx.input.len(), tx.output.len());

    // 11. Generate sighashes and sign each input
    let leaf_hash = redeem_script.tapscript_leaf_hash();
    let previous_outputs = create_previous_outputs(&sorted_utxos, &htlc_address);

    let mut sighash_generator = TapScriptSpendSigHashGenerator::new(tx.clone(), leaf_hash);

    for (i, prev_out) in previous_outputs.iter().enumerate() {
        let sighash = sighash_generator.with_prevout(i, prev_out, sighash_type)?;

        let message = Message::from_digest_slice(&sighash)?;
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        let schnorr_sig = bitcoin::taproot::Signature {
            signature: sig,
            sighash_type,
        };

        // Replace the signature placeholder in the witness
        let old_witness = &tx.input[i].witness;
        let mut new_witness = bitcoin::Witness::new();

        for (j, item) in old_witness.iter().enumerate() {
            if j == 0 && item == b"add_signature_segwit_v1" {
                // Replace placeholder with actual signature
                new_witness.push(schnorr_sig.serialize().to_vec());
            } else {
                new_witness.push(item.to_vec());
            }
        }

        tx.input[i].witness = new_witness;
    }

    println!("Transaction signed with Schnorr signatures");

    // 12. Serialize and print the raw transaction hex
    let tx_bytes = consensus::serialize(&tx);
    let tx_hex = hex::encode(&tx_bytes);
    let txid = tx.compute_txid();

    println!("\n=== Signed Transaction ===");
    println!("TxID: {}", txid);
    println!("Size: {} bytes", tx_bytes.len());
    println!("Raw hex:\n{}\n", tx_hex);

    // 13. Broadcast
    println!("Broadcasting transaction...");
    match indexer.submit_tx(&tx).await {
        Ok(()) => {
            println!("Transaction broadcast successfully!");
            println!("TxID: {}", txid);
        }
        Err(e) => {
            eprintln!("Broadcast failed: {:#}", e);
            eprintln!("\nThe raw hex has been printed above - you can manually broadcast it.");
        }
    }

    Ok(())
}
