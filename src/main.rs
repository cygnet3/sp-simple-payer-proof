use std::{collections::HashMap, str::FromStr};

use bitcoin::{Amount, Transaction, consensus::encode::deserialize_hex, secp256k1::Scalar};
use silentpayments::{
    Network, SharedSecret, SilentPaymentCode, SpVersion,
    receiving::{Label, Receiver},
    secp256k1::{PublicKey, XOnlyPublicKey},
};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// A hex string of the transaction bytes. This transaction is scanned for outputs.
    #[arg(long)]
    pub transaction: String,

    /// The silent payment address of the receiver.
    #[arg(long)]
    pub address: String,

    /// The payment proof, a.k.a the transaction shared secret. This is provided by the sender.
    #[arg(long)]
    pub proof: PublicKey,
}

fn main() {
    let args = Args::parse();

    let tx: Transaction = deserialize_hex(&args.transaction).unwrap();

    let recipient_address = SilentPaymentCode::from_str(&args.address).unwrap();

    let shared_secret: SharedSecret = args.proof.into();

    // note: normally a silent payments receiver must know the change label while scanning.
    // in this case, since we know for certain we're not looking for a change output, we just
    // provide a dummy label.
    // However, this should not be done normally!
    let dummy_label: Label = Scalar::ONE.into();
    let receiver = Receiver::new(
        SpVersion::ZERO,
        recipient_address.scan_key(),
        recipient_address.m_pubkey(),
        dummy_label,
        Network::Mainnet,
    )
    .unwrap();

    // collect all taproot outputs from the transaction
    let possible_sp_outputs: HashMap<XOnlyPublicKey, Amount> = tx
        .output
        .into_iter()
        .filter_map(|txout| {
            if txout.script_pubkey.is_p2tr() {
                // the first 2 bytes are OP_1 and OP_PUSHBYTES_32.
                // the next 32 bytes after are the taproot x-only public key.

                Some((
                    XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..]).unwrap(),
                    txout.value,
                ))
            } else {
                None
            }
        })
        .collect();

    let pubkeys_to_check: Vec<_> = possible_sp_outputs.keys().cloned().collect();

    // scan the output keys from this transaction, using the shared secret.
    // Normally this shared secret has to be calculated by the recipient, using the public tweak
    // (outpoint_hash * A_sum), multiplied by the recipients scan_sk.
    // But in this case, it is provided by the sender as proof.
    let found_outputs = receiver
        .scan_transaction(&shared_secret, &pubkeys_to_check)
        .unwrap()
        .remove(&None);

    if let Some(found_outputs) = found_outputs {
        println!();
        println!("Transaction contains outputs for this shared secret!");
        for (idx, output) in found_outputs.keys().enumerate() {
            if let Some(amount) = possible_sp_outputs.get(output) {
                println!("output {}: {} sats", idx, amount.to_sat());
            }
        }
    } else {
        println!("No relevant outputs found for this shared secret");
    }
}
