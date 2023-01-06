use super::{ScriptArgs, sequence::ScriptSequence, *};
use crate::opts::WalletType;
use ethers::{
    prelude::{Signer, SignerMiddleware, TxHash},
    providers::Middleware,
    types::{transaction::eip2718::TypedTransaction, H160},
    core::utils::to_checksum
};
use eyre::WrapErr;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use foundry_common::{try_get_http_provider};
use std::{collections::HashSet, sync::Arc};

// TODO
// [ ] Use Gnosis Gas Estimation instead of RPC call - requires another API call to Gnosis -> Line 129
// [ ] Fix address checksums (not working right for some reason)
// [ ] Some value types in the SafeTransactionServiceRequest struct are not being converted correctly. I'm not positive, but probably Operation and Data
// [ ] STS transactions still generate a "broadcast" log, but it doesn't really mean anything. Probably need to update that or skip when using STS.

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum OperationType {
    Call = 0,
    DelegateCall = 1,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SafeTransactionServiceRequest {
    //     "to": "<checksummed address>",
    //     "value": 0, // Value in wei
    //     "data": "<0x prefixed hex string>",
    //     "operation": 0,  // 0 CALL, 1 DELEGATE_CALL
    //     "safeTxGas": 0,  // Max gas to use in the transaction

    // Used by refund mechanism, not needed here
    //     "gasToken": "<checksummed address>", // Token address (hold by the Safe) to be used as a refund to the sender, if `null` is Ether
    //     "baseGas": 0,  // Gast costs not related to the transaction execution (signature check, refund payment...)
    //     "gasPrice": 0,  // Gas price used for the refund calculation
    //     "refundReceiver": "<checksummed address>", //Address of receiver of gas payment (or `null` if tx.origin)

    //     "nonce": 0,  // Nonce of the Safe, transaction cannot be executed until Safe's nonce is not equal to this nonce
    //     "contractTransactionHash": "string",  // Contract transaction hash calculated from all the field
    //     "sender": "<checksummed address>",  // Owner of the Safe proposing the transaction. Must match one of the signatures
    //     "signature": "<0x prefixed hex string>",  // One or more ethereum ECDSA signatures of the `contractTransactionHash` as an hex string

    // Not required
    //     "origin": "string"  // Give more information about the transaction, e.g. "My Custom Safe app"
    pub safe: String,
    
    pub to: String,

    pub value: U256,

    pub data: Bytes,

    pub operation: OperationType,

    pub safe_tx_gas: U256,

    pub base_gas: U256,

    pub gas_price: U256,

    pub nonce: U256,

    pub contract_transaction_hash: TxHash,

    pub sender: String,

    // pub signature: Signature, // Likely need to change this type

    pub origin: String,

}

impl SafeTransactionServiceRequest {
    pub fn new(
        safe: String,
        to: String,
        operation: OperationType,
        value: U256,
        data: Bytes,
        safe_tx_gas: U256,
        nonce: U256,
        contract_transaction_hash: TxHash,
        sender: String,
        // signature: Signature,
    ) -> Self {

        let origin: String = String::from("Foundry Script");

        Self {
            safe,
            to,
            value,
            data,
            operation,
            safe_tx_gas,
            base_gas: U256::zero(),
            gas_price: U256::zero(),
            nonce,
            contract_transaction_hash,
            sender,
            // signature,
            origin,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SafeTransactionServiceResponse {
    pub safe_tx_hash: TxHash,
}

impl ScriptArgs {
    pub async fn send_transaction_to_sts<T, S>(
        &self,
        mut tx: TypedTransaction,
        signer: &SignerMiddleware<T, S>,
        fork_url: &str,
    ) -> eyre::Result<Response>    
    where
        T: Middleware + 'static,
        S: Signer + 'static,
    {
        // Sign transaction
        let signature = signer
        .sign_transaction(
            &tx,
            signer.address() // *tx.from().expect("Tx should have a `from`."), // may need to change this to signer address, tx.from() will be the safe contract address?
        )
        .await
        .wrap_err_with(|| "Failed to sign transaction")?;

        // Get gas estimate since we are skipping on-chain simulation
        // if has_different_gas_calc(signer.signer().chain_id()) || self.skip_simulation {
        self.estimate_gas(&mut tx, signer.provider()).await?;
        // }

        // Get nonce
        let nonce = foundry_utils::next_nonce(*tx.from().expect("no sender"), fork_url, None)
                .await
                .map_err(|_| eyre::eyre!("Not able to query the EOA nonce."))?;

        // Create request
        let to = if let Some(NameOrAddress::Address(addr)) = tx.to() {
            *addr
        } else if tx.to().is_none() {
            H160::zero()
        } 
        else {
            eyre::bail!("ENS not supported")
        };

        // For now, assume all transactions are calls unless multisends
        let operation = if self.multisend {
            OperationType::DelegateCall
        } else {
            OperationType::Call
        };

        let chain_id = Some(signer.signer().chain_id() as u8);

        let sts_req: SafeTransactionServiceRequest = SafeTransactionServiceRequest::new(
            to_checksum(tx.from().expect("no sender"), chain_id),
            to_checksum(&to, chain_id),
            operation,
            *tx.value().expect("no value"), 
            tx.data().expect("no data").clone(), 
            *tx.gas().expect("gas not set"),
            nonce, 
            tx.hash(&signature) as TxHash,
            to_checksum(&signer.address(), chain_id)
        );

        println!("{:?}", sts_req);

        // Get the STS url
        let sts_url: String = match chain_id.unwrap() {
            1 => "https://safe-transaction-mainnet.safe.global".to_string(),
            5 => "https://safe-transaction-goerli.safe.global".to_string(),
            _ => "".to_string(),
        };

        // Send the transaction to the Safe Transaction Service
        let address_str = to_checksum(tx.from().expect("no sender"), chain_id);
        println!("{}", address_str);
        let url = format!("{}/api/v1/safes/{}/multisig-transactions/", &sts_url, &address_str);
        let client = reqwest::Client::new();
        let res = client.post(&url)
            .json(&sts_req)
            .send()
            .await
            .unwrap();

        Ok(res)
    }

    pub async fn send_transactions_to_sts(
        &self,
        script_sequence: &ScriptSequence,
        fork_url: &str,
        script_wallets: &[LocalWallet],
    ) -> eyre::Result<()> {
        let provider = Arc::new(try_get_http_provider(fork_url)?);

        // Get required address to construct the signer middleware
        let mut required_addresses = HashSet::new();
        required_addresses.insert(self.safe_proposer.unwrap());

        if required_addresses.len() > 1 || script_wallets.len() > 1 {
            eyre::bail!("Only one signer is supported.");
        }

        let local_wallets = self
                    .wallets
                    .find_all(provider.clone(), required_addresses, script_wallets)
                    .await?;

        // Should only be one signer
        let wallet = local_wallets.values().last().wrap_err("Error accessing local wallet when trying to send onchain transaction, did you set a private key, mnemonic or keystore?")?;

        // Iterate through transactions and send to STS
        let txs = script_sequence.transactions.clone();
        
        if txs.len() == 0 {
            eyre::bail!("No transactions to send");
        }

        for tx in txs {
            let res = match wallet {
                WalletType::Local(signer) => self.send_transaction_to_sts(tx.transaction.clone(), signer, fork_url).await?,
                WalletType::Ledger(signer) => self.send_transaction_to_sts(tx.transaction.clone(), signer, fork_url).await?,
                WalletType::Trezor(signer) => self.send_transaction_to_sts(tx.transaction.clone(), signer, fork_url).await?,
                WalletType::Aws(signer) => self.send_transaction_to_sts(tx.transaction.clone(), signer, fork_url).await?,
            };
            println!("STS Response: {:?}", res);
        }

        Ok(())
    }
}