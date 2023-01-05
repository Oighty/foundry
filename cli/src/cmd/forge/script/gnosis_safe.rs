use super;
use ethers::{
    prelude::{Provider, Signer, SignerMiddleware, TxHash, H160},
    providers::{JsonRpcClient, Middleware},
    types::{transaction::eip2718::TypedTransaction,Signature},
    utils::format_units,
};
use eyre::{bail, ContextCompat, WrapErr};
use reqwest::Response;
use serde::{Deserialize, Serialize};

/// The default address to send MultiSend transactions to: 0x998739BFdAAdde7C933B942a68053933098f9EDa
pub const DEFAULT_MULTISEND_CONTRACT: H160 = H160([153, 135, 57, 191, 218, 173, 222, 124, 147, 59, 148, 42, 104, 5, 57, 51, 9, 143, 158, 218]);

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
    pub safe: Address,
    
    pub to: Address,

    pub value: U256,

    pub data: Bytes,

    pub operation: OperationType,

    pub safe_tx_gas: U256,

    pub nonce: U256,

    pub contract_transaction_hash: TxHash,

    pub sender: Address,

    pub signature: Signature, // Likely need to change this type

    pub origin: String,

}

impl SafeTransactionServiceRequest {
    pub fn new(
        safe: Address,
        value: U256,
        data: Bytes,
        safe_tx_gas: U256,
        nonce: U256,
        contract_transaction_hash: TxHash,
        sender: Address,
        signature: Signature,
    ) -> Self {

        let to: Address = DEFAULT_MULTISEND_CONTRACT as Address;
        let operation: OperationType = OperationType::DelegateCall;
        let origin: String = String::from("Foundry Script");

        Self {
            safe,
            to,
            value,
            data,
            operation,
            safe_tx_gas,
            nonce,
            contract_transaction_hash,
            sender,
            signature,
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
        // Sign tranasction
        let signature = signer
        .sign_transaction(
            &tx,
            signer.address() // *tx.from().expect("Tx should have a `from`."), // may need to change this to signer address, tx.from() will be the safe contract address?
        )
        .await
        .wrap_err_with(|| "Failed to sign transaction")?;

        // Update gas estimate
        if has_different_gas_calc(signer.signer().chain_id()) || self.skip_simulation {
            self.estimate_gas(&mut tx, signer.provider()).await?;
        }

        // Get nonce
        let nonce = foundry_utils::next_nonce(*tx.from().expect("no sender"), fork_url, None)
                .await
                .map_err(|_| eyre::eyre!("Not able to query the EOA nonce."))?;

        // Create request
        let sts_req: SafeTransactionServiceRequest = SafeTransactionServiceRequest::new(
            *tx.from().expect("no sender"), // Should we insert the CLI provided safe address here?
            *tx.value().expect("no value"), 
            tx.data().expect("no data").clone(), 
            *tx.gas().expect("gas not set"),
            nonce, 
            tx.hash(&signature) as TxHash,
            signer.address(),
            signature
        );

        // Get the STS url
        let sts_url: String = match signer.signer().chain_id() {
            1 => "https://safe-transaction-mainnet.safe.global".to_string(),
            5 => "https://safe-transaction-goerli.safe.global".to_string(),
            _ => "".to_string(),
        };

        // Send the transaction to the Safe Transaction Service
        let url = format!("{}/v1/safes/{}/multisig-transactions/", &sts_url, tx.from().expect("no sender"));
        let client = reqwest::Client::new();
        let res = client.post(&url)
            .json(&sts_req)
            .send()
            .await
            .unwrap();

        Ok(res)
    }
}