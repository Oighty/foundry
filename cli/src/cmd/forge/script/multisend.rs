use super::{ScriptArgs, *};
use crate::cmd::forge::script::transaction::TransactionWithMetadata;
use ethers::{
    prelude::H160,
    types::transaction::eip2718::TypedTransaction
};
use eyre;

/// The default address to send MultiSend transactions to: 0x998739BFdAAdde7C933B942a68053933098f9EDa
/// Contract is deployed on most chains
pub const DEFAULT_MULTISEND_CONTRACT: H160 = H160([153, 135, 57, 191, 218, 173, 222, 124, 147, 59, 148, 42, 104, 5, 57, 51, 9, 143, 158, 218]);

impl ScriptArgs {
    pub async fn batch_transactions_in_multisend(
        &self,
        txs: VecDeque<TransactionWithMetadata>,
    ) -> eyre::Result<VecDeque<TransactionWithMetadata>> {
        if txs.len() == 0 {
            eyre::bail!("No transactions to batch");
        }

        // Assumes all broadcasted transactions are from the sender of the first transaction
        let from = Some(txs[0].transaction.from().expect("no sender").clone());

        // Assumes all broadcasted transactions are to the same rpc url
        let rpc_url: Option<RpcUrl> = txs[0].rpc.clone();

        // Track gas estimate for overall batch to use when sending
        let mut gas_estimate = U256::zero();

        // Iterate through transactions and encode them per the MultiSend contract requirements
        let mut batch_tx_data: Vec<u8> = Vec::new();
        for tx in &txs {
            let txn: TypedTransaction = tx.transaction.clone();
            let mut encoded_tx: Vec<u8> = Vec::new();
            encoded_tx.push(0); // Operation Type is CALL: 0x00

            // Address bytes
            if let Some(NameOrAddress::Address(to)) = txn.to() {
                encoded_tx.append(&mut to.as_fixed_bytes().to_vec());
            } else if txn.to().is_none() {
                let to: [u8; 20] = [0; 20];
                encoded_tx.append(&mut to.to_vec());
            } 
            else {
                eyre::bail!("ENS not supported");
            }
            
            // Value bytes
            let mut value: [u8; 32] = [0; 32];
            txn.value().expect("no value").to_little_endian(&mut value);
            encoded_tx.append(&mut value.to_vec());
            
            // Data length and data bytes
            let mut data: Vec<u8> = txn.data().expect("no data").to_vec();
            let mut len: [u8; 32] = [0; 32];
            U256::from(data.len()).to_little_endian(&mut len);
            encoded_tx.append(&mut len.to_vec());
            encoded_tx.append(&mut data);


            batch_tx_data.append(&mut encoded_tx);

            // If using STS, then we estimate gas later rather than use on-chain sims due to issue with having no private key for a safe
            if !self.safe_transaction_service {
                gas_estimate += *txn.gas().expect("no gas");
            }
            
        }

        // Create the MultiSend transaction
        let mut batch_tx = TransactionWithMetadata::from_typed_transaction(
            TypedTransaction::Legacy(
                TransactionRequest {
                    from: from,
                    to: Some(NameOrAddress::Address(DEFAULT_MULTISEND_CONTRACT)),
                    value: Some(U256::from(0)),
                    data: Some(Bytes::from(batch_tx_data)),
                    gas: Some(gas_estimate),
                    ..Default::default()
                }
            )
        );
        batch_tx.rpc = rpc_url;

        // Return a VecDeque with one member to fit into the existing code structure
        let mut batched_txs = VecDeque::new();
        batched_txs.push_back(batch_tx);
        Ok(batched_txs)
    }
}