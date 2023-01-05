use super;
use crate::cmd::forge::script::transaction::TransactionWithMetadata;
use ethers::{
    prelude::H160,
    types::transaction::eip2718::TypedTransaction
};
use eyre;

impl ScriptArgs {
    pub async fn batch_transactions_in_multisend(
        &self,
        txs: VecDeque<TransactionWithMetadata>,
    ) -> eyre::Result<VecDeque<TransactionWithMetadata>> {
        // If batch is being sent to STS, then assume it's from the provided safe address
        // Otherwise, assumes all broadcasted transactions are from the sender of the first transaction
        let from = if self.sts {
            self.from_safe
        } else {
            txs[0].transaction.from().expect("no sender")
        };

        // Assumes all broadcasted transactions are to the same rpc url
        let rpc_url: Option<RpcUrl> = txs[0].rpc().expect("no rpc url");

        // Track gas estimate for overall batch to use when sending
        let mut gas_estimate = U256::zero();

        // Iterate through transactions and encode them per the MultiSend contract requirements
        let mut batch_tx_data: Vec<u8> = Vec::new();
        for tx in &txs {
            let txn: TypedTransaction = tx.transaction();
            let mut encoded_tx: Vec<u8> = Vec::new();
            encoded_tx.push(0); // Operation Type is CALL: 0x00

            // Address bytes
            if let Some(NameOrAddress::Address(to)) = txn.to() {
                encoded_tx.append(&mut to.as_fixed_bytes().to_vec());
            } else if tx.to().is_none() {
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
            gas_estimate += txn.gas().expect("no gas");
        }

        // Create the MultiSend transaction
        let mut batch_tx = TransactionWithMetadata::from_typed_transaction(
            TypedTransaction::Legacy(
                TransactionRequest {
                    from: Some(*from),
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