package sitCoin;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class Transaction {

	public String transactionId;
	public PublicKey sender;
	public PublicKey reciepient;
	public float value;
	public byte[] signature;

	public ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();

	public ArrayList<TransactionOutput> outputs = new ArrayList<TransactionOutput>();

	private static int sequence = 0;

	public Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs) {
		this.sender = from;
		this.reciepient = to;
		this.value = value;
		this.inputs = (inputs != null) ? inputs : new ArrayList<>();
	}

	private String calulateHash() {
		sequence++; // increase the sequence to avoid 2 identical transactions having the same hash
		return StringUtil.applySha256(StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient)
				+ Float.toString(value) + sequence);
	}

	public void generateSignature(PrivateKey privateKey) {
		String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient)
				+ Float.toString(value);
		signature = StringUtil.applyECDSASig(privateKey, data);
	}

	public boolean verifiySignature() {
		String data = StringUtil.getStringFromKey(sender) + StringUtil.getStringFromKey(reciepient)
				+ Float.toString(value);
		return StringUtil.verifyECDSASig(sender, data, signature);
	}

	public boolean processTransaction() {

		if(verifiySignature() == false) {
			System.out.println("#Transaction Signature failed to verify");
			return false;
		}
				
		//gather transaction inputs (Make sure they are unspent):
		for(TransactionInput i : inputs) {
			i.UTXO = SitCoin.UTXOs.get(i.transactionOutputId);
		}

		//check if transaction is valid:
		if(getInputsValue() < SitCoin.minimumTransaction) {
			System.out.println("#Transaction Inputs to small: " + getInputsValue());
			return false;
		}

		// Generate Transaction Output
		float leftOver = getInputsValue();
		transactionId = calulateHash();
		outputs.add(new TransactionOutput(this.reciepient, value, transactionId));
		outputs.add(new TransactionOutput(this.reciepient, leftOver, transactionId));

		// Adding outputs to Unspent List
		for (TransactionOutput o : outputs) {
			SitCoin.UTXOs.put(o.id, o);
		}

		// Remove transaction inputs from UTXO Lists as spent
		for (TransactionInput i : inputs) {
			if (i.UTXO == null)
				continue;
			SitCoin.UTXOs.remove(i.UTXO.id);
		}

		return true;

	}

	// Return Sum of UTXO(Inputs) values
	public float getInputsValue() {
		float total = 0;
		for (TransactionInput i : inputs) {
			if (i.UTXO == null)
				continue;
			total = total + i.UTXO.value;
		}
		return total;
	}

	public float getOutputsValue() {
		float total = 0;
		for (TransactionOutput o : outputs) {
			total = total + o.value;
		}
		return total;
	}
}
