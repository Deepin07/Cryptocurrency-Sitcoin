package sitCoin;

import java.security.PublicKey;

public class TransactionOutput {
	
	public String id;
	public PublicKey reciepent;
	public float value;
	public String parentTransactionId;
	
	
	public TransactionOutput(PublicKey reciepent, float value, String parentTransactionId) {
		this.reciepent = reciepent;
		this.value = value;
		this.parentTransactionId = parentTransactionId;
		this.id = StringUtil.applySha256(StringUtil.getStringFromKey(reciepent)+Float.toString(value)+parentTransactionId);
	}
	
	public boolean isMine(PublicKey publicKey) {
		return (publicKey == reciepent);
	}
}
