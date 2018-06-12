/**
 * 
 */
package BtcWallet;


import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.*;
import javacard.security.MessageDigest;

/**
 * @author EdiblE
 *
 */
public class BtcCard extends Applet {
	
    final static byte BtcCard_CLA = (byte)0x80;
   
    final static byte GET_ID = (byte)0x81;
    final static byte GET_NAME = (byte)0x82;
    final static byte MINE = (byte)0x83;
    final static byte GENERATE_WALLET = (byte)0x84;
    
	final static byte MAX_LENGTH = (byte)0xFE;
	byte s;
	MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
	

	byte[] tempBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// 256 byte buffer to hold the incoming data (which will be hashed)
	byte[] dataBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// the DER prefix for a SHA256 hash in a PKCS#1 1.5 signature
	byte[] nonce = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// the nonce
	byte[] keyBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// 256 byte buffer to hold the key
	byte[] keyTempBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// 256 byte buffer to hold the key
	byte[] finalKeyBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
	// 256 byte buffer to hold the key
	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new BtcCard().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		byte[] buf = apdu.getBuffer();
		if(buf[ISO7816.OFFSET_CLA] != BtcCard_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		switch (buf[ISO7816.OFFSET_INS]) {
		case GET_ID:
			getID(apdu);
			break;
		case GET_NAME:
			getName(apdu);
			break;
		case MINE:
			mine(apdu);
			break;
		case GENERATE_WALLET:
			generateWallet(apdu);
			break;
			
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void getID(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		
		short le = apdu.setOutgoing();
		
		if(le < 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		apdu.setOutgoingLength((byte)5);
		
		buffer[0] = (byte)0x66;
		buffer[1] = (byte)0x66;
		buffer[2] = (byte)0x66;
		buffer[3] = (byte)0x66;
		buffer[4] = (byte)0x66;

		apdu.sendBytes((short)0, (short)5);
	}
	
	private void getName(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		
		short le = apdu.setOutgoing();
		
		if(le < 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		apdu.setOutgoingLength((byte)6);
		
		buffer[0] = (byte)0x66;
		buffer[1] = (byte)0x66;
		buffer[2] = (byte)0x66;
		buffer[3] = (byte)0x66;
		buffer[4] = (byte)0x66;
		buffer[5] = (byte)0x66;

		apdu.sendBytes((short)0, (short)6);
	}
	
	private void mine(APDU apdu){
		
		short i;
		byte j,k;
		byte count;
		byte successFlag = 0;
		short nonceLength = 0;
		short maxLength = 0;
		short allLength = 0;
		
		
		
		byte[] buffer = apdu.getBuffer();
		byte difficulty = (byte)buffer[ISO7816.OFFSET_P1];
		short bytesRead = apdu.setIncomingAndReceive();
		if(bytesRead > 256)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		for(i=0;i<bytesRead;i++){
			dataBuffer[i] = (byte)(buffer[ISO7816.OFFSET_CDATA + i] & 0x00FF);
		}

		nonceLength = 0;
		maxLength = 0;
		while(maxLength < 6){

			for(i=bytesRead;i<bytesRead+maxLength;i++){
				dataBuffer[i] = (byte)nonce[i-bytesRead];
			}
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, dataBuffer, (short)0, bytesRead);
			Util.arrayCopyNonAtomic(nonce, (short)0, dataBuffer, bytesRead, maxLength);
			allLength = bytesRead;
			allLength += maxLength;
			pkcs1_sha1(dataBuffer,(short)0,allLength);
			
			j = 0;
			count = 0;
			successFlag = 1;
			while(count < difficulty & successFlag == 1){
				for(k=7;k>=0;k--){
					if(count >= difficulty){
						break;
					}
					s = (byte)((tempBuffer[j] >> k) & 1);
					if((((tempBuffer[j] >> k) & 1) | 0) == 1){
						successFlag = 0;
						break;
					}
					count++;
				}
				j++;
			}
			
			if(successFlag == 1){
				break;
			}
			
			while(nonce[nonceLength] == -127){
				nonce[nonceLength] = 0;
				nonceLength ++;
			}
			nonce[nonceLength]++;
			
			if((nonceLength + 1) > maxLength)maxLength = (short)(nonceLength + 1);
			nonceLength = 0;
		}
		count = 0;
		
		if(successFlag == 1){
			short le = apdu.setOutgoing();
			
			if(le < 2)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
			apdu.setOutgoingLength((byte)27);
			
			for(i=0;i<20;i++)
			buffer[i] = tempBuffer[i];
			
			buffer[20] = 0;
			
			for(i=21;i<27;i++)
			buffer[i] = nonce[i-21];
			
			apdu.sendBytes((short)0, (short)27);
		}
		
		for(i=0;i<maxLength;i++)
		{
			nonce[i] = 0;
		}
	}
	
	public void pkcs1_sha1(byte[] toSign, short bOffset, short bLength)
	{
		// clear the hasher
		md.reset();
		// now add the actual hash
		md.doFinal(toSign, bOffset, bLength, tempBuffer, (short)0);
		// the value to sign is in tempBuffer
	}
	
	
	private void generateWallet(APDU apdu){
		
		short i;
		Ripemd160.init();
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		if(bytesRead > 256)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		for(i=0;i<bytesRead;i++){
			keyBuffer[i] = (byte)(buffer[ISO7816.OFFSET_CDATA + i] & 0x00FF);
		}
		pkcs1_sha1(keyBuffer,(short)0,bytesRead);
		for(i=0;i<20;i++){
			keyBuffer[i] = tempBuffer[i];
		}
		Ripemd160.hash32(keyBuffer, (short)0, tempBuffer, (short)0);
		for(i=0;i<20;i++){
			keyBuffer[i] = tempBuffer[i];
		}
		
		for(i=0;i<20;i++){
			keyTempBuffer[i] = tempBuffer[i];
		}
		pkcs1_sha1(keyTempBuffer,(short)0,bytesRead);
		for(i=0;i<20;i++){
			keyTempBuffer[i] = tempBuffer[i];
		}
		pkcs1_sha1(keyTempBuffer,(short)0,bytesRead);
		
		
		for(i=0;i<20;i++){
			keyBuffer[20-i]=keyBuffer[19-i];
		}
		keyBuffer[0]=(byte)0;
		for(i=0;i<4;i++){
			keyBuffer[21+i]=keyTempBuffer[i];
		}
		
		i = Base58.encode(keyBuffer, (short)0, (short)25, finalKeyBuffer, (short)0, keyTempBuffer, (short)0);

		short le = apdu.setOutgoing();
		
		if(le < 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		apdu.setOutgoingLength((byte)50);
		
		for(i=0;i<50;i++)
		buffer[i] = finalKeyBuffer[i];
		
		apdu.sendBytes((short)0, (short)50);
		
		for(i=0;i<200;i++){
			keyBuffer[i]=(byte)0;
			finalKeyBuffer[i]=(byte)0;
			keyTempBuffer[i]=(byte)0;
			tempBuffer[i]=(byte)0;
		}
	}
	
	
	
}
