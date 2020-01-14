package org.tinyradius.packet;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.tinyradius.util.RadiusException;

public class MessageAuthenticator {

	protected static final int MESSAGE_AUTHENTICATOR_ATTRIBUTE_TYPE = 80;
	protected static final byte[] NULL_BYTES = new byte[16];
	private static final String ALGORITHM = "HmacMD5";

    protected static byte[] calculate(RadiusPacket packet, int packetLength, byte[] attributes, String sharedSecret) throws RadiusException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(bos);
		try {
			dos.writeByte(packet.getPacketType());
			dos.writeByte(packet.getPacketIdentifier());
			dos.writeShort(packetLength);
			dos.write(packet.getAuthenticator());
			dos.write(attributes);
			dos.flush();

            SecretKeySpec key = new SecretKeySpec((sharedSecret).getBytes("UTF-8"), ALGORITHM);
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            byte[] bytes = mac.doFinal(bos.toByteArray());
            return bytes;
		} catch(IOException e) {
		} catch(NoSuchAlgorithmException e) {
		} catch(InvalidKeyException e) { }
		throw new RadiusException("failed to compute message authenticator attribute");
    }

}
