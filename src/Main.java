import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

	public static void main(String[] args) {

		//providers: 
		//The service provider is defined  here for the sake of the exercise,
		//Oracle recommend that for both historical reasons and by the types of services provided.
		// General purpose applications SHOULD NOT request cryptographic services from specific providers
		Crypter crypter = new Crypter();
		crypter.setProvider("SunJCE");
		crypter.setAlgorithm("AES");
		crypter.setAlgorithmMode("CBC");
		crypter.setAlgorithmPadding("PKCS5PADDING");
		crypter.setKeySize(128);			//for AES, Keysize must be equal to 128, 192, or 256.

		//Specifying Keystore values for both Pooh's keystore and Tigger's Keystore
		String poohKeyStore = "poohkeystore.keystore";
		String poohKeystorePassword = "p00h$t0re";
		String tiggerTrustedCertificateAlias = "tiggertrustedcertificate";
		String tiggerKeyStore = "tiggerkeystore.keystore";
		String tiggerKeystorePassword = "p00h$t0re";
		String tiggerPrivateKeyAlias = "ti99er";
		String tiggerPrivateKeyPassword = "ti99er";

		//getting Tigger's public key from Pooh's keystore
		PublicKey tiggerPublicKey = crypter.getPublicKeyFromKeyStore(poohKeyStore, poohKeystorePassword.toCharArray(), tiggerTrustedCertificateAlias);
		System.out.println("Tigger's public key: " + crypter.bytesToHex(tiggerPublicKey.getEncoded()));
		
		//getting Tigger's private key from Tigger's own keystore
		PrivateKey tiggerPrivateKey = crypter.getPrivateKeyFromKeyStore(tiggerKeyStore, tiggerKeystorePassword.toCharArray(), tiggerPrivateKeyAlias, tiggerPrivateKeyPassword.toCharArray());
		System.out.println("tigger's private key: " + crypter.bytesToHex(tiggerPrivateKey.getEncoded()));
		
		// encrypt the file "cleartext.txt", store the encryption in "ciphertextSymm.txt"
		// save configuration values in "config.properties", including the encrypted symmetric key,
		// and also provided Tigger's public key for encrypting the symmetric key
		crypter.encrypt("cleartext.txt", "ciphertextSymm.txt", "config.properties", tiggerPublicKey);
		
		// decrypt the file "ciphertextSymm.txt", store the decrypted text in "cleartextagain.txt"
		// read configuration values from "config.properties", including the encrypted secret key,
		// also provided Tigger's private key for decrypting the secret key
		crypter.decrypt("cleartextagain.txt", "ciphertextSymm.txt", "config.properties", tiggerPrivateKey);


	}

}
