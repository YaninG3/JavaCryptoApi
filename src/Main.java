import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

/**
 * In this program, we demonstrate the use of the Crypter class we developed
 * in the demonstration, Pooh is trying to send Tigger a text file.
 * Pooh encrypt the file, and Tigger decrypt it 
 * @author Gani Yanin & Demitry Hermetz 
 *
 */
public class Main {

	public static void main(String[] args) {

		// provider explanation: 
		// The service provider is defined  here for the sake of the exercise,
		// Oracle recommend that for both historical reasons and by the types of services provided.
		// General purpose applications SHOULD NOT request cryptographic services from specific providers
		// nonetheless, we chose the BouncyCastle Provider
		// a. since it has many more cipher suites and algorithms than the default JCE provided by Sun.
		// b. also, Bouncy Castle is Australian in origin, and therefore is not subject to the Export of cryptography from the United States.
		// the algorithm AES and the mode CBC were instructed in the exercise
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Crypter crypter = new Crypter();
		crypter.setProvider("BC");
		
		crypter.setAlgorithm("AES");
		crypter.setAlgorithmMode("CBC");
		crypter.setAlgorithmPadding("PKCS5PADDING");
		crypter.setKeySize(128);			//for AES, Keysize must be equal to 128, 192, or 256.

		System.out.println("\n\n------ Encryption Phase ------\n\n");
		//Specifying Keystore values for Pooh's keystore
		String poohKeyStore = "poohkeystore.keystore";
		String poohKeystorePassword = "p00h$t0re";
		String poohPrivateKeyAlias = "PoohKey";
		String poohPrivateKeyPassword = "W1nn1ep00h";
		String tiggerTrustedCertificateAlias = "tiggertrustedcertificate";

		//getting Tigger's public key from Pooh's keystore
		PublicKey tiggerPublicKey = crypter.getPublicKeyFromKeyStore(poohKeyStore, poohKeystorePassword.toCharArray(), tiggerTrustedCertificateAlias);
		System.out.println("Tigger's public key: " + crypter.bytesToHex(tiggerPublicKey.getEncoded()));
		
		//getting Pooh's private key from his own keystore
		PrivateKey poohPrivateKey = crypter.getPrivateKeyFromKeyStore(poohKeyStore, poohKeystorePassword.toCharArray(), poohPrivateKeyAlias, poohPrivateKeyPassword.toCharArray());
		System.out.println("Pooh's private key: " + crypter.bytesToHex(poohPrivateKey.getEncoded()));
		
		
		// encrypt the file "cleartext.txt", store the encryption in "ciphertextSymm.txt"
		// save configuration values in "config.properties", including the encrypted symmetric key,
		// and also provided Tigger's public key for encrypting the symmetric key
		crypter.SignAndEncrypt("cleartext.txt", "ciphertextSymm.txt", "config.properties", tiggerPublicKey, poohPrivateKey);
		
		System.out.println("\n\n------ Decryption Phase ------\n\n");
		//Specifying Keystore values for Tigger's keystore
		String tiggerKeyStore = "tiggerkeystore.keystore";
		String tiggerKeystorePassword = "p00h$t0re";
		String tiggerPrivateKeyAlias = "TiggerKey";
		String tiggerPrivateKeyPassword = "ti99er";
		String poohTrustedCertificateAlias = "PoohTrustedCertificate";
		
		//getting Pooh's public key from Tigger's keystore
		PublicKey poohPublicKey = crypter.getPublicKeyFromKeyStore(tiggerKeyStore, tiggerKeystorePassword.toCharArray(), poohTrustedCertificateAlias);
		System.out.println("pooh's public key: " + crypter.bytesToHex(poohPublicKey.getEncoded()));
		
		//getting Tigger's private key from Tigger's own keystore
		PrivateKey tiggerPrivateKey = crypter.getPrivateKeyFromKeyStore(tiggerKeyStore, tiggerKeystorePassword.toCharArray(), tiggerPrivateKeyAlias, tiggerPrivateKeyPassword.toCharArray());
		System.out.println("tigger's private key: " + crypter.bytesToHex(tiggerPrivateKey.getEncoded()));
		
		// decrypt the file "ciphertextSymm.txt", store the decrypted text in "cleartextagain.txt"
		// read configuration values from "config.properties", including the encrypted secret key,
		// also provided Tigger's private key for decrypting the secret key
		System.out.println("use the decryptAndVerify method");
		Boolean verified = crypter.decryptAndVerify("cleartextagain.txt", "ciphertextSymm.txt", "config.properties", tiggerPrivateKey, poohPublicKey);
		System.out.println("\nIs received file was verified?: " + verified);

	}

}
