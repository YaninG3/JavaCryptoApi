import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypter {

	private String provider = null;
	private String algorithm = null;
	private String algorithmMode = null;
	private String algorithmPadding = null;
	private Integer keySize = 128;
	
	final private char[] hexArray = "0123456789ABCDEF".toCharArray();	//used by the bytesToHex()
	/**
	 * Default constructor
	 */
	public Crypter() {
		super();
	}
	/**
	 * @param provider
	 * @param algorithm
	 * @param algorithmMode
	 * @param algorithmPadding
	 * @param keySize
	 */
	public Crypter(String provider, String algorithm, String algorithmMode, String algorithmPadding, Integer keySize) {
		super();
		this.provider = provider;
		this.algorithm = algorithm;
		this.algorithmMode = algorithmMode;
		this.algorithmPadding = algorithmPadding;
		this.keySize = keySize;
	}

	
	public String getProvider() {
		return provider;
	}
	public void setProvider(String provider) {
		this.provider = provider;
	}
	public String getAlgorithm () {
		return algorithm ;
	}
	public void setAlgorithm (String algorithm ) {
		this.algorithm  = algorithm ;
	}
	public Integer getKeySize() {
		return keySize;
	}
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	public String getAlgorithmMode() {
		return algorithmMode;
	}
	public void setAlgorithmMode(String algorithmMode) {
		this.algorithmMode = algorithmMode;
	}
	public String getAlgorithmPadding() {
		return algorithmPadding;
	}
	public void setAlgorithmPadding(String algorithmPadding) {
		this.algorithmPadding = algorithmPadding;
	}

	/**
	 * 
	 * @param key
	 * @param initVector
	 * @param value
	 * @return
	 */
	public void encrypt(String cleartextFile, String ciphertextFile, String configurationFile, PublicKey publicKey) {
        try {

        	/*
        	 * Step 0. set the input/output streams, set the configuration file, and the properties object
        	 */
            FileInputStream fis = new FileInputStream(cleartextFile);
            FileOutputStream fos = new FileOutputStream(ciphertextFile);
        	OutputStream configOutput = new FileOutputStream(configurationFile);
        	Properties prop = new Properties();
        	// store algorithm properties in prop object
        	prop.setProperty("algorithm",algorithm);
        	prop.setProperty("algorithmMode",algorithmMode);
        	prop.setProperty("algorithmPadding", algorithmPadding);
        	
        	//generate a new secureReandome
        	//and use it to obtain random key specifications
        	SecureRandom prng = new SecureRandom();
        	byte[] randomKeySpecByteArr = new byte[keySize / 8];
        	prng.nextBytes(randomKeySpecByteArr);
        	
        	//use key specification to generate secret key object
        	SecretKey secretKey = new SecretKeySpec(randomKeySpecByteArr, algorithm);
        	
        	//encrypt the secret key using the provided public key
        	//and store it to the properties object as hex format 
        	byte[] encrypedSecretKey = encryptRsaWithKey(secretKey.getEncoded(), publicKey);
        	String encrypedSecretKeyHexStr = bytesToHex(encrypedSecretKey);
        	prop.setProperty("keySpec", encrypedSecretKeyHexStr);
        	
			/**
			 * Step 2. Generating an Initialization Vector (IV) 
			 * 		a. Using SecureRandom (PRNG Algorithm - a cryptographically strong pseudo random number)
			 * 			to generate random bits.
			 * 		   The size of the IV matches the blocksize of the cipher (128 bits for AES)
			 * 		b. Construct the appropriate IvParameterSpec object for the data to pass to Cipher's init() method
			 * 
			 * Should save the IV bytes and send it in plaintext with the encrypted data for decrypting the data later
			 */
        	byte[] iv = new byte[keySize / 8];
        	prng.nextBytes(iv);
        	//save iv in hex format
        	String ivHexStr = bytesToHex(iv);
        	prop.setProperty("iv",ivHexStr);
    		// save properties to project root folder
    		prop.store(configOutput, "Cryptographic Configurations");
        	
			/**
			 * Step 3. Create a Cipher by specifying the following parameters
			 * 		a. Algorithm name - here it is AES 
			 * 		b. Mode - here it is CBC mode 
			 * 		c. Padding - e.g. PKCS7 or PKCS5
			 * 		 CBC requires padding
			 * 		string will be: AES/CBC/PKCS5PADDING
			 */
        	Cipher cipher = Cipher.getInstance(algorithm + "/" + algorithmMode + "/" + algorithmPadding, provider);
        	
			/**
			 * Step 4. Initializing the Cipher for Encryption
			 */
        	cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        	
        	/**
        	 * Step 5.
        	 * we instantiate a CipherOutputStream which is an implementation of a secure stream.
        	 * A CipherOutputStream is a FilterOutputStream which encrypts or decrypts the data passing through it
        	 *  The CipherOutputStream gets as first parameter an OutputStream which is used to write the file
        	 *  and as second parameter a fully initialized cipher object to do the encrypting or decrypting.
        	 */
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);


            /**
             * Step 6. The encryption is finally done
             * the file is read by a FileInputStream and written by the previously instantiated CipherOutputStream.
             * The data now is encrypted and written to the file specified by the OutputStream.
             */
            byte[] block = new byte[8];
            int i;
            while ((i = fis.read(block)) != -1){
            	cos.write(block, 0, i);
            }
            cos.close();
            fis.close();
            fos.close();

            
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
    }
	
	public void decrypt(String cleartextFile, String ciphertextFile, String configurationFile, PrivateKey privateKey){
		try{
        	/*
        	 * Step 0. set the input/output streams
        	 */
            FileInputStream fis = new FileInputStream(ciphertextFile);
            FileOutputStream fos = new FileOutputStream(cleartextFile);
            /*
             * read configuration file
             */
            Properties prop = new Properties();
            FileInputStream configInputStream = new FileInputStream(configurationFile);
			prop.load(configInputStream);
			String algorithm = prop.getProperty("algorithm");
			String algorithmMode = prop.getProperty("algorithmMode");
			String algorithmPadding = prop.getProperty("algorithmPadding");
			String ivHexStr = prop.getProperty("iv");
			String encodedKeySpecHexStr = prop.getProperty("keySpec");
			//get the encoded key's byte array from hex string format
            byte[] encodedKeySpec = hexStringToByteArray(encodedKeySpecHexStr);
            //decode the secret key using the provided private key
            byte[] keySpec = decryptRsaWithKey(encodedKeySpec, privateKey);
			/*
			 * prepare the secret key using the key specification retrieved 
			 */
			SecretKey secretKey = new SecretKeySpec(keySpec, algorithm);
			
			/*
			 * prepare the Initialization vector parameter
			 */
			IvParameterSpec iv = new IvParameterSpec(hexStringToByteArray(ivHexStr));
			
			/*
			 * create the Cipher using algorithm parameters from the configuration file, and the provider which is set in the class  
			 */
			Cipher cipher = Cipher.getInstance(algorithm + "/" + algorithmMode + "/" + algorithmPadding, provider);
            
			/*
             * Initialize the cipher to decrypt mode, and send the IV and secret key values
             */
			cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
			
			/*
			 * CipherOutputStream is a FilterOutputStream which encrypts or decrypts the data passing through it
        	 *  The CipherOutputStream gets as first parameter an OutputStream which is used to write the file
        	 *  and as second parameter a fully initialized cipher object to do the decrypting.
			 */
			CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            
			/*
            * the file is read by a FileInputStream and written by the previously instantiated CipherOutputStream.
            * The data now is decrypted and written to the file specified by the OutputStream.
            */
            byte[] block = new byte[8];
            int i;
            while ((i = fis.read(block)) != -1){
            	cos.write(block, 0, i);
            }
            cos.close();
            fis.close();
            fos.close();
            
		} catch (Exception ex) {
	        ex.printStackTrace();
	    }
	}
	
	public byte[] encryptRsaWithKey(byte[] data, Key key){
		try {
			//create a Cipher with RSA algorithm
			Cipher cipher = Cipher.getInstance("RSA");
			
			//initialize cipher in encrypt mode and register the key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			
			// encrypt the data with dofinal()
			byte[] cipherData = cipher.doFinal(data);
			
			return cipherData;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] decryptRsaWithKey(byte[] encryptedData, Key key){
		try {
			//create a Cipher with RSA algorithm
			Cipher cipher = Cipher.getInstance("RSA");
			
			//initialize cipher in decrypt mode and register the key
			cipher.init(Cipher.DECRYPT_MODE, key);
			
			//decrypte the encrypted data using doFinal()
			byte[] cipherData = cipher.doFinal(encryptedData);
			
			return cipherData;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * this method is converting a byte array to hex format String
	 * @param bytes
	 * @return
	 */
	public String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	/**
	 * Thhis method converting hex format string to byte array
	 * @param s
	 * @return
	 */
	public byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public PublicKey getPublicKeyFromKeyStore(String keyStorePath, char[] keyStorePassword, String alias){
		try {
			//request a KeyStore object relying on the default type
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			
			//open the keystore file as a inputstream object for reading
		    FileInputStream fis = new FileInputStream(keyStorePath);
		    
		    //load the keystore file into the Keystore Object using the provided keystore password
		    keyStore.load(fis, keyStorePassword);
		    
		    //load the certificate from the ketstore
		    Certificate cert = keyStore.getCertificate(alias);
		    
		    //load the public key from the certificate
		    PublicKey publicKey = cert.getPublicKey();
		    
		    return publicKey;
		    
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public PrivateKey getPrivateKeyFromKeyStore(String keyStorePath, char[] keyStorePassword, String privateKeyAlias, char[] keyPassword){
		try {
			//request a KeyStore object relying on the default type
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			
			//open the keystore file as a inputstream object for reading
		    FileInputStream fis = new FileInputStream(keyStorePath);
		    
		    //load the keystore file into the Keystore Object using the provided keystore password
		    keyStore.load(fis, keyStorePassword);
		    
		    //create a ProtectionParameter object using the password for private key alias
		    ProtectionParameter protParam = new KeyStore.PasswordProtection(keyPassword);
		    
		    //obtain the private key entry reference by providing the alias password for that entry
		    PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(privateKeyAlias, protParam);
		    
		    //get the private key from the private key entry
		    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		    
		    return privateKey;
		    
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
}
