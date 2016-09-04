import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
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

	private String provider = "SunJCE";
	private String algorithm = "AES";
	private String algorithmMode = "CBC";
	private String algorithmPadding = "PKCS5PADDING";
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

	/**
	 * public method that takes a clear text file and sign it with the provided private key
	 * than encode it and storing the values for decoding in the configuration file
	 * this method is using other methods in this class that specify the process 
	 * @param cleartextFile a string representation of the path where the clear text file is stored
	 * @param ciphertextFile a String representation of the path where the encoded file should be stored 
	 * @param configurationFile a String representation of the path and filename, where the configuration values should be stored
	 * @param publicKey a PublicKey object that used to encrypt the symmetric key that needed to decode the file
	 * @param privateKey a PrivateKey object that will be used to sign the clear text file
	 */
	public void SignAndEncrypt(String cleartextFile, String ciphertextFile, String configurationFile, PublicKey publicKey, PrivateKey privateKey){

		try {
	    	//set a properties object
	    	Properties prop = new Properties();
	    	
	    	//Sign the file using the private key and write  in prop object 
	    	signData(privateKey, cleartextFile, prop);
	    	
	    	//encrypt the file and write values in prop object
	    	encrypt(cleartextFile, ciphertextFile, prop, publicKey);
	    	
    		// save properties to the project's root folder
			OutputStream configOutput = new FileOutputStream(configurationFile);
    		prop.store(configOutput, "Cryptographic Configurations");
    		System.out.println("\nconfiguration file was saved in \"" + configurationFile + "\"");
	    	
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * this method is taking a cipher file and decode it using the paramaeters found
	 * in the configuration file
	 * the method also verify that the retrieved file is genuine using the public key provided 
	 * @param cleartextFile a String representation of the path and filename where the resulted decoded file should be stored
	 * @param ciphertextFile a String representation of the path and file name where the cipher file is stored 
	 * @param configurationFile a String representation of the path and file name where the configuration file is stored
	 * @param privateKey a PrivateKey object that unlocks the symmetric key from the configuration file
	 * @param publicKey a PublicKey object that used to verify the authentic of the resulted file
	 * @return a Boolean value confirming whether the resulted file is the authentic file
	 */
	public Boolean decryptAndVerify(String cleartextFile, String ciphertextFile, String configurationFile, PrivateKey privateKey, PublicKey publicKey){

		try {
	        //create properties object, and load the configuration file into it
			Properties prop = new Properties();
	        FileInputStream configInputStream = new FileInputStream(configurationFile);
			prop.load(configInputStream);
			
			// decrypt the encoded file in ciphertextFile and store decoded in cleartextFile
			// use the private key and properties object for values
			decrypt(cleartextFile, ciphertextFile, privateKey, prop);
			
			// return a boolean value which approve, or disapprove that
			// the decoded file was verified using the public key
			return verifySignature(publicKey, cleartextFile, prop);
			
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	/**
	 * encrypt clearTextFile into cipherTextFile
	 * the encryption is made by algorithm that was set in advanced in class private members
	 * the key that used to encrypt the file, is being encrypted also, by the provided Public key
	 * the needed values for decryption are saved in the properties object
	 * @param cleartextFile the clear text file to encode
	 * @param ciphertextFile the result encoded file
	 * @param prop used to store encryption values, relevant for decryption
	 * @param publicKey used to encrypt the symmetric key that is being generated
	 */
	private void encrypt(String cleartextFile, String ciphertextFile, Properties prop, PublicKey publicKey) {
        try {

        	/*
        	 * Step 0. set the input/output streams
        	 */
            FileInputStream fis = new FileInputStream(cleartextFile);
            FileOutputStream fos = new FileOutputStream(ciphertextFile);

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
             * the file is read by a InputStream and written by the previously instantiated CipherOutputStream.
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

            System.out.println("\nfile \"" + cleartextFile + "\" was encrypted to file \"" + ciphertextFile + "\"");
            System.out.println("\nEncryption algorithm: " + cipher.getAlgorithm() + ", algorithm implementation provider: " + cipher.getProvider());
	    } catch (Exception ex) {
	        ex.printStackTrace();
	    }
    }
	
	/**
	 * the method takes the file specified in ciphertextFile, and decode it
	 * the result will be saved in the  cleartextFile
	 * the method uses values from the properties object in order to handle the decryption of the file
	 * the symmetric key that is needed to decode the file, should be found in encrypted form in the properties object
	 * it will be decoded using the private key provided
	 * @param cleartextFile the result clear text file
	 * @param ciphertextFile the input encoded file
	 * @param privateKey a key that needed to decode the symmetric key
	 * @param prop a properties object that retrieved from the configuration file that was generated by the encoding method
	 */
	private void decrypt(String cleartextFile, String ciphertextFile, PrivateKey privateKey, Properties prop){
		try{
        	/*
        	 * Step 0. set the input/output streams
        	 */
            FileInputStream fis = new FileInputStream(ciphertextFile);
            FileOutputStream fos = new FileOutputStream(cleartextFile);
            /*
             * read configuration file
             */
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
            * the file is read by a InputStream and written by the previously instantiated CipherOutputStream.
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
            
            System.out.println("\nfile \"" + ciphertextFile + "\" was decrypted to file \"" + cleartextFile + "\"");
            System.out.println("\nDecryption algorithm: " + cipher.getAlgorithm() + ", algorithm implementation provider: " + cipher.getProvider());
            
		} catch (FileNotFoundException e) {
	        e.printStackTrace();
	    } catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * takes the  byte array data and encode it using RSA algorithm and the provided key
	 * @param data the data to be encrypted
	 * @param key an asymmetric key needed to encrypt the data
	 * @return encoded byte array
	 */
	private byte[] encryptRsaWithKey(byte[] data, Key key){
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
	
	/**
	 * decode the received encoded byte array with RSA algorithm
	 * @param encryptedData encoded byte array
	 * @param key asymmetric key that used to decrypt the data
	 * @return decoded byte array
	 */
	private byte[] decryptRsaWithKey(byte[] encryptedData, Key key){
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
	 * @param bytes byte array to be converted
	 * @return String object of hex representation of the byte array
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
	 * This method converting hex format string to byte array
	 * @param s an hex form representation String
	 * @return byte array that retrived from the hex String
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
	
	/**
	 * method for obtaining a public key key from a keystore
	 * @param keyStorePath the path where the keystore is placed
	 * @param keyStorePassword password needed to unlock the keystore
	 * @param alias the entry name where the public key is stored within the keystore
	 * @return PublicKey that was obtained from the keystore
	 */
	public PublicKey getPublicKeyFromKeyStore(String keyStorePath, char[] keyStorePassword, String alias){
		try {
			//request a KeyStore object relying on the default type
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			
			//open the keystore file as a inputstream object for reading
		    FileInputStream fis = new FileInputStream(keyStorePath);
		    
		    //load the keystore file into the Keystore Object using the provided keystore password
		    keyStore.load(fis, keyStorePassword);
		    
		    //load the certificate from the keystore
		    Certificate cert = keyStore.getCertificate(alias);
		    
		    //load the public key from the certificate
		    PublicKey publicKey = cert.getPublicKey();
		    
		    System.out.println("PublicKey was obtained from " + keyStorePath + ", entry: " + alias);
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
	
	/**
	 * method for obtaining a private key from a keystore
	 * @param keyStorePath the path where the keystore is placed
	 * @param keyStorePassword password needed to unlock the keystore
	 * @param privateKeyAlias the entry name where the private key is stored within the keystore
	 * @param keyPassword a password that required to reach the private key entry
	 * @return PrivateKey object representation that was obtained from the keystore
	 */
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
		    
		    System.out.println("PrivateKey was obtained from " + keyStorePath + ", entry: " + privateKeyAlias);
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
	
	/**
	 * method used to provide signature to the provided file
	 * using the private key
	 * the signature is registered as a value in the properties object
	 * @param privateKey private key needed to sign the data
	 * @param fileName the file path that needs to be sign
	 * @param prop properties object for storing the signature
	 */
	private void signData(PrivateKey privateKey, String fileName, Properties prop){
		try {
			// creating the Signature object
			Signature signature = Signature.getInstance("SHA256withRSA");
			
			// Initializing the object with a private key
			signature.initSign(privateKey);
			
			// read the provided file in sessions 
			FileInputStream fis = new FileInputStream(fileName);
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			
			// sign the file and update with each session
			while ((len = bufin.read(buffer)) >= 0) {
				signature.update(buffer, 0, len);
			}
			
			bufin.close();
			
			//get the signature
			byte[] sig = signature.sign();
			
			//convert signature to hex
			String signatureHex = bytesToHex(sig);
			
			//write it in the properties object
			prop.setProperty("signature", signatureHex);
			
			System.out.println("\nfile: \"" + fileName + "\" was signed with private keys");
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * method to verify a signed file using the public key 
	 * @param publicKey public key that match the private key that initially signed the file
	 * @param fileName the file that was signed
	 * @param prop properties object that contain the signature value
	 * @return a Boolean value which indicate if the signature match the file and the public key (true/false)
	 */
	private Boolean verifySignature(PublicKey publicKey, String fileName, Properties prop){
		try {
			//get the Signature from the properties object
			String hexSignature = prop.getProperty("signature");
			byte[] sig = hexStringToByteArray(hexSignature);
					
			// creating the Signature object
			Signature signature = Signature.getInstance("SHA256withRSA");
			
			// Initializing the object with the public key
			signature.initVerify(publicKey);
			
			// read the provided file in sessions 
			FileInputStream fis = new FileInputStream(fileName);
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			
			// verify the file and update with each session
			while ((len = bufin.read(buffer)) >= 0) {
				signature.update(buffer, 0, len);
			}
			
			bufin.close();
			
			// get the answer (true/false)
			boolean verifies = signature.verify(sig);
			
			System.out.println("\nfile: \"" + fileName + "\" has went through signature verification");
			
			return verifies;
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

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

}
