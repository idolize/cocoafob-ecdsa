package com.xk72.cocoafob;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.openssl.PEMReader;

/**
 * Generate and verify CocoaFob licenses. Based on the PHP implementation by Sandro Noel.
 * @author karlvr
 *
 */
public class LicenseGenerator {
	
	private JCEECPrivateKey privateKey;
	private JCEECPublicKey publicKey;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	protected LicenseGenerator() {}
	
	/**
	 * Construct the LicenseGenerator with a URL that points to either the private key or public key.
	 * Pass the private key for making and verifying licenses. Pass the public key for verifying only.
	 * If you this code will go onto a user's machine you MUST NOT include the private key, only include
	 * the public key in this case. 
	 * @param keyURL
	 * @throws IOException
	 */
	public LicenseGenerator(URL keyURL) throws IOException {
		this();
		initKeys(keyURL.openStream());
	}
	
	/**
	 * Construct the LicenseGenerator with an InputStream of either the private key or public key.
	 * Pass the private key for making and verifying licenses. Pass the public key for verifying only.
	 * If you this code will go onto a user's machine you MUST NOT include the private key, only include
	 * the public key in this case.
	 * @throws IOException
	 */
	public LicenseGenerator(InputStream keyInputStream) throws IOException {
		this();
		initKeys(keyInputStream);
	}
	
	private void initKeys(InputStream keyInputStream) throws IOException {
		Object readKey = readKey(keyInputStream);
		if (readKey instanceof KeyPair) {
			KeyPair keyPair = (KeyPair) readKey;
			privateKey = (JCEECPrivateKey) keyPair.getPrivate();
			publicKey = (JCEECPublicKey) keyPair.getPublic();
		} else if (readKey instanceof JCEECPublicKey) {
			publicKey = (JCEECPublicKey) readKey;
		} else {
			throw new IllegalArgumentException("The supplied key stream didn't contain a public or private key: " + readKey.getClass());
		}
	}

	private Object readKey(InputStream privateKeyInputSteam) throws IOException {
		PEMReader pemReader = new PEMReader(new InputStreamReader(new BufferedInputStream(privateKeyInputSteam)));
		try {
			return pemReader.readObject();
		} finally {
			pemReader.close();
		}
	}

	/**
	 * Make and return a license for the given {@link LicenseData}.
	 * @param licenseData
	 * @return
	 * @throws LicenseGeneratorException If the generation encounters an error, usually due to invalid input.
	 * @throws IllegalStateException If the generator is not setup correctly to make licenses.
	 */
	public String makeLicense(LicenseData licenseData) throws LicenseGeneratorException, IllegalStateException {
		if (!isCanMakeLicenses()) {
			throw new IllegalStateException("The LicenseGenerator cannot make licenses as it was not configured with a private key");
		}
		
		final String stringData = licenseData.toLicenseStringData();
		
		try {
			final Signature dsa = Signature.getInstance("SHA256withECDSA", "BC");
			dsa.initSign(privateKey);
			dsa.update(stringData.getBytes("UTF-8"));
			
			final byte[] signed = dsa.sign();
			
			/* base 64 encode the signature */
			byte[] encodedBytes = Base64.getEncoder().encode(signed);
			return new String(encodedBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new LicenseGeneratorException(e);
		} catch (NoSuchProviderException e) {
			throw new LicenseGeneratorException(e);
		} catch (InvalidKeyException e) {
			throw new LicenseGeneratorException(e);
		} catch (SignatureException e) {
			throw new LicenseGeneratorException(e);
		} catch (UnsupportedEncodingException e) {
			throw new LicenseGeneratorException(e);
		}
	}

	/**
	 * Verify the given license for the given {@link LicenseData}.
	 * @param licenseData
	 * @param license
	 * @return Whether the license verified successfully.
	 * @throws LicenseGeneratorException If the verification encounters an error, usually due to invalid input. You MUST check the return value of this method if no exception is thrown.
	 * @throws IllegalStateException If the generator is not setup correctly to verify licenses.
	 */
	public boolean verifyLicense(LicenseData licenseData, String license) throws LicenseGeneratorException, IllegalStateException {
		if (!isCanVerifyLicenses()) {
			throw new IllegalStateException("The LicenseGenerator cannot verify licenses as it was not configured with a public key");
		}
		
		final String stringData = licenseData.toLicenseStringData();
		byte[] decoded = Base64.getDecoder().decode(license.getBytes());

		try {
			Signature dsa = Signature.getInstance("SHA256withECDSA", "BC");
			dsa.initVerify(publicKey);
			dsa.update(stringData.getBytes("UTF-8"));
			return dsa.verify(decoded);
		} catch (NoSuchAlgorithmException e) {
			throw new LicenseGeneratorException(e);
		} catch (NoSuchProviderException e) {
			throw new LicenseGeneratorException(e);
		} catch (InvalidKeyException e) {
			throw new LicenseGeneratorException(e);
		} catch (SignatureException e) {
			throw new LicenseGeneratorException(e);
		} catch (UnsupportedEncodingException e) {
			throw new LicenseGeneratorException(e);
		}
	}
	
	public boolean isCanMakeLicenses() {
		return privateKey != null;
	}
	
	public boolean isCanVerifyLicenses() {
		return publicKey != null;
	}
	
}
