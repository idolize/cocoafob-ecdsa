package com.xk72.cocoafob;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class LicenseGeneratorTest {

	@Test
	public void testPrivateKey() throws IOException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		Assert.assertTrue(lg.isCanMakeLicenses());
		Assert.assertTrue(lg.isCanVerifyLicenses());
	}

	@Test
	public void testPublicKey() throws IOException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("pubkey.pem"));
		Assert.assertFalse(lg.isCanMakeLicenses());
		Assert.assertTrue(lg.isCanVerifyLicenses());
	}
	
	@Test
	public void testMakeLicense() throws IOException, IllegalStateException, LicenseGeneratorException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		LicenseData ld = new LicenseData("Test", "Karl", "karl@example.com");
		String license = lg.makeLicense(ld);
		System.out.println(ld.toLicenseStringData());
		System.out.println(license);
		Assert.assertTrue(license.length() > 0);
	}

	@Test
	public void testMakeLicense2() throws IOException, IllegalStateException, LicenseGeneratorException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		LicenseData ld = new LicenseData("Test", "Karl");
		String license = lg.makeLicense(ld);
		System.out.println(ld.toLicenseStringData());
		System.out.println(license);
		Assert.assertTrue(license.length() > 0);
	}

	@Test
	public void testMakeLicense3() throws IOException, IllegalStateException, LicenseGeneratorException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		LicenseData ld = new LicenseData("Sample Product", "John Doe", "johndoe@example.com");
		String license = lg.makeLicense(ld);
		System.out.println(ld.toLicenseStringData());
		System.out.println(license);
		Assert.assertTrue(license.length() > 0);
	}
	
	@Test
	public void testVerifyLicense() throws IOException, IllegalStateException, LicenseGeneratorException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		LicenseData licenseData = new LicenseData("Test", "Karl", "karl@example.com");
		String license = lg.makeLicense(licenseData);
		boolean verified = lg.verifyLicense(licenseData, license);
		Assert.assertTrue(verified);
	}
	
	@Test
	public void testVerifyLicense2() throws IOException, IllegalStateException, LicenseGeneratorException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		LicenseData licenseData = new LicenseData("Test", "Karl");
		String license = lg.makeLicense(licenseData);
		boolean verified = lg.verifyLicense(licenseData, license);
		Assert.assertTrue(verified);
	}
	
	@Test
	public void testFailedVerifyLicense() throws IOException, IllegalStateException, LicenseGeneratorException {
		LicenseGenerator lg = new LicenseGenerator(getClass().getResource("privkey.pem"));
		LicenseData licenseData = new LicenseData("Test", "Karl");
		Assert.assertTrue(lg.verifyLicense(licenseData, "MEUCIDhwGNouEihL65lgDP0Eia3FveC48NrGn04/GNyXOt/SAiEA2/AWtfDQqvyU3l07fcHnONhh06Cj8gG7fBsxJ7lGBzk="));
		Assert.assertFalse(lg.verifyLicense(licenseData, "MEUCIDhwGNouEihL65lgDP0Eia3FveC48NrGn04/GNyXOt/SAiEA2/AWtfDQqvyU3l07fcHnONhh06Cj8gG7fBsxJ7lGBza="));
		Assert.assertFalse(lg.verifyLicense(licenseData, "MEUCIDhwGNouEihL65lgDP0Eia3FveC48NrGn04/GNyXOt/SAiEA2/AWtfDQqvyU3l07fcHnONhh06Cj8gG7fBsxB7lGBzk="));
	}
	
}
