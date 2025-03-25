//
//  CocoaFobTests.swift
//  CocoaFobTests
//
//  Created by Gleb Dolgich on 05/07/2015.
//  Copyright © 2015 PixelEspresso. All rights reserved.
//

import XCTest

@testable import CocoaFob

class CocoaFobTests: XCTestCase {

    let privateKeyPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEILrc1X3E2snKdBwQF0paL+DTTlxK75NTOmoVJaIOTzIxoAoGCCqGSM49
        AwEHoUQDQgAEA9Uq9J5ayrQUtgx//WATsundUgXCGXAl+oWqdr/Fk6iGVTm6joS3
        s1DKZuQ8FUzoWMMJ3znfokLEk30K84b5Yg==
        -----END EC PRIVATE KEY-----
        """

    let publicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA9Uq9J5ayrQUtgx//WATsundUgXC
        GXAl+oWqdr/Fk6iGVTm6joS3s1DKZuQ8FUzoWMMJ3znfokLEk30K84b5Yg==
        -----END PUBLIC KEY-----
        """

    func testInitGeneratorPass() {
        let keygen = LicenseGenerator(privateKeyPEM: privateKeyPEM)
        XCTAssertNotNil(keygen?.privKey)
    }

    func testInitGeneratorFail() {
        let privateKeyPEM = "-----BEGIN DSA PRIVATE KEY-----\n"
        let keygen = LicenseGenerator(privateKeyPEM: privateKeyPEM)
        XCTAssert(keygen == nil)
    }

    func testGetNameData() {
        let keygen = LicenseGenerator(privateKeyPEM: privateKeyPEM)
        XCTAssertNotNil(keygen?.privKey)
        let name = "Joe Bloggs"
        let nameData = keygen?.getNameData(name)
        XCTAssertNotNil(nameData)
        if let nameData_ = nameData {
            let nameFromDataAsNSString = NSString(
                data: nameData_,
                encoding: String.Encoding.utf8.rawValue
            )
            XCTAssertNotNil(nameFromDataAsNSString)
            let nameFromData = String(nameFromDataAsNSString!)
            XCTAssertEqual(nameFromData, name)
        }
    }

    func testGeneratePass() {
        let keygen = LicenseGenerator(privateKeyPEM: privateKeyPEM)
        XCTAssertNotNil(keygen?.privKey)
        do {
            if let actual = try keygen?.generate("Joe Bloggs") {
                print(actual)
                XCTAssert(actual != "")
            }
        } catch {
            XCTAssert(false, "\(error)")
        }
    }

    func testInitVerifierPass() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
    }

    func testInitVerifierFail() {
        let publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n"
        let keychecker = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNil(keychecker?.pubKey)
    }

    func testVerifyPass() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey =
            "MEYCIQD55PlsLnMFD7DcVSJ6rbPmRpbF450SX5nizR8NBt3wAQIhAPma+XJjOpHC87Rp1C+m8Lr01PXm5QGj+vQhwDBwX+t7"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertTrue(result)
    }

    func testVerifyBadNameFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs II"
        let regKey =
            "MEYCIQD55PlsLnMFD7DcVSJ6rbPmRpbF450SX5nizR8NBt3wAQIhAPma+XJjOpHC87Rp1C+m8Lr01PXm5QGj+vQhwDBwX+t7"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyBadKeyFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey = "foo bar"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyEmptyKeyFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey = ""
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyEmptyNameAndKeyFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = ""
        let regKey = ""
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyEmptyNameFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = ""
        let regKey =
            "MEYCIQD55PlsLnMFD7DcVSJ6rbPmRpbF450SX5nizR8NBt3wAQIhAPma+XJjOpHC87Rp1C+m8Lr01PXm5QGj+vQhwDBwX+t7"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testGenerateAndVerifyPass() {
        let keygen = LicenseGenerator(privateKeyPEM: privateKeyPEM)
        XCTAssertTrue(keygen != nil)
        XCTAssertNotNil(keygen?.privKey)
        let name = "Joe Bloggs"
        do {
            if let regKey = try keygen?.generate(name) {
                let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
                XCTAssertNotNil(verifier?.pubKey)
                let result = verifier?.verify(regKey, forName: name) ?? false
                XCTAssertTrue(result)
            }
        } catch {
            XCTAssert(false, "\(error)")
        }
    }

    func testVerifyAdditionalTrailingCharactersFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey =
            "MEYCIQD55PlsLnMFD7DcVSJ6rbPmRpbF450SX5nizR8NBt3wAQIhAPma+XJjOpHC87Rp1C+m8Lr01PXm5QGj+vQhwDBwX+t7XX"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyAdditionalLeadingCharactersFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey =
            "XXMEYCIQD55PlsLnMFD7DcVSJ6rbPmRpbF450SX5nizR8NBt3wAQIhAPma+XJjOpHC87Rp1C+m8Lr01PXm5QGj+vQhwDBwX+t7"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }
}
