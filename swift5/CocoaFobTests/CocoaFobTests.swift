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

    func testToReadableKeyPass() {
        let unreadable =
            "GAWAEFCDW3KH4IP5E2DHKUHPQPN5P52V43SVGDYCCRS64XXNRYBBCT44EOGM3SKYV4272LQ6LQ======"
        let expected =
            "GAWAE-FCDW3-KH49P-5E2DH-KUHPQ-PN5P5-2V43S-VGDYC-CRS64-XXNRY-BBCT4-4E8GM-3SKYV-4272L-Q6LQ"
        let actual = unreadable.cocoaFobToReadableKey()
        XCTAssertEqual(actual, expected)
    }

    func testFromReadableKeyPass() {
        let readable =
            "GAWAE-FCDW3-KH49P-5E2DH-KUHPQ-PN5P5-2V43S-VGDYC-CRS64-XXNRY-BBCT4-4E8GM-3SKYV-4272L-Q6LQ"
        let expected = "GAWAEFCDW3KH4IP5E2DHKUHPQPN5P52V43SVGDYCCRS64XXNRYBBCT44EOGM3SKYV4272LQ6LQ"
        let actual = readable.cocoaFobFromReadableKey()
        XCTAssertEqual(actual, expected)
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
            "GBDAE-99AQE-Y5L5G-FXBNS-N6Q4A-XYKUZ-CVWP2-N2CQ9-A9FRV-D8XNZ-X4FFH-JH7YQ-E99A5-YUTFR-UAH4L-GG5B5-HNM8S-SZAMT-NNDMP-JADT4-LW9Z5-PYNTA-4X8YT-Q"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertTrue(result)
    }

    func testVerifyBadNameFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs II"
        let regKey =
            "GBDAE-99AQE-Y5L5G-FXBNS-N6Q4A-XYKUZ-CVWP2-N2CQ9-A9FRV-D8XNZ-X4FFH-JH7YQ-E99A5-YUTFR-UAH4L-GG5B5-HNM8S-SZAMT-NNDMP-JADT4-LW9Z5-PYNTA-4X8YT-Q"
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
            "GAWQE-F9AQP-XJCCL-PAFAX-NU5XX-EUG6W-KLT3H-VTEB9-A9KHJ-8DZ5R-DL74G-TU4BN-7ATPY-3N4XB-V4V27-Q"
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
            "GAWQE-F9AQP-XJCCL-PAFAX-NU5XX-EUG6W-KLT3H-VTEB9-A9KHJ-8DZ5R-DL74G-TU4BN-7ATPY-3N4XB-V4V27-Qasdf"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyAdditionalLeadingCharactersFail() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey =
            "qwertGAWQE-F9AQP-XJCCL-PAFAX-NU5XX-EUG6W-KLT3H-VTEB9-A9KHJ-8DZ5R-DL74G-TU4BN-7ATPY-3N4XB-V4V27-Q"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

    func testVerifyWhitespaceInMiddleFails() {
        let verifier = LicenseVerifier(publicKeyPEM: publicKeyPEM)
        XCTAssertNotNil(verifier?.pubKey)
        let name = "Joe Bloggs"
        let regKey =
            "GAWQE-F9AQP- XJCCL-PAFAX-NU5XX - EUG6W-KLT3H-VTEB9\n-A9KHJ-8DZ5R- DL74G-\tTU4BN-7ATPY-3N4XB-V4V27-Q"
        let result = verifier?.verify(regKey, forName: name) ?? false
        XCTAssertFalse(result)
    }

}
