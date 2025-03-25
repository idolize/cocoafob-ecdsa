//
//  CocoaFobLicGenerator.swift
//  CocoaFob
//
//  Created by Gleb Dolgich on 05/07/2015.
//  Copyright © 2015 PixelEspresso. All rights reserved.
//

import Foundation
import Security

/// Generates CocoaFob registration keys
public struct LicenseGenerator {

    var privKey: SecKey

    // MARK: - Initialization

    /**
  Initializes key generator with a private key in PEM format

  - parameter privateKeyPEM: String containing PEM representation of the private key
  */
    public init?(privateKeyPEM: String) {
        let emptyString = "" as NSString
        let password = Unmanaged.passUnretained(emptyString as AnyObject)
        var params = SecItemImportExportKeyParameters(
            version: UInt32(bitPattern: SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION),
            flags: SecKeyImportExportFlags.importOnlyOne,
            passphrase: password,
            alertTitle: Unmanaged.passUnretained(emptyString),
            alertPrompt: Unmanaged.passUnretained(emptyString),
            accessRef: nil,
            keyUsage: nil,
            keyAttributes: nil
        )
        var keyFormat = SecExternalFormat.formatOpenSSL
        var keyType = SecExternalItemType.itemTypePrivateKey
        guard let keyData = privateKeyPEM.data(using: String.Encoding.utf8) else { return nil }
        let keyBytes = [UInt8](keyData)
        guard let keyDataCF = CFDataCreate(nil, keyBytes, keyData.count) else { return nil }
        var importArray: CFArray? = nil
        let osStatus = withUnsafeMutablePointer(
            to: &keyFormat,
            { pKeyFormat -> OSStatus in
                withUnsafeMutablePointer(
                    to: &keyType,
                    { pKeyType in
                        SecItemImport(
                            keyDataCF,
                            nil,
                            pKeyFormat,
                            pKeyType,
                            SecItemImportExportFlags(rawValue: 0),
                            &params,
                            nil,
                            &importArray
                        )
                    }
                )
            }
        )
        guard osStatus == errSecSuccess,
            let importArray = importArray,
            let items = importArray as? [SecKey],
            let firstKey = items.first
        else { return nil }
        self.privKey = firstKey
    }

    // MARK: - Key generation

    /**
  Generates registration key for a user name

  - parameter userName: User name for which to generate a registration key
  - returns: Registration key
  */
    public func generate(_ name: String) throws -> String {
        guard name != "" else { throw CocoaFobError.error }
        guard let nameData = getNameData(name) else { throw CocoaFobError.error }

        // Create signature using SecKeyCreateSignature
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privKey, .sign, algorithm) else {
            throw CocoaFobError.error
        }

        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(privKey, algorithm, nameData as CFData, &error)
                as Data?
        else {
            throw CocoaFobError.error
        }

        // Encode signature to base64
        return signature.base64EncodedString()
    }

    // MARK: - Utility functions

    func getNameData(_ name: String) -> Data? {
        return name.data(using: String.Encoding.utf8)
    }

}
