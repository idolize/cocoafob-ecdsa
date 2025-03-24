//
//  CocoaFobLicVerifier.swift
//  CocoaFob
//
//  Created by Gleb Dolgich on 12/07/2015.
//  Copyright © 2015 PixelEspresso. All rights reserved.
//

import Base32
import Foundation
import Security

/// Verifies CocoaFob registration keys
public struct LicenseVerifier {

    var pubKey: SecKey

    // MARK: - Initialization

    /**
  Initializes key verifier with a public key in PEM format

  - parameter publicKeyPEM: String containing PEM representation of the public key
  */
    public init?(publicKeyPEM: String) {
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
        var keyType = SecExternalItemType.itemTypePublicKey
        guard let keyData = publicKeyPEM.data(using: String.Encoding.utf8) else { return nil }
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
              let firstKey = items.first else { return nil }
        self.pubKey = firstKey
    }

    /**
  Verifies registration key against registered name. Doesn't throw since you are most likely not interested in the reason registration verification failed.

  - parameter regKey: Registration key string
  - parameter name: Registered name string
  - returns: `true` if the registration key is valid for the given name, `false` if not
  */
    public func verify(_ regKey: String, forName name: String) -> Bool {
        let keyString = regKey.cocoaFobFromReadableKey()
        guard let nameData = name.data(using: String.Encoding.utf8) else { return false }

        // Decode base32 signature
        guard let signature = base32DecodeToData(keyString) else { return false }

        // Verify signature using SecKeyVerifySignature
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(pubKey, .verify, algorithm) else {
            return false
        }

        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            pubKey,
            algorithm,
            nameData as CFData,
            signature as CFData,
            &error
        )
        return isValid
    }

    // MARK: - Helper functions
    fileprivate func getDecoder(_ keyData: Data) throws -> SecTransform {
        let decoder = try cfTry(.error) { return SecDecodeTransformCreate(kSecBase32Encoding, $0) }
        let _ = try cfTry(.error) {
            return SecTransformSetAttribute(
                decoder,
                kSecTransformInputAttributeName,
                keyData as CFTypeRef,
                $0
            )
        }
        return decoder
    }

}
