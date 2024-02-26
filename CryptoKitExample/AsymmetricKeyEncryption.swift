//
//  AsymmetricKeyEncryption.swift
//  CryptoKitExample
//
//  Created by Roderick Presswood on 2/22/24.
//

import Foundation
import Security

// Digital signatures provide a way to verify the authenticity and integrity of data

// generate RSA key Pair and store in keychain default ***keySize is 2048 bits to make a high strength key
func generateKeyPairAndStoreInKeychain(keySize: Int = 2048, publicTag: String, privateTag: String) -> (publicKey: SecKey?, privateKey: SecKey?) {
    // creates an SecAccessControl object that specifies control conditions for the private key, here its configured to allow access to the key only when the device is unlocked and only for private key operations.
    let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)
    
    //kSecAttrIsPermanent: Saves the key to the keychain so it persists across app launches
    //kSecAttrAccessControl: Applies the access control created earlier to the key.
    //kSecAttrApplicationTag: A tag to uniquely Identify the public key in the keychain, using the provided 'public tag'
    let publicKeyParameters: [String: AnyObject] = [
        kSecAttrIsPermanent as String: true as AnyObject,
        kSecAttrAccessControl as String: access!,
        kSecAttrApplicationTag as String: publicTag.data(using: .utf8)! as AnyObject
    ]
    // similar to the public key is being done to private key except we are using the 'private tag' for the kSecAttrApplicationTag
    let privateKeyParameters: [String: AnyObject] = [
        kSecAttrIsPermanent as String: true as AnyObject,
        kSecAttrAccessControl as String: access!,
        kSecAttrApplicationTag as String: privateTag.data(using: .utf8)! as AnyObject
    ]
    
    //Combines all parameters for both keys
    // kSecAttrKeyType: Specifies the type of key to generate RSA
    // kSecAttrKeySizeInBits: The size of the keys to generate
    // kSecPublicKeyAttrs and kSecPrivateKeyAttrs: The attributes dictionaries for the public and private keys respectively
    let parameters: [String: AnyObject] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: keySize as AnyObject,
        kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject,
        kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject
    ]
    
    /* Attempts to generate the key pair using the specified parameters. 'publicKey' and 'privateKey' are output parameters that will hold references to the generated keys if successful */
    var publicKey, privateKey: SecKey?
//    let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey) // SecKeyGeneratePair depreciated
    let status = SecKeyCreateRandomKey(parameters as CFDictionary, nil) as? Int32
    
    // check to see if key generation was successful and prints error and returns nil if unsuccessful.
    guard status == errSecSuccess else {
        print("Error generating key pair: \(status ?? 0)")
        return (nil, nil)
    }
    
    return (publicKey, privateKey)
}


// Retrieve keys from keychain using a specified tag and can return the SecKey or nil
func getKeyFromKeychain(tag: String) -> SecKey? {
    //create a dictionary to query the keychain
    // kSecClass: Specifies the class of item to search for 'kSecClassKey' indicates lookup for cryptographic key
    // kSecAttrApplicationTag: Uses the provided 'tag' parameter to identify the key. tag is a unique id assigned to the key when first stored
    // kSecAttrKeyType: Specifies the type of key to retrieve
    // kSecReturnRef: A bool value that when true indicates you want a reference to the key
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecReturnRef as String: true
    ]
    
    // Attempt to retrieve the key
    // SecItemCopyMatching: Searches the keychain for items matching the query. If a matching item is found, its return through the 'item' parameter.
    // status: result of operation, errSecSuccess indicates success and any other value would mean error.
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    
    // error handling
    // if not errSecSuccess means error happened during retrieval process and will erturn nil
    guard status == errSecSuccess else {
        print("Error retrieving key from keychain: \(status)")
        return nil
    }
    
    // if key is successfully retrieved, it casts item to SecKey and returns. its force cased with as! because at this point it's guaranteed that 'item' is a 'SecKey' due to the earlier checks. It would be safer to safely unwrap this option to prevent potential runtime crashes if things are incorrect.
    return (item as! SecKey)
}


//Encrypt and decrypt using keychain stored keys
// Use the retrieved keys for encryption and decryption, as shown in the previous tutorial. No changes are needed in the encryption and decryption function themselves, but you will use 'getKeyFromKeychain(tag:)' to get the keys.
// Usage Example with Keychain

func encrypt(plainText: String, publicKey: SecKey) -> Data? {
    guard let data = plainText.data(using: .utf8) else { return nil }
    
    let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
    
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
        return nil
    }
    var error: Unmanaged<CFError>?
    
    guard let cipherData = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) as Data? else {
        print("Encryption error: \((error?.takeRetainedValue())!)")
        return nil
    }
    
    return cipherData
}

func encrypt(data: Data, publicKey:SecKey) -> Data? {
    
    let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
    
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
        return nil
    }
    var error: Unmanaged<CFError>?
    
    guard let cipherData = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) as Data? else {
        print("Encryption error: \((error?.takeRetainedValue())!)")
        return nil
    }
    
    return cipherData
}

func decryptToString(cipherData: Data, privateKey: SecKey) -> String? {
    let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
    
    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
        return nil
    }
    var error: Unmanaged<CFError>?
    
    guard let clearData = SecKeyCreateDecryptedData(privateKey, algorithm, cipherData as CFData, &error) as Data? else {
        print("Decryption error: \((error?.takeRetainedValue())!)")
        return nil
    }
    
    return String(data: clearData, encoding: .utf8)
}

func decryptToData(cipherData: Data, privateKey: SecKey) -> Data? {
    let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
    
    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
        return nil
    }
    var error: Unmanaged<CFError>?
    
    guard let clearData = SecKeyCreateDecryptedData(privateKey, algorithm, cipherData as CFData, &error) as Data? else {
        print("Decryption error: \((error?.takeRetainedValue())!)")
        return nil
    }
    
    return clearData
}

func asymmetricKeyEncryptionDecryptionExample() {
    let tags = ("publicKeyTag", "privateKeyTag")
    generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: tags.0, privateTag: tags.1)
    if let publicKey = getKeyFromKeychain(tag: tags.0), let privateKey = getKeyFromKeychain(tag: tags.1) {
     let originalString = "Hello, RSA!"
     if let encryptedData = encrypt(plainText: originalString, publicKey: publicKey),
     let decryptedString = decryptToString(cipherData: encryptedData, privateKey: privateKey) {
     print("Original: \(originalString)")
     print("This is the encryptedData \(encryptedData)")
     print("Decrypted: \(decryptedString)")
     }
    }

}

