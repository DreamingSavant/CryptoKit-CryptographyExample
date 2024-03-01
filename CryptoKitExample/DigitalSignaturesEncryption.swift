//
//  DigitalSignaturesEncryption.swift
//  CryptoKitExample
//
//  Created by Roderick Presswood on 2/22/24.
//

import Foundation
// generate a public-[rivate key pair using the Security framework SecKey APIS
import Security

// function name and parameter contains public and private key and can throw errors
func generateKeyPair() throws -> (publicKey: SecKey, privateKey: SecKey) {
    // this line is a dictionary named attributes containng key value pairs used as parameters for generating the public key pair. It specifies that the keys will be of RSA type and set the key size to 2048 bits
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: 2048
    ]
    // this line will be used to capture any errors that occur during the key generation process
    var error: Unmanaged<CFError>?
    // this line attempts to create a random private key  using SecKeyCreateRandomKey func and passes the attributes dictionary as prameters and assigns the result to private key or in case of error throws an error and exits function
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    // this line attempts to extract the public key corresponding to the private key  using the SECKeyCopyPublicKey function from the Security framework. It then assigns the result to public key or throws an error in case of error
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw error!.takeRetainedValue() as Error
    }
    // returns a tuple for public and private key
    return (publicKey, privateKey)
}

// Sign Data using private key generated in the previous func
// this line declares the function named signData that takes two parameters one being data and the private key created earlier and returns Data. It can also throw errors
func signData(data: Data, privateKey: SecKey) throws -> Data {
    // this line captures any error to throw
    var error: Unmanaged<CFError>?
    // this line attempts to create a digital signature for given data using the private key provided. it uses SecKeyCreateSignature function from Security framework, passing parameters liek the private key and a signature algorithm rsaSignatureMessagePKCS1v15SHA256 which indicates RSA with PKCS1-v1.5 padding and SHA-256 hashing with the data to be signed and a reference to error to capture any errors and will throw an error if any occurs
    guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    
    // this line returns the generated signature as a Data object
    return signature as Data
}

// Verify Signature using the public Key
// this line declares the function verifySignature that takes three parameters data, signature which is of type data and public key of type SecKey and returns a bool indicating whether the signature is vcalid. It can also throw errors if needed.
func verifySignature(data: Data, signature: Data, publicKey: SecKey) throws -> Bool {
    // this line will be used to capture any errors during the process
    var error: Unmanaged<CFError>?
    // this line attempts to verify the digital signature using the public key provided it uses the SecKeyVerifySignature function from the Security framework passing parameters public key the signature algorithm, the original data, the signature  and reference to error to capture any errors. The result will be assigned to result as an optional bool
    let result: Bool? = SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, signature as CFData, &error)
    // this line unwraps the result, if nil we will throw the error captured during the verification process. The error is converted to a swift error object using the takeRetainedValueMethod
    guard let unwrappedResult = result else {
        throw error!.takeRetainedValue() as Error
    }
    // this line returns the result of the signature verification in bool form ie true or false
    return unwrappedResult
}

// Usage Example
func digitalSignatureUsageExample() {
    do {
        let (publicKey, privateKey) = try generateKeyPair()
        let originalData = "Wassup, world!".data(using: .utf8)!
        
        let signature = try signData(data: originalData, privateKey: privateKey)
        
        let verified = try verifySignature(data: originalData, signature: signature, publicKey: publicKey)
        print("Signature verified: \(verified)")
    } catch {
        print("Error: \(error)")
    }
}
