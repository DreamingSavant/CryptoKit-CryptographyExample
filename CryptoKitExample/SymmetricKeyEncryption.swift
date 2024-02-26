//
//  SymmetricKeyEncryption.swift
//  CryptoKitExample
//
//  Created by Roderick Presswood on 2/22/24.
//

import Foundation
import CryptoKit
// Symmetric key encryption involves using the same key for both encryption and decryption. CryptoKit framework provides support for symmetric key encryption using algorithms like AES-GCM and ChaChaPoly
func encryptData(data: Data, key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.seal(data, using: key)
    return sealedBox.combined!
}

func decryptData(cipertext: Data, key: SymmetricKey) throws -> Data {
    let sealedBox = try AES.GCM.SealedBox(combined: cipertext)
    return try AES.GCM.open(sealedBox, using: key)
}

// example of usage
func exampleFunc() {
    let inputData = "Sensitive data".data(using: .utf8)!
    let key = SymmetricKey(size: .bits256)
    let encryptedData = try? encryptData(data: inputData, key: key)
    guard let encryptedData else {
        return
    }
    let decryptedData = try? decryptData(cipertext: encryptedData, key: key)
    guard let decryptedData else {
        return
    }
    let decryptedString = String(data: decryptedData, encoding: .utf8)
    print(decryptedString ?? "")
}

func exampleFuncWithDoCatch() throws {
    let inputData = "Sensitive data".data(using: .utf8)!
    let key = SymmetricKey(size: .bits256)
    do {
        let encryptedData = try encryptData(data: inputData, key: key)
        let decryptedData = try decryptData(cipertext: encryptedData, key: key)
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        print(decryptedString ?? "")
    } catch {
        print(error.localizedDescription)
        throw error
    }
    

   

    
}

