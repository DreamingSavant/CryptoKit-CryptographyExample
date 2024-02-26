//
//  HashingFunctions.swift
//  CryptoKitExample
//
//  Created by Roderick Presswood on 2/22/24.
//

import Foundation
import CryptoKit


func hashData(data: Data) -> String {
    let hashedData = SHA256.hash(data: data)
    let hashedString = hashedData.compactMap {
        // what the format means: % indicates start of format specifier
        // 0 specifies that the output should padded with zeros instead of spaces
        // 2 specifies that minimum width of output. if less than 2 characters it will be padded with zeros to ensure at least two characters
        // x specifies that interget should be formatted as hexadecimal number using lowercase letters a-f
        String(format: "%02x", $0 )
    }.joined()
    return hashedString
}


// usage example
func hashingExample() {
    // converting string to data
    let inputData = "Hello, Crypto!".data(using: .utf8)!
    // insert to hash function
    let hashedString = hashData(data: inputData)
    // print return hashed string
    print(hashedString)
}

