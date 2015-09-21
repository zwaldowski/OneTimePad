//: [Previous](@previous)

import OneTimePad

//: # Random Data
//:
//: Generating random numbers securely is important to any app using cryptography. A weak generator can compromise the lasting security of encrypted data, and an inefficient one can have compound effects on an entire app.
//:
//: The random number generator in CommonCrypto can pull randomness from several sources, including a dedicated random number generator in hardware.
//:
//: OneTimePad provides bridges random data in efficiently onto Swift's core buffer types, `Array`, `ArraySlice`, and `ContiguousArray`.

//: The one-step random initializer creates an entire collection of integers.

let allRandom = try! Array<UInt8>(randomCount: 6)

//: The range-wise random data generator replaces a subset of an integer collection with random numbers. This will perform more efficiently if you already have an array.

var customRandom = Array<UInt8>(count: 6, repeatedValue: 0)
try! customRandom.fillWithRandomData(inRange: 1...4)
customRandom

//: [Next](@next)
