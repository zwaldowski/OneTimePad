//
//  Random.swift
//  OneTimePad
//
//  Created by Zachary Waldowski on 9/20/15.
//  Copyright © 2015 Zachary Waldowski. All rights reserved.
//

import CommonCryptoShim.Private

/// A collection that may be accessed efficiently in a contiguous manner from C.
public protocol BufferType: RangeReplaceableCollectionType {
    
    /// Construct an instance that contains `count` elements having the
    /// value `repeatedValue`.
    init(count: Index.Distance, repeatedValue: Generator.Element)
    
    /// Call `body(p)`, where `p` is a pointer to the type's mutable
    /// contiguous storage. If no such storage exists, it must first be created.
    ///
    /// Often, the optimizer can eliminate bounds- and uniqueness-checks
    /// within an algorithm, but when that fails, invoking the same algorithm
    /// on the contiguous storage lets you trade safety for speed.
    ///
    /// - warning: Do not rely on anything about `self` (the reciever of this
    ///   method) during the execution of `body`: it may not appear to have its
    ///   correct value. Instead, use only the buffer passed to `body`.
    mutating func withUnsafeMutableBufferPointer(@noescape body: (inout UnsafeMutableBufferPointer<Generator.Element>) throws -> ()) rethrows
    
}

public extension BufferType where Generator.Element: IntegerType {
    
    /// Construct an instance that contains `count` elements having the
    /// value `repeatedValue`.
    public init(count: Index.Distance, repeatedValue: Generator.Element) {
        self.init()
        appendContentsOf(Repeat(count: numericCast(count), repeatedValue: repeatedValue))
    }
    
}

extension Array: BufferType {}
extension ArraySlice: BufferType {}
extension ContiguousArray: BufferType {}

public extension BufferType where Generator.Element: IntegerType {
    
    private typealias Element = Generator.Element
    
    private mutating func fillWithRandomData() throws {
        try withUnsafeMutableBufferPointer { buffer in
            let byteCount = sizeof(Element) * numericCast(buffer.count)
            try cc_call {
                CCRandomGenerateBytes(buffer.baseAddress, byteCount)
            }
        }
    }
    
    /// Create a collection filled with random bytes.
    ///
    /// The random number generator, provided by the hardware or platform, can
    /// create cryptographically strong random data suitable for use as
    /// cryptographic keys, IVs, nonces etc.
    ///
    /// - throws:
    ///   - `CryptoError.RNGFailure` if the source of random numbers could not
    ///   produce cryptographically-strong random data.
    init(randomCount count: Index.Distance) throws {
        self.init(count: count, repeatedValue: Element.allZeros)
        try fillWithRandomData()
    }
    
}

public extension MutableCollectionType where SubSequence: BufferType, SubSequence.Generator.Element: IntegerType {
    
    private typealias Element = Generator.Element
    
    /// Fill a pre-allocated buffer with random bytes.
    ///
    /// The random number generator, provided by the hardware or platform, can
    /// create cryptographically strong random data suitable for use as
    /// cryptographic keys, IVs, nonces etc.
    ///
    /// - parameter range: Optional sub-range to fill with data. If not
    ///   provided, the entire contents of the collection will be replaced.
    /// - throws:
    ///   - `CryptoError.RNGFailure` if the source of random numbers could not
    ///   produce cryptographically-strong random data.
    mutating func fillWithRandomData(inRange range: Range<Index>? = nil) throws {
        let range = range ?? indices
        try self[range].fillWithRandomData()
    }
    
}
