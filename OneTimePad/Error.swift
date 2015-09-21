//
//  Error.swift
//  OneTimePad
//
//  Created by Zachary Waldowski on 9/6/15.
//  Copyright © 2015 Zachary Waldowski. All rights reserved.
//

import CommonCryptoShim.Private

public struct CryptoError: ErrorType {
    
    private let rawValue: CCStatus
    
    init(_ rawValue: CCStatus) {
        self.rawValue = rawValue
    }
    
    /// Illegal parameter value.
    static let InvalidParameters      = CryptoError(kCCParamError)
    /// Insufficent buffer provided for specified operation.
    static let BufferTooSmall         = CryptoError(kCCBufferTooSmall)
    /// Memory allocation failure.
    static let CouldNotAllocateMemory = CryptoError(kCCMemoryFailure)
    /// Input size was not aligned properly.
    static let MisalignedMemory       = CryptoError(kCCAlignmentError)
    /// Input data did not decode or decrypt properly.
    static let DecodingFailure        = CryptoError(kCCDecodeError)
    /// Function not implemented for the current algorithm.
    static let Unimplemented          = CryptoError(kCCUnimplemented)
    static let Overflow               = CryptoError(kCCOverflow)
    static let RNGFailure             = CryptoError(kCCRNGFailure)
    
}

extension CryptoError: Hashable {
    
    public var hashValue: Int {
        return rawValue.hashValue
    }
    
}

public func ==(lhs: CryptoError, rhs: CryptoError) -> Bool {
    return lhs.rawValue == rhs.rawValue
}

public func ~=(match: CryptoError, error: ErrorType) -> Bool {
    guard let error = error as? CryptoError else { return false }
    return error == match
}
