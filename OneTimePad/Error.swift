//
//  Error.swift
//  OneTimePad
//
//  Created by Zachary Waldowski on 9/6/15.
//  Copyright © 2015 Zachary Waldowski. All rights reserved.
//

import CommonCryptoShim.Private

public enum CryptoError: Int32, ErrorType {
    /// Illegal parameter value.
    case InvalidParameters      = -4300
    /// Insufficent buffer provided for specified operation.
    case BufferTooSmall         = -4301
    /// Memory allocation failure.
    case CouldNotAllocateMemory = -4302
    /// Input size was not aligned properly.
    case MisalignedMemory       = -4303
    /// Input data did not decode or decrypt properly.
    case DecodingFailure        = -4304
    /// Function not implemented for the current algorithm.
    case Unimplemented          = -4305
    case Overflow               = -4306
    case RNGFailure             = -4307
}

