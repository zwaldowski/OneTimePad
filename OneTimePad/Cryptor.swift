//
//  Cryptor.swift
//  OneTimePad
//
//  Created by Zachary Waldowski on 9/6/15.
//  Copyright © 2015 Zachary Waldowski. All rights reserved.
//

import CommonCryptoShim.Private

private typealias CCCryptor = CCCryptorRef

/// This interface provides access to a number of symmetric encryption
/// algorithms. Symmetric encryption algorithms come in two "flavors" -  block
/// ciphers, and stream ciphers. Block ciphers process data in discrete chunks
/// called blocks; stream ciphers operate on arbitrary sized data.
///
/// The type declared in this interface, `Cryptor`, provides access to both
/// block ciphers and stream ciphers with the same API; however, some options
/// are available for block ciphers that do not apply to stream ciphers.
///
/// The general operation of a cryptor is:
///  - Initialize it with raw key data and other optional fields
///  - Process input data via one or more calls to the `update` method, each of
///    which may result in output data being written to caller-supplied memory
///  - Obtain possible remaining output data with the `finalize` method.
///  - Reuse the cryptor with the same key data by calling the `reset` method.
///
/// One option for block ciphers is padding, as defined in PKCS7;
/// when padding is enabled, the total amount of data encrypted
/// does not have to be an even multiple of the block size, and
/// the actual length of plaintext is calculated during decryption.
///
/// Another option for block ciphers is Cipher Block Chaining, known as CBC
/// mode. When using CBC, an Initialization Vector (IV) is provided along with
/// the key when starting an operation. If CBC mode is selected and no IV is
/// provided, an IV of all zeroes will be used.
///
/// `Cryptor` also implements block bufferring, such that individual calls to
/// update the context do not have to provide data whose length is aligned to
/// the block size. If padding is disabled, block cipher encryption does require
/// that the *total* length of data input be aligned to the block size.
///
/// A given `Cryptor` can only be used by one thread at a time; multiple threads
/// can use safely different `Cryptor`s at the same time.
public struct Cryptor {
    
    private struct AlgorithmConfiguration {
        let mode: CCMode
        let algorithm: CCAlgorithm
        let padding: CCPadding
        let iv: UnsafePointer<Void>
        let tweak: UnsafeBufferPointer<Void>?
        let numberOfRounds: Int32?
    }
    
    private let ccCryptor: CCPointer
    
    private static func createCryptor(operation op: CCOperation, configuration c: AlgorithmConfiguration, key: UnsafeBufferPointer<Void>, cryptor: UnsafeMutablePointer<CCCryptor>) -> CCStatus {
        return CCCryptorCreateWithMode(op, c.mode, c.algorithm, c.padding, c.iv, key.baseAddress, key.count, c.tweak?.baseAddress ?? nil, c.tweak?.count ?? 0, c.numberOfRounds ?? 0, [], cryptor)
    }
    
    private init(operation op: CCOperation, configuration c: AlgorithmConfiguration, key: UnsafeBufferPointer<Void>) throws {
        ccCryptor = try CCPointer(destructor: CCCryptorRelease) {
            Cryptor.createCryptor(operation: op, configuration: c, key: key, cryptor: $0)
        }
    }

    /// Process (encrypt or decrypt) some data. The result, if any, is written
    /// to a caller-provided buffer.
    ///
    /// This method can be called multiple times. The caller does not need to
    /// align the size of input data to block sizes; input is buffered as
    /// as necessary for block ciphers.
    ///
    /// When performing symmetric encryption with block ciphers and padding is
    /// enabled, the total number of bytes provided by all calls to this method
    /// when encrypting can be arbitrary (i.e., the total number of bytes does
    /// not have to be block aligned). However, if padding is disabled, or when
    /// decrypting, the total number of bytes does have to be aligned to the
    /// block size; otherwise `finalize` will throw an error.
    ///
    /// A general rule for the size of the output buffer which must be provided
    /// is that for block ciphers, the output length is never larger than the
    /// input length plus the block size. For stream ciphers, the output length
    /// is always exactly the same as the input length.
    ///
    /// Generally, when all data has been processed, call `finalize`. In the
    /// following cases, finalizing is superfluous as it will not yield any
    /// data, nor return an error:
    ///   - Encrypting or decrypting with a block cipher with padding
    ///     disabled, when the total amount of data provided to `update` is an
    ///     an integral multiple of the block size.
    ///   - Encrypting or decrypting with a stream cipher.
    ///
    /// - parameter data: Data to process.
    /// - parameter output: The result, if any, is written here. Must be
    ///   allocated by the caller. Encryption and decryption can be performed
    ///   "in-place", with the same buffer used for input and output.
    /// - returns: The number of bytes written to `output`.
    /// - throws:
    ///   - `CryptoError.BufferTooSmall` to indicate insufficient space in the
    ///     `output` buffer. Use `outputLengthForInputLength` to determine the
    ///     required output buffer size in this case. The update can be retried;
    ///     no state has been lost.
    /// - seealso: outputLengthForInputLength(_:finalizing:)
    public func update(data: UnsafeBufferPointer<Void>, inout output: UnsafeMutableBufferPointer<Void>!) throws -> Int {
        return try ccCryptor.call {
            CCCryptorUpdate($0, data.baseAddress, data.count, output?.baseAddress ?? nil, output?.count ?? 0, $1)
        }
    }
    
    /// Finish an encrypt or decrypt operation, and obtain final data output.
    ///
    /// Upon successful return, the `Cryptor` can no longer be used for
    /// subsequent operations unless `reset` is called on it.
    ///
    /// It is not necessary to call this method when performing symmetric
    /// encryption with padding disabled, or when using a stream cipher.
    ///
    /// It is not necessary to call this method when aborting an operation.
    ///
    /// - parameter output: The result, if any, is written here. Must be
    ///   allocated by the caller.
    /// - returns: The number of bytes written to `output`.
    /// - throws: CryptoError.BufferTooSmall to indicate insufficient space
    ///   in the `output` buffer. Use `outputLengthForInputLength` to determine
    ///   to determine the required output buffer size in this case. The update
    ///   can be re-tried; no state has been lost.
    /// - throws: CryptoError.MisalignedMemory if the total number of bytes
    ///   provided to `update` is not an integral multiple of the current
    ///   algorithm's block size.
    /// - throws:
    ///   - `CryptoError.DecodingFailure` to indicate garbled ciphertext or
    ///     the wrong key during decryption.
    /// - seealso: outputLengthForInputLength(_:finalizing:)
    public func finalize(inout output: UnsafeMutableBufferPointer<Void>) throws -> Int {
        return try ccCryptor.call {
            CCCryptorFinal($0, output.baseAddress, output.count, $1)
        }
    }
    
    /// Reinitialize an existing `Cryptor`, possibly with a new initialization
    /// vector.
    ///
    /// This can be called on a `Cryptor` with data pending (i.e. in a padded
    /// mode operation before finalized); any pending data will be lost.
    ///
    /// - note: Not implemented for stream ciphers.
    /// - parameter iv: New initialization vector, optional. If present, must
    ///   be the same size as the current algorithm's block size.
    /// - throws:
    ///   - `CryptoError.InvalidParameters` to indicate an invalid IV.
    ///   - `CryptoError.Unimplemented` for stream ciphers.
    public func reset(iv: UnsafePointer<Void> = nil) throws {
        return try ccCryptor.call {
            CCCryptorReset($0, iv)
        }
    }
    
    /// Determine output buffer size required to process a given input size.
    ///
    /// Some general rules apply that allow callers to know a priori how much
    /// output buffer space will be required generally:
    ///  - For stream ciphers, the output size is always equal to the input
    ///    size.
    ///  - For block ciphers, the output size will always be less than or equal
    ///    to the input size plus the size of one block. For block ciphers, if
    ///    the input size provided to each call to `update` is is an integral
    ///    multiple of the block size, then the output size for each call to
    ///    `update` is less than or equal to the input size for that call.
    ///
    /// `finalize` only produces output when using a block cipher with padding
    /// enabled.
    ///
    /// - parameter inputLength:  The length of data which will be provided to 
    ///   `update`.
    /// - parameter finalizing: If `false`, the size will indicate the
    ///   space needed when 'inputLength' bytes are provided to `update`.
    ///   If `true`, the size will indicate the space needed when 'inputLength'
    ///   bytes are provided to `update`, prior to a call to `finalize`.
    /// - returns: The maximum buffer space need to perform `update` and
    ///   optionally `finalize`.
    public func outputLengthForInputLength(inputLength: Int, finalizing: Bool = false) -> Int {
        return CCCryptorGetOutputLength(ccCryptor.rawValue, inputLength, finalizing)
    }
    
}

public extension Cryptor {
    
    /// Padding for Block Ciphers
    enum Padding {
        /// No padding.
        case None
        /// Padding, as defined in PKCS#7 (RFC #2315)
        case PKCS7
    }
    
    enum Mode {
        /// Electronic Code Book Mode
        case ECB
        /// Cipher Block Chaining Mode
        ///
        /// If the IV is `nil`, an all zeroes IV will be used.
        case CBC(iv: UnsafePointer<Void>)
        /// Output Feedback Mode.
        ///
        /// If the IV is `nil`, an all zeroes IV will be used.
        case CFB(iv: UnsafePointer<Void>)
        /// Counter Mode
        ///
        /// If the IV is `nil`, an all zeroes IV will be used.
        case CTR(iv: UnsafePointer<Void>)
        /// Output Feedback Mode
        ///
        /// If the IV is `nil`, an all zeroes IV will be used.
        case OFB(iv: UnsafePointer<Void>)
        /// XEX-based Tweaked CodeBook Mode
        case XTS(tweak: UnsafeBufferPointer<Void>)
        /// Cipher Feedback Mode producing 8 bits per round.
        ///
        /// If the IV is `nil`, an all zeroes IV will be used.
        case CFB8(iv: UnsafePointer<Void>, numberOfRounds: Int32)
    }
    
    enum Algorithm {
        /// Advanced Encryption Standard, 128-bit block
        case AES(Mode, Padding)
        /// Data Encryption Standard
        case DES(Mode, Padding)
        /// Triple-DES, three key, EDE configuration
        case TripleDES(Mode, Padding)
        /// CAST
        case CAST(Mode, Padding)
        /// RC4 stream cipher
        case RC4
        /// Blowfish block cipher
        case Blowfish(Mode, Padding)
    }
    
}

public extension Cryptor.Algorithm {
    
    /// Block size, in bytes, for supported algorithms.
    var blockSize: Int {
        switch self {
        case .AES:
            return kCCBlockSizeAES128
        case .DES:
            return kCCBlockSizeDES
        case .TripleDES:
            return kCCBlockSize3DES
        case .CAST:
            return kCCBlockSizeCAST
        case .RC4:
            return kCCBlockSizeRC4
        case .Blowfish:
            return kCCBlockSizeBlowfish
        }
    }

    /// Key sizes, in bytes, for supported algorithms.  Use this range to select
    /// key-size variants you wish to use.
    ///
    /// - DES and TripleDES have fixed key sizes.
    /// - AES has three discrete key sizes in 64-bit increments.
    /// - CAST and RC4 have variable key sizes.
    var validKeySizes: ClosedInterval<Int> {
        switch self {
        case .AES:
            return kCCKeySizeAES128...kCCKeySizeAES256
        case .DES:
            return kCCKeySizeDES...kCCKeySizeDES
        case .TripleDES:
            return kCCKeySize3DES...kCCKeySize3DES
        case .CAST:
            return kCCKeySizeMinCAST...kCCKeySizeMaxCAST
        case .RC4:
            return kCCKeySizeMinRC4...kCCKeySizeMaxRC4
        case .Blowfish:
            return kCCKeySizeMinBlowfish...kCCKeySizeMaxBlowfish
        }
    }
    
}

private extension Cryptor.Padding {
    
    private var rawValue: CCPadding {
        switch self {
        case .None: return .None
        case .PKCS7: return .PKCS7
        }
    }
    
}

private extension Cryptor.AlgorithmConfiguration {
    
    init(_ alg: CCAlgorithm, mode: Cryptor.Mode, padding: Cryptor.Padding) {
        let pad = padding.rawValue
        switch mode {
        case .ECB:
            self.init(mode: .ECB, algorithm: alg, padding: pad, iv: nil, tweak: nil, numberOfRounds: nil)
        case let .CBC(iv):
            self.init(mode: .CBC, algorithm: alg, padding: pad, iv: iv, tweak: nil, numberOfRounds: nil)
        case let .CFB(iv):
            self.init(mode: .CFB, algorithm: alg, padding: pad, iv: iv, tweak: nil, numberOfRounds: nil)
        case let .CTR(iv):
            self.init(mode: .CTR, algorithm: alg, padding: pad, iv: iv, tweak: nil, numberOfRounds: nil)
        case let .OFB(iv):
            self.init(mode: .OFB, algorithm: alg, padding: pad, iv: iv, tweak: nil, numberOfRounds: nil)
        case let .XTS(tweak):
            self.init(mode: .XTS, algorithm: alg, padding: pad, iv: nil, tweak: tweak, numberOfRounds: nil)
        case let .CFB8(iv, numberOfRounds):
            self.init(mode: .CFB8, algorithm: alg, padding: pad, iv: iv, tweak: nil, numberOfRounds: numberOfRounds)
        }
    }
    
    init(_ conf: Cryptor.Algorithm) {
        
        switch conf {
        case .RC4:
            self.init(mode: .RC4, algorithm: .RC4, padding: .None, iv: nil, tweak: nil, numberOfRounds: nil)
        case let .AES(mode, padding):
            self.init(.AES, mode: mode, padding: padding)
        case let .DES(mode, padding):
            self.init(.DES, mode: mode, padding: padding)
        case let .TripleDES(mode, padding):
            self.init(.TripleDES, mode: mode, padding: padding)
        case let .CAST(mode, padding):
            self.init(.CAST, mode: mode, padding: padding)
        case let .Blowfish(mode, padding):
            self.init(.Blowfish, mode: mode, padding: padding)
        }
    }
    
}

public extension Cryptor {
    
    /// Create a context for encryption.
    ///
    /// - parameter algorithm: Defines the algorithm and its mode.
    /// - parameter key: Raw key material. Length must be appropriate for the
    ///   selected algorithm; some algorithms provide for varying key lengths.
    /// - throws:
    ///   - `CryptoError.InvalidParameters`
    ///   - `CryptoError.CouldNotAllocateMemory`
    init(forEncryptionWithAlgorithm alg: Algorithm, key: UnsafeBufferPointer<Void>) throws {
        try self.init(operation: .Encrypt, configuration: AlgorithmConfiguration(alg), key: key)
    }
    
    /// Create a context for decryption.
    ///
    /// - parameter algorithm: Defines the algorithm and its mode.
    /// - parameter key: Raw key material. Length must be appropriate for the
    ///   selected algorithm; some algorithms provide for varying key lengths.
    /// - throws:
    ///   - `CryptoError.InvalidParameters`
    ///   - `CryptoError.CouldNotAllocateMemory`
    init(forDecryptionWithAlgorithm alg: Algorithm, key: UnsafeBufferPointer<Void>) throws {
        try self.init(operation: .Decrypt, configuration: AlgorithmConfiguration(alg), key: key)
    }
    
}

public extension Cryptor {
    
    public enum OneShotError: ErrorType {
        /// Insufficent buffer provided for specified operation.
        case BufferTooSmall(Int)
    }
    
    private static func cryptWithAlgorithm(operation op: CCOperation, configuration c: AlgorithmConfiguration, key: UnsafeBufferPointer<Void>, input: UnsafeBufferPointer<Void>, inout output: UnsafeMutableBufferPointer<Void>!) throws -> Int {
        var cryptor = CCCryptor()
        try CCPointer.call {
            Cryptor.createCryptor(operation: op, configuration: c, key: key, cryptor: &cryptor)
        }
        
        defer {
            CCCryptorRelease(cryptor)
        }
        
        var dataOut = output.baseAddress
        var dataOutAvailable = output.count
        var updateLen = 0
        var finalLen = 0
        
        let needed = CCCryptorGetOutputLength(cryptor, input.count, true)
        guard needed > output.count else {
            throw OneShotError.BufferTooSmall(needed)
        }
        
        do {
            try CCPointer.call {
                CCCryptorUpdate(cryptor, input.baseAddress, input.count, dataOut, dataOutAvailable, &updateLen)
            }
        } catch CryptoError.BufferTooSmall {
            throw OneShotError.BufferTooSmall(needed)
        }
        
        dataOut += updateLen
        dataOutAvailable -= updateLen
        
        do {
            try CCPointer.call {
                CCCryptorFinal(cryptor, dataOut, dataOutAvailable, &finalLen)
            }
        } catch CryptoError.BufferTooSmall {
            throw OneShotError.BufferTooSmall(needed)
        }
        
        return updateLen + finalLen
    }
    
    /// Stateless, one-shot encryption.
    ///
    /// This basically performs a sequence of `Cryptor.init()`, `update`, and
    /// `finalize`.
    ///
    /// - parameter algorithm: Defines the algorithm and its mode.
    /// - parameter key: Raw key material. Length must be appropriate for the
    ///   selected algorithm; some algorithms provide for varying key lengths.
    /// - parameter input: Data to encrypt or decrypt.
    /// - parameter output: The result, is written here. Must be allocated by
    ///   the caller. Encryption and decryption can be performed "in-place",
    ///   with the same buffer used for input and output.
    /// - returns: The number of bytes written to `output`.
    /// - throws: 
    ///   - A special `Cryptor.OneShotError.BufferToSmall` indicates insufficent
    ///     space in the output buffer, with the minimum size attached. The
    ///     operation can be retried with minimal runtime penalty.
    ///   - `CryptoError.MisalignedMemory` if the number of bytes provided
    ///     is not an integral multiple of the algorithm's block size.
    static func encryptWithAlgorithm(algorithm alg: Algorithm, key: UnsafeBufferPointer<Void>, input: UnsafeBufferPointer<Void>, inout output: UnsafeMutableBufferPointer<Void>!) throws -> Int {
        return try cryptWithAlgorithm(operation: .Encrypt, configuration: AlgorithmConfiguration(alg), key: key, input: input, output: &output)
    }
    
    /// Stateless, one-shot decryption.
    ///
    /// This basically performs a sequence of `Cryptor.init()`, `update`, and
    /// `finalize`.
    ///
    /// - parameter algorithm: Defines the algorithm and its mode.
    /// - parameter key: Raw key material. Length must be appropriate for the
    ///   selected algorithm; some algorithms provide for varying key lengths.
    /// - parameter input: Data to encrypt or decrypt.
    /// - parameter output: The result, is written here. Must be allocated by
    ///   the caller. Encryption and decryption can be performed "in-place",
    ///   with the same buffer used for input and output.
    /// - returns: The number of bytes written to `output`.
    /// - throws:
    ///   - A special `Cryptor.OneShotError.BufferToSmall` indicates insufficent
    ///     space in the output buffer, with the minimum size attached. The
    ///     operation can be retried with minimal runtime penalty.
    ///   - `CryptoError.MisalignedMemory` if the number of bytes provided
    ///     is not an integral multiple of the algorithm's block size.
    ///   - `CryptoError.DecodingFailure` Indicates improperly formatted
    ///     ciphertext or a "wrong key" error.
    static func decryptWithAlgorithm(algorithm alg: Algorithm, key: UnsafeBufferPointer<Void>, input: UnsafeBufferPointer<Void>, inout output: UnsafeMutableBufferPointer<Void>!) throws -> Int {
        return try cryptWithAlgorithm(operation: .Decrypt, configuration: AlgorithmConfiguration(alg), key: key, input: input, output: &output)
    }
    
}
