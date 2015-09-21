/*
 * CommonCryptor.h - Generic interface for symmetric encryption.
 * Copyright (c) 2006-2014 Apple Inc. All Rights Reserved. Licensed under APSL.
 */

#import <CoreFoundation/CoreFoundation.h>
#import "CommonCryptoError.h"

CF_ASSUME_NONNULL_BEGIN

typedef struct _CCCryptor *CCCryptorRef;

typedef CF_ENUM(uint32_t, CCOperation) {
    kCCEncrypt = 0, 
    kCCDecrypt
};

typedef CF_ENUM(uint32_t, CCAlgorithm) {
    kCCAlgorithmAES = 0,
    kCCAlgorithmDES,
    kCCAlgorithmTripleDES,
    kCCAlgorithmCAST,       
    kCCAlgorithmRC4,
    kCCAlgorithmRC2,   
    kCCAlgorithmBlowfish
};

typedef CF_ENUM(uint32_t, CCMode) {
	kCCModeECB                   = 1,
	kCCModeCBC                   = 2,
	kCCModeCFB                   = 3,
	kCCModeCTR                   = 4,
	kCCModeF8 _CC_UNIMPLEMENTED  = 5,
	kCCModeLRW _CC_UNIMPLEMENTED = 6,
	kCCModeOFB                   = 7,
	kCCModeXTS                   = 8,
	kCCModeRC4                   = 9,
	kCCModeCFB8                  = 10,
};

typedef CF_ENUM(uint32_t, CCPadding) {
    kCCPaddingNone  = 0,
    kCCPaddingPKCS7 = 1
};

typedef CF_OPTIONS(uint32_t, CCModeOptions) {
	kCCModeOptionCTR_LE = 0x0001,
	kCCModeOptionCTR_BE = 0x0002
};

extern CCCryptorStatus CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding, const void *_Nullable iv, const void *key, size_t keyLength, const void *_Nullable tweak, size_t tweakLength, int numRounds, CCModeOptions options, CCCryptorRef _Nullable *_Nonnull cryptorRef) CF_AVAILABLE(10_7, 5_0);

extern CCCryptorStatus CCCryptorRelease(CCCryptorRef cryptorRef) CF_AVAILABLE(10_4, 2_0);

extern CCCryptorStatus CCCryptorUpdate(CCCryptorRef cryptorRef, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) CF_AVAILABLE(10_4, 2_0);

extern CCCryptorStatus CCCryptorFinal(CCCryptorRef cryptorRef, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) CF_AVAILABLE(10_4, 2_0);

extern CCCryptorStatus CCCryptorReset(CCCryptorRef cryptorRef, const void *_Nullable iv) CF_AVAILABLE(10_4, 2_0);

extern size_t CCCryptorGetOutputLength(CCCryptorRef cryptorRef, size_t inputLength, bool final) CF_AVAILABLE(10_4, 2_0);

enum: uint32_t {
    kCCBlockSizeAES128        = 16,
    kCCBlockSizeDES           = 8,
    kCCBlockSize3DES          = 8,
    kCCBlockSizeCAST          = 8,
    kCCBlockSizeRC4           = 0,
    kCCBlockSizeBlowfish      = 8,
};

enum: uint32_t {
    kCCKeySizeAES128          = 16,
    kCCKeySizeAES192          = 24,
    kCCKeySizeAES256          = 32,
    kCCKeySizeDES             = 8,
    kCCKeySize3DES            = 24,
    kCCKeySizeMinCAST         = 5,
    kCCKeySizeMaxCAST         = 16,
    kCCKeySizeMinRC4          = 1,
    kCCKeySizeMaxRC4          = 512,
    kCCKeySizeMinRC2          = 1,
    kCCKeySizeMaxRC2          = 128,
    kCCKeySizeMinBlowfish     = 8,
    kCCKeySizeMaxBlowfish     = 56,
};

CF_ASSUME_NONNULL_END
