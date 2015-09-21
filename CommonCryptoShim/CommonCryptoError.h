/*
 * CommonCryptoError.h - Common return values from CommonCrypto operations.
 * Copyright (c) 2006-2014 Apple Inc. All Rights Reserved. Licensed under APSL.
 */

#import <CoreFoundation/CoreFoundation.h>

CF_ASSUME_NONNULL_BEGIN

typedef int32_t CCStatus;

enum: CCStatus {
    CCSuccess = 0
};
    
enum: CCStatus {
    kCCParamError       = -4300,
    kCCBufferTooSmall   = -4301,
    kCCMemoryFailure    = -4302,
    kCCAlignmentError   = -4303,
    kCCDecodeError      = -4304,
    kCCUnimplemented    = -4305,
    kCCOverflow         = -4306,
    kCCRNGFailure       = -4307,
};

#define _CC_UNIMPLEMENTED __OS_AVAILABILITY_MSG(macosx,unavailable,"Unimplemented for now (not included)") __OS_AVAILABILITY_MSG(ios,unavailable,"Unimplemented for now (not included)")

CF_ASSUME_NONNULL_END
