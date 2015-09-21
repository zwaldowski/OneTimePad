/*
 * CommonRandom.h - An interface to a system random number generator.
 * Copyright (c) 2014 Apple Inc. All Rights Reserved. Licensed under APSL.
 */

#import <CoreFoundation/CoreFoundation.h>
#import "CommonCryptoError.h"

CF_ASSUME_NONNULL_BEGIN

typedef CCStatus CCRNGStatus;

extern CCRNGStatus CCRandomGenerateBytes(void *bytes, size_t count) CF_AVAILABLE(10_10, 8_0);

CF_ASSUME_NONNULL_END
