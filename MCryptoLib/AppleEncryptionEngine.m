//
//                           MMMMMMMMMMMM
//                     MMMMMMMMMMMMMMMMMMMMMMMM
//                 MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//             MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//           MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//         MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//       MMMMMMMMMMMMMMMMMMMMMMM     MMMMMMMMMMMMMMMMMMMMMMMM
//      MMMMMMMMM                        MMMMMMMMMMMMMMMMMMMMM
//     MMMMMMMMMM  MMMMMMMMMMMMMMMMMMM               MMMMMMMMMM
//    MMMMMMMMMMM  MM           MMM  MMMMMMMMMMMMMM  MMMMMMMMMMM
//   MMMMMMMMMMMM  MMMMMMMMMMMMMMMM  MMMMMMM     MM    MMMMMMMMMM
//   MMMMMMMMM     MM            MM  MMMMMMM     MM     MMMMMMMMM
//  MMMMMMMMMM     MMMMMMMMMMMMMMMM  MM    M   MMMM     MMMMMMMMMM
//  MMMMMMMMMM          MMM     MMM  MMMMMMMMMM         MMMMMMMMMM
//  MMMMMMMMMM             MMMMMMMM  MM   M             MMMMMMMMMM
//  MMMMMMMMMM                   MMMM                   MMMMMMMMMM
//  MMMMMMMMMM                                          MMMMMMMMMM
//  MMMMMMMMMM                                          MMMMMMMMMM
//  MMMMMMMMMM        MMMMM                MMMMM        MMMMMMMMMM
//  MMMMMMMMMM        MMMMMMMMM       MMMMMMMMMM        MMMMMMMMMM
//   MMMMMMMMM        MMMMMMMMMMMMMMMMMMMMMMMMMM        MMMMMMMMM
//   MMMMMMMMM        MMMMMMMMMMMMMMMMMMMMMMMMMM        MMMMMMMMM
//    MMMMMMMM        MMMMMMMMMMMMMMMMMMMMMMMMMM        MMMMMMMM
//     MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//      MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//       MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//         MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//           MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//             MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//                 MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
//                     MMMMMMMMMMMMMMMMMMMMMMMM
//                           MMMMMMMMMMMM
//
//
//	Copyright © 2012 - 2015 Roman Priebe
//
//	This file is part of M - Safe email made simple.
//
//	M is free software: you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, either version 3 of the License, or
//	(at your option) any later version.
//
//	M is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU General Public License for more details.
//
//	You should have received a copy of the GNU General Public License
//	along with M.  If not, see <http://www.gnu.org/licenses/>.
//





#import "AppleEncryptionEngine.h"
#import <CommonCrypto/CommonCrypto.h>
#import "NSData+Base64.h"
#import "PrivateKeyData.h"
#import "KeychainHelper.h"
#import "MynigmaErrorFactory.h"
#import "MynigmaError.h"



@interface AppleEncryptionEngine()

@property KeychainHelper* keychainHelper;

@end


@implementation AppleEncryptionEngine


- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper
{
    self = [super init];
    if (self)
    {
        self.keychainHelper = keychainHelper;
    }
    return self;
}

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        self.keychainHelper = [KeychainHelper sharedInstance];
    }
    return self;
}



#pragma mark - HASHES

/**
 * Hash some data using SHA-512
 */
- (NSData*)SHA512DigestOfData:(NSData*)data
{
    if(!data.length)
        return nil;
    
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    
    CC_SHA512([data bytes], (CC_LONG)[data length], digest);
    
    NSData* digestData = [NSData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
    
    return digestData;
}

/**
 * Hash some data using SHA-256
 */
- (NSData*)SHA256DigestOfData:(NSData*)data
{
    if(!data.length)
        return nil;
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA256([data bytes], (CC_LONG)[data length], digest);
    
    NSData* digestData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    
    return digestData;
}




#pragma mark - AES

/**
 * Encrypt data of arbitrary length using AES with 128 bit key in CBC mode with random IV
 * The IV is prepended to the result
 */
- (NSData*)AESEncryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData error:(NSError**)error
{
    //fill IV with random data
    NSData* initialVector = [self randomBytesOfLength:16];
    
    return [self AESEncryptData:data withSessionKey:sessionKeyData IV:initialVector error:error];
}

/**
 * Encrypt data of arbitrary length using AES with 128 bit key in CBC mode with specified IV
 * The IV is prepended to the result
 */
- (NSData*)AESEncryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData IV:(NSData*)initialVector error:(NSError**)error
{
    //the data buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void* buffer = malloc(bufferSize);
    
    //will be set to the number of bytes actually encrypted
    size_t numBytesEncrypted = 0;
    
    //encrypting in CBC mode
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, [sessionKeyData bytes], kCCKeySizeAES128, (char*)[initialVector bytes], [data bytes], [data length], buffer, bufferSize, &numBytesEncrypted);
    
    //the number of actually encrypted bytes should never be shorter than the data
    if(numBytesEncrypted<[data length])
    {
        //        NSLog(@"INCOMPLETE DATA ENCRYPTED!!!!! %ld vs. %ld bytes...",numBytesEncrypted,(unsigned long)data.length);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorAESTooFewBytesEncrypted];
        if(buffer)
            free(buffer);
        return nil;
    }
    
    if (cryptStatus == kCCSuccess)
    {
        //encryption successful
        
        //first take the IV
        NSMutableData* encodedData = [initialVector mutableCopy];
        
        //then append the encrypted data
        [encodedData appendData:[[NSData alloc] initWithBytes:buffer length:numBytesEncrypted]];
        
        free(buffer);
        //now return the result
        return encodedData;
    }
    
    free(buffer);
    
    //error
    //    NSLog(@"Error AES encrypting data!");
    if(error)
        *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorAESCCCryptorFail];
    
    return nil;
}

/**
 * Decrypts data of arbitrary length containing an IV followed by some data encrypted using AES with 128 bit key in CBC mode
 */
- (NSData*)AESDecryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData error:(NSError**)error
{
    //IV and a single block of encrypted data should be at least 128 bits + 128 bits = 32 bytes
    if(data.length < 32)
    {
        //        NSLog(@"Trying to AES-decrypt invalid data!");
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorAESDataTooShort];
        
        return nil;
    }
    
    //first 16 bytes are the IV
    NSData* initialVector = [data subdataWithRange:NSMakeRange(0, 16)];
    
    //the rest is data to be decrypted
    NSData* actualData = [data subdataWithRange:NSMakeRange(16,[data length]-16)];
    
    //the buffer for the decrypted data
    size_t bufferSize = [actualData length];
    void* buffer = malloc(bufferSize);
    
    //will be set to the number of bytes actually decrypted
    size_t numBytesDecrypted = 0;
    
    //perform decryption
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, [sessionKeyData bytes], kCCKeySizeAES128, (char*)[initialVector bytes], [actualData bytes], [actualData length], buffer, bufferSize, &numBytesDecrypted);
    if (cryptStatus == kCCSuccess)
    {
        //decryption successful
        NSData* decodedData = [[NSData alloc] initWithBytes:buffer length:numBytesDecrypted];
        
        free(buffer);
        
        //return decoded data
        return decodedData;
    }
    
    free(buffer);
    
    if(error)
        *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorAESCCCryptorFail];
    //error
    //    NSLog(@"Error AES decrypting data!");
    return nil;
}





#pragma mark - RSA

/**
 * Encrypts a single block of data using RSA with OAEP padding
 *
 */
- (NSData*)RSAEncryptData:(NSData*)data withKeyLabel:(NSString*)keyLabel withSHA512MGF:(BOOL)useSHA512MGF error:(NSError**)error
{
    SecKeyRef publicEncryptionKeyRef = [self.keychainHelper publicSecKeyRefWithLabel:keyLabel forEncryption:YES];
    
    if(!publicEncryptionKeyRef)
    {
        //        NSLog(@"No public encryption key ref for key label %@", keyLabel);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSANoPublicKeyForLabel];
        return nil;
    }
    
#if TARGET_OS_IPHONE
    
    OSStatus status = noErr;
    
    size_t cipherBufferSize = SecKeyGetBlockSize(publicEncryptionKeyRef);
    uint8_t *cipherBuffer = (uint8_t*)malloc(cipherBufferSize);
    
    //  Error handling
    
    if (cipherBufferSize < sizeof(data))
    {
        if(cipherBuffer)
            free(cipherBuffer);
        //        NSLog(@"Could not encrypt.  Packet too large.\n");
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSAPacketTooLarge];
        return nil;
    }
    
    // Encrypt using RSA with OAEP padding
    status = SecKeyEncrypt(publicEncryptionKeyRef, kSecPaddingOAEP, (uint8_t*)data.bytes, (size_t) data.length, cipherBuffer, &cipherBufferSize);
    
    NSData *encryptedData = nil;
    
    if(status==noErr && cipherBufferSize)
    {
        encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    }
    else
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSAWithOSStatus OSStatus:@(status)];
    }
    
    free(cipherBuffer);
    
    return encryptedData;
    
#else
    
    //create encryption transform
    CFErrorRef errorRef;
    SecTransformRef rsaEncryptionRef = SecEncryptTransformCreate(publicEncryptionKeyRef, &errorRef);
    
    if(errorRef)
    {
        //        NSLog(@"Error creating RSA transform: %@",errorRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSACannotCreateTransform];
        if(rsaEncryptionRef)
            CFRelease(rsaEncryptionRef);
        return nil;
    }
    
    //input is the data argument provided
    SecTransformSetAttribute(rsaEncryptionRef, kSecTransformInputAttributeName, (__bridge CFDataRef)data, &errorRef);
    if(errorRef)
    {
        //        NSLog(@"Error setting RSA input: %@",errorRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSACannotSetInput];
        if(rsaEncryptionRef)
            CFRelease(rsaEncryptionRef);
        return nil;
    }
    
    //set padding to OAEP
    SecTransformSetAttribute(rsaEncryptionRef, kSecPaddingKey, kSecPaddingOAEPKey, &errorRef);
    if(errorRef)
    {
        //        NSLog(@"Error setting padding to OAEP: %@",errorRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSACannotSetPadding];
        if(rsaEncryptionRef)
            CFRelease(rsaEncryptionRef);
        return nil;
    }
    
    //SHA1 no longer recommended for new applications, so set digest algorithm to SHA2 instead
    /*SecTransformSetAttribute(rsaEncryptionRef, kSecOAEPMGF1DigestAlgorithmAttributeName, kSecDigestSHA2, &errorRef);
     if(errorRef)
     {
     NSLog(@"Error setting OAEP digest algorithm to sha2: %@",errorRef);
     return nil;
     }*/
    
    //perform the encryption
    NSData* encryptedData = CFBridgingRelease(SecTransformExecute(rsaEncryptionRef, &errorRef));
    if(errorRef)
    {
        //        NSLog(@"Error RSA encrypting session key: %@",errorRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSACannotExecuteTransform];
        if(rsaEncryptionRef)
            CFRelease(rsaEncryptionRef);
        return nil;
    }
    
    CFRelease(rsaEncryptionRef);
    
    //return the result
    return encryptedData;
    
#endif
}

/**
 * Decrypts a single block of data using RSA with OAEP padding
 *
 */
- (NSData*)RSADecryptData:(NSData*)data withKeyLabel:(NSString*)keyLabel withSHA512MGF:(BOOL)useSHA512MGF error:(NSError**)error
{
    
    SecKeyRef privateDecryptionKeyRef = [self.keychainHelper privateSecKeyRefWithLabel:keyLabel forEncryption:YES];
    
    if(!privateDecryptionKeyRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSANoPublicKeyForLabel];
        return nil;
    }
    
#if TARGET_OS_IPHONE
    
    size_t plainBufferSize = SecKeyGetBlockSize(privateDecryptionKeyRef);
    uint8_t* plainBuffer = (uint8_t*)malloc(plainBufferSize);
    
    if(plainBufferSize < sizeof(data))
    {
        if(plainBuffer)
            free(plainBuffer);
        // Ordinarily, you would split the data up into blocks
        // equal to plainBufferSize, with the last block being
        // shorter. For simplicity, this example assumes that
        // the data is short enough to fit.
        //        NSLog("Could not decrypt.  Packet too large.\n");
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSAPacketTooLarge];
        return nil;
    }
    
    //  Error handling
    
    OSStatus status = SecKeyDecrypt(privateDecryptionKeyRef, kSecPaddingOAEP, (uint8_t*)data.bytes, (size_t)data.length, plainBuffer, &plainBufferSize);
    
    NSData* decryptedData = nil;
    
    if(status==noErr && plainBufferSize)
    {
        decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    }
    else
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSAWithOSStatus OSStatus:@(status)];
    }
    
    free(plainBuffer);
    
    //    SessionKeys* sessionKeys = [SessionKeys sessionKeysFromData:decryptedData];
    
    return decryptedData;
    
#else
    
    //create decryption transform
    CFErrorRef errorRef;
    SecTransformRef rsaDecryptionRef = SecDecryptTransformCreate(privateDecryptionKeyRef, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSACannotCreateTransform];
        //        NSLog(@"Error creating RSA transform: %@",errorRef);
        if(rsaDecryptionRef)
            CFRelease(rsaDecryptionRef);
        return nil;
    }
    
    //input is the data to be decrypted
    SecTransformSetAttribute(rsaDecryptionRef, kSecTransformInputAttributeName, (__bridge CFDataRef)data, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSACannotSetInput];
        //        NSLog(@"Error setting RSA input: %@",errorRef);
        if(rsaDecryptionRef)
            CFRelease(rsaDecryptionRef);
        return nil;
    }
    
    //set padding to OAEP
    SecTransformSetAttribute(rsaDecryptionRef, kSecPaddingKey, kSecPaddingOAEPKey, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSACannotSetPadding];
        //        NSLog(@"Error setting padding to OAEP: %@",errorRef);
        if(rsaDecryptionRef)
            CFRelease(rsaDecryptionRef);
        return nil;
    }
    
    //set digest algorithm to SHA2
    /*SecTransformSetAttribute(rsaDecryptionRef, kSecOAEPMGF1DigestAlgorithmAttributeName, kSecDigestSHA2, &errorRef);
     if(errorRef)
     {
     NSLog(@"Error setting OAEP digest algorithm to sha2: %@",errorRef);
     return nil;
     }*/
    
    //perform decryption
    NSData* decryptedData = (__bridge_transfer NSData*)SecTransformExecute(rsaDecryptionRef, &errorRef);
    
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorRSACannotExecuteTransform];
        //        NSLog(@"Error RSA decrypting session key: %@",errorRef);
        if(rsaDecryptionRef)
            CFRelease(rsaDecryptionRef);
        return nil;
    }
    
    if(rsaDecryptionRef)
        CFRelease(rsaDecryptionRef);
    
    //    SessionKeys* sessionKeys = [SessionKeys sessionKeysFromData:decryptedData];
    
    //return result
    return decryptedData;
    
#endif
}

/**
 * Signs a single block of data using RSA with PKCS#1v1.5 or PSS padding
 *
 */
- (NSData*)RSASignHash:(NSData*)mHash withKeyLabel:(NSString*)keyLabel withPSSPadding:(BOOL)usePSSPadding error:(NSError**)error
{
    SecKeyRef privateSigningKeyRef = [self.keychainHelper privateSecKeyRefWithLabel:keyLabel forEncryption:NO];
    
#if TARGET_OS_IPHONE
    
    if(!privateSigningKeyRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorNoKeyForKeyLabel];
        return nil;
    }
    
    size_t signedDataBufferSize = SecKeyGetBlockSize(privateSigningKeyRef);
    uint8_t* signedDataBuffer = (uint8_t*)malloc(signedDataBufferSize);
    
    if (signedDataBufferSize < sizeof(mHash))
    {
        if(signedDataBuffer)
            free(signedDataBuffer);
        // Ordinarily, you would split the data up into blocks
        // equal to plainBufferSize, with the last block being
        // shorter. For simplicity, this example assumes that
        // the data is short enough to fit.
        //        NSLog(@"Could not decrypt.  Packet too large.\n");
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSAPacketTooLarge];
        
        return nil;
    }
    
    OSStatus status = SecKeyRawSign(privateSigningKeyRef, kSecPaddingPKCS1SHA512, (uint8_t*)mHash.bytes, mHash.length, signedDataBuffer, &signedDataBufferSize);
    
    NSData* signedData = nil;
    
    if(status==noErr && signedDataBufferSize)
    {
        signedData = [NSData dataWithBytes:signedDataBuffer length:signedDataBufferSize];
    }
    else
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSAWithOSStatus OSStatus:@(status)];
        //        NSLog(@"Error signing data: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
    }
    
    free(signedDataBuffer);
    
    return signedData;
    
#else
    
    CFErrorRef errorRef;
    SecTransformRef rsaSigningRef = SecSignTransformCreate(privateSigningKeyRef, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotCreateTransform];
        //        NSLog(@"Error creating RSA signature transform");
        if(rsaSigningRef)
            CFRelease(rsaSigningRef);
        return nil;
    }
    
    //CFRelease(privateSigningKeyRef);
    
    SecTransformSetAttribute(rsaSigningRef, kSecTransformInputAttributeName, (__bridge CFDataRef)mHash, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotSetInput];
        //        NSLog(@"Error setting RSA signature input: %@",errorRef);
        if(rsaSigningRef)
            CFRelease(rsaSigningRef);
        return nil;
    }
    
    //CFStringRef typeRef = (CFStringRef)SecTransformGetAttribute(rsaSigningRef, kSecInputIsAttributeName);
    
    //NSLog(@"Input: %@", (__bridge NSString*)typeRef);
    
    
    SecTransformSetAttribute(rsaSigningRef, kSecInputIsAttributeName, kSecInputIsDigest, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotSetInputTypeToDigest];
        //        NSLog(@"Error setting input type to digest: %@",errorRef);
        return nil;
    }
    
    SecTransformSetAttribute(rsaSigningRef, kSecPaddingKey, kSecPaddingPKCS1Key, &errorRef);
    if (errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotSetPadding];
        return nil;
    }
    
    SecTransformSetAttribute(rsaSigningRef, kSecDigestTypeAttribute, kSecDigestSHA2, &errorRef);
    if(errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotSetDigest];
        return nil;
    }
    
    
    Boolean set = SecTransformSetAttribute(rsaSigningRef, kSecDigestLengthAttribute, (__bridge CFNumberRef)@512, &errorRef);
    if (!set || errorRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotSetDigestLength];
        return nil;
    }
    
    
    NSData* rsaSignature = CFBridgingRelease(SecTransformExecute(rsaSigningRef, &errorRef));
    if(errorRef)
    {
        //        NSLog(@"Error RSA signing message digest: %@",errorRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotExecuteTransform];
        if(rsaSigningRef)
            CFRelease(rsaSigningRef);
        return nil;
    }
    CFRelease(rsaSigningRef);
    
    //NSLog(@"Signature: %@",rsaSignature);
    
    return rsaSignature;
    
#endif
}

/**
 * Verifies the signature on a single block of data using RSA with PKCS#1v1.5 or PSS padding
 *
 */
- (BOOL)RSAVerifySignature:(NSData*)signature ofHash:(NSData*)dataHash withPSSPadding:(BOOL)usePSSPadding withKeyLabel:(NSString*)keyLabel error:(NSError**)error
{
    SecKeyRef publicVerificationKeyRef = [self.keychainHelper publicSecKeyRefWithLabel:keyLabel forEncryption:NO];
    
    if(!publicVerificationKeyRef)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorNoKey];
        return NO;
    }
    
#if TARGET_OS_IPHONE
    
    OSStatus status = SecKeyRawVerify(publicVerificationKeyRef, kSecPaddingPKCS1SHA512, (uint8_t*)dataHash.bytes, (size_t)dataHash.length, (uint8_t*)signature.bytes, (size_t)signature.length);
    
    if(status==errSecSuccess)
    {
        return YES;
    }
    
    if(error)
        *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSAInvalidSignature];
    
    return NO;
    
#else
    
    CFErrorRef errorRef = nil;
    SecTransformRef rsaVerificationRef = SecVerifyTransformCreate(publicVerificationKeyRef, (__bridge CFDataRef)signature, &errorRef);
    if(errorRef)
    {
        //        NSLog(@"Error creating RSA signature transform: %@ = %@ = %@",errorRef, dataHash, publicVerificationKeyRef);
        if(rsaVerificationRef)
            CFRelease(rsaVerificationRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSACannotCreateTransform];
        return NO;
    }
    
    //CFRelease(publicVerificationKeyRef);
    
    SecTransformSetAttribute(rsaVerificationRef, kSecTransformInputAttributeName, (__bridge CFTypeRef)dataHash, &errorRef);
    if(errorRef)
    {
        //        NSLog(@"Error setting RSA signature input: %@",errorRef);
        if(rsaVerificationRef)
            CFRelease(rsaVerificationRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSACannotSetInput];
        return NO;
    }
    
    SecTransformSetAttribute(rsaVerificationRef, kSecPaddingKey, kSecPaddingPKCS1Key, &errorRef);
    if(errorRef)
    {
        //        NSLog(@"Error setting padding to PKCS1: %@",errorRef);
        if(rsaVerificationRef)
            CFRelease(rsaVerificationRef);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSACannotSetPadding];
        return NO;
    }
    
    @try
    {
        
        if(CFBridgingRelease(SecTransformExecute(rsaVerificationRef, &errorRef)))
        {
            if(rsaVerificationRef)
                CFRelease(rsaVerificationRef);
            
            if(errorRef)
            {
                if(error)
                    *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSACannotExecuteTransform];
                return NO;
            }
            
            //NSLog(@"Signature is OK!!");
            return YES;
        }
    }
    @catch(NSException* exception)
    {
        //        NSLog(@"Exception raised while trying to verify signature!!! %@", exception);
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSAExceptionCaught];
        return NO;
    }
    
    if(rsaVerificationRef)
        CFRelease(rsaVerificationRef);
    
    //    NSLog(@"Signature does not match!! %@",errorRef);
    
    if(error)
        *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSAInvalidSignature];
    
    return NO;
    
#endif
}


#pragma mark - HMAC


/**
 * Computes the SHA512 HMAC of message with secret
 *
 */
- (NSData*)HMACForMessage:(NSData *)message withSecret:(NSData *)secret
{
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA512, secret.bytes, secret.length, message.bytes, message.length, digest);
    
    return [NSData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
}


/**
 * Coompares HMAC with the SHA512 HMAC of message using secret
 */
- (BOOL)verifyHMAC:(NSData*)HMAC ofMessage:(NSData*)message withSecret:(NSData*)secret
{
    NSData* computedHMAC = [self HMACForMessage:message withSecret:secret];
    
    if(!computedHMAC.length || !HMAC.length)
    {
        return NO;
    }
    
    return [computedHMAC isEqual:HMAC];
}


#pragma mark - KEY GENERATION

/**
 * Return #length cryptographically secure pseudo-random bytes
 */
- (NSData*)randomBytesOfLength:(NSInteger)length
{
    uint8_t* randomDataBuffer = (uint8_t*)malloc(length);
    
    int result = SecRandomCopyBytes(kSecRandomDefault, length, randomDataBuffer);
    
    NSData* sessionKeyData = nil;
    
    if(result == 0)
    {
        sessionKeyData = [NSData dataWithBytes:randomDataBuffer length:length];
    }
    else
    {
        NSLog(@"Error generating random data!!!");
    }
    
    if(randomDataBuffer)
        free(randomDataBuffer);
    
    return sessionKeyData;
}

/**
 * Return 128/8 = 16 cryptographically secure pseudo-random bytes
 */
- (NSData*)generateNewAESSessionKeyData
{
    return [self randomBytesOfLength:kCCBlockSizeAES128];
}

/**
 * Return 1024/8 = 128 cryptographically secure pseudo-random bytes
 */
- (NSData*)generateNewHMACSecret
{
    //1024 bits = 128 bytes
    return [self randomBytesOfLength:128];
}

/**
 * Generate a fresh RSA private key of length 4096 bit
 */
- (void)generateNewPrivateKeyWithCallback:(void(^)(NSData* publicKeyData, NSData* privateKeyData, NSError* error))callback
{
    //asynchronous generation
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        
        //the dictionary of properties for the keychain items to be added
        
        //general
        __block NSMutableDictionary* passDict = [NSMutableDictionary new];
        [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [passDict setObject:@4096 forKey:(__bridge id)kSecAttrKeySizeInBits];
        
        
        //specific to signature keys
        [passDict setObject:@"Mynigma" forKey:(__bridge id)kSecAttrApplicationLabel];
        [passDict setObject:@NO forKey:(__bridge id)kSecAttrIsPermanent];
        [passDict setObject:@YES forKey:(__bridge id)kSecReturnRef];
        
        SecKeyRef publicKeyRef = NULL;
        SecKeyRef privateKeyRef = NULL;
        
        //generate the key pair
        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)passDict, &publicKeyRef, &privateKeyRef);
        
        if(status != noErr)
        {
            NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
            NSLog(@"Error creating key pair: %@", error);
            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
            callback(nil, nil, error);
            return;
        }
        
        //export the generated key pair data
        NSData* publicKeyData = [self.keychainHelper dataForSecKeyRef:publicKeyRef isPrivate:NO];
        
        NSData* privateKeyData = [self.keychainHelper dataForSecKeyRef:privateKeyRef isPrivate:YES];
        
        if(callback)
            callback(publicKeyData, privateKeyData, nil);
        
    });
}



#pragma mark - PBKDF2

/**
 * PBKDF2 key derivation from password with 5000 iterations and SHA512 hash function
 */
- (NSData*)AES128KeyFromPassword:(NSString*)password withSalt:(NSData*)salt
{
    return [self AES128KeyUsingPBKDF2WithPassword:password salt:salt iterations:5000];
}

/**
 * PBKDF2 key derivation from password with the specified number of iterations and SHA512 hash function
 */
- (NSData*)AES128KeyUsingPBKDF2WithPassword:(NSString*)password salt:(NSData*)salt iterations:(NSUInteger)iterations
{
    NSData* passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char key[16];
    CCKeyDerivationPBKDF(kCCPBKDF2, passwordData.bytes, passwordData.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA512, (int)iterations, key, 16);

    return [NSData dataWithBytes:key length:16];
}


@end
