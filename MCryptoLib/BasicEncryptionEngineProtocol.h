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


#import <Foundation/Foundation.h>
#import "MynigmaKeyManager.h"






/**
 * Protocol for basic encryption operations
 * It is implemented by AppleEncryptionEngine and OpenSSLEncryptionEngine
 */
@protocol BasicEncryptionEngineProtocol <NSObject>




#pragma mark - HASHES

/**
 * Hash some data using SHA-512
 */
- (NSData*)SHA512DigestOfData:(NSData*)data;

/**
 * Hash some data using SHA-256
 */
- (NSData*)SHA256DigestOfData:(NSData*)data;



#pragma mark - AES

/**
 * Encrypt data of arbitrary length using AES with 128 bit key in CBC mode with random IV
 * The IV is prepended to the result
 */
- (NSData*)AESEncryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData error:(NSError**)error;

/**
 * Encrypt data of arbitrary length using AES with 128 bit key in CBC mode with specified IV
 * The IV is prepended to the result
 */
- (NSData*)AESEncryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData IV:(NSData*)initialVector error:(NSError**)error;

/**
 * Decrypt data of arbitrary length containing an IV followed by some data encrypted using AES with 128 bit key in CBC mode
 */
- (NSData*)AESDecryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData error:(NSError**)error;




#pragma mark - RSA

/**
 * Encrypt a single block of data using RSA with OAEP padding
 *
 * @param useSHA512MGF Pass YES to use SHA512 as MGF, NO for default (SHA1)
 */
- (NSData*)RSAEncryptData:(NSData*)data withKeyLabel:(NSString*)keyLabel withSHA512MGF:(BOOL)useSHA512MGF error:(NSError**)error;

/**
 * Decrypt a single block of data using RSA with OAEP padding
 *
 * @param useSHA512MGF Pass YES to use SHA512 as MGF, NO for default (SHA1)
 */
- (NSData*)RSADecryptData:(NSData*)data withKeyLabel:(NSString*)keyLabel withSHA512MGF:(BOOL)useSHA512MGF error:(NSError**)error;

/**
 * Sign the hash of some data using RSA with PKCS#1v1.5 or PSS padding
 *
 */
- (NSData*)RSASignHash:(NSData*)mHash withKeyLabel:(NSString*)keyLabel withPSSPadding:(BOOL)usePSSPadding error:(NSError**)error;

/**
 * Verify the signature on a hash of data some data using RSA with PKCS#1v1.5 or PSS padding
 *
 */
- (BOOL)RSAVerifySignature:(NSData*)signature ofHash:(NSData*)dataHash withPSSPadding:(BOOL)usePSSPadding withKeyLabel:(NSString*)keyLabel error:(NSError**)error;




#pragma mark - HMAC


/**
 * Computes the SHA512 HMAC of message with secret
 */
- (NSData*)HMACForMessage:(NSData *)message withSecret:(NSData *)secret;

/**
 * Coompares HMAC with the SHA512 HMAC of message using secret
 */
- (BOOL)verifyHMAC:(NSData*)HMAC ofMessage:(NSData*)message withSecret:(NSData*)secret;



#pragma mark - KEY GENERATION

/**
 * Return #length cryptographically secure pseudo-random bytes
 */
- (NSData*)randomBytesOfLength:(NSInteger)length;

/**
 * Return 128/8 = 16 cryptographically secure pseudo-random bytes
 */
- (NSData*)generateNewAESSessionKeyData;

/**
 * Return 1024/8 = 128 cryptographically secure pseudo-random bytes
 */
- (NSData*)generateNewHMACSecret;

/**
 * Generate a fresh RSA private key of length 4096 bit
 */
- (void)generateNewPrivateKeyWithCallback:(void(^)(NSData* publicKeyData, NSData* privateKeyData, NSError* error))callback;





#pragma mark - PBKDF2

/**
 * PBKDF2 key derivation from password with 5000 iterations and SHA512 hash function
 */
- (NSData*)AES128KeyFromPassword:(NSString*)password withSalt:(NSData*)salt;

/**
 * PBKDF2 key derivation from password with the specified number of iterations and SHA512 hash function
 */
- (NSData*)AES128KeyUsingPBKDF2WithPassword:(NSString*)password salt:(NSData*)salt iterations:(NSUInteger)iterations;


@end
