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

#import "netpgp.h"
#import "keyring.h"





@class KeychainHelper, OpenSSLEncryptionEngine, EmailAddress;

@interface PGPKeyManager : NSObject

@property KeychainHelper* keychainHelper;
@property OpenSSLEncryptionEngine* openSSLEngine;



- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper;



+ (BOOL)stringIsArmoured:(NSString*)string;
+ (BOOL)dataIsArmoured:(NSData*)data;


- (netpgp_t*)buildnetpgp;

- (BOOL)importKeyFromFileWithURL:(NSURL*)fileURL;



//- (NSArray*)verificationKeysForEmailAddress:(EmailAddress*)emailAddress;
//
//- (NSArray*)decryptionKeyForUserID:(NSString*)userID;
//
//- (PGPPrivateKey*)signatureKeyForUserID:(NSString*)userID;
//
//- (PGPPublicKey*)encryptionKeyForUserID:(NSString*)userID;




//- (__ops_key_t*)opsPublicKeyForUserID:(NSString*)userID;

//- (const __ops_key_t*)opsPrivateKeyForUserID:(NSString*)userID;





- (BOOL)generateKeyForUserID:(NSString*)userID bitLength:(NSInteger)bitLength;

- (NSArray*)listKeys;


- (NSData*)PKCS8DataForOpsPGPPublicKey:(const __ops_key_t*)opsKey;

- (NSData*)PKCS8DataForOpsPGPPrivateKey:(const __ops_key_t*)opsKey;




- (__ops_key_t*)opsPublicKeyForUserID:(NSString*)userID forEncryption:(BOOL)forEncryption;

- (__ops_key_t*)opsPrivateKeyForUserID:(NSString*)userID forEncryption:(BOOL)forEncryption;
@end
