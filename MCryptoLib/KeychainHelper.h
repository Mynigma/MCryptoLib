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




@class PublicKeyData, PrivateKeyData, PublicKeychainItemRefs, PrivateKeychainItemRefs, OpenSSLEncryptionEngine, MynigmaPublicKey, MynigmaPrivateKey, MynigmaKeyManager;

@interface KeychainHelper : NSObject


@property OpenSSLEncryptionEngine* openSSLEngine;


+ (KeychainHelper*)sharedInstance;

- (instancetype)initWithKeyManager:(MynigmaKeyManager*)keyManager;

#pragma mark - UUID

//- (NSString*)fetchUUIDFromKeychain;
//
//- (BOOL)saveUUIDToKeychain:(NSString*)UUID;



#pragma mark - PASSWORDS

////lists passwords saved to the keychain by other clients
////doesn't work for Apple Mail accounts in newer OS versions
////this is used for initial account setup
//- (NSArray*)listLocalKeychainItems;
//
////fetches a password from the keychain
//- (NSString*)passwordForPersistentRef:(NSData*)persistentRef;
//
////when the user enters his email address into the setup dialogue this method is called to check if an appropriate password is already stored in the login keychain
//+ (NSString*)findPasswordForEmail:(NSString*)email andServer:(NSString*)server;
//
////finds a password using the keychain refs associated with an account
//+ (NSString*)findPasswordForAccount:(NSManagedObjectID*)accountSettingID incoming:(BOOL)isIncoming;
//
////upon adding an account, this will create appropriate entries in the keychain and save the persistent refs to the database
//+ (BOOL)savePassword:(NSString*)password forAccount:(NSManagedObjectID*)accountSettingID incoming:(BOOL)isIncoming;
//
////saves a password asynchronously
//+ (void)saveAsyncPassword:(NSString*)password forAccountSetting:(IMAPAccountSetting*)accountSetting incoming:(BOOL)isIncoming withCallback:(void(^)(BOOL success))callback;
//
////is there a password in the keychain matching this email and IMAP/SMTP server
//+ (BOOL)haveKeychainPasswordForEmail:(NSString*)email andServer:(NSString*)server;
//
////removes the password stored for the specified account
//+ (BOOL)removePasswordForAccount:(NSManagedObjectID*)accountSettingID incoming:(BOOL)isIncoming;





#pragma mark - PUBLIC KEYS

//- (void)fetchAllKeysFromKeychainWithCallback:(void(^)(void))callback;

- (PublicKeychainItemRefs*)addPublicKeyDataToKeychain:(PublicKeyData*)publicKeyData;

- (BOOL)havePublicKeychainItemWithLabel:(NSString*)keyLabel;

- (BOOL)removePublicKeychainItemWithLabel:(NSString*)keyLabel;

- (BOOL)doesKeychainItemMatchPublicKeyData:(PublicKeyData*)publicKeyData;

- (PublicKeyData*)dataForPublicKey:(MynigmaPublicKey*)publicKey;

- (PublicKeyData*)dataForPublicKeychainItemWithLabel:(NSString*)keyLabel;

//+ (NSArray*)persistentRefsForPublicKeychainItemWithLabel:(NSString*)keyLabel;

//a list of all public keys in the keychain
//including presistent references
//- (NSArray*)listPublicKeychainItems;

//- (PublicKeychainItemRefs*)refsForPublicKeychainItemWithLabel:(NSString*)keyLabel;




#pragma mark - PRIVATE KEYS

- (PrivateKeychainItemRefs*)addPrivateKeyDataToKeychain:(PrivateKeyData*)privateKeyData;

- (BOOL)havePrivateKeychainItemWithLabel:(NSString*)keyLabel;

- (BOOL)removePrivateKeychainItemWithLabel:(NSString*)keyLabel;

- (BOOL)doesKeychainItemMatchPrivateKeyData:(PrivateKeyData*)privateKeyData;

//- (PrivateKeyData*)dataForPrivateKeyWithLabel:(NSString*)keyLabel;

- (PrivateKeyData*)dataForPrivateKey:(MynigmaPrivateKey*)privateKey;

- (PrivateKeyData*)dataForPrivateKeychainItemWithLabel:(NSString*)keyLabel;

//+ (NSArray*)persistentRefsForPrivateKeychainItemWithLabel:(NSString*)keyLabel;

//a list of all private keys in the keychain
//including presistent references
//- (NSArray*)listPrivateKeychainItems;

//- (PrivateKeychainItemRefs*)refsForPrivateKeychainItemWithLabel:(NSString*)keyLabel;



#pragma mark - Keychain refs

//return the SecKeyRef for the key with the specified label
- (SecKeyRef)privateSecKeyRefWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption;
- (SecKeyRef)publicSecKeyRefWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption;

- (NSData*)dataForPersistentRef:(NSData*)persistentRef isPrivate:(BOOL)isPrivate;
- (NSData*)dataForSecKeyRef:(SecKeyRef)secKeyRef isPrivate:(BOOL)isPrivate;

+ (SecKeyRef)secKeyRefFromPersistentKeyRef:(NSData*)persistentKeyRef;
+ (NSData*)persistentKeyRefFromSecKeyRef:(SecKeyRef)publicSecKeyRef;




@end
