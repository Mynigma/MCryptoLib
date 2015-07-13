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


#define ACCESS_GROUP @"org.mynigma.Mynigma"


#import "KeychainHelper+AttributeDictionaries.h"

@implementation KeychainHelper (AttributeDictionaries)


//returns a generic dictionary with the account and server settings set to the sepcified values - this is amended with further object-key pairs and then passed to the keychain functions such as SecItemCopyMatching
+ (NSMutableDictionary*)queryDictionaryForEmail:(NSString*)email withServer:(NSString*)server
{
    NSMutableDictionary *query = [NSMutableDictionary new];
    [query setObject:(__bridge id)kSecClassInternetPassword forKey:(__bridge id)kSecClass];
    [query setObject:[email lowercaseString] forKey:(__bridge id)kSecAttrAccount];
    [query setObject:[server lowercaseString] forKey:(__bridge id)kSecAttrServer];
    
    return query;
}


#pragma mark - Key attribute dictionaries

//a dictionary of generic values for Mynigma-type RSA keys
+ (NSMutableDictionary*)RSAKeyAttributes
{
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    //[passDict setObject:@4096 forKey:(__bridge id)kSecAttrKeySizeInBits];
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    return passDict;
}

//a dictionary describing a Mynigma public key corresponding to the specified label - this dictionary is used for adding a key to the keychain and contains more attributes than the search dictionary, just to be on the safe side, since attributes might change in future versions
+ (NSMutableDictionary*)publicKeyAdditionDictForLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
#if TARGET_OS_IPHONE
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
    
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrApplicationTag];
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    
    return passDict;
    
#else
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    [passDict setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [passDict setObject:@4096 forKey:(id)kSecAttrKeySizeInBits];
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    //    SecAccessRef accessRef = [KeychainHelper accessRef:NO];
    //    if(accessRef)
    //        [passDict setObject:(__bridge id)accessRef forKey:kSecAttrAccess];
    
    NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
    
    
    if(forEncryption)
    {
        [passDict setObject:@"Mynigma encryption key" forKey:(__bridge id)kSecAttrDescription];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanVerify];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanSign];
        [passDict setObject:@YES forKey:(__bridge id)kSecAttrCanEncrypt];
    }
    else
    {
        [passDict setObject:@"Mynigma signature key" forKey:(__bridge id)kSecAttrDescription];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanDecrypt];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanEncrypt];
        [passDict setObject:@YES forKey:(__bridge id)kSecAttrCanVerify];
    }
    
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    
    [passDict setObject:@YES forKey:kSecAttrIsPermanent];
    
    return passDict;
    
#endif
}

+ (NSMutableDictionary*)publicKeySearchDictForLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
#if TARGET_OS_IPHONE
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
    
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    
    return passDict;
    
#else
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
    
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    
    return passDict;
    
#endif
}


//a dictionary describing a Mynigma private key corresponding to the specified label
+ (NSMutableDictionary*)privateKeyAdditionDictForLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    
#if TARGET_OS_IPHONE
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    NSString* attrLabel = [NSString stringWithFormat:@"%@%@", forEncryption?@"Mynigma encryption key ":@"Mynigma signature key ", keyLabel];
    
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrApplicationTag];
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [passDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    
    return passDict;
    
#else
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    [passDict setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [passDict setObject:@4096 forKey:(id)kSecAttrKeySizeInBits];
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    NSString* attrLabel = [NSString stringWithFormat:@"%@%@", forEncryption?@"Mynigma encryption key ":@"Mynigma signature key ", keyLabel];
    
    if(forEncryption)
    {
        [passDict setObject:@"Mynigma encryption key" forKey:(__bridge id)kSecAttrDescription];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanVerify];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanSign];
    }
    else
    {
        [passDict setObject:@"Mynigma signature key" forKey:(__bridge id)kSecAttrDescription];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanDecrypt];
        [passDict setObject:(__bridge id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanEncrypt];
    }
    
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    
    [passDict setObject:@YES forKey:kSecAttrIsPermanent];
    
    return passDict;
    
#endif
}

+ (NSMutableDictionary*)privateKeySearchDictForLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
#if TARGET_OS_IPHONE
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    NSString* attrLabel = [NSString stringWithFormat:@"%@%@", forEncryption?@"Mynigma encryption key ":@"Mynigma signature key ", keyLabel];
    
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    //[passDict setObject:[NSData dataWithBytes:[attrLabel UTF8String] length:[attrLabel length]] forKey:(__bridge id)kSecAttrApplicationTag];
    
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    
    //[passDict setObject:@YES forKey:(__bridge id<NSCopying>)(kSecAttrIsPermanent)];
    
    return passDict;
    
#else
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    NSString* attrLabel = [NSString stringWithFormat:@"%@%@", forEncryption?@"Mynigma encryption key ":@"Mynigma signature key ", keyLabel];
    
    [passDict setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    [passDict setObject:attrLabel forKey:(__bridge id)kSecAttrLabel];
    
    [passDict setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [passDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    
    [passDict setObject:@YES forKey:kSecAttrIsPermanent];
    
    return passDict;
    
#endif
}


#if TARGET_OS_IPHONE

#else

+ (SecItemImportExportKeyParameters)importExportParams:(BOOL)forEncryption
{
    SecItemImportExportKeyParameters params;
    
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    
    params.keyAttributes = NULL;
    
    if(forEncryption)
        params.keyUsage = (__bridge CFArrayRef)@[(__bridge id)kSecAttrCanEncrypt];
    else
        params.keyUsage = (__bridge CFArrayRef)@[(__bridge id)kSecAttrCanVerify];
    
    return params;
}

#endif






#pragma mark - S/MIME

+ (NSMutableDictionary*)SMIMECertificateAdditionDict
{
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
   passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassCertificate;
 
    //    kSecClassCertificate item attributes:
    //
    //    kSecAttrAccessible
    //    kSecAttrAccessControl
    //    kSecAttrAccessGroup
    //    kSecAttrCertificateType (read-only)
    //    kSecAttrCertificateEncoding (read-only)
    //    kSecAttrLabel
    //    kSecAttrSubject (read-only)
    //    kSecAttrIssuer (read-only)
    //    kSecAttrSerialNumber (read-only)
    //    kSecAttrSubjectKeyID (read-only)
    //    kSecAttrPublicKeyHash (read-only)
    
    //need to be able to access certificates to process messages in the background
    passDict[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    
    //TODO: set proper access control
    
        SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleAfterFirstUnlock, 0, NULL);
    
        if(accessControlRef && &kSecAttrAccessControl)
            passDict[(__bridge id)kSecAttrAccessControl] = (__bridge id)(accessControlRef);

//    if(&kSecAttrAccessGroup)
//        passDict[(__bridge id)kSecAttrAccessGroup] = ACCESS_GROUP;
    
    passDict[(__bridge id)kSecAttrLabel] = @"Mynigma S/MIME certificate";
    
    return passDict;
}

+ (NSMutableDictionary*)SMIMEPrivateKeyAdditionDictForFingerprint:(NSData*)fingerprint
{
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
//    kSecClassKey item attributes:
//    
//    kSecAttrAccessible
//    kSecAttrAccessControl
//    kSecAttrAccessGroup
//    kSecAttrKeyClass
//    kSecAttrLabel
//    kSecAttrApplicationLabel
//    kSecAttrIsPermanent
//    kSecAttrApplicationTag
//    kSecAttrKeyType
//    kSecAttrKeySizeInBits
//    kSecAttrEffectiveKeySize
//    kSecAttrCanEncrypt
//    kSecAttrCanDecrypt
//    kSecAttrCanDerive
//    kSecAttrCanSign
//    kSecAttrCanVerify
//    kSecAttrCanWrap
//    kSecAttrCanUnwrap
    
    //need to be able to access private keys to process messages in the background
    passDict[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    
    SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleAfterFirstUnlock, 0, NULL);
    
    if(accessControlRef && &kSecAttrAccessControl)
        passDict[(__bridge id)kSecAttrAccessControl] = (__bridge id)(accessControlRef);
    
//    if(&kSecAttrAccessGroup)
//        passDict[(__bridge id)kSecAttrAccessGroup] = ACCESS_GROUP;
    
    passDict[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPrivate;

    passDict[(__bridge id)kSecAttrLabel] = @"Mynigma S/MIME private key";
    
    //not sure this will work
    //perhaps the keychain has its own ideas
    //it's badly documented
    passDict[(__bridge id)kSecAttrApplicationLabel] = fingerprint;
    
    passDict[(__bridge id)kSecAttrIsPermanent] = @YES;
    
    //try this, too(!)
    passDict[(__bridge id)kSecAttrApplicationTag] = fingerprint;
    
    //not setting the other properties
    //the keychain functions should be able to work out the key size from the data provided
    //we don't want the buggy keychain to manage restrictions on use for encryption/signature etc.
    
    return passDict;
}



#pragma mark - PGP

+ (NSMutableDictionary*)publicPGPKeyAdditionDict
{
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
    //    kSecClassKey item attributes:
    //
    //    kSecAttrAccessible
    //    kSecAttrAccessControl
    //    kSecAttrAccessGroup
    //    kSecAttrKeyClass
    //    kSecAttrLabel
    //    kSecAttrApplicationLabel
    //    kSecAttrIsPermanent
    //    kSecAttrApplicationTag
    //    kSecAttrKeyType
    //    kSecAttrKeySizeInBits
    //    kSecAttrEffectiveKeySize
    //    kSecAttrCanEncrypt
    //    kSecAttrCanDecrypt
    //    kSecAttrCanDerive
    //    kSecAttrCanSign
    //    kSecAttrCanVerify
    //    kSecAttrCanWrap
    //    kSecAttrCanUnwrap
    
    //need to be able to access certificates to process messages in the background
    passDict[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    
    //TODO: set proper access control
    
    SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleAfterFirstUnlock, 0, NULL);
    
    if(accessControlRef && &kSecAttrAccessControl)
        passDict[(__bridge id)kSecAttrAccessControl] = (__bridge id)(accessControlRef);
    
    //    if(&kSecAttrAccessGroup)
    //        passDict[(__bridge id)kSecAttrAccessGroup] = ACCESS_GROUP;
    
    passDict[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPublic;
              
    passDict[(__bridge id)kSecAttrLabel] = @"Mynigma PGP public key";
    
    return passDict;
}

+ (NSMutableDictionary*)privatePGPKeyAdditionDict
{
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
    //    kSecClassKey item attributes:
    //
    //    kSecAttrAccessible
    //    kSecAttrAccessControl
    //    kSecAttrAccessGroup
    //    kSecAttrKeyClass
    //    kSecAttrLabel
    //    kSecAttrApplicationLabel
    //    kSecAttrIsPermanent
    //    kSecAttrApplicationTag
    //    kSecAttrKeyType
    //    kSecAttrKeySizeInBits
    //    kSecAttrEffectiveKeySize
    //    kSecAttrCanEncrypt
    //    kSecAttrCanDecrypt
    //    kSecAttrCanDerive
    //    kSecAttrCanSign
    //    kSecAttrCanVerify
    //    kSecAttrCanWrap
    //    kSecAttrCanUnwrap
    
    //need to be able to access certificates to process messages in the background
    passDict[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    
    //TODO: set proper access control
    
    SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleAfterFirstUnlock, 0, NULL);
    
    if(accessControlRef && &kSecAttrAccessControl)
        passDict[(__bridge id)kSecAttrAccessControl] = (__bridge id)(accessControlRef);
    
    //    if(&kSecAttrAccessGroup)
    //        passDict[(__bridge id)kSecAttrAccessGroup] = ACCESS_GROUP;
    
    passDict[(__bridge id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPrivate;
    
    passDict[(__bridge id)kSecAttrLabel] = @"Mynigma PGP private key";
    
    return passDict;
}




@end
