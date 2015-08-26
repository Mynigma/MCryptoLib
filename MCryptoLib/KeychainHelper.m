
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



#import "TargetConditionals.h"

#if TARGET_OS_IPHONE


#else

#import <Security/SecAccess.h>

#endif

#import <Security/Security.h>

#import "KeychainHelper.h"
#import "NSData+Base64.h"
#import "PublicKeyData.h"
#import "PrivateKeyData.h"
#import "KeychainHelper+AttributeDictionaries.h"
#import "KeyParser.h"
#import "PublicKeychainItemRefs.h"
#import "PrivateKeychainItemRefs.h"
#import "MynigmaPrivateKey.h"

#import "MynigmaKeyManager.h"

//#import "ThreadHelper.h"




//TODO: add synchronisableany property to password search queries


static dispatch_queue_t _keychainHelperDispatchQueue;




@implementation KeychainHelper



+ (instancetype)sharedInstance
{
    static dispatch_once_t p = 0;
    
    __strong static id sharedObject = nil;
    
    dispatch_once(&p, ^{
        sharedObject = [self new];
    });
    
    return sharedObject;
}

- (instancetype)initWithKeyManager:(MynigmaKeyManager*)keyManager
{
    self = [super init];
    if (self) {
        
        self.openSSLEngine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:keyManager];
    }
    return self;
}

- (instancetype)init
{
    return [self initWithKeyManager:[[MynigmaKeyManager alloc] initWithKeychainHelper:self]];
}


+ (dispatch_queue_t)keychainHelperDispatchQueue
{
    if(!_keychainHelperDispatchQueue)
        _keychainHelperDispatchQueue = dispatch_queue_create("MCryptoLib KeychainHelper dispatch queue", NULL);
    
    return _keychainHelperDispatchQueue;
}




#pragma mark - KEYCHAIN ITEMS LISTS

//lists all Mynigma public keys found in the keychain (as dictionaries of attributes)
//including a persistent reference
- (NSArray*)listPublicKeychainItems
{
    __block NSArray* returnValue = [NSMutableArray new];
    
    dispatch_sync([KeychainHelper keychainHelperDispatchQueue], ^{

         NSMutableArray* workingArray = [NSMutableArray new];
         
         __block NSMutableDictionary* passDict = [KeychainHelper RSAKeyAttributes];
         
         [passDict setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
         [passDict setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
         [passDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnPersistentRef];
         [passDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
         
         CFArrayRef resultsArray = nil;
         OSStatus oserr = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, (CFTypeRef*)&resultsArray);
         NSArray* array = CFBridgingRelease(resultsArray);
         if(oserr == noErr && array.count>0)
         {
             [workingArray addObjectsFromArray:array];
         }
         
         returnValue = workingArray;
     });
    
    return returnValue;
}

//lists all Mynigma private keys found in the keychain (as dictionaries of attributes)
//including a persistent reference
- (NSArray*)listPrivateKeychainItems
{
    __block NSArray* returnValue = [NSMutableArray new];
    
    dispatch_sync([KeychainHelper keychainHelperDispatchQueue], ^{
        
         NSMutableArray* workingArray = [NSMutableArray new];
         
         __block NSMutableDictionary* passDict = [KeychainHelper RSAKeyAttributes];
         
         [passDict setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
         [passDict setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
         [passDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnPersistentRef];
         [passDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
         
         CFArrayRef resultsArray = nil;
         OSStatus oserr = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, (CFTypeRef*)&resultsArray);
         NSArray* array = CFBridgingRelease(resultsArray);
         if(oserr == noErr && array.count>0)
         {
             [workingArray addObjectsFromArray:array];
         }
         returnValue = workingArray;
    });
    
    return returnValue;
}



#pragma mark - PUBLIC KEYS


#if TARGET_OS_IPHONE

//adds a single public key to the keychain
- (NSData*)addPublicKeyWithData:(NSData*)data toKeychainWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    if(!data)
    {
        NSLog(@"No data to add to keychain!!");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);

        return nil;
    }
    
    data = [KeyParser convertPublicKeyData:data fromFormat:MynigmaKeyFormatDefault toFormat:MynigmaKeyFormatX509];
    
    if(!data)
    {
        NSLog(@"Cannot add public key: data is nil!!");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);

        return nil;
    }
    
    SecCertificateRef cert = SecCertificateCreateWithData (kCFAllocatorDefault, (__bridge CFDataRef)(data));
    CFArrayRef certs = CFArrayCreate(kCFAllocatorDefault, (const void **) &cert, 1, NULL);
    
    SecTrustRef trustRef;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustCreateWithCertificates(certs, policy, &trustRef);
    SecTrustResultType trustResult;
    SecTrustEvaluate(trustRef, &trustResult);
    SecKeyRef publicKeyRef = SecTrustCopyPublicKey(trustRef);
    
    if(certs)
        CFRelease(certs);
    
    __block NSMutableDictionary* passDict = [KeychainHelper publicKeyAdditionDictForLabel:keyLabel forEncryption:forEncryption];
    
    [passDict setObject:(__bridge id)publicKeyRef forKey:(__bridge id)kSecValueRef];
    [passDict setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnPersistentRef];
    
    __block CFTypeRef result = NULL;

    dispatch_sync([KeychainHelper keychainHelperDispatchQueue], ^{
        
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
    
    if (status != noErr)
    {
        if(result)
            CFRelease(result);
        
        NSLog(@"Error adding keychain item! %@",[NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        
        return;
    }
        
    });
    
    return CFBridgingRelease(result);
}

#else

//adds a single public key to the keychain
- (NSData*)addPublicKeyWithData:(NSData*)data toKeychainWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    if(!data)
    {
        NSLog(@"No data to add to keychain!!");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        
        return nil;
    }
    
    if([self havePublicKeychainItemWithLabel:keyLabel])
    {
        NSArray* dataArray = [self persistentRefsForPublicKeychainItemWithLabel:keyLabel];
        if(dataArray.count<2)
            return nil;
        
        return forEncryption?dataArray[0]:dataArray[1];
    }
    
    __block NSData* persistentRef = NULL;
    
    dispatch_sync([KeychainHelper keychainHelperDispatchQueue], ^{
    
    //first import the key: turn the PEM file into a SecKeyRef
    SecItemImportExportKeyParameters params = [KeychainHelper importExportParams:forEncryption];
    
    SecExternalItemType itemType = kSecItemTypePublicKey;
    SecExternalFormat externalFormat = kSecFormatPEMSequence;
    int flags = 0;
    
    CFArrayRef temparray;
    OSStatus oserr = SecItemImport((__bridge CFDataRef)data, NULL, &externalFormat, &itemType, flags, &params, NULL /*don't add to a keychain*/, &temparray);
    if (oserr != noErr || CFArrayGetCount(temparray)<1)
    {
        NSLog(@"Error importing key! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return;
    }
    
    SecKeyRef encrKeyRef = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
    
    //now add it to the keychain - without a label at first (using a label doesn't work on add, so need to update the item later...)
    __block NSMutableDictionary* passDict = [KeychainHelper publicKeyAdditionDictForLabel:keyLabel forEncryption:forEncryption];
    
    [passDict setObject:(__bridge id)(encrKeyRef) forKey:kSecValueRef];
    
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    [passDict removeObjectForKey:(__bridge id)kSecAttrLabel];
    
    CFTypeRef result;
    
    oserr = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
    
    if(oserr != noErr)
    {
        NSLog(@"Error adding public keychain item: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
    }
    
    persistentRef = CFArrayGetValueAtIndex(result, 0);
    
    //almost done - just need to add the missing label
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:@{(__bridge id)kSecValuePersistentRef:persistentRef}];
    
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
    NSMutableDictionary* newAttributes = [NSMutableDictionary new];
    
    NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
    
    newAttributes[(__bridge id)kSecAttrLabel] = attrLabel;
    
//    SecKeychainItemRef itemRef = (SecKeychainItemRef)[KeychainHelper secKeyRefFromPersistentKeyRef:persistentRef];
    
    oserr = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)newAttributes);
    if (oserr != noErr)
    {
        NSLog(@"Error updating keychain item! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
    }
    
    });
    
//    [self setAccessRightsForKey:itemRef withDescription:@"Mynigma public key"];
    
    return persistentRef;
}

#endif



- (PublicKeychainItemRefs*)addPublicKeyDataToKeychain:(PublicKeyData *)publicKeyData
{
    NSString* keyLabel = publicKeyData.keyLabel;
    
    if(!keyLabel)
        return nil;
    
    if([self havePublicKeychainItemWithLabel:keyLabel])
    {
        if([self doesKeychainItemMatchPublicKeyData:publicKeyData])
        {
            //already have the same item in the keychain
            //we just need to return the keychain refs
            
            PublicKeychainItemRefs* keychainItemRefs = [self refsForPublicKeychainItemWithLabel:publicKeyData.keyLabel];
            
            return keychainItemRefs;
        }
        else
            return nil;
    }
    
    
    NSData* persistentEncrRef = [self addPublicKeyWithData:publicKeyData.publicKeyEncData toKeychainWithLabel:keyLabel forEncryption:YES];
    
    NSData* persistentVerRef = [self addPublicKeyWithData:publicKeyData.publicKeyVerData toKeychainWithLabel:keyLabel forEncryption:NO];
    
    if(persistentEncrRef && persistentVerRef)
    {
        return [[PublicKeychainItemRefs alloc] initWithPersistentEncKeyRef:persistentEncrRef persistentVerKeyRef:persistentVerRef];
    }
    
    return nil;
}

- (BOOL)havePublicKeychainItemWithLabel:(NSString*)keyLabel
{
    BOOL allOK = YES;
    
    NSMutableDictionary* passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    CFTypeRef result;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    return allOK;
}

- (BOOL)removePublicKeychainItemWithLabel:(NSString*)keyLabel
{
    BOOL allOK = YES;
    
    __block NSMutableDictionary* passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    return allOK;
}

- (BOOL)doesKeychainItemMatchPublicKeyData:(PublicKeyData*)publicKeyData
{
    PublicKeyData* existingKeyData = [self dataForPublicKeychainItemWithLabel:publicKeyData.keyLabel];
    
    return [existingKeyData isEqual:publicKeyData];
}

- (PublicKeyData*)dataForPublicKey:(MynigmaPublicKey*)publicKey
{
    if(!publicKey)
        return nil;

    NSData* encrData = [self dataForPersistentRef:publicKey.publicEncrKeyRef isPrivate:NO];
    NSData* verData = [self dataForPersistentRef:publicKey.publicVerifyKeyRef isPrivate:NO];
    
    if(encrData && verData)
        return [[PublicKeyData alloc] initWithKeyLabel:publicKey.keyLabel encData:encrData verData:verData];
    
    return [self dataForPublicKeychainItemWithLabel:publicKey.keyLabel];
}

- (PublicKeyData*)dataForPublicKeychainItemWithLabel:(NSString*)keyLabel
{
    NSMutableDictionary* passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        return nil;
    }
    
    NSData* persistentRefData = CFBridgingRelease(result);
    
    NSData* encKeyData = [self dataForPersistentRef:persistentRefData isPrivate:NO];
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    persistentRefData = CFBridgingRelease(result);
    
    NSData* verKeyData = [self dataForPersistentRef:persistentRefData isPrivate:NO];
    
    if(encKeyData && verKeyData)
        return [[PublicKeyData alloc] initWithKeyLabel:keyLabel encData:encKeyData verData:verKeyData];
    
    return nil;
}

- (PublicKeychainItemRefs*)refsForPublicKeychainItemWithLabel:(NSString*)keyLabel
{
    NSMutableDictionary* passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentEncRef = CFBridgingRelease(result);
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentVerRef = CFBridgingRelease(result);
    
    if(persistentEncRef && persistentVerRef)
        return [[PublicKeychainItemRefs alloc] initWithPersistentEncKeyRef:persistentEncRef persistentVerKeyRef:persistentVerRef];
    
    return nil;
}







#pragma mark - PRIVATE KEYS


#if TARGET_OS_IPHONE

//adds a single private key to the keychain (low level, private method)
- (NSData*)addPrivateKeyWithData:(NSData*)keyData toKeychainWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    //need a passphrase!!
    //without it, the addition to the keychain will succeed
    //we will be able to obtain a SecKeyRef/persistent ref
    //without problems or errors
    //but any attempts to use it for encryption/signature will fail
    //thanks, Apple.
    NSString* passphrase = @"";
    
    if(passphrase)
    {
        NSData* PKCS12KeyData = [KeyParser convertPrivateKeyData:keyData fromFormat:MynigmaKeyFormatDefault toFormat:MynigmaKeyFormatPKCS12 inPassphrase:nil outPassphrase:passphrase];
        
        if(!PKCS12KeyData)
            return nil;
        
        NSDictionary* optionsDict = @{(__bridge id)kSecImportExportPassphrase:passphrase};
        
        CFArrayRef results = NULL;
        
        OSStatus status = SecPKCS12Import((__bridge CFDataRef)PKCS12KeyData, (__bridge CFDictionaryRef)optionsDict, &results);
        
        if (status != errSecSuccess || !results)
        {
            if(results)
                CFRelease(results);
            
            NSLog(@"Failed to import private key!! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);

            return nil;
        }
        
        NSArray* items = CFBridgingRelease(results);
        
        if(items.count>0)
        {
            NSDictionary* identityAndTrust = items[0];
            SecIdentityRef identityRef = (__bridge SecIdentityRef)(identityAndTrust[(__bridge id)kSecImportItemIdentity]);
            
            SecKeyRef privateKey = NULL;
            status = SecIdentityCopyPrivateKey(identityRef, &privateKey);
            
            if (status) {
                NSLog(@"SecIdentityCopyPrivateKey failed. %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
                NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);

                if(privateKey)
                    CFRelease(privateKey);
                
                return nil;
            }
            
            NSMutableDictionary* passDict = [KeychainHelper privateKeyAdditionDictForLabel:keyLabel forEncryption:forEncryption];
            
            [passDict setObject:(__bridge id)(privateKey) forKey:(__bridge id)kSecValueRef];
            [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
            
            
            CFTypeRef result = NULL;
            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
            
            if(privateKey)
                CFRelease(privateKey);
            
            if (status != errSecSuccess || !result)
            {
                if(result)
                    CFRelease(result);
                NSLog(@"Error adding keychain item!!! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
                NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
                return nil;
            }
            
            return CFBridgingRelease(result);
        }
        
        return nil;
    }
    else
    {
        NSMutableDictionary* passDict = [KeychainHelper privateKeyAdditionDictForLabel:keyLabel forEncryption:forEncryption];
        
        [passDict setObject:keyData forKey:(__bridge id)kSecValueData];
        [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
        
        
        CFTypeRef result = NULL;
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
        
        if (status != errSecSuccess || !result)
        {
            if(result)
                CFRelease(result);
            NSLog(@"Error adding keychain item! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
            return nil;
        }
        
        return CFBridgingRelease(result);
    }
    
    return nil;
}

#else

- (NSData*)addPrivateKeyWithData:(NSData*)keyData toKeychainWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    if([self havePrivateKeychainItemWithLabel:keyLabel])
    {
        NSArray* dataArray = [self persistentRefsForPrivateKeychainItemWithLabel:keyLabel];
        if(dataArray.count<2)
            return nil;
        
        return forEncryption?dataArray[0]:dataArray[1];
    }
    
    SecItemImportExportKeyParameters params = [KeychainHelper importExportParams:forEncryption];
    
    SecExternalItemType itemType = kSecItemTypePrivateKey;
    SecExternalFormat externalFormat = kSecFormatOpenSSL;
    int flags = 0;
    
    params.keyUsage = forEncryption?(__bridge CFArrayRef)@[(__bridge id)kSecAttrCanDecrypt]:(__bridge CFArrayRef)@[(__bridge id)kSecAttrCanSign];
    
    CFArrayRef temparray;
    OSStatus oserr = SecItemImport((__bridge CFDataRef)keyData, NULL, &externalFormat /*NULL*/, &itemType, flags, &params, NULL, &temparray);
    
    if (oserr != noErr || CFArrayGetCount(temparray)<1) {
        NSLog(@"Error importing key! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        return nil;
    }
    
    SecKeyRef encrKeyRef = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
    
    //now add it to the keychain - without a label at first (using a label doesn't work on add, so need to update the item later...)
    __block NSMutableDictionary* passDict = [KeychainHelper privateKeyAdditionDictForLabel:keyLabel forEncryption:forEncryption];
    
    [passDict setObject:(__bridge id)(encrKeyRef) forKey:kSecValueRef];
    
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    [passDict removeObjectForKey:(__bridge id)kSecAttrLabel];
    
    CFTypeRef result;
    
    oserr = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
    
    if(oserr != noErr)
    {
        NSLog(@"Error adding private key to keychain: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
    }
    
    NSData* persistentRef = CFArrayGetValueAtIndex(result, 0);
    
    //almost done - just need to add the missing label
    NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:@{(__bridge id)kSecValuePersistentRef:persistentRef}];
    
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
    NSMutableDictionary* newAttributes = [NSMutableDictionary new];
    
    NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
    
    newAttributes[(__bridge id)kSecAttrLabel] = attrLabel;
    
    //    SecAccessRef accessRef = [self accessRef:NO];
    //    if(accessRef)
    //        newAttributes[(__bridge id)kSecAttrAccess] = (__bridge id)accessRef;
    
    
    oserr = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)newAttributes);
    if (oserr != noErr)
    {
        NSLog(@"Error updating keychain item! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
    }
    
//    SecKeychainItemRef keyRef = (SecKeychainItemRef)[self keyRefForPersistentRef:persistentRef];
    
//    [self setAccessRightsForKey:keyRef withDescription:@"Mynigma private key"];
    
    //    [self dumpAccessRefForKeyRefToLog:keyRef];
    
    return persistentRef;
}

#endif




- (PrivateKeychainItemRefs*)addPrivateKeyDataToKeychain:(PrivateKeyData*)privateKeyData;
{
    if(!privateKeyData.keyLabel)
        return nil;
    
    
    if([self havePrivateKeychainItemWithLabel:privateKeyData.keyLabel])
    {
        if([self doesKeychainItemMatchPrivateKeyData:privateKeyData])
        {
            //already have the same item in the keychain
            //nonetheless, need to point the persistent refs of the MynigmaPublicKey object to the correct location in the keychain
                return [self refsForPrivateKeychainItemWithLabel:privateKeyData.keyLabel];
        }
        else
            return nil;
    }
    
    if([self havePublicKeychainItemWithLabel:privateKeyData.keyLabel])
    {
        if(![self doesKeychainItemMatchPublicKeyData:privateKeyData])
            NSLog(@"Adding private key that doesn't match the existing public key data(!!!)");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
    }
    
    
    NSData* persistentDecrRef = [self addPrivateKeyWithData:privateKeyData.privateKeyDecData toKeychainWithLabel:privateKeyData.keyLabel forEncryption:YES];
    
    NSData* persistentSignRef = [self addPrivateKeyWithData:privateKeyData.privateKeySigData toKeychainWithLabel:privateKeyData.keyLabel forEncryption:NO];
    
    NSData* persistentEncrRef = [self addPublicKeyWithData:privateKeyData.publicKeyEncData toKeychainWithLabel:privateKeyData.keyLabel forEncryption:YES];
    
    NSData* persistentVerRef = [self addPublicKeyWithData:privateKeyData.publicKeyVerData toKeychainWithLabel:privateKeyData.keyLabel forEncryption:NO];
    
    if(persistentDecrRef && persistentSignRef && persistentEncrRef && persistentVerRef)
    {
        return [[PrivateKeychainItemRefs alloc] initWithPersistentEncKeyRef:persistentEncrRef persistentVerKeyRef:persistentVerRef persistentDecKeyRef:persistentDecrRef persistentSigKeyRef:persistentSignRef];
    }
    
    return nil;
}


- (BOOL)havePrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    NSMutableDictionary* passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    CFTypeRef result;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        return NO;
    }
    
    passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        return NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        return NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        return NO;
    }
    
    return YES;
}


- (BOOL)removePrivateKeychainItemWithLabel:(NSString*)keyLabel
{
#if TARGET_OS_IPHONE
    
    BOOL allOK = YES;
    
    NSMutableDictionary* passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    return allOK;
    
#else
    
    BOOL allOK = YES;
    
    NSMutableDictionary* passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    [passDict setObject:kSecMatchLimitAll forKey:kSecMatchLimit];
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    status = SecItemDelete((__bridge CFDictionaryRef)passDict);
    
    if(status != noErr)
    {
        allOK = NO;
    }
    
    return allOK;
    
#endif
}


- (BOOL)doesKeychainItemMatchPrivateKeyData:(PrivateKeyData*)privateKeyData
{
    PrivateKeyData* existingKeyData = [self dataForPrivateKeychainItemWithLabel:privateKeyData.keyLabel];
    
    return [existingKeyData isEqual:privateKeyData];
}

- (PrivateKeyData*)dataForPrivateKey:(MynigmaPrivateKey*)privateKey
{
    if(!privateKey)
        return nil;
    
        NSData* decrData = [self dataForPersistentRef:privateKey.privateDecrKeyRef isPrivate:YES];
        NSData* sigData = [self dataForPersistentRef:privateKey.privateSignKeyRef isPrivate:YES];
        NSData* encrData = [self dataForPersistentRef:privateKey.publicEncrKeyRef isPrivate:NO];
        NSData* verData = [self dataForPersistentRef:privateKey.publicVerifyKeyRef isPrivate:NO];
    
    if(decrData && sigData && encrData && verData)
        return [[PrivateKeyData alloc] initWithKeyLabel:privateKey.keyLabel decData:decrData sigData:sigData encData:encrData verData:verData];
    
    return [self dataForPrivateKeychainItemWithLabel:privateKey.keyLabel];
}

- (PrivateKeyData*)dataForPrivateKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    __block NSData* decrData = nil;
    __block NSData* sigData = nil;
    __block NSData* encrData = nil;
    __block NSData* verData = nil;
    
        PrivateKeychainItemRefs* privateKeyRefs = [self refsForPrivateKeychainItemWithLabel:keyLabel];
        
         if(privateKeyRefs)
         {
             decrData = [self dataForPersistentRef:[privateKeyRefs persistentPrivateKeyRefForEncryption:YES] isPrivate:YES];
             sigData = [self dataForPersistentRef:[privateKeyRefs persistentPrivateKeyRefForEncryption:NO] isPrivate:YES];
             encrData = [self dataForPersistentRef:[privateKeyRefs persistentPublicKeyRefForEncryption:YES] isPrivate:NO];
             verData = [self dataForPersistentRef:[privateKeyRefs persistentPublicKeyRefForEncryption:NO] isPrivate:NO];
         }
    
    if(decrData && sigData && encrData && verData)
        return [[PrivateKeyData alloc] initWithKeyLabel:keyLabel decData:decrData sigData:sigData encData:encrData verData:verData];
    
    return nil;
}


/*returns the exported private key as a PrivateKeyData object*/
- (PrivateKeyData*)dataForPrivateKeychainItemWithLabel:(NSString*)keyLabel
{
#if TARGET_OS_IPHONE
    
    PublicKeyData* publicKeyData = [self dataForPublicKeychainItemWithLabel:keyLabel];
    
    NSMutableDictionary* passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:YES];
    
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnData];
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* decKeyData = CFBridgingRelease(result);
    
    //armour the base64 encoded data
    decKeyData = [[KeyParser armourPrivateKeyData:decKeyData] dataUsingEncoding:NSUTF8StringEncoding];
    
    passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:NO];
    
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnData];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* sigKeyData = CFBridgingRelease(result);
    
    //armour the base64 encoded data
    sigKeyData = [[KeyParser armourPrivateKeyData:sigKeyData] dataUsingEncoding:NSUTF8StringEncoding];
    
    if(decKeyData && sigKeyData && publicKeyData.publicKeyEncData && publicKeyData.publicKeyVerData)
        return [[PrivateKeyData alloc] initWithKeyLabel:keyLabel decData:decKeyData sigData:sigKeyData encData:publicKeyData.publicKeyEncData verData:publicKeyData.publicKeyVerData];
    
    return nil;
    
#else
    
    PublicKeyData* publicKeyData = [self dataForPublicKeychainItemWithLabel:keyLabel];
    
    NSMutableDictionary* passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:YES];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentRefData = CFBridgingRelease(result);
    
    NSData* decKeyData = [self dataForPersistentRef:persistentRefData isPrivate:YES];
    
    passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:NO];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    persistentRefData = CFBridgingRelease(result);
    
    NSData* sigKeyData = [self dataForPersistentRef:persistentRefData isPrivate:YES];
    
    NSData* encKeyData = publicKeyData.publicKeyEncData;
    
    NSData* verKeyData = publicKeyData.publicKeyVerData;
    
    
    if(decKeyData && sigKeyData && encKeyData && verKeyData)
        return [[PrivateKeyData alloc] initWithKeyLabel:keyLabel decData:decKeyData sigData:sigKeyData encData:encKeyData verData:verKeyData];
    
    return nil;
    
#endif
}


- (PrivateKeychainItemRefs*)refsForPrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    NSMutableDictionary* passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:YES];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentDecKeyRef = CFBridgingRelease(result);
    
    passDict = [KeychainHelper privateKeySearchDictForLabel:keyLabel forEncryption:NO];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentSigKeyRef = CFBridgingRelease(result);
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:YES];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentEncKeyRef = CFBridgingRelease(result);
    
    passDict = [KeychainHelper publicKeySearchDictForLabel:keyLabel forEncryption:NO];
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentVerKeyRef = CFBridgingRelease(result);
    
    
    if(persistentDecKeyRef && persistentSigKeyRef && persistentEncKeyRef && persistentVerKeyRef)
        return [[PrivateKeychainItemRefs alloc] initWithPersistentEncKeyRef:persistentEncKeyRef persistentVerKeyRef:persistentVerKeyRef persistentDecKeyRef:persistentDecKeyRef persistentSigKeyRef:persistentSigKeyRef];
    
    return nil;
}








#if TARGET_OS_IPHONE

- (NSData*)dataForPersistentRef:(NSData*)persistentRef isPrivate:(BOOL)isPrivate
{
    if(!persistentRef)
        return nil;
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecValuePersistentRef] = persistentRef;
    passDict[(__bridge id)kSecReturnData] = @YES;
//    passDict[(__bridge id)kSecAttrKeyClass] = (__bridge id)(isPrivate?kSecAttrKeyClassPrivate:kSecAttrKeyClassPublic);
//    passDict[(__bridge id)kSecAttrKeyType] = (__bridge id)(kSecAttrKeyTypeRSA);
//    passDict[(__bridge id)kSecAttrKeySizeInBits] = @4096;
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* extractedKeyData = CFBridgingRelease(result);

    if(isPrivate)
    {
        //the format for private keys is OpenSSL (basically a PKCS#1 PrivateKeyInfo), which is what we get from the keychain
        return extractedKeyData;
    }
    
    //for public keys, we need to change the format appending the object identifier 1.2.840.113549.1.1, applying base64 encoding and adding an armour
    return [KeyParser armourPKCS1PublicKeyData:extractedKeyData];
}

#else

- (NSData*)dataForPersistentRef:(NSData*)persistentRef isPrivate:(BOOL)isPrivate
{
    if(!persistentRef)
        return nil;
    
    //first get a SecKeyRef from the persistent reference
    SecKeyRef keyRef = [KeychainHelper secKeyRefFromPersistentKeyRef:persistentRef];
    
    if(!keyRef)
        return nil;
    
    SecItemImportExportKeyParameters params = {0};
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    
    SecExternalFormat externalFormat = kSecFormatOpenSSL;
    
    int armour = kSecItemPemArmour;
    
    CFDataRef keyData = NULL;
    
    if(isPrivate)
    {
        //private keys need a passphrase to be exported
        //set a dummy one
        //we are going to remove it anyway
        NSString* dummyPassphrase = @"password'); DROP TABLE PASSWORDS; --";
        params.passphrase = (__bridge_retained CFStringRef)dummyPassphrase;
        externalFormat = kSecFormatWrappedPKCS8;
        
        OSStatus oserr = SecItemExport(keyRef, externalFormat, armour , &params, &keyData);
        
        if(oserr == noErr)
        {
            
            NSData* wrappedKey = CFBridgingRelease(keyData);
            
            //need the key in OpenSSL format
            //the OpenSSLEncryptionEngine(KeyParsing) comes to the rescue
            return [[OpenSSLEncryptionEngine sharedInstance] PKCS1DataForWrappedPrivateKeyData:wrappedKey withPassphrase:dummyPassphrase];
        }
    }
    else
    {
        //public keychain items need to have
//        [self temporarilyGrantPermissiveAccessRightsForPublicKeyKeychainItem:(SecKeychainItemRef)keyRef];

        OSStatus oserr = SecItemExport(keyRef, externalFormat, armour , &params, &keyData);
            
            if(oserr == noErr)
            {
                //public keys come out of the keychain with armour ----BEGIN RSA PUBLIC KEY-----
                //this is bad practice - the key is in PKCS#8 format, so includes an algorithm identifier
                //replace the armour with the more appropriate -----BEGIN PUBLIC KEY-----
                NSString* keyString = [[NSString alloc] initWithData:CFBridgingRelease(keyData) encoding:NSUTF8StringEncoding];
                keyString = [keyString stringByReplacingOccurrencesOfString:@"RSA PUBLIC KEY" withString:@"PUBLIC KEY"];
                
                NSData* keyDataWithProperArmour = [keyString dataUsingEncoding:NSUTF8StringEncoding];
                
                return keyDataWithProperArmour;
            }
    }

    
    return nil;
}

#endif


#if TARGET_OS_IPHONE

- (NSData*)dataForSecKeyRef:(SecKeyRef)secKeyRef isPrivate:(BOOL)isPrivate
{
    if(!secKeyRef)
        return nil;
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
    passDict[(__bridge id)kSecValueRef] = (__bridge id)(secKeyRef);
    passDict[(__bridge id)kSecReturnData] = @YES;
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* extractedKeyData = CFBridgingRelease(result);
    
    if(isPrivate)
    {
        //the format for private keys is OpenSSL (basically a PKCS#1 PrivateKeyInfo), which is what we get from the keychain
        return extractedKeyData;
    }
    
    //for public keys, we need to change the format appending the object identifier 1.2.840.113549.1.1, applying base64 encoding and adding an armour
    return [KeyParser armourPKCS1PublicKeyData:extractedKeyData];
}

#else

- (NSData*)dataForSecKeyRef:(SecKeyRef)keyRef isPrivate:(BOOL)isPrivate
{
    if(!keyRef)
        return nil;
    
    SecItemImportExportKeyParameters params = {0};
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    
    SecExternalFormat externalFormat = kSecFormatOpenSSL;
    
    int armour = kSecItemPemArmour;
    
    CFDataRef keyData = NULL;
    
    if(isPrivate)
    {
        //private keys need a passphrase to be exported
        //set a dummy one
        //we are going to remove it anyway
        NSString* dummyPassphrase = @"password'); DROP TABLE PASSWORDS; --";
        params.passphrase = (__bridge_retained CFStringRef)dummyPassphrase;
        externalFormat = kSecFormatWrappedPKCS8;
        
        OSStatus oserr = SecItemExport(keyRef, externalFormat, armour , &params, &keyData);
        
        if(oserr == noErr)
        {
            
            NSData* wrappedKey = CFBridgingRelease(keyData);
            
            //need the key in OpenSSL format
            //the OpenSSLEncryptionEngine(KeyParsing) comes to the rescue
            return [[OpenSSLEncryptionEngine sharedInstance] PKCS1DataForWrappedPrivateKeyData:wrappedKey withPassphrase:dummyPassphrase];
        }
    }
    else
    {
        //public keychain items need to have
//        [self temporarilyGrantPermissiveAccessRightsForPublicKeyKeychainItem:(SecKeychainItemRef)keyRef];
        
//        if(isPublic)
//        {
            OSStatus oserr = SecItemExport(keyRef, externalFormat, armour , &params, &keyData);
            
            if(oserr == noErr)
            {
                //public keys come out of the keychain with armour ----BEGIN RSA PUBLIC KEY-----
                //this is bad practice - the key is in PKCS#8 format, so includes an algorithm identifier
                //replace the armour with the more appropriate -----BEGIN PUBLIC KEY-----
                NSString* keyString = [[NSString alloc] initWithData:CFBridgingRelease(keyData) encoding:NSUTF8StringEncoding];
                keyString = [keyString stringByReplacingOccurrencesOfString:@"RSA PUBLIC KEY" withString:@"PUBLIC KEY"];
                
                NSData* keyDataWithProperArmour = [keyString dataUsingEncoding:NSUTF8StringEncoding];
                
                return keyDataWithProperArmour;
            }
//        }
        
    }
    
    
    return nil;
}

#endif

+ (SecKeyRef)secKeyRefFromPersistentKeyRef:(NSData*)persistentRef
{
    if(!persistentRef)
        return nil;
    
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecValuePersistentRef] = persistentRef;
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    [passDict setObject:@YES forKey:(__bridge id)kSecReturnRef];
    
    SecKeyRef keyRef = NULL;
    OSStatus oserr = SecItemCopyMatching((__bridge CFDictionaryRef)(passDict), (CFTypeRef*)&keyRef);
    
    if(oserr != noErr)
    {
        if(keyRef)
            CFRelease(keyRef);
        NSLog(@"Error turning persistent ref into key ref: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
    }
    
    if(keyRef)
        return keyRef;
    
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassCertificate;
    
    oserr = SecItemCopyMatching((__bridge CFDictionaryRef)(passDict), (CFTypeRef*)&keyRef);
    
    if(oserr != noErr)
    {
        if(keyRef)
            CFRelease(keyRef);
        NSLog(@"Error turning persistent ref into key ref! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    return keyRef;
}



- (SecKeyRef)privateSecKeyRefWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    //if the keyLabel is invalid return immediately
    if(!keyLabel)
    {
        NSLog(@"Trying to find key with nil label!!!");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    __block SecKeyRef keyRef = NULL;
    
        PrivateKeychainItemRefs* keychainItemRefs = [self refsForPrivateKeychainItemWithLabel:keyLabel];
        
        keyRef = [keychainItemRefs privateSecKeyRefForEncryption:forEncryption];
    
    return keyRef;
}

- (SecKeyRef)publicSecKeyRefWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    if(!keyLabel)
        return nil;
    
    __block SecKeyRef keyRef = NULL;
    
        PublicKeychainItemRefs* keychainItemRefs = [self refsForPublicKeychainItemWithLabel:keyLabel];
        
        keyRef = [keychainItemRefs publicSecKeyRefForEncryption:forEncryption];
    
    return keyRef;
}




//+ (SecKeyRef)secKeyRefFromPersistentKeyRef:(NSData*)persistentKeyRef
//{
//    NSMutableDictionary* passDict = [NSMutableDictionary new];
//    
//    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
//    
//    passDict[(__bridge id)kSecReturnRef] = @YES;
//    passDict[(__bridge id)kSecValuePersistentRef] = persistentKeyRef;
//    
//    CFTypeRef result = nil;
//    
//    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
//    
//    if(status != noErr)
//    {
//        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
//        NSLog(@"Error exporting key: %@", error);
//        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
//        return nil;
//    }
//    
//    SecKeyRef publicKeyRef = (SecKeyRef)result;
//    
//    return publicKeyRef;
//}


+ (NSData*)persistentKeyRefFromSecKeyRef:(SecKeyRef)publicSecKeyRef
{
    NSMutableDictionary* passDict = [NSMutableDictionary new];
    
    passDict[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    
    passDict[(__bridge id)kSecReturnPersistentRef] = @YES;
    passDict[(__bridge id)kSecValueRef] = (__bridge id)publicSecKeyRef;
    
    CFTypeRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)passDict, &result);
    
    if(status != noErr)
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        NSLog(@"Error exporting key: %@", error);
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return nil;
    }
    
    NSData* persistentRef = CFBridgingRelease(result);
    
    return persistentRef;
}

- (NSArray*)persistentRefsForPublicKeychainItemWithLabel:(NSString*)keyLabel
{
    return nil;
}

- (NSArray*)persistentRefsForPrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    return nil;
}








@end
