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


#import "KeychainHelper+SMIME.h"
#import "KeychainHelper+AttributeDictionaries.h"

#import "OpenSSLEncryptionEngine.h"
#import "KeyParser.h"


@interface KeychainHelper()

+ (dispatch_queue_t)keychainHelperDispatchQueue;

@end



@implementation KeychainHelper (SMIME)

#pragma mark - S/MIME


- (BOOL)haveSMIMECertificateInKeychain
{
    return NO;
}

- (BOOL)doesSMIMECertificateInKeychainMatchData:(NSData*)data
{
    return NO;
}

//- (NSData*)persistentRefForCertificateWith



#if TARGET_OS_IPHONE

- (NSData*)addSMIMECertificateWithX509Data:(NSData*)data
{
    if(!data)
    {
        NSLog(@"No data to add to keychain!!");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        
        return nil;
    }
    
    if([self haveSMIMECertificateInKeychain])
    {
        //TODO: compare added item to existing one
        return nil;
    }
        __block NSData* returnValue = nil;
    
    dispatch_sync([KeychainHelper keychainHelperDispatchQueue], ^{
        
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
        
        __block NSMutableDictionary* passDict = [KeychainHelper SMIMECertificateAdditionDict];
        
        if(!publicKeyRef)
            return;
        
        passDict[(__bridge id)kSecValueRef] = (__bridge id)publicKeyRef;
        passDict[(__bridge id)kSecReturnPersistentRef] = @YES;
        
        __block CFTypeRef result = NULL;
        
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
        
        if (status != noErr)
        {
            if(result)
                CFRelease(result);
            
            NSLog(@"Error adding keychain item! %@",[NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil]);
            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
            
            return;
        }
        
        returnValue = CFBridgingRelease(result);
    });
    
    return returnValue;
}

#else

//- (NSDictionary*)addSMIMECertificateWithData:(NSData*)data
//{
//    if(!data)
//    {
//        NSLog(@"No data to add to keychain!!");
//        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
//
//        return nil;
//    }
//
//    __block NSData* persistentRef = NULL;
//
//    dispatch_sync([KeychainHelper keychainHelperDispatchQueue], ^{
//
//        //first import the key: turn the PEM file into a SecKeyRef
//        SecItemImportExportKeyParameters params = [KeychainHelper importExportParams:forEncryption];
//
//        SecExternalItemType itemType = kSecItemTypePublicKey;
//        SecExternalFormat externalFormat = kSecFormatPEMSequence;
//        int flags = 0;
//
//        CFArrayRef temparray;
//        OSStatus oserr = SecItemImport((__bridge CFDataRef)data, NULL, &externalFormat, &itemType, flags, &params, NULL /*don't add to a keychain*/, &temparray);
//        if (oserr != noErr || CFArrayGetCount(temparray)<1)
//        {
//            NSLog(@"Error importing key! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
//            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
//            return;
//        }
//
//        SecKeyRef encrKeyRef = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
//
//        //now add it to the keychain - without a label at first (using a label doesn't work on add, so need to update the item later...)
//        __block NSMutableDictionary* passDict = [KeychainHelper publicKeyAdditionDictForLabel:keyLabel forEncryption:forEncryption];
//
//        [passDict setObject:(__bridge id)(encrKeyRef) forKey:kSecValueRef];
//
//        [passDict setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
//
//        [passDict removeObjectForKey:(__bridge id)kSecAttrLabel];
//
//        CFTypeRef result;
//
//        oserr = SecItemAdd((__bridge CFDictionaryRef)passDict, &result);
//
//        if(oserr != noErr)
//        {
//            NSLog(@"Error adding public keychain item: %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
//            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
//        }
//
//        persistentRef = CFArrayGetValueAtIndex(result, 0);
//
//        //almost done - just need to add the missing label
//        NSMutableDictionary* query = [NSMutableDictionary dictionaryWithDictionary:@{(__bridge id)kSecValuePersistentRef:persistentRef}];
//
//        query[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
//
//        NSMutableDictionary* newAttributes = [NSMutableDictionary new];
//
//        NSString* attrLabel = forEncryption?[NSString stringWithFormat:@"Mynigma encryption key %@", keyLabel]:[NSString stringWithFormat:@"Mynigma signature key %@", keyLabel];
//
//        newAttributes[(__bridge id)kSecAttrLabel] = attrLabel;
//
//        //    SecKeychainItemRef itemRef = (SecKeychainItemRef)[KeychainHelper secKeyRefFromPersistentKeyRef:persistentRef];
//
//        oserr = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)newAttributes);
//        if (oserr != noErr)
//        {
//            NSLog(@"Error updating keychain item! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
//            NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
//        }
//
//    });
//
//    //    [self setAccessRightsForKey:itemRef withDescription:@"Mynigma public key"];
//
//    return persistentRef;
//}

#endif



#if TARGET_OS_IPHONE

- (NSData*)addSMIMEPrivateKeyWithPKCS8Data:(NSData*)keyData withFingerprint:(NSData*)fingerprint
{
    //need a passphrase!!
    //without it, the addition to the keychain will succeed
    //we will be able to obtain a SecKeyRef/persistent ref
    //without problems or errors
    //but any attempts to use it for encryption/signature will fail
    //thanks, Apple.
    NSString* passphrase = @"";
    
    NSData* PKCS12KeyData = [self.openSSLEngine convertPrivateKeyData:keyData fromFormat:MynigmaKeyFormatDefault toFormat:MynigmaKeyFormatPKCS12 inPassphrase:nil outPassphrase:passphrase];
    
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
        
        NSMutableDictionary* passDict = [KeychainHelper SMIMEPrivateKeyAdditionDictForFingerprint:fingerprint];
        
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

#else

- (NSDictionary*)addSMIMEPrivateKeyWithPKCS8Data:(NSData*)data
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


@end
