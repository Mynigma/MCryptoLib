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


#import "UnitTestKeychainHelper.h"
#import "PublicKeyData.h"
#import "PrivateKeyData.h"
#import "TestHelper.h"
#import "NSData+Base64.h"
#import "KeychainHelper+AttributeDictionaries.h"
#import "KeyParser.h"
#import "PublicKeychainItemRefs.h"
#import "PrivateKeychainItemRefs.h"







@implementation UnitTestKeychainHelper


- (NSMutableDictionary*)content
{
    if(![self keychainContent])
    {
        [self setKeychainContent:[NSMutableDictionary new]];
        
        PrivateKeyData* privateKeyData1 = [TestHelper privateKeyData:@1 withKeyLabel:@"TestKeyLabel1"];
        [self keychainContent][@"TestKeyLabel1"] = privateKeyData1;
        
        PrivateKeyData* privateKeyData2 = [TestHelper privateKeyData:@2 withKeyLabel:@"TestKeyLabel2"];
        [self keychainContent][@"TestKeyLabel2"] = privateKeyData2;
        
        [self keychainContent][@"TestKeyLabel3"] = [TestHelper privateKeyData:@3 withKeyLabel:@"TestKeyLabel3"];
        [self keychainContent][@"TestKeyLabel4"] = [TestHelper privateKeyData:@4 withKeyLabel:@"TestKeyLabel4"];
        [self keychainContent][@"TestKeyLabel5"] = [TestHelper privateKeyData:@5 withKeyLabel:@"TestKeyLabel5"];

        [self keychainContent][@"TestKeyLabel6"] = [TestHelper publicKeyData:@6 withKeyLabel:@"TestKeyLabel6"];
        [self keychainContent][@"TestKeyLabel7"] = [TestHelper publicKeyData:@7 withKeyLabel:@"TestKeyLabel7"];
        [self keychainContent][@"TestKeyLabel8"] = [TestHelper publicKeyData:@8 withKeyLabel:@"TestKeyLabel8"];
        [self keychainContent][@"TestKeyLabel9"] = [TestHelper publicKeyData:@9 withKeyLabel:@"TestKeyLabel9"];
        [self keychainContent][@"TestKeyLabel10"] = [TestHelper publicKeyData:@10 withKeyLabel:@"TestKeyLabel10"];
}

    return [self keychainContent];
}



#pragma mark - PUBLIC KEYS


- (PublicKeychainItemRefs*)addPublicKeyDataToKeychain:(PublicKeyData*)publicKeyData
{
    NSString* keyLabel = publicKeyData.keyLabel;
    
    if(!keyLabel)
        return nil;
    
    if([self havePublicKeychainItemWithLabel:publicKeyData.keyLabel])
    {
        if(![self doesKeychainItemMatchPublicKeyData:publicKeyData])
            return nil;
    
        return [self refsForPublicKeychainItemWithLabel:keyLabel];
    }
    
    [[self content] setObject:publicKeyData forKey:keyLabel];
    
    return [self refsForPublicKeychainItemWithLabel:keyLabel];
}

- (BOOL)havePublicKeychainItemWithLabel:(NSString*)keyLabel
{
    return [[self content].allKeys containsObject:keyLabel];
}

- (BOOL)removePublicKeychainItemWithLabel:(NSString*)keyLabel
{
    BOOL haveKeychainItem = [self havePublicKeychainItemWithLabel:keyLabel];
    [[self content] removeObjectForKey:keyLabel];
    
    return haveKeychainItem;
}

- (BOOL)doesKeychainItemMatchPublicKeyData:(PublicKeyData*)publicKeyData
{
    NSString* keyLabel = publicKeyData.keyLabel;
    
    if(!keyLabel)
        return NO;
    
    PublicKeyData* existingPublicKeyData = [[self content] objectForKey:keyLabel];
    
    return [publicKeyData isEqual:existingPublicKeyData];
}

- (PublicKeyData*)dataForPublicKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    return [[self content] objectForKey:keyLabel];
}

- (PublicKeyData*)dataForPublicKeychainItemWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    PublicKeyData* publicKeyData = [[self content] objectForKey:keyLabel];
    
    if([publicKeyData isKindOfClass:[PrivateKeyData class]])
        return [(PrivateKeyData*)publicKeyData publicKeyData];
    
    return publicKeyData;
}

//a list of all public keys in the keychain
//including presistent references
- (NSArray*)listPublicKeychainItems
{
    return nil;
}





#pragma mark - PRIVATE KEYS

- (PrivateKeychainItemRefs*)addPrivateKeyDataToKeychain:(PrivateKeyData*)privateKeyData
{
    if([self havePrivateKeychainItemWithLabel:privateKeyData.keyLabel])
    {
        if(![self doesKeychainItemMatchPrivateKeyData:privateKeyData])
            return nil;
        
//        return [self secKey]
    }
    
    [[self content] setObject:privateKeyData forKey:privateKeyData.keyLabel];
    
    return nil; //[self sec];
}

- (BOOL)havePrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return NO;
    
    PublicKeyData* existingPrivateKeyData = [[self content] objectForKey:keyLabel];
    
    return [existingPrivateKeyData isKindOfClass:[PrivateKeyData class]];
}

- (BOOL)removePrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return NO;
    
    PublicKeyData* existingPublicKeyData = [[self content] objectForKey:keyLabel];
    
    if(![existingPublicKeyData isKindOfClass:[PrivateKeyData class]])
        return NO;
    
    [[self content] removeObjectForKey:keyLabel];
    
    return YES;
}

- (BOOL)doesKeychainItemMatchPrivateKeyData:(PrivateKeyData*)privateKeyData
{
    NSString* keyLabel = privateKeyData.keyLabel;
    
    if(!keyLabel)
        return NO;
    
    PrivateKeyData* existingPrivateKeyData = [[self content] objectForKey:keyLabel];
    
    return [privateKeyData isEqual:existingPrivateKeyData];
}

- (PrivateKeyData*)dataForPrivateKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    PrivateKeyData* existingPrivateKeyData = [[self content] objectForKey:keyLabel];
    
    return [existingPrivateKeyData isKindOfClass:[PrivateKeyData class]]?existingPrivateKeyData:nil;
}

- (PrivateKeyData*)dataForPrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    PrivateKeyData* existingPrivateKeyData = [[self content] objectForKey:keyLabel];
    
    return existingPrivateKeyData;
}

//a list of all private keys in the keychain
//including presistent references
- (NSArray*)listPrivateKeychainItems
{
    return nil;
}



#pragma mark - GENERIC


- (SecKeyRef)keyRefForPersistentRef:(NSData*)persistentRef
{
    //makes little sense: the whole point of this unit test keychain helper is that the keychain need not be accessed, so there should not be a persistent ref
    //could mock this for specific tests, though
    return nil;
}


- (SecKeyRef)publicSecKeyRefWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    if([self havePublicKeychainItemWithLabel:keyLabel])
    {
        PublicKeyData* publicKeyData = [self dataForPublicKeychainItemWithLabel:keyLabel];
        
        NSData* rawKeyData = forEncryption?publicKeyData.publicKeyEncData:publicKeyData.publicKeyVerData;
        
#if TARGET_OS_IPHONE
        
        NSData* X509CertificateData = [KeyParser convertPublicKeyData:rawKeyData fromFormat:MynigmaKeyFormatDefault toFormat:MynigmaKeyFormatX509];
        
        //get a SecKeyRef without adding the key to any keychains
        SecCertificateRef cert = SecCertificateCreateWithData (kCFAllocatorDefault, (__bridge CFDataRef)(X509CertificateData));
        CFArrayRef certs = CFArrayCreate(kCFAllocatorDefault, (const void **) &cert, 1, NULL);
        
        SecTrustRef trustRef;
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustCreateWithCertificates(certs, policy, &trustRef);
        SecTrustResultType trustResult;
        SecTrustEvaluate(trustRef, &trustResult);
        SecKeyRef publicKeyRef = SecTrustCopyPublicKey(trustRef);
        
        CFRelease(certs);
        
        return publicKeyRef;
        
#else
        
        CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
        CFDictionarySetValue(parameters, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionarySetValue(parameters, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        
        //remove the armour
        NSString* keyString = [[NSString alloc] initWithData:rawKeyData encoding:NSUTF8StringEncoding];
        NSArray* keyComponents = [keyString componentsSeparatedByString:@"-----"];
        if(keyComponents.count<3)
            return nil;
        //we want the middle bit, and we also need to base64 decode it
        NSString* mainDataString = keyComponents[2];
        NSData* mainData = [NSData dataWithBase64String:mainDataString];
        
        CFErrorRef error = NULL;
        SecKeyRef key = SecKeyCreateFromData(parameters, (__bridge CFDataRef)mainData, &error);
        
        return key;
        
#endif
    }
    
    return nil;
}

- (SecKeyRef)privateSecKeyRefWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    if([self havePrivateKeychainItemWithLabel:keyLabel])
    {
        PrivateKeyData* privateKeyData = [self dataForPrivateKeychainItemWithLabel:keyLabel];
        
        NSData* keyData = forEncryption?privateKeyData.privateKeyDecData:privateKeyData.privateKeySigData;
        
#if TARGET_OS_IPHONE
        
        NSString* password = @"TEST PASSWORD";
        NSData* p12Data = [KeyParser convertPrivateKeyData:keyData fromFormat:MynigmaKeyFormatDefault toFormat:MynigmaKeyFormatPKCS12 inPassphrase:nil outPassphrase:password];
        
        NSMutableDictionary *options = [[NSMutableDictionary alloc] init];
        SecKeyRef privateKey = NULL;
        [options setObject:password forKey:(__bridge id)kSecImportExportPassphrase];
        CFArrayRef items = NULL;
        OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)p12Data, (__bridge CFDictionaryRef)options, &items);
        
        if (securityError == noErr && CFArrayGetCount(items) > 0)
        {
            CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
            SecIdentityRef identityApp =
            (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
            securityError = SecIdentityCopyPrivateKey(identityApp, &privateKey);
            if (securityError != noErr)
            {
                privateKey = NULL;
            }
        }
        
        CFRelease(items);
        options = nil;
        p12Data = nil;
        
        return privateKey;

#else
        
        SecItemImportExportKeyParameters params = [KeychainHelper importExportParams:forEncryption];
        
        params.keyUsage = (__bridge CFArrayRef)@[(__bridge id)kSecAttrCanDecrypt, (__bridge id)kSecAttrCanSign];
        
        SecExternalItemType itemType = kSecItemTypePrivateKey;
        SecExternalFormat externalFormat = kSecFormatOpenSSL;
        int flags = 0;
        
        CFArrayRef temparray;
        OSStatus oserr = SecItemImport((__bridge CFDataRef)keyData, NULL, &externalFormat, &itemType, flags, &params, NULL, &temparray);
        
        
        if (oserr != noErr || CFArrayGetCount(temparray)<1) {
            NSLog(@"Error importing key! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
            
            return nil;
        }
        
        SecKeyRef keyRef = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
        
        //        CFRelease(temparray);
        
        return keyRef;
        
#endif
    }
    
    return nil;
}






- (PublicKeychainItemRefs*)refsForPublicKeychainItemWithLabel:(NSString*)keyLabel
{
    SecKeyRef publicEncRef = [self publicSecKeyRefWithLabel:keyLabel forEncryption:YES];
    SecKeyRef publicVerRef = [self publicSecKeyRefWithLabel:keyLabel forEncryption:NO];
    
    if(publicEncRef && publicVerRef)
    {
        PublicKeychainItemRefs* keychainItemRefs = [[PublicKeychainItemRefs alloc] initWithEncKeyRef:publicEncRef verKeyRef:publicVerRef];
        
        return keychainItemRefs;
    }
    
    return nil;
}

- (PrivateKeychainItemRefs*)refsForPrivateKeychainItemWithLabel:(NSString*)keyLabel
{
    SecKeyRef publicEncRef = [self publicSecKeyRefWithLabel:keyLabel forEncryption:YES];
    SecKeyRef publicVerRef = [self publicSecKeyRefWithLabel:keyLabel forEncryption:NO];
    
    SecKeyRef privateDecRef = [self privateSecKeyRefWithLabel:keyLabel forEncryption:YES];
    SecKeyRef privateSigRef = [self privateSecKeyRefWithLabel:keyLabel forEncryption:NO];

    if(publicEncRef && publicVerRef && privateDecRef && privateSigRef)
    {
        PrivateKeychainItemRefs* keychainItemRefs = [[PrivateKeychainItemRefs alloc] initWithEncKeyRef:publicEncRef verKeyRef:publicVerRef decKeyRef:privateDecRef sigKeyRef:privateSigRef];
        
        return keychainItemRefs;
    }
    
    return nil;
}


@end
