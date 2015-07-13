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


#import "SMIMEKeyManager.h"

#import "KeychainHelper+SMIME.h"

#import "SMIMEPublicKey.h"
#import "SMIMEPrivateKey.h"
#import "EmailAddress.h"




@implementation SMIMEKeyManager


- (instancetype)init
{
    self = [super init];
    if(self)
    {
        self.keychainHelper = [KeychainHelper new];
    }
    return self;
}





- (SMIMEPublicKey*)publicKeyForFingerprint:(NSData*)fingerprint
{
    if(!fingerprint)
        return nil;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"SMIMEPublicKey"];
    
    NSPredicate* fingerprintMatch = [NSPredicate predicateWithFormat:@"fingerprint == %@", fingerprint];
    
    [fetchRequest setPredicate:fingerprintMatch];
    
    NSArray* results = [MAIN_CONTEXT executeFetchRequest:fetchRequest error:nil];
    
    //TODO: error handling
    
    return results.firstObject;
}

- (BOOL)havePublicKeyWithFingerprint:(NSData*)fingerprint
{
    if(!fingerprint)
        return NO;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"SMIMEPublicKey"];
    
    NSPredicate* fingerprintMatch = [NSPredicate predicateWithFormat:@"fingerprint == %@", fingerprint];
    
    [fetchRequest setPredicate:fingerprintMatch];
    [fetchRequest setFetchLimit:1];
    
    NSInteger count = [MAIN_CONTEXT countForFetchRequest:fetchRequest error:nil];
    
    //TODO: error handling
    
    return count > 0;
}

- (BOOL)havePrivateKeyWithFingerprint:(NSData*)fingerprint
{
    if(!fingerprint)
        return NO;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"SMIMEPrivateKey"];
    
    NSPredicate* fingerprintMatch = [NSPredicate predicateWithFormat:@"fingerprint == %@", fingerprint];
    
    [fetchRequest setPredicate:fingerprintMatch];
    [fetchRequest setFetchLimit:1];
    
    NSInteger count = [MAIN_CONTEXT countForFetchRequest:fetchRequest error:nil];
    
    //TODO: error handling
    
    return count > 0;
}





#pragma mark - Email address associations

- (SMIMEPublicKey*)encryptionKeyForEmailAddress:(NSString*)emailAddress
{
//    EmailAddress* emailAddress = [EmailAddress
    return nil;
}

- (SMIMEPrivateKey*)signatureKeyForEmailAddress:(NSString*)emailAddress
{
    return nil;
}


- (X509*)encryptionCertificateForEmailAddress:(NSString*)emailAddress
{
    return nil;
}

- (EVP_PKEY*)signatureEVPKeyForEmailAddress:(NSString*)emailAddress
{
    return nil;
}






- (SMIMEPublicKey*)addPublicKeyWithX509Data:(NSData*)data SHA256Fingerprint:(NSData*)fingerprint
{
    if(!data.length)
        return nil;
    
    if([self havePublicKeyWithFingerprint:fingerprint])
    {
        //TODO: deal with this case
        return nil;
    }
    
    NSData* persistentRef = [self.keychainHelper addSMIMECertificateWithX509Data:data];

    if(!persistentRef)
        return nil;
    
    NSEntityDescription* entity = [NSEntityDescription entityForName:@"SMIMEPublicKey" inManagedObjectContext:MAIN_CONTEXT];
    
    SMIMEPublicKey* publicKey = [[SMIMEPublicKey alloc] initWithEntity:entity insertIntoManagedObjectContext:MAIN_CONTEXT];
    
    [publicKey setFingerprint:fingerprint];
    [publicKey setFingerprintAlgorithm:@"SHA256"];
    [publicKey setKeychainRef:persistentRef];

    return publicKey;
}

- (SMIMEPrivateKey*)addPrivateKeyWithPKCS8Data:(NSData*)PKCS8Data andX509Data:(NSData*)X509Data SHA256Fingerprint:(NSData*)fingerprint
{
    if(!PKCS8Data.length || !X509Data.length)
        return nil;
    
    if([self havePrivateKeyWithFingerprint:(NSData*)fingerprint])
    {
        //TODO: deal with this case
        
        return nil;
    }
    
    if([self havePublicKeyWithFingerprint:(NSData*)fingerprint])
    {
        //TODO: deal with this case
        
        return nil;
    }
    
    NSData* publicPersistentRef = [self.keychainHelper addSMIMECertificateWithX509Data:X509Data];
    
    if(!publicPersistentRef)
        return nil;
    
    NSData* privatePersistentRef = [self.keychainHelper addSMIMEPrivateKeyWithPKCS8Data:PKCS8Data withFingerprint:fingerprint];
    
    if(!privatePersistentRef)
        return nil;
    
    NSEntityDescription* entity = [NSEntityDescription entityForName:@"SMIMEPrivateKey" inManagedObjectContext:MAIN_CONTEXT];
    
    SMIMEPrivateKey* privateKey = [[SMIMEPrivateKey alloc] initWithEntity:entity insertIntoManagedObjectContext:MAIN_CONTEXT];
    
    [privateKey setFingerprint:fingerprint];
    [privateKey setFingerprintAlgorithm:@"SHA256"];
    [privateKey setKeychainRef:publicPersistentRef];
    [privateKey setPrivateKeychainRef:privatePersistentRef];
    
    return privateKey;
}


@end
