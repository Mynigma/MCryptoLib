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



#import "BackupHelper.h"

#import <MProtoBuf/BackupPasswordFileWrapperDataStructure.h>
#import <MProtoBuf/PlainBackupDataStructure.h>
#import <MProtoBuf/PrivateKeyDataStructure.h>
#import <MProtoBuf/PublicKeyDataStructure.h>
#import <MProtoBuf/KeyExpectationDataStructure.h>

#import "ThreadHelper.h"
#import "MynigmaKeyManager.h"
#import "MynigmaEncryptionEngine.h"
#import "CoreDataHelper.h"

#import "PrivateKeyData.h"
#import "MynigmaPublicKey.h"
#import "MynigmaPrivateKey.h"
#import "EmailAddress.h"
#import "MynigmaDevice.h"
#import "KeyExpectation.h"




#define INTEGRITY_CHECK_STRING @"Mynigma integrity check"


@interface EmailAddress()

+ (EmailAddress*)emailAddressForEmail:(NSString*)emailString inContext:(NSManagedObjectContext*)keyContext;

@end



@interface MynigmaPublicKey()

- (void)associateKeyWithEmail:(NSString*)emailString forceMakeCurrent:(BOOL)makeCurrent inContext:(NSManagedObjectContext*)keyContext;

+ (MynigmaPublicKey*)syncMakeNewWithPublicKeyData:(PublicKeyData *)publicKeyData forEmail:(NSString*)email inContext:(NSManagedObjectContext*)keyContext;

+ (MynigmaPublicKey*)publicKeyWithLabel:(NSString*)keyLabel inContext:(NSManagedObjectContext*)keyContext;

@end



@interface MynigmaPrivateKey()

+ (MynigmaPrivateKey*)privateKeyWithLabel:(NSString*)keyLabel inContext:(NSManagedObjectContext*)keyContext;

@end;





@implementation BackupHelper



+ (instancetype)sharedInstance
{
    static dispatch_once_t p = 0;
    
    __strong static id sharedObject = nil;
    
    dispatch_once(&p, ^{
        sharedObject = [BackupHelper new];
    });
    
    return sharedObject;
}


- (NSData*)makeCompleteBackupWithPassword:(NSString*)password inContext:(NSManagedObjectContext*)localContext
{
    /*private keys*/
    NSFetchRequest* fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"MynigmaPrivateKey"];
    
    NSArray* keyPairs = [localContext executeFetchRequest:fetchRequest error:nil];
    
    fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"MynigmaPublicKey"];
    
    NSArray* publicKeys = [localContext executeFetchRequest:fetchRequest error:nil];
    
    fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"KeyExpectation"];
    
    NSArray* keyExpectations = [localContext executeFetchRequest:fetchRequest error:nil];
    
    return [self backUpPrivateKeys:keyPairs publicKeys:publicKeys keyExpectations:(NSArray*)keyExpectations password:password];
}

- (NSData*)makeSyncDataPackageWithEmailAddresses:(NSSet*)emailAddresses inContext:(NSManagedObjectContext*)localContext
{
    /*private keys*/
    NSFetchRequest* fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"MynigmaPrivateKey"];
    
    NSPredicate* emailsPredicate = [NSPredicate predicateWithFormat:@"(currentKeyForEmail.address IN %@) OR (ANY emailAddresses.address IN %@)", emailAddresses, emailAddresses.copy];
    
    [fetchRequest setPredicate:emailsPredicate];
    
    NSArray* keyPairs = [localContext executeFetchRequest:fetchRequest error:nil];
    
    fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"MynigmaPublicKey"];
    
    NSArray* publicKeys = [localContext executeFetchRequest:fetchRequest error:nil];
    
    fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"KeyExpectation"];
    
    NSArray* keyExpectations = [localContext executeFetchRequest:fetchRequest error:nil];
    
    return [self backUpPrivateKeys:keyPairs publicKeys:publicKeys keyExpectations:(NSArray*)keyExpectations password:nil];
}



- (NSData*)backUpPrivateKeys:(NSArray*)privateKeys publicKeys:(NSArray*)publicKeys keyExpectations:(NSArray*)keyExpectations password:(NSString*)password
{
    NSData* plainData = [self plainBackupDataForPrivateKeys:privateKeys publicKeys:publicKeys keyExpectations:keyExpectations];
    
    NSData* salt = nil;
    
    NSData* payloadData = nil;
    
    if(password)
    {
        //128 bit salt
        salt = [self.engine.basicEngine randomBytesOfLength:128 / 8];
        
        NSData* AESSessionKey = [self.engine.basicEngine AES128KeyFromPassword:password withSalt:salt];
        
        NSError* error = nil;
        
        NSData* encryptedData = [self.engine.basicEngine AESEncryptData:plainData withSessionKey:AESSessionKey error:&error];
        
        if(error || !encryptedData)
            return nil;
        
        payloadData = encryptedData;
    }
    else
    {
        payloadData = plainData;
    }
    
    BackupPasswordFileWrapperDataStructure* backUpDataStructure = [[BackupPasswordFileWrapperDataStructure alloc] initWithPayloadData:payloadData hasPassword:password!=nil salt:salt version:MYNIGMA_VERSION];

    return [backUpDataStructure serialisedData];
}




- (NSData*)plainBackupDataForPrivateKeys:(NSArray*)privateKeys publicKeys:(NSArray*)publicKeys keyExpectations:(NSArray*)keyExpectations
{
    NSMutableArray* privateKeyDataStructures = [NSMutableArray new];
    
    /*private keys*/
    for(MynigmaPrivateKey* keyPair in privateKeys)
    {
        //the private key data
        
        PrivateKeyData* pemData = [self.keyManager dataForPrivateKeyWithLabel:keyPair.keyLabel];
        
        if(pemData)
        {
            NSData* decPemData = pemData.privateKeyDecData;
            
            NSData* sigPemData = pemData.privateKeySigData;
            
            NSData* encPemData = pemData.publicKeyEncData;
            
            NSData* verPemData = pemData.publicKeyVerData;
            
            if(encPemData && sigPemData && decPemData && verPemData)
            {
                NSMutableArray* keyForEmails = [NSMutableArray new];
                for(EmailAddress* emailAddress in keyPair.keyForEmail)
                {
                    [keyForEmails addObject:emailAddress.address];
                }
                
                NSMutableArray* currentKeyForEmails = [NSMutableArray new];
                NSMutableArray* anchorDates = [NSMutableArray new];
               for(EmailAddress* emailAddress in keyPair.currentKeyForEmail)
                {
                    [currentKeyForEmails addObject:emailAddress.address?emailAddress.address:@""];
                    [anchorDates addObject:emailAddress.dateCurrentKeyAnchored?emailAddress.dateCurrentKeyAnchored:[NSDate date]];
                }
                
                NSMutableArray* keyForDevices = [NSMutableArray new];
                for(MynigmaDevice* device in keyPair.syncKeyForDevice)
                {
                    [keyForDevices addObject:device.deviceUUID];
                }
                
                PrivateKeyDataStructure* privateKeyStructure = [[PrivateKeyDataStructure alloc] initWithPrivateKeyLabel:keyPair.keyLabel encData:encPemData verData:verPemData decData:decPemData sigData:sigPemData dateAnchored:keyPair.firstAnchored isCompromised:keyPair.isCompromised.boolValue keyForEmails:keyForEmails currentForEmails:currentKeyForEmails datesCurrentKeysAnchored:anchorDates keyForDevices:keyForDevices version:MYNIGMA_VERSION];
                
                [privateKeyDataStructures addObject:privateKeyStructure];
            }
        }
        else
            continue;
    }
    
    NSMutableArray* publicKeyDataStructures = [NSMutableArray new];
    
    /*public keys*/
    for(MynigmaPublicKey* publicKey in publicKeys)
    {
        PublicKeyData* pemData = [self.keyManager dataForPublicKeyWithLabel:publicKey.keyLabel];
        
        if(pemData)
        {
            NSData* encPemData = pemData.publicKeyEncData;
            
            NSData* verPemData = pemData.publicKeyVerData;
            
            if(encPemData && verPemData)
            {
                NSMutableArray* introducesKeys = [NSMutableArray new];
                for(MynigmaPublicKey* introducedKey in publicKey.introducesKeys)
                {
                    [introducesKeys addObject:introducedKey.keyLabel];
                }
                
                NSMutableArray* isIntroducedByKeys = [NSMutableArray new];
                for(MynigmaPublicKey* introducingKey in publicKey.isIntroducedByKeys)
                {
                    [isIntroducedByKeys addObject:introducingKey.keyLabel];
                }
                
                NSMutableArray* keyForEmails = [NSMutableArray new];
                for(EmailAddress* emailAddress in publicKey.keyForEmail)
                {
                    [keyForEmails addObject:emailAddress.address];
                }
                
                NSMutableArray* currentKeyForEmails = [NSMutableArray new];
                NSMutableArray* anchorDates = [NSMutableArray new];
                for(EmailAddress* emailAddress in publicKey.currentKeyForEmail)
                {
                    [currentKeyForEmails addObject:emailAddress.address?emailAddress.address:@""];
                    [anchorDates addObject:emailAddress.dateCurrentKeyAnchored?emailAddress.dateCurrentKeyAnchored:[NSDate date]];
                }
                
                NSMutableArray* keyForDevices = [NSMutableArray new];
                for(MynigmaDevice* device in publicKey.syncKeyForDevice)
                {
                    [keyForDevices addObject:device.deviceUUID];
                }
                
                PublicKeyDataStructure* publicKeyStructure = [[PublicKeyDataStructure alloc] initWithPublicKeyLabel:publicKey.keyLabel encData:encPemData verData:verPemData introducesKeys:introducesKeys isIntroducedByKeys:isIntroducedByKeys dateAnchored:publicKey.firstAnchored keyForEmails:keyForEmails currentForEmails:currentKeyForEmails datesCurrentKeysAnchored:anchorDates keyForDevices:keyForDevices version:MYNIGMA_VERSION];
                
                [publicKeyDataStructures addObject:publicKeyStructure];
            }
        }
    }
    
    NSMutableArray* keyExpectationDataStructures = [NSMutableArray new];
    
    /*key expectations*/
    for(KeyExpectation* keyExpectation in keyExpectations)
    {
        NSString* fromEmail = keyExpectation.fromAddress.address;
        
        NSString* toEmail = keyExpectation.toAddress.address;
        
        NSString* version = MYNIGMA_VERSION;
        
        NSString* keyLabel = keyExpectation.expectedSignatureKey.keyLabel;
        
        NSDate* dateCreated = keyExpectation.dateLastChanged;
        
        if(!fromEmail || !toEmail || !keyLabel)
        {
            NSLog(@"Insufficient data in key expectation: %@, %@, %@", fromEmail, toEmail, keyLabel);
            continue;
        }
        
        KeyExpectationDataStructure* keyExpectationDataStructure = [[KeyExpectationDataStructure alloc] initWithKeyLabel:keyLabel fromAddress:fromEmail toAddress:toEmail dateAnchored:dateCreated version:version];
        
        [keyExpectationDataStructures addObject:keyExpectationDataStructure];
    }
    
    
    PlainBackupDataStructure* plainDataStructure = [[PlainBackupDataStructure alloc] initWithPrivateKeys:privateKeyDataStructures publicKeys:publicKeyDataStructures keyExpectations:keyExpectationDataStructures integrityCheck:INTEGRITY_CHECK_STRING version:MYNIGMA_VERSION];
    
    return [plainDataStructure serialisedData];
}

- (BOOL)backupDataHasPassword:(NSData*)fileWrapperData
{
    BackupPasswordFileWrapperDataStructure* dataStructure = [BackupPasswordFileWrapperDataStructure deserialiseData:fileWrapperData];

    return dataStructure.hasPassword;
}

- (NSData*)plainDataFromFileWrapperData:(NSData*)fileWrapperData password:(NSString*)password error:(NSError**)error
{
    BackupPasswordFileWrapperDataStructure* dataStructure = [BackupPasswordFileWrapperDataStructure deserialiseData:fileWrapperData];
    
    if(!dataStructure.payloadData)
    {
        if(error)
        {
            NSError* newError = [NSError errorWithDomain:@"MCryptoLib backup data import" code:1 userInfo:@{NSLocalizedDescriptionKey : NSLocalizedString(@"Invalid data", nil), NSLocalizedFailureReasonErrorKey : NSLocalizedString(@"Invalid data", nil)}];
            *error = newError;
        }
        return nil;
    }
    
    NSData* plainData = nil;
    
    if(dataStructure.hasPassword)
    {
        if(!dataStructure.passwordSalt.length)
        {
            if(error)
            {
                NSError* newError = [NSError errorWithDomain:@"Backup data import" code:4 userInfo:@{NSLocalizedDescriptionKey : NSLocalizedString(@"Invalid data (no salt)", nil), NSLocalizedFailureReasonErrorKey : NSLocalizedString(@"Invalid data (no salt)", nil)}];
                *error = newError;
            }
            return nil;
        }
        
        NSData* AESSessionKey = [self.engine.basicEngine AES128KeyFromPassword:password withSalt:dataStructure.passwordSalt];

        NSError* decryptionError = nil;
        
        plainData = [self.engine.basicEngine AESDecryptData:dataStructure.payloadData withSessionKey:AESSessionKey error:&decryptionError];
        
        if(decryptionError || !plainData)
        {
            NSError* newError = [NSError errorWithDomain:@"Backup data import" code:1 userInfo:@{NSLocalizedDescriptionKey : NSLocalizedString(@"Invalid password", nil), NSLocalizedFailureReasonErrorKey : NSLocalizedString(@"Invalid password", nil)}];
            
            if(error)
                *error = newError;
        }
    }
    else
    {
        plainData = dataStructure.payloadData;
    }
    
    return plainData;
}

- (void)importBackupData:(NSData*)data password:(NSString*)password inContext:(NSManagedObjectContext*)localContext withCallback:(void(^)(NSError* error))callback
{
    //remember errors and continue, if possible
    NSError* error = nil;

    //first unwrap the file wrapper to get the unencrypted plain data
    NSData* plainData = [self plainDataFromFileWrapperData:data password:password error:&error];
    
    //this is not recoverable(!)
    if(error)
    {
        if(callback)
            callback(error);
        return;
    }
    
    PlainBackupDataStructure* plainDataStructure = [PlainBackupDataStructure deserialiseData:plainData];
    
    //parse the integrity check string to verify that the decrypted data is valid
    NSString* integrityCheckString = plainDataStructure.integrityCheck;
    
    if(![integrityCheckString isEqualToString:INTEGRITY_CHECK_STRING])
    {
        if(callback)
            callback([NSError errorWithDomain:@"Backup data import" code:2 userInfo:@{NSLocalizedDescriptionKey : NSLocalizedString(@"Invalid password", nil), NSLocalizedFailureReasonErrorKey : NSLocalizedString(@"Invalid password", nil)}]);
        return;
    }
    
    //first import the private keys
    for(PrivateKeyDataStructure* privateKeyDataStructure in plainDataStructure.privateKeys)
    {
        NSString* keyLabel = privateKeyDataStructure.keyLabel;
        
        //only add the key if we don't already have one
        //give preference to existing items in keychain, even if they have no associated objects in the store
        
        MynigmaPrivateKey* privateKey = [MynigmaPrivateKey privateKeyWithLabel:keyLabel inContext:localContext];
        
        if(!privateKey)
        {
            NSData* decKeyData = privateKeyDataStructure.decrKeyData;
            NSData* sigKeyData = privateKeyDataStructure.signKeyData;
            NSData* encKeyData = privateKeyDataStructure.encrKeyData;
            NSData* verKeyData = privateKeyDataStructure.verKeyData;
            
            if(decKeyData && sigKeyData && encKeyData && verKeyData)
            {
                PrivateKeyData* privateKeyData = [[PrivateKeyData alloc] initWithKeyLabel:keyLabel decData:decKeyData sigData:sigKeyData encData:encKeyData verData:verKeyData];
                
                [self.keyManager addPrivateKeyWithData:privateKeyData];
                
                privateKey = [self.keyManager privateKeyWithLabel:privateKeyData.keyLabel inContext:localContext];
            }
        }

        if(!privateKey)
        {
            NSLog(@"Failed to import private key with label %@", keyLabel);
            continue;
        }
        
        if(privateKeyDataStructure.dateAnchored)
        {
            NSUInteger currentUNIXAnchorDate = privateKey.firstAnchored.timeIntervalSince1970;
            
            NSDate* anchorDate = privateKeyDataStructure.dateAnchored;
            
            //take the earlier of the two anchor dates
            if(!currentUNIXAnchorDate && [privateKey.firstAnchored compare:anchorDate] == NSOrderedDescending)
            {
                [privateKey setFirstAnchored:anchorDate];
            }
        }
        
                BOOL isCompromised = privateKeyDataStructure.isCompromised;
                
                [privateKey setIsCompromised:@(isCompromised || privateKey.isCompromised.boolValue)];
   
        //no need to set the version
//                NSString* versionString = [[NSString alloc] initWithBytes:privKey->keylabel().data() length:privKey->keylabel().length() encoding:NSUTF8StringEncoding];
//                
//                [privateKey setVersion:versionString];
//
        
        for(NSString* emailAddress in privateKeyDataStructure.keyForEmails)
        {
            [privateKey associateKeyWithEmail:emailAddress forceMakeCurrent:NO inContext:localContext];
        }
        
        if(privateKeyDataStructure.currentKeyForEmails.count == privateKeyDataStructure.datesCurrentKeysAnchored.count)
        {
        
        for(NSInteger index = 0; index < privateKeyDataStructure.currentKeyForEmails.count; index++)
        {
            //update the current key only if the key's anchor date is older than the anchor date of the existing key
            NSString* email = privateKeyDataStructure.currentKeyForEmails[index];
            
            NSDate* anchorDate = privateKeyDataStructure.datesCurrentKeysAnchored[index];
            
//            EmailAddress* address = [EmailAddress emailAddressForEmail:email inContext:localContext];
            
            [self.keyManager updateCurrentKeyLabel:privateKeyDataStructure.keyLabel forEmail:email ifAnchorDateIsNewerThan:anchorDate];
        }
            
        }
        
//        for(NSString* deviceUUID in privateKeyDataStructure.keyForDevices)
//        {
            //currently not setting device keys
            //we need to consider the security implications first
            //for now, device keys are only set after trust establishment and not synced
            //may need to add this to make synchronisation between more than two devices easier/faster
//        }
        
        //TODO: also parse introduces and isIntroducedByKeys
        //this needs to be added to PrivateKeyDataStructure in MProtoBufLib first...
        
        //TODO: look into creation date synchronising
        
//        NSDate* anchorDate = privateKeyDataStructure.dateAnchored;
//        
//        if(creationUNIXDate)
//        {
//            NSUInteger currentUNIXCreationDate = privateKey.dateCreated.timeIntervalSince1970;
//            
//            NSDate* creationDate = [NSDate dateWithTimeIntervalSince1970:creationUNIXDate];
//        
//            //take the earlier of the two creation dates
//            if(!currentUNIXCreationDate && [privateKey.dateCreated compare:creationDate] == NSOrderedDescending)
//            {
//                [privateKey setDateCreated:creationDate];
//            }
//        }
    }
    
    
    /*public keys*/
    for(PublicKeyDataStructure* publicKeyDataStructure in plainDataStructure.publicKeys)
    {
        NSString* keyLabel = publicKeyDataStructure.keyLabel;
        
        //only add the key if we don't already have one
        //give preference to existing items in keychain, even if they have no associated objects in the store
        
        MynigmaPublicKey* publicKey = [MynigmaPublicKey publicKeyWithLabel:keyLabel inContext:localContext];
        
        if(!publicKey)
        {
            NSData* encKeyData = publicKeyDataStructure.encrKeyData;
            NSData* verKeyData = publicKeyDataStructure.verKeyData;
            
            if(encKeyData && verKeyData)
            {
                PublicKeyData* publicKeyData = [[PublicKeyData alloc] initWithKeyLabel:keyLabel encData:encKeyData verData:verKeyData];
                
                [self.keyManager addPublicKeyWithData:publicKeyData];
                
                publicKey = [self.keyManager publicKeyWithLabel:publicKeyData.keyLabel inContext:localContext];
            }
        }
        
        if(!publicKey)
        {
            NSLog(@"Failed to import private key with label %@", keyLabel);
            continue;
        }
        
        if(publicKeyDataStructure.dateAnchored)
        {
            NSUInteger currentUNIXAnchorDate = publicKey.firstAnchored.timeIntervalSince1970;
            
            NSDate* anchorDate = publicKeyDataStructure.dateAnchored;
            
            //take the earlier of the two anchor dates
            if(!currentUNIXAnchorDate && [publicKey.firstAnchored compare:anchorDate] == NSOrderedDescending)
            {
                [publicKey setFirstAnchored:anchorDate];
            }
        }
        
//        BOOL isCompromised = publicKeyDataStructure.isCompromised;
//        
//        [publicKey setIsCompromised:@(isCompromised || publicKey.isCompromised.boolValue)];
        
        //no need to set the version
        //                NSString* versionString = [[NSString alloc] initWithBytes:privKey->keylabel().data() length:privKey->keylabel().length() encoding:NSUTF8StringEncoding];
        //
        //                [privateKey setVersion:versionString];
        //
        
        for(NSString* emailAddress in publicKeyDataStructure.keyForEmails)
        {
            [publicKey associateKeyWithEmail:emailAddress forceMakeCurrent:NO inContext:localContext];
        }
        
        if(publicKeyDataStructure.currentKeyForEmails.count == publicKeyDataStructure.datesCurrentKeysAnchored.count)
        {
            
            for(NSInteger index = 0; index < publicKeyDataStructure.currentKeyForEmails.count; index++)
            {
                //update the current key only if the key's anchor date is older than the anchor date of the existing key
                NSString* email = publicKeyDataStructure.currentKeyForEmails[index];
                
                NSDate* anchorDate = publicKeyDataStructure.datesCurrentKeysAnchored[index];
                
                //            EmailAddress* address = [EmailAddress emailAddressForEmail:email inContext:localContext];
                
                [self.keyManager updateCurrentKeyLabel:publicKeyDataStructure.keyLabel forEmail:email ifAnchorDateIsNewerThan:anchorDate];
            }
            
        }
        
        //        for(NSString* deviceUUID in privateKeyDataStructure.keyForDevices)
        //        {
        //currently not setting device keys
        //we need to consider the security implications first
        //for now, device keys are only set after trust establishment and not synced
        //may need to add this to make synchronisation between more than two devices easier/faster
        //        }
        
        //TODO: add parsing of introduces and isIntroducedBy keys
//        for(NSString* introducedKeyLabel in publicKeyDataStructure.introducesKeys)
//        {
//            [self.keyManager ]
//        }
        
        
        //TODO: look into creation date synchronising
        
        //        NSDate* anchorDate = privateKeyDataStructure.dateAnchored;
        //
        //        if(creationUNIXDate)
        //        {
        //            NSUInteger currentUNIXCreationDate = privateKey.dateCreated.timeIntervalSince1970;
        //
        //            NSDate* creationDate = [NSDate dateWithTimeIntervalSince1970:creationUNIXDate];
        //
        //            //take the earlier of the two creation dates
        //            if(!currentUNIXCreationDate && [privateKey.dateCreated compare:creationDate] == NSOrderedDescending)
        //            {
        //                [privateKey setDateCreated:creationDate];
        //            }
        //        }
    }
//    for(int i=0; i<backupData->pubkeys_size(); i++)
//    {
//        mynigma::publicKey* pubKey = new mynigma::publicKey;
//        *pubKey = backupData->pubkeys(i);
//        
//        NSString* keyLabel = [[NSString alloc] initWithBytes:pubKey->keylabel().data() length:pubKey->keylabel().length() encoding:NSUTF8StringEncoding];
//        
//        MynigmaPublicKey* publicKey = [MynigmaPublicKey publicKeyWithLabel:keyLabel inContext:localContext];
//        
//        if(!publicKey)
//        {
//            NSData* encKeyData = [NSData dataWithBytes:pubKey->encrkeydata().data() length:pubKey->encrkeydata().size()];
//            
//            NSData* verKeyData = [NSData dataWithBytes:pubKey->verkeydata().data() length:pubKey->verkeydata().size()];
//            
//            if(encKeyData && verKeyData)
//            {
//                PublicKeyData* publicKeyData = [[PublicKeyData alloc] initWithKeyLabel:keyLabel encData:encKeyData verData:verKeyData];
//                
//                publicKey = [MynigmaPublicKey syncMakeNewWithPublicKeyData:publicKeyData forEmail:nil inContext:localContext];
//            }
//        }
//        
//        if(!publicKey)
//        {
//            NSLog(@"Failed to import public key with label %@", keyLabel);
//            continue;
//        }
//        
//        BOOL isCompromised = pubKey->iscompromised();
//        
//        [publicKey setIsCompromised:@(isCompromised || publicKey.isCompromised.boolValue)];
//        
//        //no need to set the version
//        //                NSString* versionString = [[NSString alloc] initWithBytes:privKey->keylabel().data() length:privKey->keylabel().length() encoding:NSUTF8StringEncoding];
//        //
//        //                [privateKey setVersion:versionString];
//        //
//        for(int j=0; j<pubKey->currentkeyforemails_size(); j++)
//        {
//            NSString* emailString = [[NSString alloc] initWithBytes:pubKey->currentkeyforemails(j).data() length:pubKey->currentkeyforemails(j).size() encoding:NSUTF8StringEncoding];
//            
//            if(emailString)
//                [publicKey associateKeyWithEmail:emailString forceMakeCurrent:NO inContext:localContext];
//        }
//        
//        for(int j=0; j<pubKey->keyforemails_size(); j++)
//        {
//            NSString* emailString = [[NSString alloc] initWithBytes:pubKey->keyforemails(j).data() length:pubKey->keyforemails(j).size() encoding:NSUTF8StringEncoding];
//            
//            EmailAddress* emailAddress = [EmailAddress emailAddressForEmail:emailString inContext:localContext];
//            
//            if(emailAddress)
//                [publicKey addKeyForEmailObject:emailAddress];
//        }
//        
//        for(int j=0; j<pubKey->introduceskeys_size(); j++)
//        {
//            NSString* keyLabel = [[NSString alloc] initWithBytes:pubKey->introduceskeys(j).data() length:pubKey->introduceskeys(j).size() encoding:NSUTF8StringEncoding];
//            
//            if(keyLabel)
//            {
//                MynigmaPublicKey* introducedKey = [MynigmaPublicKey publicKeyWithLabel:keyLabel inContext:localContext];
//                
//                if(introducedKey)
//                    [publicKey addIntroducesKeysObject:introducedKey];
//            }
//        }
//        
//        for(int j=0; j<pubKey->isintroducedbykeys_size(); j++)
//        {
//            NSString* keyLabel = [[NSString alloc] initWithBytes:pubKey->isintroducedbykeys(j).data() length:pubKey->isintroducedbykeys(j).size() encoding:NSUTF8StringEncoding];
//            
//            if(keyLabel)
//            {
//                MynigmaPublicKey* introducingKey = [MynigmaPublicKey publicKeyWithLabel:keyLabel inContext:localContext];
//                
//                if(introducingKey)
//                    [publicKey addIsIntroducedByKeysObject:introducingKey];
//            }
//        }
//        
//        long long creationUNIXDate = pubKey->datecreated();
//        
//        if(creationUNIXDate)
//        {
//            NSUInteger currentUNIXCreationDate = publicKey.dateCreated.timeIntervalSince1970;
//            
//            NSDate* creationDate = [NSDate dateWithTimeIntervalSince1970:creationUNIXDate];
//            
//            //take the earlier of the two creation dates
//            if(!currentUNIXCreationDate && [publicKey.dateCreated compare:creationDate] == NSOrderedDescending)
//            {
//                [publicKey setDateCreated:creationDate];
//            }
//        }
//    }
//
    
    for(KeyExpectationDataStructure* keyExpectationDataStructure in plainDataStructure.keyExpectations)
    {
                NSString* fromEmail = keyExpectationDataStructure.fromAddress;
                NSString* toEmail = keyExpectationDataStructure.toAddress;
                NSString* keyLabel = keyExpectationDataStructure.keyLabel;
        
                NSDate* creationDate = keyExpectationDataStructure.dateAnchored;
        
                if(fromEmail && toEmail && keyLabel && creationDate)
                {
                    [self.keyManager updateExpectedKeyLabelFrom:fromEmail to:toEmail keyLabel:keyLabel date:creationDate];
                }
    }
    
    [self.coreDataHelper saveWithCallback:^{
        
        if(callback)
            callback(error);
    }];
}


@end
