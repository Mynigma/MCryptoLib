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


#import "CommonHeader.h"


#import "MynigmaKeyManager.h"
#import "KeychainHelper.h"
#import "NSData+Base64.h"
#import "EmailAddress.h"
#import "NSString+EmailAddresses.h"
#import "KeyExpectation.h"
#import "AppleEncryptionEngine.h"
#import "ThreadHelper.h"

#import "MynigmaPublicKey.h"
#import "MynigmaPrivateKey.h"

#import "PublicKeyData.h"
#import "PrivateKeyData.h"






@interface MynigmaKeyManager()

@property BOOL haveCompiledKeyIndex;
@property NSMutableDictionary* keyIndex;
@property dispatch_queue_t keyIndexQueue;

@end



@implementation MynigmaKeyManager



- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper coreDataHelper:(CoreDataHelper*)coreDataHelper
{
    self = [super init];
    if (self) {
        
        self.keychainHelper = keychainHelper;
        self.coreDataHelper = [CoreDataHelper sharedInstance];

        self.haveCompiledKeyIndex = NO;
        self.keyIndex = [NSMutableDictionary new];
        self.keyIndexQueue = dispatch_queue_create("org.mynigma.publicKeyIndexQueue", NULL);
    }
    return self;
}

- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper
{
    return [self initWithKeychainHelper:keychainHelper coreDataHelper:[CoreDataHelper sharedInstance]];
}

- (instancetype)init
{
    return [self initWithKeychainHelper:[KeychainHelper sharedInstance] coreDataHelper:[CoreDataHelper sharedInstance]];
}



+ (dispatch_group_t)keyGenerationGroup
{
    static dispatch_group_t _keyGenerationDispatchGroup = NULL;
    
    if(!_keyGenerationDispatchGroup)
        _keyGenerationDispatchGroup = dispatch_group_create();
    
    return _keyGenerationDispatchGroup;
}

+ (dispatch_queue_t)keyGenerationQueue
{
    static dispatch_queue_t _keyGenerationQueue = NULL;
    
    if(!_keyGenerationQueue)
        _keyGenerationQueue = dispatch_queue_create("Mynigma key generation dispatch queue", NULL);
    
    return _keyGenerationQueue;
}


#pragma mark - Obtaining objects

- (KeyExpectation*)keyExpectationFrom:(EmailAddress*)fromAddress to:(EmailAddress*)toAddress inContext:(NSManagedObjectContext*)keyContext makeIfNecessary:(BOOL)makeIfNecessary
{
    if(!fromAddress || !toAddress)
        return nil;
    
    //lock to ensure uniqueness of KeyExpectation objects for a given (toAddress, fromAddress) pair
    //first fetch, then create if none found
    @synchronized(@"KEY_EXPECTATION_LOCK")
    {
        
        NSPredicate* fetchPredicate = [NSPredicate predicateWithFormat:@"(toAddress == %@) AND (fromAddress == %@)", toAddress, fromAddress];
        
        KeyExpectation* fetchedResult = (KeyExpectation*)[self.coreDataHelper fetchObjectOfClass:[KeyExpectation class] withPredicate:fetchPredicate inContext:keyContext];
        
        if(fetchedResult)
            return fetchedResult;
        
        //none found - create a new one(!)
        if(!makeIfNecessary)
            return nil;
        
        NSEntityDescription* entityDescription = [NSEntityDescription entityForName:@"KeyExpectation" inManagedObjectContext:keyContext];
        KeyExpectation* newKeyExpectation = [[KeyExpectation alloc] initWithEntity:entityDescription insertIntoManagedObjectContext:keyContext];
        
        [newKeyExpectation setFromAddress:fromAddress];
        [newKeyExpectation setToAddress:toAddress];
        
        NSError* error = nil;
        
        [keyContext save:&error];
        
        if(error)
        {
            NSLog(@"Error saving key context after adding key expectation!! %@", error);
        }
        
        //save the main context and the store context, persisting the key expectation to disk
        [self.coreDataHelper save];
        
        return newKeyExpectation;
    }
}

- (EmailAddress*)emailAddressForEmail:(NSString*)emailString inContext:(NSManagedObjectContext*)keyContext makeIfNecessary:(BOOL)shouldCreate
{
    @synchronized(@"EMAIL_ADDRESS_LOCK")
    {
        emailString = [emailString canonicalForm];
        
        if(!emailString)
            return nil;
        
        NSPredicate* predicate = [NSPredicate predicateWithFormat:@"address == %@", emailString];
        
        EmailAddress* fetchResult = (EmailAddress*)[self.coreDataHelper fetchObjectOfClass:[EmailAddress class] withPredicate:predicate inContext:keyContext];
        
        if(fetchResult)
            return fetchResult;
        
        //no email address exists
        
        if(!shouldCreate)
            return nil;
        
        NSEntityDescription* entityDescription = [NSEntityDescription entityForName:@"EmailAddress" inManagedObjectContext:keyContext];
        EmailAddress* newAddress = [[EmailAddress alloc] initWithEntity:entityDescription insertIntoManagedObjectContext:keyContext];
        
        NSError* error = nil;
        
        [keyContext obtainPermanentIDsForObjects:@[newAddress] error:&error];
        
        if(error)
        {
            NSLog(@"Error obtaining permanent objectID for EmailAddress object: %@", error);
        }
        
        [newAddress setDateAdded:[NSDate date]];
        
        [newAddress setAddress:emailString.canonicalForm];
        
        return newAddress;
    }
}

- (MynigmaPublicKey*)publicKeyWithLabel:(NSString*)keyLabel inContext:(NSManagedObjectContext*)keyContext
{
    if(!keyLabel)
        return nil;
    
    MynigmaPublicKey* fetchedResult = (MynigmaPublicKey*)[self.coreDataHelper fetchObjectOfClass:[MynigmaPublicKey class] withPredicate:[NSPredicate predicateWithFormat:@"keyLabel == %@",keyLabel] inContext:keyContext];
    
    return fetchedResult;
}

- (MynigmaPrivateKey*)privateKeyWithLabel:(NSString*)keyLabel inContext:(NSManagedObjectContext*)keyContext
{
    if(!keyLabel)
        return nil;
    
    MynigmaPrivateKey* fetchedResult = (MynigmaPrivateKey*)[self.coreDataHelper fetchObjectOfClass:[MynigmaPrivateKey class] withPredicate:[NSPredicate predicateWithFormat:@"keyLabel == %@",keyLabel] inContext:keyContext];
    
    return fetchedResult;
}



#pragma mark - Querying keys

- (BOOL)havePublicKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return NO;
    
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext) {
    
        returnValue = [self.coreDataHelper haveObjectOfClass:[MynigmaPublicKey class] withPredicate:[NSPredicate predicateWithFormat:@"keyLabel == %@",keyLabel] inContext:keyContext];
    }];
    
    return returnValue;
}

- (BOOL)havePrivateKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return NO;
    
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext) {
        
        returnValue = [self.coreDataHelper haveObjectOfClass:[MynigmaPrivateKey class] withPredicate:[NSPredicate predicateWithFormat:@"keyLabel == %@",keyLabel] inContext:keyContext];
    }];
    
    return returnValue;
}





- (PublicKeyData*)dataForPublicKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    __block PublicKeyData* returnValue = nil;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext)
     {
         MynigmaPublicKey* publicKey = [self publicKeyWithLabel:keyLabel inContext:keyContext];
         
         returnValue = [self.keychainHelper dataForPublicKey:publicKey];
     }];
    
    return returnValue;
}



- (PrivateKeyData*)dataForPrivateKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    __block PrivateKeyData* returnValue = nil;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext)
     {
         MynigmaPrivateKey* privateKey = [self privateKeyWithLabel:keyLabel inContext:keyContext];
         
         if([privateKey isKindOfClass:[MynigmaPrivateKey class]])
             returnValue = [self.keychainHelper dataForPrivateKey:privateKey];
     }];
    
    return returnValue;
}


- (NSArray*)listAllPrivateKeyLabels
{
    //TODO
    return nil;
}


#pragma mark - Adding keys

- (BOOL)addPublicKeyWithData:(PublicKeyData*)publicKeyData
{
    @synchronized(@"PUBLIC_KEY_DATA")
    {
    NSString* keyLabel = publicKeyData.keyLabel;
    
    NSData* encKeyData = publicKeyData.publicKeyEncData;
    NSData* verKeyData = publicKeyData.publicKeyVerData;
    
    if(!keyLabel || !encKeyData || !encKeyData)
    {
        NSLog(@"Cannot make new public key with label %@ and data %@, %@", keyLabel, encKeyData, verKeyData);
        return NO;
    }
        
        __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext) {
        
        PublicKeyData* existingPublicKeyData = [self dataForPublicKeyWithLabel:keyLabel];
    
    if(existingPublicKeyData)
    {
        //already have a key - just compare it with the current data and return the existing key only if the data matches
        if([existingPublicKeyData isEqual:publicKeyData])
        {
            returnValue = YES;
            return;
        }
        
        //no luck, the key doesn't match
        NSLog(@"Key to be added doesn't match the data already in the keychain!");
        return;
    }
    else
    {
        //ok, no key with such a label exists so far. add a new one:
        
        //first deal with the keychain
        //we can't have zombie key objects wandering around
        //that don't have a corresponding item in the keychain
        if([self.keychainHelper havePublicKeychainItemWithLabel:keyLabel])
        {
            if([self.keychainHelper doesKeychainItemMatchPublicKeyData:publicKeyData])
            {
                //if the key is actually a private key, it should be extracted from the keychain
                //don't add a public key, use a private key instead(!)
                if([self.keychainHelper havePrivateKeychainItemWithLabel:keyLabel])
                {
                    PrivateKeyData* privateKeyData = [self.keychainHelper dataForPrivateKeychainItemWithLabel:keyLabel];
                    
                    if(!privateKeyData)
                        return;
                    
                    returnValue = [self addPrivateKeyWithData:privateKeyData];
                    return;
                }
            }
            else
            {
                NSLog(@"Trying to add public key that doesn't match the data already in the keychain!!");
                return;
            }
            
        }
        
        NSEntityDescription* entityDescription = [NSEntityDescription entityForName:@"MynigmaPublicKey" inManagedObjectContext:keyContext];
        MynigmaPublicKey* publicKey = [[MynigmaPublicKey alloc] initWithEntity:entityDescription insertIntoManagedObjectContext:keyContext];
       
        if(![self.keychainHelper addPublicKeyDataToKeychain:publicKeyData])
        {
            NSLog(@"Failed to add new public key to keychain!!!");
        }

        [publicKey setKeyLabel:keyLabel];
        [publicKey setIsCompromised:@NO];
        
        NSDate* date = [NSDate date];
        
        [publicKey setFirstAnchored:date];
        [publicKey setDateObtained:date];
        
        [self.coreDataHelper save];
        
        returnValue = YES;
    }
    }];
        
        return returnValue;
    }
}

- (BOOL)addPrivateKeyWithData:(PrivateKeyData*)privateKeyData
{
    if(!privateKeyData.keyLabel)
        return NO;
    
    if([self havePrivateKeyWithLabel:privateKeyData.keyLabel])
    {
        PrivateKeyData* existingPrivateKeyData = [self dataForPrivateKeyWithLabel:privateKeyData.keyLabel];
        return [existingPrivateKeyData isEqual:privateKeyData];
    }
    
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext) {
    
    MynigmaPublicKey* existingPublicKey = [self publicKeyWithLabel:privateKeyData.keyLabel inContext:keyContext];
        
        if(existingPublicKey)
        {
    //check that the data matches
        PublicKeyData* existingPublicKeyData = [self dataForPublicKeyWithLabel:privateKeyData.keyLabel];
        
        if(![existingPublicKeyData isEqual:privateKeyData])
        {
            //existing public key does not match private key data to be added
            return;
        }
         
            [self removePublicKeyWithLabel:privateKeyData.keyLabel];
        }
    
    NSEntityDescription* entityDescription = [NSEntityDescription entityForName:@"MynigmaPrivateKey" inManagedObjectContext:keyContext];
    MynigmaPrivateKey* privateKey = [[MynigmaPrivateKey alloc] initWithEntity:entityDescription insertIntoManagedObjectContext:keyContext];
    
    [privateKey setKeyLabel:privateKeyData.keyLabel];
    
    [privateKey setDateCreated:[NSDate date]];
    
    [privateKey setVersion:MYNIGMA_VERSION];
    
    [privateKey setIsCompromised:@NO];
        
    [self.coreDataHelper save];
        
    [self.keychainHelper addPrivateKeyDataToKeychain:privateKeyData];
    
    returnValue = YES;
    }];
    
    return returnValue;
}

- (BOOL)generatePrivateKeyWithLabel:(NSString*)keyLabel
{
    //TODO
    return NO;
}

- (void)generateMynigmaPrivateKeyForEmail:(NSString*)emailAddress engine:(id<BasicEncryptionEngineProtocol>)engine withCallback:(void(^)(void))callback
{
    NSString* email = [emailAddress canonicalForm];
    
    if(!email)
    {
        if(callback)
            callback();
        return;
    }
    
    dispatch_group_t keyGenerationDispatchGroup = [MynigmaKeyManager keyGenerationGroup];
    dispatch_queue_t keyGenerationQueue = [MynigmaKeyManager keyGenerationQueue];
    
    dispatch_group_notify(keyGenerationDispatchGroup, keyGenerationQueue, ^{

        dispatch_group_enter(keyGenerationDispatchGroup);
        
        if([self haveCurrentPrivateKeyForEmailAddress:emailAddress])
        {
            dispatch_group_leave(keyGenerationDispatchGroup);
            if(callback)
                callback();
            return;
        }
        
    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext){
        
        [engine generateNewPrivateKeyWithCallback:^(NSData *publicEncKeyData, NSData *privateDecKeyData, NSError *encGenError) {
            
            [engine generateNewPrivateKeyWithCallback:^(NSData *publicVerKeyData, NSData *privateSigKeyData, NSError *verGenError) {
                
                //use the current date for the second part of the keyLabel
                __block NSDate* currentDate = [NSDate date];
                
                //the email address is the first part
                __block NSString* keyLabel = [NSString stringWithFormat:@"%@|%f",email,[currentDate timeIntervalSince1970]];
           
                PrivateKeyData* privateKeyData = [[PrivateKeyData alloc] initWithKeyLabel:keyLabel decData:privateDecKeyData sigData:privateSigKeyData encData:publicEncKeyData verData:publicVerKeyData];
                
                if(!encGenError && !verGenError && [self addPrivateKeyWithData:privateKeyData])
                {
                    [self setCurrentKeyForEmailAddress:email keyLabel:keyLabel overwrite:YES];
                }
                
                dispatch_group_leave(keyGenerationDispatchGroup);
                if(callback)
                    callback();
            }];
        }];
    }];
    });
}

- (BOOL)removePublicKeyWithLabel:(NSString*)keyLabel
{
    return NO;
}


#pragma mark - Current keys

- (BOOL)setCurrentKeyForEmailAddress:(NSString*)emailString keyLabel:(NSString*)keyLabel overwrite:(BOOL)overwritePrevious
{
    if(!emailString.length)
        return NO;
    
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext)
    {
        EmailAddress* emailAddress = [self emailAddressForEmail:emailString inContext:keyContext makeIfNecessary:YES];
        
        MynigmaPublicKey* publicKey = [self publicKeyWithLabel:keyLabel inContext:keyContext];
        
        //add this key to the list of keys associated with this email address
        [emailAddress addAllKeysObject:publicKey];
        
        //if there is no current key or the forceMakeCurrent flag is set, make this the current key
        if(publicKey && (!emailAddress.currentMynigmaKey || overwritePrevious))
        {
            [emailAddress setCurrentMynigmaKey:publicKey];
            
            //the anchor date is important for synchronisation between devices
            //essentially, it's the date the key was first found
            //earlier anchor dates take precedence
            //the dates of messages are irrelevant, as headers can be spoofed
            [emailAddress setDateCurrentKeyAnchored:[NSDate date]];
            
            returnValue = YES;
        }
        
        //if the current key is already set to the correct one, just return YES
        if([publicKey isEqual:emailAddress.currentMynigmaKey])
            returnValue = YES;
    }];
    
    return returnValue;
}

- (BOOL)haveCurrentKeyForEmailAddress:(NSString*)emailString
{
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext* keyContext)
    {
        EmailAddress* emailAddress = [self emailAddressForEmail:emailString inContext:keyContext makeIfNecessary:NO];
        
        MynigmaPublicKey* publicKey = (MynigmaPublicKey*)emailAddress.currentMynigmaKey;
        
        if([publicKey isKindOfClass:[MynigmaPublicKey class]])
            returnValue = YES;
    }];
    
    return returnValue;
}

- (BOOL)haveCurrentPrivateKeyForEmailAddress:(NSString*)emailString
{
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext* keyContext) {
        
        EmailAddress* emailAddress = [self emailAddressForEmail:emailString inContext:keyContext makeIfNecessary:NO];
        
        MynigmaPublicKey* publicKey = (MynigmaPublicKey*)emailAddress.currentMynigmaKey;
        
        returnValue = [publicKey isKindOfClass:[MynigmaPrivateKey class]];
    }];
    
    return returnValue;
}

- (NSString*)currentKeyLabelForEmailAddress:(NSString*)emailString
{
    __block NSString* returnValue = nil;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext* keyContext) {
        
        EmailAddress* emailAddress = [self emailAddressForEmail:emailString inContext:keyContext makeIfNecessary:NO];
        
        MynigmaPublicKey* publicKey = (MynigmaPublicKey*)emailAddress.currentMynigmaKey;
        
        if([publicKey isKindOfClass:[MynigmaPublicKey class]])
            returnValue = publicKey.keyLabel;
    }];
    
    return returnValue;
}

- (BOOL)updateCurrentKeyLabel:(NSString*)publicKeyLabel forEmail:(NSString*)emailString ifAnchorDateIsNewerThan:(NSDate*)anchorDate
{
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext* keyContext)
    {
        
        EmailAddress* emailAddress = [self emailAddressForEmail:emailString inContext:keyContext makeIfNecessary:YES];
        
    if(!emailAddress.dateCurrentKeyAnchored || [emailAddress.dateCurrentKeyAnchored compare:anchorDate] == NSOrderedDescending)
    {
        [self setCurrentKeyForEmailAddress:emailString keyLabel:publicKeyLabel overwrite:YES];
        
        returnValue = YES;
    }
    }];
    
    return returnValue;
}


#pragma mark - Key expectations

- (BOOL)setExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail keyLabel:(NSString*)keyLabel date:(NSDate*)date overwrite:(BOOL)overwritePrevious
{
    if([[senderEmail canonicalForm] isEqualToString:[recipientEmail canonicalForm]])
        return NO;
    
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext) {
        
        EmailAddress* fromAddress = [self emailAddressForEmail:senderEmail inContext:keyContext makeIfNecessary:YES];
        
        EmailAddress* toAddress = [self emailAddressForEmail:recipientEmail inContext:keyContext makeIfNecessary:YES];
        
        KeyExpectation* keyExpectation = [self keyExpectationFrom:fromAddress to:toAddress inContext:keyContext makeIfNecessary:YES];
        
        if(keyExpectation.expectedSignatureKey && !overwritePrevious)
            return;
        
        if(!keyLabel)
        {
            [keyExpectation setExpectedSignatureKey:nil];
 
            returnValue = YES;
        }
        else
        {
            MynigmaPublicKey* publicKey = [self publicKeyWithLabel:keyLabel inContext:keyContext];
            
            if(!publicKey)
            {
                NSLog(@"Failed to create public key");
                return;
            }

            [keyExpectation setExpectedSignatureKey:publicKey];
            [keyExpectation setDateLastChanged:date];
        
            returnValue = YES;
        }
    }];
    
    return returnValue;
}

- (NSString*)expectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail
{
    if([[senderEmail canonicalForm] isEqualToString:[recipientEmail canonicalForm]])
        return [self currentKeyLabelForEmailAddress:senderEmail];
    
    __block NSString* returnValue = nil;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext) {
        
        EmailAddress* fromAddress = [self emailAddressForEmail:senderEmail inContext:keyContext makeIfNecessary:YES];
        
        EmailAddress* toAddress = [self emailAddressForEmail:recipientEmail inContext:keyContext makeIfNecessary:YES];
        
        KeyExpectation* keyExpectation = [self keyExpectationFrom:fromAddress to:toAddress inContext:keyContext makeIfNecessary:NO];
        
        returnValue = keyExpectation.expectedSignatureKey.keyLabel;
    }];
    
    return returnValue?returnValue:[self currentKeyLabelForEmailAddress:senderEmail];
}

- (NSDate*)anchorDateFrom:(NSString*)senderEmail to:(NSString*)recipientEmail
{
    __block NSDate* returnValue = nil;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext)
    {
        EmailAddress* fromAddress = [self emailAddressForEmail:senderEmail inContext:keyContext makeIfNecessary:YES];
        
        EmailAddress* toAddress = [self emailAddressForEmail:recipientEmail inContext:keyContext makeIfNecessary:YES];
        
        KeyExpectation* keyExpectation = [self keyExpectationFrom:fromAddress to:toAddress inContext:keyContext makeIfNecessary:NO];
        
        returnValue = keyExpectation.dateLastChanged;
    }];
    
    return returnValue;
}

- (BOOL)haveExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail
{
    __block BOOL returnValue = NO;
    
    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext)
    {
        EmailAddress* fromAddress = [self emailAddressForEmail:senderEmail inContext:keyContext makeIfNecessary:YES];
        
        EmailAddress* toAddress = [self emailAddressForEmail:recipientEmail inContext:keyContext makeIfNecessary:YES];
        
        KeyExpectation* keyExpectation = [self keyExpectationFrom:fromAddress to:toAddress inContext:keyContext makeIfNecessary:NO];
        
        returnValue = keyExpectation.expectedSignatureKey != nil;
    }];
    
    return returnValue;
}

- (BOOL)updateExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail keyLabel:(NSString*)keyLabel date:(NSDate*)date
{
    __block BOOL returnValue = NO;
 
    if(!date)
        date = [NSDate date];
    
    if(!senderEmail.length || !recipientEmail.length || !keyLabel.length)
        return NO;

    [self.coreDataHelper runSyncOnKeyContext:^(NSManagedObjectContext *keyContext)
    {
         EmailAddress* fromAddress = [self emailAddressForEmail:senderEmail inContext:keyContext makeIfNecessary:YES];
         
         EmailAddress* toAddress = [self emailAddressForEmail:recipientEmail inContext:keyContext makeIfNecessary:YES];
         
         KeyExpectation* keyExpectation = [self keyExpectationFrom:fromAddress to:toAddress inContext:keyContext makeIfNecessary:YES];
         
         MynigmaPublicKey* newExpectedKey = [self publicKeyWithLabel:keyLabel inContext:keyContext];
         
         //make sure there is actually a valid key
         //actually it doesn't make much sense to use a public (not private) key here, but never mind...
         if(!newExpectedKey)
             return;
         
         //don't accept expectations if the date is in the future
         if([date compare:[NSDate date]]==NSOrderedDescending)
             return;
         
         //nor if the new anchor date is older than the previous one
         if(keyExpectation.dateLastChanged && [date compare:keyExpectation.dateLastChanged]==NSOrderedAscending)
             return;
         
         [keyExpectation setExpectedSignatureKey:newExpectedKey];
         [keyExpectation setDateLastChanged:date];
         
         returnValue = YES;
     }];
    
    return returnValue;
}


#pragma mark - Devices

- (NSString*)currentDeviceUUID
{
    //TODO
    return nil;
}

- (MynigmaDevice*)deviceWithUUID:(NSString*)deviceUUID addIfNotFound:(BOOL)addIfNotFound inContext:(NSManagedObjectContext*)localContext
{
    //TODO
    return nil;
}

- (BOOL)setCurrentKeyForDeviceWithUUID:(NSString*)deviceUUID keyLabel:(NSString*)keyLabel overwrite:(BOOL)overwritePrevious
{
    //TODO
    return NO;
}

- (BOOL)haveCurrentKeyForDeviceWithUUID:(NSString*)deviceUUID
{
    //TODO
    return NO;
}

- (BOOL)haveCurrentPrivateKeyForDeviceWithUUID:(NSString*)deviceUUID
{
    //TODO
    return NO;
}

- (NSString*)currentKeyLabelForDeviceWithUUID:(NSString*)deviceUUID
{
    //TODO
    return nil;
}


- (void)distrustAllDevices
{
    //TODO
}









#pragma mark - Header representations

- (NSData*)cleanKeyData:(NSString*)keyString
{
    NSMutableString* keyDataString = [keyString mutableCopy];
    
    [keyDataString replaceOccurrencesOfString:@"\r" withString:@"" options:0 range:NSMakeRange(0, keyDataString.length)];
    [keyDataString replaceOccurrencesOfString:@"\n" withString:@"" options:0 range:NSMakeRange(0, keyDataString.length)];    [keyDataString replaceOccurrencesOfString:@" " withString:@"" options:0 range:NSMakeRange(0, keyDataString.length)];
    
    NSMutableString* unBase64edKeyString = [[NSString stringWithBase64String:keyDataString] mutableCopy];
    
    //the old format for public keys used the wrong kind of armour
    //-----BEGIN PUBLIC KEY----- is correct, since the key includes an RSA OID
    [unBase64edKeyString replaceOccurrencesOfString:@"RSA PUBLIC" withString:@"PUBLIC" options:0 range:NSMakeRange(0, unBase64edKeyString.length)];
    
    //replace "\r\n" with "\n" line breaks
    [unBase64edKeyString replaceOccurrencesOfString:@"\r" withString:@"" options:0 range:NSMakeRange(0, unBase64edKeyString.length)];
    
    return [unBase64edKeyString dataUsingEncoding:NSUTF8StringEncoding];
}

- (PublicKeyData*)getPublicKeyDataFromExtraHeaderValues:(NSDictionary*)headerValues
{
    NSString* key = headerValues[@"x-myn-pk"];
    NSString* keyLabel = headerValues[@"x-myn-kl"];
    
    if (!key.length)
        return nil;
    
    if (!keyLabel.length)
        return nil;
    
    // TODO: check that RFC 2047 conforming conversion into regular string is done by MailCore
    
    keyLabel = [NSString stringWithBase64String:keyLabel];
    
    NSArray* components = [key componentsSeparatedByString:@"-"];
    
    if(components.count < 2)
        return nil;
    
    NSData* encData = [self cleanKeyData:components[0]];
    
    NSData* verData = [self cleanKeyData:components[1]];
    
    if(keyLabel && encData.length && verData.length)
    {
        PublicKeyData* publicKeyData = [[PublicKeyData alloc] initWithKeyLabel:keyLabel encData:encData verData:verData];
        
        return publicKeyData;
    }
    
    return nil;
}




#pragma mark - Easy reading fingerprints

- (NSArray*)pronouns
{
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"Pronouns" withExtension:@""];
    
    NSString* wordListString = [NSString stringWithContentsOfURL:fileURL encoding:NSUTF8StringEncoding error:nil];
    
    return [wordListString componentsSeparatedByString:@"\n"];
}


- (NSArray*)adjectives
{
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"Adjectives" withExtension:@""];
    
    NSString* wordListString = [NSString stringWithContentsOfURL:fileURL encoding:NSUTF8StringEncoding error:nil];
    
    return [wordListString componentsSeparatedByString:@"\n"];
}

- (NSArray*)verbs
{
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"Verbs" withExtension:@""];
    
    NSString* wordListString = [NSString stringWithContentsOfURL:fileURL encoding:NSUTF8StringEncoding error:nil];
    
    return [wordListString componentsSeparatedByString:@"\n"];
}

- (NSArray*)nouns
{
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"Nouns" withExtension:@""];
    
    NSString* wordListString = [NSString stringWithContentsOfURL:fileURL encoding:NSUTF8StringEncoding error:nil];
    
    return [wordListString componentsSeparatedByString:@"\n"];
}

- (NSArray*)prepositions
{
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"Prepositions" withExtension:@""];
    
    NSString* wordListString = [NSString stringWithContentsOfURL:fileURL encoding:NSUTF8StringEncoding error:nil];
    
    return [wordListString componentsSeparatedByString:@"\n"];
}


- (NSString*)easyReadingSentenceForBytes:(Byte[32])indexValues
{
    //[pronoun] [adjective] [noun] [preposition] [pronoun] [adjective] [noun] [verb] [pronoun] [noun] and [pronoun] [adjective] [noun] [preposition] [pronoun] [adjective] [noun] [verb] [preposition] [pronoun] [noun]
    
    NSInteger pronounIndex1 = indexValues[0] % (2 << 3);
    NSInteger adjectiveIndex1 = indexValues[1] % (2 << 7);
    NSInteger nounIndex1 = (256*indexValues[2] + indexValues[3]) % (2 << 9);
    NSInteger prepositionIndex1 = indexValues[4] % (2 << 2);
    NSInteger pronounIndex2 = indexValues[5] % (2 << 2);
    NSInteger adjectiveIndex2 = indexValues[6] % (2 << 7);
    NSInteger nounIndex2 = (256*indexValues[7] + indexValues[8]) % (2 << 9);
    NSInteger verbIndex1 = (256*indexValues[9] + indexValues[10]) % (2 << 8);
    NSInteger pronounIndex3 = indexValues[11] % (2 << 3);
    NSInteger adjectiveIndex3 = indexValues[12] % (2 << 7);
    NSInteger nounIndex3 = (256*indexValues[13] + indexValues[14]) % (2 << 9);
    
    NSString* pronoun1 = [self pronouns][pronounIndex1];
    NSString* adjective1 = [self adjectives][adjectiveIndex1];
    NSString* noun1 = [self nouns][nounIndex1];
    NSString* preposition1 = [self prepositions][prepositionIndex1];
    NSString* pronoun2 = [self pronouns][pronounIndex2];
    NSString* adjective2 = [self adjectives][adjectiveIndex2];
    NSString* noun2 = [self nouns][nounIndex2];
    NSString* verb1 = [self verbs][verbIndex1];
    NSString* pronoun3 = [self pronouns][pronounIndex3];
    NSString* adjective3 = [self adjectives][adjectiveIndex3];
    NSString* noun3 = [self nouns][nounIndex3];
    
    NSString* easyReadingSentence = [NSString stringWithFormat:@"%@ %@ %@ %@ %@ %@ %@ %@ %@ %@ %@", pronoun1, adjective1, noun1, preposition1, pronoun2, adjective2, noun2, verb1, pronoun3, adjective3, noun3];

    return easyReadingSentence;
}



- (NSString*)easyReadingFingerprintForKeyWithLabel:(NSString*)keyLabel
{
    PublicKeyData* publicKeyData = [self dataForPublicKeyWithLabel:keyLabel];
    
    if(!publicKeyData)
        return @"-- error --";
    
    NSMutableData* concatenatedData = [NSMutableData dataWithData:publicKeyData.publicKeyEncData];
    
    [concatenatedData appendData:publicKeyData.publicKeyVerData];
    [concatenatedData appendData:[keyLabel dataUsingEncoding:NSUTF8StringEncoding]];
    
    
    AppleEncryptionEngine* engine = [AppleEncryptionEngine new];
    
    
    NSData* hashValue = [engine SHA256DigestOfData:concatenatedData];
    

    Byte firstValues[16];
    [hashValue getBytes:firstValues length:16];
    
    Byte secondValues[16];
    [hashValue getBytes:secondValues range:NSMakeRange(16, 16)];
    
    NSString* firstSentence = [self easyReadingSentenceForBytes:firstValues];
    
    NSString* secondSentence = [self easyReadingSentenceForBytes:secondValues];
    
    NSString* easyReadingFingerprint = [NSString stringWithFormat:@"%@ and %@.", firstSentence, secondSentence];
    
    //Capitalise first letter
    easyReadingFingerprint = [easyReadingFingerprint stringByReplacingCharactersInRange:NSMakeRange(0,1) withString:[[easyReadingFingerprint substringToIndex:1] capitalizedString]];
    
    return easyReadingFingerprint;
}



@end
