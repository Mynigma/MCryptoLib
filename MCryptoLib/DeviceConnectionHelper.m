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





#import "DeviceConnectionHelper.h"

#import "KeychainHelper.h"
#import "ThreadHelper.h"
#import "MynigmaKeyManager.h"
#import "DeviceConnectionDelegate.h"
#import "MynigmaEncryptionEngine.h"

#import "MynigmaDevice.h"
#import "MynigmaPublicKey.h"
#import "MynigmaPrivateKey.h"
#import "PublicKeyData.h"
#import "SessionKeys.h"
#import "NSString+EmailAddresses.h"
#import "NSData+Base64.h"

#import "MimeHelper.h"
#import "MynigmaMessageEncryptionContext.h"
#import "BackupHelper.h"

#import <MProtoBuf/PublicKeyDataStructure.h>
#import <MProtoBuf/DeviceMessageDataStructure.h>
#import <MProtoBuf/AnnounceInfoPayloadDataStructure.h>
#import <MProtoBuf/ConfirmConnectionPayloadDataStructure.h>
#import <MProtoBuf/DeviceDiscoveryPayloadDataStructure.h>
#import <MProtoBuf/DeviceMessageDataStructure.h>
#import <MProtoBuf/PlainBackupDataStructure.h>
#import <MProtoBuf/HMACDataStructure.h>
#import <MProtoBuf/SignedDataStructure.h>
#import <MProtoBuf/DigestInfoPartDataStructure.h>
#import <MProtoBuf/DigestInfoPairDataStructure.h>



#define VERBOSE_TRUST_ESTABLISHMENT NO


//messages expire after 10 minutes
#define EXPIRY_INTERVAL_IN_SECS (10*60)





static NSString* currentThreadID;
static NSSet* expectedMessageCommands;

//this is the date of the 1_ANNOUNCE_INFO message that started the trust establishment/device connection protocol
//only one device connection should be attempted at any one time
//the date is used to decide which one in a way that both devices will agree on (preference is given to earlier connection attempts)
static NSDate* currentThreadInitiationDate;

static NSString* partnerEmailAddress;

static NSString* partnerDeviceUUID;
static NSString* partnerSyncKeyLabel;
static NSData* partnerSecretData;
static NSData* partnerHashData;

static NSString* ownEmailAddress;

static NSString* ownDeviceUUID;
static NSString* ownSyncKeyLabel;
static NSData* ownSecretData;
static NSData* ownHashData;



@interface DeviceConnectionHelper()

@property MynigmaKeyManager* keyManager;

@property id<DeviceConnectionDelegate> delegate;

@property MynigmaEncryptionEngine* engine;

@end




@interface MynigmaEncryptionEngine()

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context;

@end



@implementation DeviceConnectionHelper


#pragma mark - SHARED INSTANCE

+ (DeviceConnectionHelper*)sharedInstance
{
    static dispatch_once_t p = 0;
    
    __strong static id sharedObject = nil;
    
    dispatch_once(&p, ^{
        sharedObject = [DeviceConnectionHelper new];
    });
    
    return sharedObject;
}




#pragma mark - KEY GENERATION

+ (dispatch_group_t)keyGenerationGroup
{
    static dispatch_group_t _keyGenerationDispatchGroup = NULL;
    
    if(!_keyGenerationDispatchGroup)
        _keyGenerationDispatchGroup = dispatch_group_create();
    
    return _keyGenerationDispatchGroup;
    
}

- (void)ensureDeviceKeyGenerated
{
    NSString* deviceUUID = [self.keyManager currentDeviceUUID];
    
    static dispatch_once_t p = 0;
    
    //don't generate more than one key
    dispatch_once(&p, ^{
        
        dispatch_group_enter([DeviceConnectionHelper keyGenerationGroup]);
        
        //check if a key has already been generated
        if([self.keyManager haveCurrentKeyForDeviceWithUUID:deviceUUID])
        {
            dispatch_group_leave([DeviceConnectionHelper keyGenerationGroup]);
        }
        else
        {
            //generate a new key and assign it to the device
            NSString* keyLabel = [NSString stringWithFormat:@"%@@mynigma.org", [NSUUID UUID].UUIDString];
            
            BOOL success = [self.keyManager generatePrivateKeyWithLabel:keyLabel];
            
            if(!success)
                NSLog(@"Failed to generate device key!!!");
            
            [self.keyManager setCurrentKeyForDeviceWithUUID:deviceUUID keyLabel:keyLabel overwrite:NO];
            
            dispatch_group_leave([DeviceConnectionHelper keyGenerationGroup]);
        }
    });
}




#pragma mark - DEVICE MESSAGE PROCESSING


- (BOOL)messageIsTargetedToThisDevice:(DeviceMessageDataStructure*)messageDataStructure
{
    NSString* ownUUID = [self.keyManager currentDeviceUUID];
    
    if(!messageDataStructure.recipientUUIDs.count || [messageDataStructure.recipientUUIDs containsObject:ownUUID])
        return YES;
    
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Not processing device message not targeted at this device: %@\nTargets: %@\nThis device: %@", messageDataStructure.messageCommand, messageDataStructure.recipientUUIDs, ownUUID);
    }
    
    return NO;
}


- (BOOL)messageIsRecent:(DeviceMessageDataStructure*)messageDataStructure
{
    NSDate* expiryDate = messageDataStructure.expiryDate;
    
    if(expiryDate && [[NSDate date] compare:expiryDate] != NSOrderedAscending)
    {
        //the message has expired
        if(VERBOSE_TRUST_ESTABLISHMENT)
        {
            NSLog(@"Not processing expired device message: %@", messageDataStructure.messageCommand);
        }
        
        return NO;
    }
    
    return YES;
}




#pragma mark Generic

- (void)processDeviceMessageWithDownloadedData:(NSData*)downloadedData inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL toBeDeleted))callback
{
    DeviceMessageDataStructure* messageDataStructure = [DeviceMessageDataStructure deserialiseData:downloadedData];
    
    //first check if the message is targeted at this device
    
    //this has already been done in populateMessage: to determine whether the download is urgent
    //however, here we are parsing the actual payload
    //and the purpose is different, too:
    //we are determining whether the message should be processed
    if(![self messageIsTargetedToThisDevice:messageDataStructure])
    {
        //not targeted to this device, so no need to do anything
        if(callback)
            callback(NO);
        
        return;
    }
    
    //OK, we are the intended recipient
    //proceed
    
    //check that the message hasn't expired
    if([self messageIsRecent:messageDataStructure])
    {
        //the message has expired
        if([DeviceConnectionHelper isEstablishingTrustInThreadWithID:messageDataStructure.threadID])
            [DeviceConnectionHelper stopTrustEstablishment];
        
        if(callback)
            callback(YES);
        
        return;
    }
    
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Processing device message: %@", messageDataStructure.messageCommand);
    }
    
    //this will kick off the generation of a device synchronisation key pair, if necessary
    [self ensureDeviceKeyGenerated];
    
    //don't start processing the messages before a key has been generated
    dispatch_group_notify([DeviceConnectionHelper keyGenerationGroup], dispatch_get_main_queue(), ^{
        
        
        //process the message
        NSString* messageCommand = messageDataStructure.messageCommand;
        
        if([messageCommand isEqual:SYNC_DATA])
        {
            [self processSyncDataMessageWithPayload:messageDataStructure.payload fromDeviceWithUUID:messageDataStructure.senderUUID inAccountWithEmailAddress:emailAddress withCallback:^(BOOL successfullyProcessed){
                
                if(callback)
                    callback(messageDataStructure.burnAfterReading);
            }];
        }
        else if([messageCommand isEqual:DEVICE_DISCOVERY])
        {
            [self processDeviceDiscoveryMessageWithPayload:messageDataStructure.payload andDate:messageDataStructure.sentDate inAccountWithEmailAddress:emailAddress withCallback:^(BOOL successfullyProcessed){
                
                if(callback)
                    callback(messageDataStructure.burnAfterReading);
            }];
        }
        else if([messageCommand isEqual:ANNOUNCE_INFO])
        {
            //these messages require trust establishment already in progress
            NSString* threadID = messageDataStructure.threadID;
            
            if(![DeviceConnectionHelper isEstablishingTrustInThreadWithID:threadID])
            {
                NSLog(@"Not establishing trust in this thread!");
                if(callback)
                    callback(messageDataStructure.burnAfterReading);
                return;
            }

            
            [self processAnnounceInfoMessageWithPayload:messageDataStructure.payload threadID:messageDataStructure.threadID senderUUID:messageDataStructure.senderUUID trustInitiationDate:messageDataStructure.sentDate inAccountWithEmailAddress:emailAddress withCallback:^(BOOL successfullyProcessed){
                
                //                if(!successfullyProcessed)
                //                    [DeviceConnectionHelper stopTrustEstablishment];
                
                if(callback)
                    callback(messageDataStructure.burnAfterReading);
            }];
        }
        else
        {
            //these messages require trust establishment already in progress
            NSString* threadID = messageDataStructure.threadID;
            
            if(![DeviceConnectionHelper isEstablishingTrustInThreadWithID:threadID])
            {
                NSLog(@"Not establishing trust in this thread!");
                if(callback)
                    callback(messageDataStructure.burnAfterReading);
                return;
            }
            
            if([messageCommand isEqual:ACK_ANNOUNCE_INFO])
            {
                [self processAnnounceInfoMessageWithPayload:messageDataStructure.payload threadID:messageDataStructure.threadID senderUUID:messageDataStructure.senderUUID trustInitiationDate:messageDataStructure.sentDate inAccountWithEmailAddress:emailAddress withCallback:^(BOOL successfullyProcessed){
                    
                    if(!successfullyProcessed)
                        [DeviceConnectionHelper stopTrustEstablishment];
                    
                    if(callback)
                        callback(messageDataStructure.burnAfterReading);
                }];
            }
            else if([messageCommand isEqual:CONFIRM_CONNECTION])
            {
                [self processConfirmConnectionMessageWithPayload:messageDataStructure.payload threadID:messageDataStructure.threadID withCallback:^(BOOL successfullyProcessed){
                    
                    if(!successfullyProcessed)
                        [DeviceConnectionHelper stopTrustEstablishment];
                    
                    if(callback)
                        callback(messageDataStructure.burnAfterReading);
                }];
            }
            else if([messageCommand isEqual:ACK_CONFIRM_CONNECTION])
            {
                [self processConfirmConnectionMessageWithPayload:messageDataStructure.payload threadID:messageDataStructure.threadID withCallback:^(BOOL successfullyProcessed){
                    
                    if(!successfullyProcessed)
                        [DeviceConnectionHelper stopTrustEstablishment];
                    
                    if(callback)
                        callback(messageDataStructure.burnAfterReading);
                }];
            }
        }
    });
}



#pragma mark Specific

- (void)processDeviceDiscoveryMessageWithPayload:(NSData*)payload andDate:(NSDate*)date inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL successfullyProcessed))callback
{
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Processing device discovery message");
    }
    
    DeviceDiscoveryPayloadDataStructure* newStructure = [DeviceDiscoveryPayloadDataStructure deserialiseData:payload];
    
    if(!newStructure.UUID)
    {
        NSLog(@"Unable to unwrap device discovery data: no UUID!");
        if(callback)
            callback(NO);
        
        return;
    }
    
    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext)
     {
         [self addDeviceFromDiscoveryPayload:newStructure inContext:localContext];
         
         if([newStructure.UUID isEqual:[self.keyManager currentDeviceUUID]])
         {
             //no need to parse any data concerning the current device(!)
             //we already know the info and don't want an attacker to be able to change it...
             if(callback)
                 callback(NO);
             
             return;
         }
         
         MynigmaDevice* device = [self.keyManager deviceWithUUID:newStructure.UUID addIfNotFound:YES inContext:localContext];
         
         BOOL deviceisNew = (device.lastUpdatedInfo == nil);
         
         if(device.lastUpdatedInfo && [device.lastUpdatedInfo compare:date]!=NSOrderedAscending)
         {
             //the device info being processed is no more recent than the one in the store - abort
             if(callback)
                 callback(NO);
             
             return;
         }
         
         [device setLastUpdatedInfo:[NSDate date]];
         
         if(newStructure.name)
             [device setDisplayName:newStructure.name];
         
         if(newStructure.type)
             [device setType:newStructure.type];
         
         BOOL currentlyEstablishingTrust = [DeviceConnectionHelper isEstablishingTrust];
         
         if(deviceisNew && !currentlyEstablishingTrust)
             [self.delegate informUserAboutNewlyDiscoveredDeviceWithUUID:device.deviceUUID displayName:device.displayName type:device.type OSIdentifier:device.operatingSystemIdentifier withCallback:^(BOOL confirmed) {
                 
                 
             }];
         
         if(callback)
             callback(YES);
     }];
}

- (void)processAnnounceInfoMessageWithPayload:(NSData*)payloadData threadID:(NSString*)threadID senderUUID:(NSString*)senderUUID trustInitiationDate:(NSDate*)initiationDate inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL successfullyProcessed))callback
{
    AnnounceInfoPayloadDataStructure* payload = [AnnounceInfoPayloadDataStructure deserialiseData:payloadData];
    
    if(!payload.keyLabel.length)
    {
        if(VERBOSE_TRUST_ESTABLISHMENT)
        {
            NSLog(@"Not processing announce info message; invalid payload: %@", payloadData);
        }
        if(callback)
            callback(NO);
        
        return;
    }
    
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Processing announce info message");
    }
    
    //add the device with name, type, etc. - if necessary
    DeviceDiscoveryPayloadDataStructure* discoveryPayload = [DeviceDiscoveryPayloadDataStructure deserialiseData:payload.deviceDiscoveryPayloadData];
    
    [self addDeviceFromDiscoveryPayload:discoveryPayload inContext:MAIN_CONTEXT];
    
    if(![DeviceConnectionHelper startEstablishingTrustInThreadID:threadID inAccountWithEmailAddress:emailAddress withDate:initiationDate deviceUUID:senderUUID])
    {
        NSLog(@"Already establishing trust in another thread!");
        if(callback)
            callback(NO);
        
        return;
    }
    
    //ask user to confirm connection
    [self.delegate askUserToConfirmConnectionToDeviceWithUUID:discoveryPayload.UUID displayName:discoveryPayload.name type:discoveryPayload.type OSIdentifier:discoveryPayload.OSIdentifier withCallback:^(BOOL confirmed)
     {
         if(!confirmed)
         {
             if(VERBOSE_TRUST_ESTABLISHMENT)
             {
                 NSLog(@"User cancelled device connection");
             }
             
             [DeviceConnectionHelper stopTrustEstablishment];
             
             if(callback)
                 callback(NO);
             
             return;
         }
         
         [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext)
          {
              
              ownEmailAddress = emailAddress;
              
              partnerDeviceUUID = senderUUID;
              
              if(!payload.keyLabel.length)
              {
                  //zero length key labels are unacceptable
                  if(VERBOSE_TRUST_ESTABLISHMENT)
                  {
                      NSLog(@"Stopped processing device message: zero length key label");
                  }
                  [DeviceConnectionHelper stopTrustEstablishment];
                  
                  if(callback)
                      callback(NO);
                  
                  return;
              }
              
              
              PublicKeyData* publicKeyData = [[PublicKeyData alloc] initWithKeyLabel:payload.keyLabel encData:payload.publicKeyEncData verData:payload.publicKeyVerData];
              
              
              if(![self.keyManager addPublicKeyWithData:publicKeyData])
              {
                  if(VERBOSE_TRUST_ESTABLISHMENT)
                  {
                      NSLog(@"Stopped processing device message: couldn't add key");
                  }
                  [DeviceConnectionHelper stopTrustEstablishment];
                  if(callback)
                      callback(NO);
                  return;
              }
              
              if([partnerDeviceUUID isEqualToString:[self.keyManager currentDeviceUUID]])
              {
                  if(VERBOSE_TRUST_ESTABLISHMENT)
                  {
                      NSLog(@"Stopped processing device message: partner device is same as current");
                  }
                  [DeviceConnectionHelper stopTrustEstablishment];
                  if(callback)
                      callback(NO);
                  return;
              }
              
              if(![self.keyManager setCurrentKeyForDeviceWithUUID:partnerDeviceUUID keyLabel:payload.keyLabel overwrite:NO])
              {
                  if(VERBOSE_TRUST_ESTABLISHMENT)
                  {
                      NSLog(@"Stopped processing device message: failed to set current key for partner device");
                  }
                  [DeviceConnectionHelper stopTrustEstablishment];
                  if(callback)
                      callback(NO);
                  return;
              }
             
              
              partnerSyncKeyLabel = payload.keyLabel;
              
              partnerHashData = payload.hashData;
              
              
              
              //this is the current device
              NSString* syncKeyLabel = [self.keyManager currentKeyLabelForDeviceWithUUID:[self.keyManager currentDeviceUUID]];
              
              if(!syncKeyLabel)
              {
                  if(VERBOSE_TRUST_ESTABLISHMENT)
                  {
                      NSLog(@"Stopped processing device message: no own sync key label");
                  }
                  [DeviceConnectionHelper stopTrustEstablishment];
                  if(callback)
                      callback(NO);
                  return;
              }
              
              ownSyncKeyLabel = syncKeyLabel;
              
              [self generateOwnSecretAndHashData];

              //respond with the next message in the protocol
              
              AnnounceInfoPayloadDataStructure* newPayload = [[AnnounceInfoPayloadDataStructure alloc] initWithPublicKeyLabel:ownSyncKeyLabel encData:publicKeyData.publicKeyEncData verData:publicKeyData.publicKeyVerData hashData:ownHashData deviceDiscoveryPayloadData:[self deviceDiscoveryPayloadDataInContext:localContext] version:MYNIGMA_VERSION];
              
              
              DeviceMessageDataStructure* deviceMessageDataStructure = [[DeviceMessageDataStructure alloc] initWithMessageCommand:ACK_ANNOUNCE_INFO payload:newPayload.serialisedData sentDate:[NSDate date] expiryDate:[[NSDate date] dateByAddingTimeInterval:EXPIRY_INTERVAL_IN_SECS] burnAfterReading:YES threadID:threadID senderUUID:ownDeviceUUID recipientUUIDs:@[partnerDeviceUUID] version:MYNIGMA_VERSION];
              
              NSData* payloadData = deviceMessageDataStructure.serialisedData;
              
              NSData* messageData = [MimeHelper deviceMessageDataWithPayloadData:payloadData];
              
              [self.delegate postDeviceMessageWithData:messageData intoAccountWithEmailAddress:ownEmailAddress];
              
              expectedMessageCommands = [NSSet setWithObject:CONFIRM_CONNECTION];
              
              if(callback)
                  callback(YES);
          }];
     }];
}


- (void)processAckAnnounceInfoMessageWithPayload:(NSData*)payloadData threadID:(NSString*)threadID senderUUID:(NSString*)senderUUID trustInitiationDate:(NSDate*)initiationDate inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL successfullyProcessed))callback
{
    AnnounceInfoPayloadDataStructure* payload = [AnnounceInfoPayloadDataStructure deserialiseData:payloadData];
    
    if(!payload)
    {
        if(VERBOSE_TRUST_ESTABLISHMENT)
        {
            NSLog(@"Not processing announce info message; invalid payload: %@", payloadData);
        }
        if(callback)
            callback(NO);
        
        return;
    }
    
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Processing announce info message");
    }
    
    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {

        if(!payload.keyLabel.length)
        {
            //zero length key labels are unacceptable
            if(VERBOSE_TRUST_ESTABLISHMENT)
            {
                NSLog(@"Stopped processing device message: zero length key label");
            }
            [DeviceConnectionHelper stopTrustEstablishment];
            
            if(callback)
                callback(NO);
            
            return;
        }
        
        
        PublicKeyData* publicKeyData = [[PublicKeyData alloc] initWithKeyLabel:payload.keyLabel encData:payload.publicKeyEncData verData:payload.publicKeyVerData];
        
        
        if(![self.keyManager addPublicKeyWithData:publicKeyData])
        {
            if(VERBOSE_TRUST_ESTABLISHMENT)
            {
                NSLog(@"Stopped processing device message: couldn't add key");
            }
            [DeviceConnectionHelper stopTrustEstablishment];
            if(callback)
                callback(NO);
            return;
        }
        
        if([partnerDeviceUUID isEqualToString:[self.keyManager currentDeviceUUID]])
        {
            if(VERBOSE_TRUST_ESTABLISHMENT)
            {
                NSLog(@"Stopped processing device message: partner device is same as current");
            }
            [DeviceConnectionHelper stopTrustEstablishment];
            if(callback)
                callback(NO);
            return;
        }
        
        if(![self.keyManager setCurrentKeyForDeviceWithUUID:partnerDeviceUUID keyLabel:payload.keyLabel overwrite:NO])
        {
            if(VERBOSE_TRUST_ESTABLISHMENT)
            {
                NSLog(@"Stopped processing device message: failed to set current key for partner device");
            }
            [DeviceConnectionHelper stopTrustEstablishment];
            if(callback)
                callback(NO);
            return;
        }
        

        
        partnerSyncKeyLabel = payload.keyLabel;
        partnerHashData = payload.hashData;
        
        
        //respond with the next message in the protocol
        
        ConfirmConnectionPayloadDataStructure* payloadDataStructure = [[ConfirmConnectionPayloadDataStructure alloc] initWithSecretKeyData:ownSecretData version:MYNIGMA_VERSION];
        
        DeviceMessageDataStructure* deviceMessageDataStructure = [[DeviceMessageDataStructure alloc] initWithMessageCommand:CONFIRM_CONNECTION payload:payloadDataStructure.serialisedData sentDate:[NSDate date] expiryDate:[[NSDate date] dateByAddingTimeInterval:EXPIRY_INTERVAL_IN_SECS] burnAfterReading:YES threadID:threadID senderUUID:ownDeviceUUID recipientUUIDs:@[partnerDeviceUUID] version:MYNIGMA_VERSION];
        
        NSData* payloadData = deviceMessageDataStructure.serialisedData;
        
        NSData* messageData = [MimeHelper deviceMessageDataWithPayloadData:payloadData];
        
        [self.delegate postDeviceMessageWithData:messageData intoAccountWithEmailAddress:ownEmailAddress];
        
        expectedMessageCommands = [NSSet setWithObject:ACK_CONFIRM_CONNECTION];
        
        if(callback)
            callback(YES);
    }];
}

- (void)processConfirmConnectionMessageWithPayload:(NSData*)payloadData threadID:(NSString*)threadID withCallback:(void(^)(BOOL successfullyProcessed))callback
{
    ConfirmConnectionPayloadDataStructure* payload = [ConfirmConnectionPayloadDataStructure deserialiseData:payloadData];
    
    if(!payload)
    {
        if(VERBOSE_TRUST_ESTABLISHMENT)
        {
            NSLog(@"Not processing confirm connection message; invalid payload: %@", payloadData);
        }
        
        if(callback)
            callback(NO);
        
        return;
    }
    
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Processing confirm connection message");
    }
    
    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
        
        if([payload.secretKeyData length] == 64)
            partnerSecretData = payload.secretKeyData;
        
        if(![self partnerHashCorrect])
        {
            NSLog(@"Invalid hash computed!!!");
            [DeviceConnectionHelper stopTrustEstablishment];
            if(callback)
                callback(NO);
            return;
        }
        
        if(![self haveCompleteData])
        {
            NSLog(@"Incomplete data!!!");
            [DeviceConnectionHelper stopTrustEstablishment];
            if(callback)
                callback(NO);
            return;
        }
        
        
        NSArray* shortDigestChunks = [self shortDigestChunksAsInitiator:NO];
        
        [ThreadHelper runAsyncOnMain:^{
            
            [self.delegate showDigestChunks:shortDigestChunks withCallback:^(BOOL userConfirmed)
            {
                
            }];
        }];
        
        
        //respond with the next message in the protocol - it's a confirm connection response
        ConfirmConnectionPayloadDataStructure* payloadDataStructure = [[ConfirmConnectionPayloadDataStructure alloc] initWithSecretKeyData:ownSecretData version:MYNIGMA_VERSION];
        
        DeviceMessageDataStructure* deviceMessageDataStructure = [[DeviceMessageDataStructure alloc] initWithMessageCommand:ACK_CONFIRM_CONNECTION payload:payloadDataStructure.serialisedData sentDate:[NSDate date] expiryDate:[[NSDate date] dateByAddingTimeInterval:EXPIRY_INTERVAL_IN_SECS] burnAfterReading:YES threadID:threadID senderUUID:ownDeviceUUID recipientUUIDs:@[partnerDeviceUUID] version:MYNIGMA_VERSION];
        
        NSData* payloadData = deviceMessageDataStructure.serialisedData;
        
        NSData* messageData = [MimeHelper deviceMessageDataWithPayloadData:payloadData];
        
        [self.delegate postDeviceMessageWithData:messageData intoAccountWithEmailAddress:ownEmailAddress];
        
        expectedMessageCommands = [NSSet set];
        
        if(callback)
            callback(YES);
    }];
}

- (void)processAckConfirmConnectionMessageWithPayload:(NSData*)payloadData threadID:(NSString*)threadID withCallback:(void(^)(BOOL successfullyProcessed))callback
{
    ConfirmConnectionPayloadDataStructure* payload = [ConfirmConnectionPayloadDataStructure deserialiseData:payloadData];
    
    if(!payload)
    {
        if(VERBOSE_TRUST_ESTABLISHMENT)
        {
            NSLog(@"Not processing confirm connection message; invalid payload: %@", payloadData);
        }
        
        if(callback)
            callback(NO);
        
        return;
    }
    
    if(VERBOSE_TRUST_ESTABLISHMENT)
    {
        NSLog(@"Processing confirm connection message");
    }
    
    partnerSecretData = payload.secretKeyData;
    
    if(![self partnerHashCorrect])
    {
        NSLog(@"Invalid hash computed!!!");
        [DeviceConnectionHelper stopTrustEstablishment];
        if(callback)
            callback(NO);
        return;
    }
    
    if(![self haveCompleteData])
    {
        NSLog(@"Incomplete data!!!");
        [DeviceConnectionHelper stopTrustEstablishment];
        if(callback)
            callback(NO);
        return;
    }
    
    NSArray* shortDigestChunks = [self shortDigestChunksAsInitiator:YES];
    
    [ThreadHelper runAsyncOnMain:^{
        
        [self.delegate showDigestChunks:shortDigestChunks withCallback:^(BOOL userConfirmed)
        {
            
        }];
    }];
    
    expectedMessageCommands = [NSSet set];
    
    if(callback)
        callback(YES);
}

- (void)processSyncDataMessageWithPayload:(NSData*)payloadData fromDeviceWithUUID:(NSString*)deviceUUID inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL successfullyProcessed))callback
{
    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext)
    {
        MynigmaMessageEncryptionContext* context = [MynigmaMessageEncryptionContext contextForDecryptedDeviceMessageWithPayload:payloadData];

        [self.engine decryptMessage:context];
        
         NSData* decryptedData = context.decryptedData;
         
         if(!decryptedData)
             return;
         
         SignedDataStructure* signedDataStructure = [SignedDataStructure deserialiseData:decryptedData];
        
        NSData* hashedData = [self.engine.basicEngine SHA512DigestOfData:signedDataStructure.dataToBeSigned];
        
         BOOL validSignature = [self.engine.basicEngine RSAVerifySignature:signedDataStructure.signature ofHash:hashedData withPSSPadding:NO withKeyLabel:signedDataStructure.keyLabel error:nil];
         
         if(!validSignature)
             return;
         
         //finally, we need to make sure the device is trusted and everything else is oojah-cum-spiff
         MynigmaDevice* device = [self.keyManager deviceWithUUID:deviceUUID addIfNotFound:NO inContext:localContext];
         
         if(!device.syncKey.keyLabel)
             return;
         
         if(!device.isTrusted.boolValue)
             return;
         
         if(![signedDataStructure.keyLabel isEqualToString:device.syncKey.keyLabel])
             return;
         
         //OK, the signature is valid
         //the data was signed with the correct key
         //the device is trusted
         //let's import it!
        
        [[BackupHelper sharedInstance] importBackupData:signedDataStructure.dataToBeSigned password:nil inContext:localContext withCallback:^(NSError *error)
        {
            if(callback)
                callback(error!=nil);
        }];
     }];
}



#pragma mark - STARTING A THREAD

- (void)initiateTrustEstablishmentWithDeviceUUID:(NSString*)partnerDeviceUUID inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL))callback
{
    if(!partnerDeviceUUID)
    {
        NSLog(@"Cannot initialise a thread of the partner device has no UUID!!");
    }
    
    //generate a new threadID
    NSString* threadID = [@"thread@threadID.com" generateMessageID];
    
    NSDate* trustInitiationDate = [NSDate date];
    
    if(![DeviceConnectionHelper startEstablishingTrustInThreadID:threadID inAccountWithEmailAddress:emailAddress withDate:trustInitiationDate deviceUUID:partnerDeviceUUID])
    {
        NSLog(@"Already establishing trust in another thread!");
        return;
    }
    
    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
     
        NSString* email = emailAddress;
        
        if(!email)
        {
            MynigmaDevice* partnerDevice = [self.keyManager deviceWithUUID:partnerDeviceUUID addIfNotFound:NO inContext:localContext];
            
            if(!partnerDevice.usedByAccounts.count)
            {
                NSLog(@"Partner device is using no accounts, apparently...");
            }
            
            email = partnerDevice.usedByAccounts.anyObject;
        }
        
        ownEmailAddress = email;
        
        if(!email)
        {
            NSLog(@"Cannot start a thread without an account!!");
            [DeviceConnectionHelper stopTrustEstablishment];
            return;
        }
        
        
        //this is the current device
        NSString* syncKeyLabel = [self.keyManager currentKeyLabelForDeviceWithUUID:[self.keyManager currentDeviceUUID]];
        
        if(!syncKeyLabel)
        {
            NSLog(@"Cannot sync without key label");
            [DeviceConnectionHelper stopTrustEstablishment];
            return;
        }
        
        ownSyncKeyLabel = syncKeyLabel;
        ownDeviceUUID = [self.keyManager currentDeviceUUID];
        
        PublicKeyData* publicKeyData = [self.keyManager dataForPublicKeyWithLabel:ownSyncKeyLabel];
        
        AnnounceInfoPayloadDataStructure* newPayload = [[AnnounceInfoPayloadDataStructure alloc] initWithPublicKeyLabel:ownSyncKeyLabel encData:publicKeyData.publicKeyEncData verData:publicKeyData.publicKeyVerData hashData:ownHashData deviceDiscoveryPayloadData:[self deviceDiscoveryPayloadDataInContext:localContext] version:MYNIGMA_VERSION];

        DeviceMessageDataStructure* deviceMessageDataStructure = [[DeviceMessageDataStructure alloc] initWithMessageCommand:ANNOUNCE_INFO payload:newPayload.serialisedData sentDate:trustInitiationDate expiryDate:[[NSDate date] dateByAddingTimeInterval:EXPIRY_INTERVAL_IN_SECS] burnAfterReading:YES threadID:threadID senderUUID:ownDeviceUUID recipientUUIDs:@[partnerDeviceUUID] version:MYNIGMA_VERSION];
        
        NSData* payloadData = deviceMessageDataStructure.serialisedData;
        
        NSData* messageData = [MimeHelper deviceMessageDataWithPayloadData:payloadData];
        
        [self.delegate postDeviceMessageWithData:messageData intoAccountWithEmailAddress:ownEmailAddress];
        
        expectedMessageCommands = [NSSet setWithObject:ACK_ANNOUNCE_INFO];
        
        if(callback)
            callback(YES);
    }];
}




#pragma mark - DEVICE DISCOVERY PAYLOAD

- (void)addDeviceFromDiscoveryPayload:(DeviceDiscoveryPayloadDataStructure*)deviceDiscoveryPayload inContext:(NSManagedObjectContext*)localContext
{
    NSString* UUID = deviceDiscoveryPayload.UUID;
    NSString* type = deviceDiscoveryPayload.type;
    NSString* name = deviceDiscoveryPayload.name;
    NSString* OSIdentifier = deviceDiscoveryPayload.OSIdentifier;
    
    if(UUID && name && type)
    {
        MynigmaDevice* device = [self.keyManager deviceWithUUID:UUID addIfNotFound:YES inContext:localContext];
        
        if(!device.displayName)
            [device setDisplayName:name];
        
        if(!device.type)
            [device setType:type];
        
        if(!device.operatingSystemIdentifier)
            [device setOperatingSystemIdentifier:OSIdentifier];
        
        [localContext save:nil];
    }
}

- (NSData*)deviceDiscoveryPayloadDataInContext:(NSManagedObjectContext*)localContext
{
    DeviceDiscoveryPayloadDataStructure* newStructure = [DeviceDiscoveryPayloadDataStructure new];
    
    MynigmaDevice* currentDevice = [self.keyManager deviceWithUUID:[self.keyManager currentDeviceUUID] addIfNotFound:NO inContext:localContext];
    
    [newStructure setUUID:[self.keyManager currentDeviceUUID]];
    [newStructure setName:currentDevice.displayName];
    
    [newStructure setEmailAddresses:[self.delegate usersEmailAddresses]];
    
    [newStructure setOSIdentifier:currentDevice.operatingSystemIdentifier];
    
    NSMutableArray* newPrivateKeys = [NSMutableArray new];
    
    for(NSString* privateKeyLabel in [self.keyManager listAllPrivateKeyLabels])
    {
        [newPrivateKeys addObject:privateKeyLabel];
    }
    
    [newStructure setPrivateKeyLabels:newPrivateKeys];
    
    [newStructure setType:currentDevice.type];
    [newStructure setVersion:MYNIGMA_VERSION];
    
    return newStructure.serialisedData;
}





#pragma mark - POSTING MESSAGES

//- (void)postDeviceDiscoveryAndSyncDataMessages
//{
//    //first remove any previous, unused device discovery messages
//    NSArray* allDeviceMessages = [DeviceMessage listAllDeviceMessagesInContext:MAIN_CONTEXT];
//    
//    for(DeviceMessage* deviceMessage in allDeviceMessages)
//    {
//        //remove any unnecessary device messages
//        if([deviceMessage.messageCommand isEqual:@"DEVICE_DISCOVERY"])
//        {
//            //is the message associated with this device?
//            if(![deviceMessage.sender isEqual:[MynigmaDevice currentDevice]])
//                continue;
//            
//            //is it obsolete?
//            if(deviceMessage.discoveryMessageForDevice)
//                continue;
//            
//            //remove all instances!
//            NSSet* allInstances = [NSSet setWithSet:deviceMessage.instances];
//            for(EmailMessageInstance* messageInstance in allInstances)
//            {
//                [messageInstance deleteInstance];
//            }
//        }
//        else if([deviceMessage.messageCommand isEqual:@"SYNC_DATA"])
//        {
//            //is the message actually associated with this device?
//            if(![deviceMessage.sender isEqual:[MynigmaDevice currentDevice]])
//                continue;
//            
//            //is it the current message?
//            if(deviceMessage.dataSyncMessageForDevice)
//                continue;
//            
//            //remove all instances!
//            NSSet* allInstances = [NSSet setWithSet:deviceMessage.instances];
//            for(EmailMessageInstance* messageInstance in allInstances)
//            {
//                [messageInstance deleteInstance];
//            }
//        }
//    }
//    
//    //go through the accounts and ensure that the current device discovery message instance is present in each account
//    for(IMAPAccountSetting* accountSetting in [UserSettings currentUserSettings].accounts)
//        if(accountSetting.shouldUse.boolValue)
//        {
//            BOOL haveDeviceMessageForThisAccount = NO;
//            
//            for(EmailMessageInstance* messageInstance in [MynigmaDevice currentDevice].discoveryMessage.instances)
//            {
//                if([messageInstance.accountSetting isEqual:accountSetting] && !messageInstance.deletedFromFolder)
//                    haveDeviceMessageForThisAccount = YES;
//            }
//            
//            if(!haveDeviceMessageForThisAccount)
//            {
//                //no device message instance present
//                //add one!
//                [DeviceConnectionHelper postDeviceDiscoveryMessageWithAccountSetting:accountSetting];
//            }
//            
//            
//            //only post the sync data if there is a paired device
//            BOOL needToPostSyncData = [MynigmaDevice haveTrustedDevices];
//            
//            if(needToPostSyncData)
//            {
//                NSManagedObjectID* accountSettingObjectID = accountSetting.objectID;
//                
//                //This may be nil if no sync data message has been created yet
//                [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
//                    
//                    DeviceMessage* syncDataMessage = [DeviceMessage syncDataMessageFromDevice:[MynigmaDevice currentDeviceInContext:localContext] inContext:localContext];
//                    
//                    [localContext save:nil];
//                    
//                    IMAPAccountSetting* accountSetting = (IMAPAccountSetting*)[localContext objectWithID:accountSettingObjectID];
//                    
//                    BOOL haveSyncDataMessageInstanceForThisAccount = NO;
//                    
//                    for(EmailMessageInstance* messageInstance in syncDataMessage.instances)
//                    {
//                        if([messageInstance.accountSetting isEqual:accountSetting] && !messageInstance.deletedFromFolder)
//                            haveSyncDataMessageInstanceForThisAccount = YES;
//                    }
//                    if(!haveSyncDataMessageInstanceForThisAccount)
//                    {
//                        //no device message instance present
//                        //add one!
//                        [DeviceConnectionHelper postSyncDataMessageWithAccountSetting:accountSetting];
//                    }
//                }];
//            }
//        }
//}
//
//+ (void)postDeviceDiscoveryMessageWithAccountSetting:(IMAPAccountSetting*)accountSetting
//{
//    NSManagedObjectID* mainAccountSettingObjectID = accountSetting.objectID;
//    
//    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
//        
//        IMAPAccountSetting* localAccountSetting = (IMAPAccountSetting*)[localContext existingObjectWithID:mainAccountSettingObjectID error:nil];
//        
//        MynigmaDevice* currentDevice = [MynigmaDevice currentDeviceInContext:localContext];
//        
//        DeviceMessage* discoveryMessage = currentDevice.discoveryMessage;
//        
//        if(discoveryMessage)
//        {
//            //return if the message has already been posted to this account
//            if([[discoveryMessage.instances valueForKeyPath:@"inFolder.inIMAPAccount"] containsObject:accountSetting])
//                return;
//        }
//        else
//        {
//            discoveryMessage = [DeviceMessage deviceDiscoveryMessageInContext:localContext];
//            
//            if(discoveryMessage)
//                [currentDevice setDiscoveryMessage:discoveryMessage];
//        }
//        
//        if(discoveryMessage)
//            [DeviceConnectionHelper postDeviceMessage:discoveryMessage intoAccountSetting:localAccountSetting inContext:localContext];
//        
//        [localContext save:nil];
//        
//        if(localAccountSetting.spamFolder)
//            [MergeLocalChangesHelper mergeDeviceMessagesForAccount:localAccountSetting.account inFolder:localAccountSetting.spamFolder];
//    }];
//}
//
//+ (void)postSyncDataMessageWithAccountSetting:(IMAPAccountSetting*)accountSetting
//{
//    NSManagedObjectID* mainAccountSettingObjectID = accountSetting.objectID;
//    
//    [ThreadHelper runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
//        
//        IMAPAccountSetting* localAccountSetting = (IMAPAccountSetting*)[localContext existingObjectWithID:mainAccountSettingObjectID error:nil];
//        
//        MynigmaDevice* currentDevice = [MynigmaDevice currentDeviceInContext:localContext];
//        
//        DeviceMessage* dataSyncMessage = [DeviceMessage syncDataMessageFromDevice:currentDevice inContext:localContext];
//        
//        [DeviceConnectionHelper postDeviceMessage:dataSyncMessage intoAccountSetting:localAccountSetting inContext:localContext];
//    }];
//}
//
//+ (void)postDeviceMessage:(DeviceMessage*)deviceMessage inThread:(TrustEstablishmentThread*)thread inContext:(NSManagedObjectContext*)localContext
//{
//    NSManagedObjectID* mainDeviceMessageObjectID = deviceMessage.objectID;
//    NSManagedObjectID* mainAccountSettingObjectID = thread.accountSettingObjectID;
//    
//    IMAPAccountSetting* localAccountSetting = (IMAPAccountSetting*)[localContext existingObjectWithID:mainAccountSettingObjectID error:nil];
//    
//    DeviceMessage* localDeviceMessage = (DeviceMessage*)[DeviceMessage messageWithObjectID:mainDeviceMessageObjectID inContext:localContext];
//    
//    [DeviceConnectionHelper postDeviceMessage:localDeviceMessage intoAccountSetting:localAccountSetting inContext:localContext];
//    
//    [MergeLocalChangesHelper mergeDeviceMessagesForAccount:localAccountSetting.account inFolder:localAccountSetting.mynigmaFolder];
//}
//
//+ (void)postDeviceMessage:(DeviceMessage*)deviceMessage intoAccountSetting:(IMAPAccountSetting*)accountSetting inContext:(NSManagedObjectContext*)localContext
//{
//    [ThreadHelper ensureLocalThread:localContext];
//    
//    BOOL alreadyFoundOne = NO;
//    
//    IMAPFolderSetting* folderSetting = accountSetting.mynigmaFolder;
//    
//    EmailMessageInstance* newInstance = [EmailMessageInstance findOrMakeNewInstanceForMessage:deviceMessage inFolder:folderSetting alreadyFoundOne:&alreadyFoundOne];
//    
//    if(alreadyFoundOne)
//        return;
//    
//    [newInstance setAddedToFolder:newInstance.inFolder];
//    
//    [newInstance setFlags:@(MCOMessageFlagSeen)];
//    
//    NSError* error = nil;
//    [localContext save:&error];
//    if(error)
//        NSLog(@"Error saving temporary context after posting device messages: %@",error);
//}
//
//+ (void)postDeviceMessageIntoAllAccounts:(DeviceMessage*)deviceMessage
//{
//    NSManagedObjectContext* localContext = deviceMessage.managedObjectContext;
//    
//    for(IMAPAccountSetting* accountSetting in [UserSettings usedAccountsInContext:localContext])
//    {
//        [DeviceConnectionHelper postDeviceMessage:deviceMessage intoAccountSetting:accountSetting inContext:localContext];
//    }
//}
//


#pragma mark - Trust establishment

+ (BOOL)startEstablishingTrustInThreadID:(NSString*)threadID inAccountWithEmailAddress:(NSString*)emailAddress withDate:(NSDate*)initiationDate deviceUUID:(NSString*)deviceUUID
{
    if(!initiationDate)
    {
        NSLog(@"No date provided for trust establishment!!");
    }
    
    if(currentThreadID)
    {
        //proceed only if the initiation date is earlier than the current one(!)
        if([currentThreadInitiationDate compare:initiationDate] == NSOrderedAscending)
            return NO;
    }
    
    ownEmailAddress = emailAddress;
    
    currentThreadID = threadID;
    currentThreadInitiationDate = initiationDate;
    partnerDeviceUUID = deviceUUID;
    
    return YES;
}

+ (BOOL)isEstablishingTrustInThreadWithID:(NSString*)threadID
{
    return [currentThreadID isEqual:threadID];
}

+ (BOOL)isEstablishingTrust
{
    return currentThreadID!=nil;
}


+ (void)stopTrustEstablishment
{
    currentThreadID = nil;
    expectedMessageCommands = nil;
    currentThreadInitiationDate = nil;
    
    partnerEmailAddress = nil;
    
    partnerDeviceUUID = nil;
    partnerSyncKeyLabel = nil;
    partnerSecretData = nil;
    partnerHashData = nil;
    
    ownEmailAddress = nil;
    
    ownDeviceUUID = nil;
    ownSyncKeyLabel = nil;
    ownSecretData = nil;
    ownHashData = nil;
}

- (void)resetAllSyncInfo
{
    [DeviceConnectionHelper stopTrustEstablishment];
    
    //now reset all device states
    [self.keyManager distrustAllDevices];
}





- (void)generateOwnSecretAndHashData
{
    if(!ownSecretData)
        ownSecretData = [self.engine.basicEngine randomBytesOfLength:64];
        
    
    //hash the secret data followed by the UUID
    NSMutableData* dataToBeHashed = [NSMutableData dataWithData:ownSecretData];
    
    [dataToBeHashed appendData:[ownDeviceUUID dataUsingEncoding:NSUTF8StringEncoding]];
    
    NSData* hashedData = [self.engine.basicEngine SHA512DigestOfData:dataToBeHashed];
    
    ownHashData = hashedData;
}

- (BOOL)partnerHashCorrect
{
    if(!partnerSecretData || !partnerDeviceUUID || !partnerHashData)
        return NO;
    
    NSMutableData* dataToBeHashed = [NSMutableData dataWithData:partnerSecretData];
    
    [dataToBeHashed appendData:[partnerDeviceUUID dataUsingEncoding:NSUTF8StringEncoding]];
    
    NSData* hashedData = [self.engine.basicEngine SHA512DigestOfData:dataToBeHashed];
    
    return [hashedData isEqual:partnerHashData];
}


- (BOOL)haveCompleteData
{
    PublicKeyData* ownKeyData = [self.keyManager dataForPublicKeyWithLabel:ownSyncKeyLabel];
    PublicKeyData* partnerKeyData = [self.keyManager dataForPublicKeyWithLabel:partnerSyncKeyLabel];
    
    return partnerSyncKeyLabel!=nil && partnerKeyData.publicKeyEncData!=nil && partnerKeyData.publicKeyVerData!=nil && partnerDeviceUUID!=nil && partnerSecretData!=nil && ownSyncKeyLabel!=nil && ownKeyData.publicKeyEncData!=nil && ownKeyData.publicKeyVerData!=nil && ownDeviceUUID && ownSecretData!=nil;
}


- (NSArray*)shortDigestChunksAsInitiator:(BOOL)initiator
{
    PublicKeyData* ownKeyData = [self.keyManager dataForPublicKeyWithLabel:ownSyncKeyLabel];
    PublicKeyData* partnerKeyData = [self.keyManager dataForPublicKeyWithLabel:partnerSyncKeyLabel];

    DigestInfoPartDataStructure* ownPart = [[DigestInfoPartDataStructure alloc] initWithSyncKeyLabel:ownSyncKeyLabel publicEncKeyData:ownKeyData.publicKeyEncData publicVerKeyData:ownKeyData.publicKeyVerData deviceUUID:ownDeviceUUID secretData:ownSecretData];
    
    DigestInfoPartDataStructure* partnerPart = [[DigestInfoPartDataStructure alloc] initWithSyncKeyLabel:partnerSyncKeyLabel publicEncKeyData:partnerKeyData.publicKeyEncData publicVerKeyData:partnerKeyData.publicKeyVerData deviceUUID:partnerDeviceUUID secretData:partnerSecretData];
    
    DigestInfoPairDataStructure* digestDataStructure = [DigestInfoPairDataStructure alloc];
    
    //for the digest chunks of both parties to match, the device's own data and its partner's data must be switched in one case
    if(initiator)
    {
        [digestDataStructure setInitiatorDataStructure:ownPart];
        [digestDataStructure setResponderDataStructure:partnerPart];
    }
    else
    {
        [digestDataStructure setInitiatorDataStructure:partnerPart];
        [digestDataStructure setResponderDataStructure:ownPart];
    }
    
    NSArray* shortDigestChunks = [self shortDigestChunksOfData:[digestDataStructure serialisedData]];
    
    return shortDigestChunks;
}

- (NSArray*)shortDigestChunksOfData:(NSData*)data
{
    NSData* sha512Digest = [self.engine.basicEngine SHA512DigestOfData:data];
    
    if(!sha512Digest)
        return nil;
    
    NSMutableArray* digestChunks = [NSMutableArray new];
    
    for(NSInteger chunkIndex = 0; chunkIndex<3; chunkIndex++)
    {
        NSInteger chunkSize = 3; //24 bits = 3 bytes = 4 base64 chars
        
        NSData* subData = [sha512Digest subdataWithRange:NSMakeRange(chunkIndex*chunkSize, chunkSize)];
        
        NSString* chunk = [subData base64];
        
        [digestChunks addObject:chunk];
    }
    
    return digestChunks;
}

@end
