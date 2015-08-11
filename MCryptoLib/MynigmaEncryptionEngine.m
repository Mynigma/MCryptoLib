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


#import "MynigmaEncryptionEngine.h"
#import "DefaultKeyManager.h"
#import "AppleEncryptionEngine.h"
#import "BasicEncryptionEngineProtocol.h"
#import "SessionKeys.h"
#import "MynigmaMessageEncryptionContext.h"
#import "PublicKeyData.h"
#import "MynigmaAttachmentEncryptionContext.h"
#import "OpenSSLEncryptionEngine.h"
#import "MynigmaErrorFactory.h"
#import "CommonHeader.h"
#import "GenericEmailMessage.h"
#import "GenericEmailAddressee.h"
#import "SessionKeyCache.h"


#import <MProtoBuf/EmailRecipientDataStructure.h>
#import <MProtoBuf/SignedDataStructure.h>
#import <MProtoBuf/KeyIntroductionDataStructure.h>
#import <MProtoBuf/SessionKeyEntryDataStructure.h>
#import <MProtoBuf/HMACDataStructure.h>
#import <MProtoBuf/EncryptedDataStructure.h>
#import <MProtoBuf/PayloadPartDataStructure.h>
#import <MProtoBuf/FileAttachmentDataStructure.h>





@interface MynigmaEncryptionEngine()


- (NSData*)introductionDataFromKeyLabel:(NSString*)oldKeyLabel toKeyLabel:(NSString*)newKeyLabel;

- (NSData*)introductionDataFromKeyLabel:(NSString*)oldKeyLabel toKeyLabel:(NSString*)newKeyLabel date:(NSDate*)date version:(NSString*)version;

- (BOOL)processIntroductionData:(NSData*)introductionData fromEmail:(NSString*)senderEmailString;




/**
 *  Encrypt a message previously loaded into the message encryption context
 *
 *  @param context The context containing the message encryption info
 *  @param error   Optional error information
 *
 *  @return YES if the operation was successful, NO otherwise
 */
- (BOOL)encryptMessage:(MynigmaMessageEncryptionContext*)context;

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context;



@end





@implementation MynigmaEncryptionEngine

+ (instancetype)sharedInstance
{
    static MynigmaEncryptionEngine* sharedInstance = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        sharedInstance = [MynigmaEncryptionEngine new];
    });
    
    return sharedInstance;
}

- (instancetype)initWithKeyManager:(MynigmaKeyManager*)keyManager basicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine
{
    self = [super init];
    if(self)
    {
        self.keyManager = keyManager;
        self.basicEngine = basicEngine;
    }
    return self;
}

- (instancetype)initWithKeyManager:(MynigmaKeyManager*)keyManager
{
    self = [super init];
    if(self)
    {
        self.keyManager = keyManager;
        self.basicEngine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:keyManager];
    }
    return self;
}

- (instancetype)initWithBasicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine
{
    self = [super init];
    if(self)
    {
        self.keyManager = [MynigmaKeyManager new];
        self.basicEngine = basicEngine;
    }
    return self;
}

- (instancetype)init
{
    self = [super init];
    if(self)
    {
        self.keyManager = [MynigmaKeyManager new];
        self.basicEngine = [AppleEncryptionEngine new];
    }
    return self;
}


#pragma mark - MEDIUM LEVEL ENCRYPTION METHODS


/**
 *  Sign a single block of data using RSA, using the current version string
 *
 *  @param data     The data to be signed
 *  @param keyLabel The keyLabel of the key to be used
 *  @param error    Optional error information
 *
 *  @return The signed data
 */
- (NSData*)signData:(NSData*)data withKeyLabel:(NSString*)keyLabel error:(NSError**)error
{
    return [self signData:data withKeyLabel:keyLabel version:MYNIGMA_VERSION error:error];
}

/**
 *  Sign a single block of data using RSA
 *
 *  @param data     The data to be signed
 *  @param keyLabel The keyLabel of the key to be used
 *  @param version  The version number determines padding
 *  @param error    Optional error information
 *
 *  @return The signed data
 */
- (NSData*)signData:(NSData*)data withKeyLabel:(NSString*)keyLabel version:(NSString*)version error:(NSError**)error
{
    if(![self.keyManager havePrivateKeyWithLabel:keyLabel])
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorNoKeyForKeyLabel];
        return nil;
    }
    
    if(!data.length)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSANoData];
        return nil;
    }
    
    NSData* hashedData = [self.basicEngine SHA512DigestOfData:data];
    
    NSData* signedDataBlob = [self.basicEngine RSASignHash:hashedData withKeyLabel:keyLabel withPSSPadding:NO error:nil];
    
    if(!signedDataBlob.length || (error && *error))
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorEmptySignedData];
        return nil;
    }
    
    SignedDataStructure* dataStructure = [[SignedDataStructure alloc] initWithDataToBeSigned:data signature:signedDataBlob keyLabel:keyLabel version:version];
    NSData* signedData = dataStructure.serialisedData;
    
    return signedData;
}

- (NSData*)verifySignedData:(SignedDataStructure*)signedDataStructure error:(NSError**)error
{
    NSString* keyLabel = signedDataStructure.keyLabel;
    
    if(!keyLabel.length)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorNoKeyLabel];
        return nil;
    }
    
    NSData* signature = signedDataStructure.signature;
    NSData* dataToBeSigned = signedDataStructure.dataToBeSigned;
    
    NSData* hashedData = [self.basicEngine SHA512DigestOfData:dataToBeSigned];
    
    
    if(![self.basicEngine RSAVerifySignature:signature ofHash:hashedData withPSSPadding:NO withKeyLabel:keyLabel error:error])
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorInvalidSignature];
        
        return nil;
    }
    
    return dataToBeSigned;
}



- (NSData*)introductionDataFromKeyLabel:(NSString*)oldKeyLabel toKeyLabel:(NSString*)newKeyLabel
{
    return [self introductionDataFromKeyLabel:oldKeyLabel toKeyLabel:newKeyLabel date:[NSDate date] version:MYNIGMA_VERSION];
}


- (NSData*)introductionDataFromKeyLabel:(NSString*)oldKeyLabel toKeyLabel:(NSString*)newKeyLabel date:(NSDate*)date version:(NSString*)version
{
    //if there is no fromLabel, that is, there is no previous key to introduce the new one with, simply sign the introduction with the introduced key
    if(!oldKeyLabel)
        oldKeyLabel = newKeyLabel;
    
    if(oldKeyLabel && newKeyLabel)
    {
        PublicKeyData* newPublicKeyData = [self.keyManager dataForPublicKeyWithLabel:newKeyLabel];
        
        if(!newPublicKeyData)
        {
            NSLog(@"Public key with label %@ has invalid data!", newKeyLabel);
            return nil;
        }
        
        KeyIntroductionDataStructure* dataStructure = [[KeyIntroductionDataStructure alloc] initWithOldKeyLabel:oldKeyLabel newKeyLabel:newPublicKeyData.keyLabel newEncData:newPublicKeyData.publicKeyEncData newVerData:newPublicKeyData.publicKeyVerData date:date version:version];
        
        // sign introduction data with old key label
        NSData* signedDataWithOldKeyLabel = [self signData:dataStructure.serialisedData withKeyLabel:oldKeyLabel version:version error:nil];
        
        
        // sign the signed introduction data with new key label
        NSData* signedDataWithNewKeyLabel = [self signData:signedDataWithOldKeyLabel withKeyLabel:newKeyLabel version:version error:nil];
        
        return signedDataWithNewKeyLabel;
    }
    
    return nil;
}



- (BOOL)processIntroductionData:(NSData*)introductionData fromEmail:(NSString*)senderEmailString
{
    if(!introductionData.length)
        return NO;
    
    // parse the protocol buffers structure "signedData"
    // (the signed keyIntroduction data that was signed using the new key)
    SignedDataStructure* signedDataStructureWithNewKeyLabel = [SignedDataStructure deserialiseData:introductionData];
    
    if(!senderEmailString)
        return NO;
    
    NSData* signedDataWithNewKeyLabel = signedDataStructureWithNewKeyLabel.dataToBeSigned;
    
    if(!signedDataWithNewKeyLabel)
        return NO;

    SignedDataStructure* signedDataStructureWithOldKeyLabel = [SignedDataStructure deserialiseData:signedDataWithNewKeyLabel];
    
    NSData* signedDataWithOldKeyLabel = signedDataStructureWithOldKeyLabel.dataToBeSigned;
    
    if(!signedDataWithOldKeyLabel)
        return NO;
    
    KeyIntroductionDataStructure* keyIntroductionDataStructure = [KeyIntroductionDataStructure deserialiseData:signedDataWithOldKeyLabel];
    
    if(!keyIntroductionDataStructure)
        return NO;
    
    PublicKeyData* newPublicKeyData = [[PublicKeyData alloc] initWithKeyLabel:keyIntroductionDataStructure.theNewKeyLabel encData:keyIntroductionDataStructure.theNewEncKey verData:keyIntroductionDataStructure.theNewVerKey];
    
    //check that the keyLabels coincide
    if(![newPublicKeyData.keyLabel isEqual:signedDataStructureWithNewKeyLabel.keyLabel])
        return NO;
    
    NSString* oldKeyLabel = keyIntroductionDataStructure.theOldKeyLabel;
    
    if(![oldKeyLabel isEqual:signedDataStructureWithOldKeyLabel.keyLabel])
        return NO;
    
    //if the addition of the new key fails, it means that the key already in the store is different - abort!
    if(![self.keyManager addPublicKeyWithData:newPublicKeyData])
        return NO;
    
    if(![self verifySignedData:signedDataStructureWithNewKeyLabel error:nil])
        return NO;
    
    if(![self verifySignedData:signedDataStructureWithOldKeyLabel error:nil])
        return NO;
    
    NSString* previousKeyLabel = [self.keyManager currentKeyLabelForEmailAddress:senderEmailString];
    
    if(!previousKeyLabel || [oldKeyLabel isEqual:previousKeyLabel])
    {
        return [self.keyManager setCurrentKeyForEmailAddress:senderEmailString keyLabel:newPublicKeyData.keyLabel overwrite:YES];
    }
    
    return NO;
}



- (NSArray*)generateSessionKeyTableForContext:(MynigmaMessageEncryptionContext*)context error:(NSError**)error
{
    //for each recipient, take the key the recipient is deemed to expect and use it to sign the key the message is actually signed with
    NSMutableArray* sessionKeyTable = [NSMutableArray new];
    
    for(NSInteger index = 0; index < context.encryptionKeyLabels.count; index++)
    {
        NSString* encryptionKeyLabel = context.encryptionKeyLabels[index];
        
        //the expected signature key label is the label of the key that the recipient is deemed to expect
        //it will be used to introduce the actual signature key
        NSString* expectedSignatureKeyLabel = context.expectedSignatureKeyLabels[index];
        
        NSData* encryptedSessionKeyData = [self.basicEngine RSAEncryptData:context.sessionKeys.concatenatedKeys withKeyLabel:encryptionKeyLabel withSHA512MGF:NO error:nil];
        
        NSData* introductionData = [self introductionDataFromKeyLabel:expectedSignatureKeyLabel toKeyLabel:context.signatureKeyLabel];
        
        NSData* encryptedIntroductionData = nil;
        
        if(introductionData)
        {
            encryptedIntroductionData = [self.basicEngine AESEncryptData:introductionData withSessionKey:context.sessionKeys.AESSessionKey error:nil];
        }
        
        SessionKeyEntryDataStructure* entry = [[SessionKeyEntryDataStructure alloc] initWithKeyLabel:encryptionKeyLabel encrSessionKeyEntry:encryptedSessionKeyData introductionData:encryptedIntroductionData emailAddress:context.recipientEmails[index]];
        
        [sessionKeyTable addObject:entry];
    }
    
    //add another session key table entry for the signature key
    NSString* signatureKeyLabel = context.signatureKeyLabel;
    
    NSData* encryptedSessionKeyData = [self.basicEngine RSAEncryptData:context.sessionKeys.concatenatedKeys withKeyLabel:signatureKeyLabel withSHA512MGF:NO error:error];
    
    if(error && *error)
    {
        //there was an error encrypting the session key
        //the details are in the feedback structure
        return nil;
    }
    
    SessionKeyEntryDataStructure* ownEntry = [[SessionKeyEntryDataStructure alloc] initWithKeyLabel:signatureKeyLabel encrSessionKeyEntry:encryptedSessionKeyData introductionData:nil emailAddress:context.senderEmail];
    
    [sessionKeyTable addObject:ownEntry];
    
    return sessionKeyTable;
}

//- (BOOL)encryptAttachmentsForContext:(MynigmaMessageEncryptionContext*)context
//{
//    for(MynigmaAttachmentEncryptionContext* attachmentContext in context.attachmentEncryptionContexts)
//    {
//        //first set the hash value
//        //this was not done when the context was initialised, as it requires SHA512 and hence a basic encryption engine
//        NSData* data = attachmentContext.decryptedData;
//        NSData* hashedValue = [self.basicEngine SHA512DigestOfData:data];
//
//        [attachmentContext.attachmentMetaDataStructure setHashedValue:hashedValue];
//
//        //now encrypt the attachment
//
//    }
//
//    return YES;
//}



/**
 *  Fill in recipientEmails, encryptionKeyLabels etc. if they are missing from the context
 *
 *  @param context The context containing the message encryption info
 *
 */
- (void)fillInMissingRecipientAndKeyLabelInfoInContext:(MynigmaMessageEncryptionContext*)context
{
    if(!context.senderEmail)
    {
        for(EmailRecipientDataStructure* emailRecipientDataStructure in context.payloadPart.addressees)
        {
            if(emailRecipientDataStructure.addresseeType == AddresseeTypeFrom && emailRecipientDataStructure.email)
            {
                context.senderEmail = emailRecipientDataStructure.email;
            }
        }
    }
    
    if(!context.recipientEmails)
    {
        NSMutableArray* recipientEmails = [NSMutableArray new];
        
        for(EmailRecipientDataStructure* emailRecipientDataStructure in context.payloadPart.addressees)
        {
            NSString* email = emailRecipientDataStructure.email;
            
            if(email)
                [recipientEmails addObject:email];
        }
        
        [context setRecipientEmails:recipientEmails];
    }
    
    if(!context.signatureKeyLabel)
    {
        context.signatureKeyLabel = [self.keyManager currentKeyLabelForEmailAddress:context.senderEmail];
        
        if(!context.signatureKeyLabel)
        {
            //TODO: report an error(!)
            //avoid crash later when trying to add nil to array
            return;
        }
    }
    
    if(!context.encryptionKeyLabels)
    {
        NSMutableArray* encryptionKeyLabels = [NSMutableArray new];
        NSMutableArray* expectedSignatureKeyLabels = [NSMutableArray new];
        
        for(NSString* recipientEmailString in context.recipientEmails)
        {
            NSString* encryptionKeyLabel = [self.keyManager currentKeyLabelForEmailAddress:recipientEmailString];
            NSString* expectedSignatureKeyLabel = [self.keyManager expectedKeyLabelFrom:context.senderEmail to:recipientEmailString];
            
            //we do need encryptionKeyLabel to be non-nil
            //otherwise there will be an error later
            if(encryptionKeyLabel)
            {
                [encryptionKeyLabels addObject:encryptionKeyLabel];
            
            if(expectedSignatureKeyLabel)
                [expectedSignatureKeyLabels addObject:expectedSignatureKeyLabel];
            else
                //use the actual signature label if there is no expected signature key label available
                [expectedSignatureKeyLabels addObject:context.signatureKeyLabel];
            }
            else
            {
                NSLog(@"Failed to find current key for email address: %@", recipientEmailString);
                
                [context pushErrorWithCode:MynigmaEncryptionErrorNoCurrentPublicKeyLabel];
            }
        }
        
        [context setEncryptionKeyLabels:encryptionKeyLabels];
        [context setExpectedSignatureKeyLabels:expectedSignatureKeyLabels];
    }
}


/**
 *  Encrypt a message previously loaded into the message encryption context
 *
 *  @param context The context containing the message encryption info
 *
 *  @return YES if the operation was successful, NO otherwise
 */
- (BOOL)encryptMessage:(MynigmaMessageEncryptionContext*)context
{
    PayloadPartDataStructure* payloadPartDataStructure = context.payloadPart;
    
    NSData* AESSessionKey = [self.basicEngine generateNewAESSessionKeyData];
    
    NSData* HMACSecret = [self.basicEngine generateNewHMACSecret];
    
    SessionKeys* sessionKeys = [[SessionKeys alloc] initWithAESSessionKey:AESSessionKey andHMACSecret:HMACSecret];
    
    context.sessionKeys = sessionKeys;
    
    NSError* error = nil;
    
    
    //compute and set the hash value of each attachment
    //it will be needed in the payload
    NSMutableArray* hashedValues = [NSMutableArray new];
    for(MynigmaAttachmentEncryptionContext* attachmentContext in context.attachmentEncryptionContexts)
    {
        NSData* unencryptedData = [attachmentContext decryptedData];
        NSData* hashedValue = [self.basicEngine SHA512DigestOfData:unencryptedData];
        if(hashedValue)
            [hashedValues addObject:hashedValue];
        
        //TO DO: deal gracefully with missing attachment data...
    }
    
    for(FileAttachmentDataStructure* attachmentMetaData in payloadPartDataStructure.attachments)
    {
        NSInteger index = [payloadPartDataStructure.attachments indexOfObject:attachmentMetaData];
        
        if(index >=0 && index < hashedValues.count)
        {
            NSData* hashedValue = hashedValues[index];
            [attachmentMetaData setHashedValue:hashedValue];
        }
    }
    
    [self fillInMissingRecipientAndKeyLabelInfoInContext:context];
    
    NSData* dataToBeSigned = payloadPartDataStructure.serialisedData;
    
    NSData* signedData = [self signData:dataToBeSigned withKeyLabel:context.signatureKeyLabel error:&error];
                          
    if(!signedData.length || error)
    {
        NSLog(@"Signature operation failed!!!! Key label: %@", context.signatureKeyLabel);
        if(error)
            [context pushErrorWithCode:error.code];
        return NO;
    }
    
    NSData* encryptedMessageData = [self.basicEngine AESEncryptData:signedData withSessionKey:AESSessionKey error:&error];
    
    if(!encryptedMessageData.length || error)
    {
        NSLog(@"Encrypted message data is invalid: %@!!!",encryptedMessageData);
        if(error)
            [context pushErrorWithCode:error.code];
        return NO;
    }
    
    if(context.encryptionKeyLabels.count != context.expectedSignatureKeyLabels.count || context.encryptionKeyLabels.count != context.recipientEmails.count)
    {
        NSLog(@"Cannot encrypt message: expected key labels, encryption key labels and recipient emails do not have matching counts!!! %ld vs. %ld vs. %ld", (long)context.encryptionKeyLabels.count, (long)context.expectedSignatureKeyLabels.count, (long)context.recipientEmails.count);
        
        [context pushErrorWithCode:MynigmaEncryptionErrorKeyAndLabelCountMismatch];
        return NO;
    }
    
    
    //first wrap the key introductions
    NSArray* sessionKeyTable = [self generateSessionKeyTableForContext:context error:&error];
    
    if(error)
    {
        [context pushErrorWithCode:error.code];
        return NO;
    }
    
    //now encrypt each attachment and store the result in encryptedData
    NSMutableArray* attachmentHMACList = [NSMutableArray new];
    for(MynigmaAttachmentEncryptionContext* attachmentContext in context.attachmentEncryptionContexts)
    {
        NSData* unencryptedData = [attachmentContext decryptedData];
        
        if(!unencryptedData)
        {
            [context pushErrorWithCode:MynigmaEncryptionErrorAttachmentHasNoData];
            
            return NO;
        }
        
        NSData* encryptedAttachmentData = [self.basicEngine AESEncryptData:unencryptedData withSessionKey:sessionKeys.AESSessionKey error:&error];
        
        if(!encryptedAttachmentData.length || error)
        {
            //an error was encountered during AES encryption
            if(error)
                [context pushErrorWithCode:error.code];
            return NO;
        }
        
        NSData* HMACForAttachment = [self.basicEngine HMACForMessage:encryptedAttachmentData withSecret:sessionKeys.HMACSecret];
        
        [attachmentHMACList addObject:HMACForAttachment];
        
        [attachmentContext setEncryptedData:encryptedAttachmentData];
    }
    
    EncryptedDataStructure* encryptedDataStructure = [[EncryptedDataStructure alloc] initWithEncrMessageData:encryptedMessageData encrSessionKeyTable:sessionKeyTable info:nil attachmentsHMACs:attachmentHMACList messageHMAC:nil version:MYNIGMA_VERSION];
    
    NSData* serialisedEncryptedData = encryptedDataStructure.serialisedData;
    
    NSData* HMAC = [self.basicEngine HMACForMessage:serialisedEncryptedData withSecret:sessionKeys.HMACSecret];
    
    NSString* version = MYNIGMA_VERSION;
    
    //now append an HMAC
    HMACDataStructure* HMACStructure = [[HMACDataStructure alloc] initWithEncryptedData:serialisedEncryptedData HMAC:HMAC version:version];
    
    context.encryptedPayload = HMACStructure.serialisedData;
    
        NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
        
        if(context.extraHeaders)
            [extraHeaders addEntriesFromDictionary:context.extraHeaders];
        
        [extraHeaders addEntriesFromDictionary:@{ @"x-mynigma-safe-message" : @"Mynigma Safe Email" }];
        
        [context setExtraHeaders:extraHeaders];

    return YES;
}

+ (NSString*)extractVersionFromData:(NSData*)data
{
    VersionDataStructure* versionDataStructure = [VersionDataStructure deserialiseData:data];
    
    return versionDataStructure.version;
}


/**
 *  Decrypt all attachments of the encrypted message loaded into the message encryption context
 *
 *  @param messageContext A message encryption context containing a list of attachment encryption contexts, a payload part with attachments meta data and a list of HMAC values
 *
 */
- (void)decryptAttachmentsForContext:(MynigmaMessageEncryptionContext*)messageContext
{
    // we can only do this once the attachments meta data has been extracted, as we want to be resistant to changes in
    // the order of MIME attachments
    // thus we need to identify the MIME parts by contentID
    // in other words, we need to match the attachment encryption
    // contexts to the attachment meta data structures in the payload
    // data structure
    NSArray* encryptionContexts = messageContext.attachmentEncryptionContexts;
    NSArray* metaDataStructures = messageContext.payloadPart.attachments;
    
    // we will create a new list containing all the attachment
    // encryption contexts in the correct order
    NSMutableArray* sortedContexts = [NSMutableArray new];
    for (FileAttachmentDataStructure* attachmentMetaDataStructure in metaDataStructures)
    {
        if (!attachmentMetaDataStructure.contentID.length)
        {
            [sortedContexts addObject:[MynigmaAttachmentEncryptionContext contextForMissingAttachment]];
            continue;
        }
        
        BOOL foundMatchingContentID = NO;
        
        for (MynigmaAttachmentEncryptionContext* attachmentContext in encryptionContexts)
        {
            if (attachmentContext.attachmentMetaDataStructure.contentID && [attachmentContext.attachmentMetaDataStructure.contentID isEqual:attachmentMetaDataStructure.contentID])
            {
                [sortedContexts addObject:attachmentContext];
                
                // fill in all the meta data info like size and
                // hashedValue
                [attachmentContext setAttachmentMetaDataStructure:attachmentMetaDataStructure];
                foundMatchingContentID = YES;
                continue;
            }
        }
        
        if(!foundMatchingContentID)
            [sortedContexts addObject:[MynigmaAttachmentEncryptionContext contextForMissingAttachment]];
    }
    
    // check if any attachments have been added
    for (MynigmaAttachmentEncryptionContext* attachmentContext in encryptionContexts)
    {
        //set the session keys
        [attachmentContext setSessionKeys:messageContext.sessionKeys];
        
        if (![sortedContexts containsObject:attachmentContext])
        {
            [sortedContexts addObject:MynigmaAttachmentEncryptionContext.contextForSuperfluousAttachment];
        }
    }
    
    // OK, attachment sorting is done
    messageContext.attachmentEncryptionContexts = sortedContexts;
    
    // now decrypt
    // the decryption method will check HMAC and hash value
    for (MynigmaAttachmentEncryptionContext* attachmentContext in messageContext.attachmentEncryptionContexts)
    {
        // locate the matching HMAC
        NSInteger index = [messageContext.attachmentEncryptionContexts indexOfObject:attachmentContext];
        
        if(index < messageContext.attachmentHMACValues.count)
        {
            NSData* HMACValue = messageContext.attachmentHMACValues[index];
            
            attachmentContext.HMACOfEncryptedData = HMACValue;
        }
        
        NSError* error = nil;
        
        if(attachmentContext.encryptedData)
        {
        [self decryptFileAttachment:attachmentContext error:&error];
        
        if(error)
        {
            [messageContext pushErrorWithCode:error.code];
        }
        }
        else
        {
            //without the data, we cannot decrypt the attachment
            //cache the context so we can decrypt it when the data has been downloaded
            NSString* uniqueKey = [NSString stringWithFormat:@"%@\n%@", messageContext.messageID, attachmentContext.index];
            [SessionKeyCache cacheAttachmentEncryptionContext:attachmentContext forUniqueKey:uniqueKey];
        }
    }
}

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context
{
    return [self decryptMessage:context insertHeaderValue:YES];
}

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context insertHeaderValue:(BOOL)insertHeaderValue
{
    //TODO: use version to deal with deprecated encryption formats
    //NSString* versionString = [self extractVersionFromData:context.encryptedPayload];
    
    HMACDataStructure* HMACStructure = [HMACDataStructure deserialiseData:context.encryptedPayload];
    
    NSData* encryptedData = HMACStructure.encryptedData;
    
    if(!encryptedData.length)
    {
        [context pushErrorWithCode:MynigmaDecryptionErrorNoData];
        return NO;
    }
    
    EncryptedDataStructure* encryptedDataStructure = [EncryptedDataStructure deserialiseData:encryptedData];
    
    BOOL keyFound = NO;
    NSString* keyPairLabel = nil;
    NSData* encrSessionKeyData = nil;
    NSData* encrIntroData = nil;
    
    NSMutableArray* keyLabels = [NSMutableArray new];
    
    //first find the correct keyLabel
    for(SessionKeyEntryDataStructure* sessionKeyEntry in encryptedDataStructure.encrSessionKeyTable)
    {
        NSString* keyLabel = sessionKeyEntry.keyLabel;
        
        if(keyLabel.length)
        {
            [keyLabels addObject:keyLabel];
            
            BOOL foundKeyPairLabel = [self.keyManager havePrivateKeyWithLabel:keyLabel];
            if(foundKeyPairLabel)
            {
                keyPairLabel = keyLabel;
                encrSessionKeyData = sessionKeyEntry.encrSessionKey;
                encrIntroData = sessionKeyEntry.introductionData;
                keyFound = YES;
                
                if(sessionKeyEntry.emailAddress.length)
                {
                    
                    //update the expected key
                    //that is, the key that should be used as the basis for introductions sent to this contact
                    //it should be the same that this contact used to encrypt the message to us
                    [self.keyManager updateExpectedKeyLabelFrom:context.senderEmail to:sessionKeyEntry.emailAddress keyLabel:keyPairLabel date:context.sentDate];
                }
                else if([encryptedDataStructure.version compare:@"2.15"]==NSOrderedAscending)
                {
                    //the old-school style session key entry which did not have an email address
                    //use all recipients
                    NSArray* allRecipients = context.recipientEmails;
                    for(NSString* recipientEmail in allRecipients)
                    {
                        [self.keyManager updateExpectedKeyLabelFrom:context.senderEmail to:recipientEmail keyLabel:keyPairLabel date:context.sentDate];
                    }
                }
                
                
                break;
            }
        }
        else
            NSLog(@"One of the key labels was empty");
    }
    
    if(!keyFound)
    {
        [context pushErrorWithCode:MynigmaDecryptionErrorNoKey];
        return NO;
    }
    
    //    //update the expected key
    //    //that is, the key that should be used as the basis for introductions sent to this contact
    //    //it should be the same that this contact used to encrypt the message to us
    //        for(NSString* recipientEmailAddress in context.recipientEmails)
    //        {
    //
    //
    //            if(recipientEmailAddress)
    //            {
    //                //this is a simplification
    //                //if several matching decryption keys are found, we cannot actually assume that the sender expects this key to be used by this address
    //                //ususally, it should make little difference
    //                //this is an edge case we need to consider at a later date
    //                [self.keyManager updateExpectedKeyLabelFrom:emailString to:recipientEmailAddress keyLabel:keyPairLabel date:date];
    //            }
    //        }
    
    if(!encrSessionKeyData.length)
    {
        [context pushErrorWithCode:MynigmaDecryptionErrorNoData];
        return NO;
    }
    
    MynigmaError* decryptionError = nil;
    
    //a key was found
    SessionKeys* sessionKeys = [SessionKeys sessionKeysFromData:[self.basicEngine RSADecryptData:encrSessionKeyData withKeyLabel:keyPairLabel withSHA512MGF:NO error:&decryptionError]];
    
    context.sessionKeys = sessionKeys;
    
    if(decryptionError)
    {
        //an error was encountered during RSA decryption
        //details are in the feedback object
        [context pushErrorWithCode:decryptionError.code];
        
        return NO;
    }
    
    if(sessionKeys)
    {
        if(![self.basicEngine verifyHMAC:HMACStructure.HMAC ofMessage:encryptedData withSecret:sessionKeys.HMACSecret])
        {
            [context pushErrorWithCode:MynigmaDecryptionErrorInvalidHMAC];
            
            return NO;
        }
        
        NSData* messageData = encryptedDataStructure.encrMessageData;
        
        //if there is a key introduction process this before attempting to decrypt the message
        if(encrIntroData.length)
        {
            //no feedback needs to be provided, as errors in introduction parsing shouldn't be presented to the user
            NSData* decryptedIntroductionData = [self.basicEngine AESDecryptData:encrIntroData withSessionKey:sessionKeys.AESSessionKey error:nil];
            
            [self processIntroductionData:decryptedIntroductionData fromEmail:context.senderEmail];
        }
        
        MynigmaError* decryptionError = nil;
        
        NSData* decryptedData = [self.basicEngine AESDecryptData:messageData withSessionKey:sessionKeys.AESSessionKey error:&decryptionError];
        
        if(decryptedData.length && !decryptionError)
        {
            SignedDataStructure* signedDataStructure = [SignedDataStructure deserialiseData:decryptedData];
            
            NSData* unwrappedData = signedDataStructure.dataToBeSigned;
            
#warning TODO: verify signature
            
            
            
            
            
            
            
            
            [context setDecryptedData:unwrappedData];
            context.payloadPart = [PayloadPartDataStructure deserialiseData:unwrappedData];
            
            //now decrypt the attachments
            [context setAttachmentHMACValues:encryptedDataStructure.attachmentHMACs];
            [self decryptAttachmentsForContext:context];
            
            //alter the header values
            NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
            
            if(context.extraHeaders)
                [extraHeaders addEntriesFromDictionary:context.extraHeaders];
            
            //remove the safe message indicator
            [extraHeaders removeObjectForKey:@"x-mynigma-safe-message"];
            
            if(insertHeaderValue)
                [extraHeaders addEntriesFromDictionary:@{ @"x-mynigma-was-sent-safely" : @"yes"}];
            
            [context setExtraHeaders:extraHeaders];

            
            return YES;
        }
        else
        {
            if(decryptionError)
                [context pushErrorWithCode:decryptionError.code];
            
            return NO;
        }
    }
    else
    {
        [context pushErrorWithCode:MynigmaDecryptionErrorNoSessionKey];
        
        return NO;
    }
}


- (MynigmaAttachmentEncryptionContext*)decryptAttachmentData:(NSData*)encryptedData forMessageID:(NSString*)messageID atIndex:(NSNumber*)index error:(NSError**)error
{
    NSString* uniqueKey = [NSString stringWithFormat:@"%@\n%@", messageID, index];

    MynigmaAttachmentEncryptionContext* attachmentEncryptionContext = [SessionKeyCache attachmentContextForUniqueKey:uniqueKey];
    
    [attachmentEncryptionContext setEncryptedData:encryptedData];
    
    [self decryptFileAttachment:attachmentEncryptionContext error:error];
    
    return attachmentEncryptionContext;
}

- (BOOL)decryptFileAttachment:(MynigmaAttachmentEncryptionContext*)attachmentContext error:(NSError**)error
{
    NSData* encryptedData = [attachmentContext encryptedData];
    
    if(!encryptedData.length)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorAttachmentNotDownloaded];
        return NO;
    }
    
    //check the HMAC, if present
    if(attachmentContext.HMACOfEncryptedData && ![self.basicEngine verifyHMAC:attachmentContext.HMACOfEncryptedData ofMessage:encryptedData withSecret:attachmentContext.sessionKeys.HMACSecret])
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorInvalidHMAC];
        return NO;
    }
    
    NSData* decryptedData = [self.basicEngine AESDecryptData:encryptedData withSessionKey:attachmentContext.sessionKeys.AESSessionKey error:error];
    
    if(!decryptedData.length || (error && *error))
    {
        return NO;
    }
    
    NSData* decryptedDataHash = [self.basicEngine SHA512DigestOfData:decryptedData];
    
    if(!decryptedDataHash.length)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorAttachmentHashIsEmpty];
        return NO;
    }
    
    //compare the computed hash of the decrypted data to the expected hashValue provided in the message body
    
    if(!attachmentContext.attachmentMetaDataStructure.hashedValue.length)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorNoHashValue];
        return NO;
    }
    
    if([decryptedDataHash isEqualToData:attachmentContext.attachmentMetaDataStructure.hashedValue])
    {
        [attachmentContext setDecryptedData:decryptedData];
        
        return YES;
    }
    else
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaDecryptionErrorInvalidHash];
        
        return NO;
    }
    
}



- (BOOL)isSenderSafe:(NSString*)senderEmailString
{
    return [self.keyManager haveCurrentPrivateKeyForEmailAddress:senderEmailString];
}

- (BOOL)isRecipientSafe:(NSString*)emailAddressString
{
    return [self.keyManager haveCurrentKeyForEmailAddress:emailAddressString];
}

- (BOOL)areRecipientsSafe:(NSArray*)emailAddressStrings
{
    for(NSString* emailAddressString in emailAddressStrings)
    {
        if(![self.keyManager haveCurrentKeyForEmailAddress:emailAddressString])
            return NO;
    }
    
    return YES;
}

- (void)ensureValidCurrentKeyForSender:(NSString*)senderEmailString
{
    return [self ensureValidCurrentKeyForSender:senderEmailString withCallback:nil];
}

- (void)ensureValidCurrentKeyForSender:(NSString*)senderEmailString withCallback:(void(^)(void))callback
{
    if([self.keyManager haveCurrentPrivateKeyForEmailAddress:senderEmailString])
        return;
    
    [self.keyManager generateMynigmaPrivateKeyForEmail:senderEmailString engine:[OpenSSLEncryptionEngine new] withCallback:callback];
}

- (void)injectPublicKeyIntoHeaders:(GenericEmailMessage*)message
{
    NSDictionary* publicKeyExtraHeaderValues = [self.keyManager extraHeaderValuesForEmailAddress:message.senderEmail];
    
    NSMutableDictionary* extraHeaders = [message.extraHeaders mutableCopy];
    
    if(publicKeyExtraHeaderValues)
        [extraHeaders addEntriesFromDictionary:publicKeyExtraHeaderValues];
    
    [message setExtraHeaders:extraHeaders];
}


- (BOOL)processPublicKeyInExtraHeaders:(NSDictionary*)extraHeaders fromSender:(NSString*)senderAddress
{
    PublicKeyData* publicKeyData = [self.keyManager getPublicKeyDataFromExtraHeaderValues:extraHeaders];
    
    if (![self.keyManager addPublicKeyWithData:publicKeyData])
        return false;
    
    return [self.keyManager setCurrentKeyForEmailAddress:senderAddress keyLabel:publicKeyData.keyLabel overwrite:NO];
}




#pragma mark - PUBLIC METHODS

- (GenericEmailMessage*)processIncomingMessage:(GenericEmailMessage*)message
{
    // first check if the message is safe
    NSString* safeMessageHeaderIndicator = message.extraHeaders[MCryptoSafeMessageHeaderField];
    
    BOOL messageIsSafe = safeMessageHeaderIndicator.length > 0;
    
    if (messageIsSafe)
    {
        MynigmaMessageEncryptionContext* messageContext = [[MynigmaMessageEncryptionContext alloc] initWithEncryptedEmailMessage:message];
        
        [self decryptMessage:messageContext];
        
        GenericEmailMessage* decryptedMessage = messageContext.decryptedMessage;
        
        if(!decryptedMessage.HTMLBody)
        {
//            NSError* firstError = messageContext.errors.firstObject;
            
            [decryptedMessage setSubject:NSLocalizedString(@"Sichere Nachricht", nil)];
            
            [decryptedMessage setHTMLBody:NSLocalizedString(@"Die Nachricht konnte nicht entschlüsselt werden", nil)];
            
//            //alter the header values
//            NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
//            
//            if(decryptedMessage.extraHeaders)
//                [extraHeaders addEntriesFromDictionary:decryptedMessage.extraHeaders];
//            
//            //remove the safe message indicator
//            [extraHeaders removeObjectForKey:@"x-mynigma-safe-message"];
//            
//            [extraHeaders addEntriesFromDictionary:@{ @"x-mynigma-was-sent-safely" : @"yes"}];
//            
//            [decryptedMessage setExtraHeaders:extraHeaders];
        }
        
        return decryptedMessage;
    }
    else
    {
        [self processPublicKeyInExtraHeaders:message.extraHeaders fromSender:message.senderEmail];
        
        return message;
    }
}

- (GenericEmailMessage*)processOutgoingMessage:(GenericEmailMessage*)message withHeaderField:(BOOL)hasHeaderField didEncrypt:(BOOL*)didEncrypt
{
    NSString* safeMessageHeaderIndicator = message.extraHeaders[MCryptoWillBeSentSafelyHeaderField];
    
    BOOL needsToBeEncrypted = (safeMessageHeaderIndicator.length > 0) && hasHeaderField && !([safeMessageHeaderIndicator.lowercaseString isEqual:@"no"]);
    
    if(didEncrypt)
        *didEncrypt = needsToBeEncrypted;

    if(needsToBeEncrypted)
    {
        MynigmaMessageEncryptionContext* context = [[MynigmaMessageEncryptionContext alloc] initWithUnencryptedEmailMessage:message];
        
        [[MynigmaEncryptionEngine sharedInstance] encryptMessage:context];
        
        return context.encryptedMessage;
    }
    else
    {
        [self injectPublicKeyIntoHeaders:message];
    }
    
    //TODO: encrypt if the header field neither exists nor is required, but the recipients are safe
    
    return message;
}

- (GenericEmailMessage*)processOutgoingMessage:(GenericEmailMessage*)message
{
    return [self processOutgoingMessage:message withHeaderField:YES didEncrypt:nil];
}

@end
