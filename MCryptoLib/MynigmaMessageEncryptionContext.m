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


#import "MynigmaMessageEncryptionContext.h"

#import <MProtoBuf/PayloadPartDataStructure.h>
#import <MProtoBuf/EmailRecipientDataStructure.h>
#import <MProtoBuf/FileAttachmentDataStructure.h>

#import "MynigmaAttachmentEncryptionContext.h"

#import "GenericEmailMessage.h"
#import "GenericEmailAttachment.h"
#import "GenericEmailAddressee.h"

#import "BasicEncryptionEngineProtocol.h"

#import "MynigmaEncryptionEngine.h"
#import "AppleEncryptionEngine.h"
#import "SessionKeys.h"
#import "CoreDataHelper.h"
#import "MIMEHelper.h"





@implementation MynigmaMessageEncryptionContext


#pragma mark - Init with generic email object

- (instancetype)initWithUnencryptedEmailMessage:(GenericEmailMessage*)genericEmailMessage
{
    self = [super init];
    if (self) {
        
        self.sentDate = genericEmailMessage.sentDate;
        
        
        //look for the sender
        self.senderEmail = [genericEmailMessage senderEmail];
        
        self.messageID = genericEmailMessage.messageID;
        
        if(!self.messageID)
            self.messageID = [MimeHelper generateFreshMessageID];
        
        self.recipientEmails = [genericEmailMessage.addressees valueForKey:@"address"];
        
        
        NSMutableArray* addresseesAsEmailRecipientDataStructures = [NSMutableArray new];
        
        for(GenericEmailAddressee* genericAddressee in genericEmailMessage.addressees)
        {
            EmailRecipientDataStructure* emailRecipient = [[EmailRecipientDataStructure alloc] initWithName:genericAddressee.name emailAddress:genericAddressee.address addresseeType:genericAddressee.addresseeType.integerValue];
            
            [addresseesAsEmailRecipientDataStructures addObject:emailRecipient];
        }
        
        //now initialise the attachment contexts
        NSMutableArray* newEncryptedAttachmentContexts = [NSMutableArray new];
        
        NSMutableArray* newFileAttachmentDataStructures = [NSMutableArray new];
        
        NSArray* attachments = genericEmailMessage.attachments;
        
        for(GenericEmailAttachment* attachment in attachments)
        {
            MynigmaAttachmentEncryptionContext* attachmentContext = [[MynigmaAttachmentEncryptionContext alloc] initWithUnencryptedAttachment:attachment];
            
            if(!attachment.contentID)
                [attachment setContentID:[MimeHelper generateFreshMessageID]];
            
            [newEncryptedAttachmentContexts addObject:attachmentContext];
            
            FileAttachmentDataStructure* fileAttachentDataStructure = [[FileAttachmentDataStructure alloc] initWithFileName:attachment.fileName contentID:attachment.contentID size:attachment.size.integerValue hashedValue:nil partID:nil remoteURL:nil isInline:attachment.isInline.boolValue contentType:attachment.MIMEType];
            
            [newFileAttachmentDataStructures addObject:fileAttachentDataStructure];
        }
        
        self.attachmentEncryptionContexts = newEncryptedAttachmentContexts;

        
        self.payloadPart = [[PayloadPartDataStructure alloc] initWithBody:genericEmailMessage.plainBody HTMLBody:genericEmailMessage.HTMLBody subject:genericEmailMessage.subject dateSent:genericEmailMessage.sentDate addressees:addresseesAsEmailRecipientDataStructures attachments:newFileAttachmentDataStructures];
        
        
        
        //extra headers
        NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
        for(NSString* extraHeaderName in genericEmailMessage.extraHeaders.allKeys)
        {
            NSString* extraHeaderValue = [genericEmailMessage.extraHeaders objectForKey:extraHeaderName];
            
            if(extraHeaderValue)
                extraHeaders[extraHeaderName.lowercaseString] = extraHeaderValue;
        }
        [self setExtraHeaders:extraHeaders];
    }
    return self;
}

- (instancetype)initWithEncryptedEmailMessage:(GenericEmailMessage*)genericEmailMessage
{
    self = [super init];
    if (self) {
        
        self.sentDate = genericEmailMessage.sentDate;
        
        
        //look for the sender
        for(GenericEmailAddressee* addressee in genericEmailMessage.addressees)
        {
            if(addressee.addresseeType.integerValue == AddresseeTypeFrom)
            {
                self.senderEmail = addressee.address;
                self.senderName = addressee.name;
                break;
            }
        }
        
        self.messageID = genericEmailMessage.messageID;
        
        if(!self.messageID)
            self.messageID = [MimeHelper generateFreshMessageID];
        
        self.recipientEmails = [genericEmailMessage.addressees valueForKey:@"address"];
        
        //first wrap the message data
        self.encryptedPayload = genericEmailMessage.encryptedPayload;
        
        
        //now initialise the attachment contexts
        NSMutableArray* newEncryptedAttachmentContexts = [NSMutableArray new];
        
        NSArray* attachments = genericEmailMessage.encryptedAttachments;
        
        for(GenericEmailAttachment* attachment in attachments)
        {
            MynigmaAttachmentEncryptionContext* attachmentContext = [[MynigmaAttachmentEncryptionContext alloc] initWithEncryptedAttachment:attachment];
            
            NSInteger index = [genericEmailMessage.attachments indexOfObject:attachment];
            
            if(index != NSNotFound)
                [attachmentContext setIndex:@(index)];
            
            [newEncryptedAttachmentContexts addObject:attachmentContext];
        }
        
        self.attachmentEncryptionContexts = newEncryptedAttachmentContexts;
        
        //extra headers
        NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
        for(NSString* extraHeaderName in genericEmailMessage.extraHeaders.allKeys)
        {
            NSString* extraHeaderValue = [genericEmailMessage.extraHeaders objectForKey:extraHeaderName];
            
            if(extraHeaderValue)
                extraHeaders[extraHeaderName.lowercaseString] = extraHeaderValue;
        }
        [self setExtraHeaders:extraHeaders];
    }
    return self;
}



#pragma mark - Obtain generic email object

- (GenericEmailMessage*)encryptedMessage
{
    GenericEmailMessage* message = [GenericEmailMessage new];
    
    //first set the message body
    NSURL* mynigmaMessageURL = [[CoreDataHelper bundle] URLForResource:@"MynigmaMessage" withExtension:@"html"];
    
    NSString* formatString = [NSString stringWithContentsOfURL:mynigmaMessageURL encoding:NSUTF8StringEncoding error:nil];
    
    NSString* displayedSenderEmail = self.senderEmail?self.senderEmail:@"";
    
    NSString* displayedSenderName = self.senderName?self.senderName:self.senderEmail;
    
    if(!displayedSenderName)
        displayedSenderName = @"";
    
    NSString* bodyString = [NSString stringWithFormat:formatString, [displayedSenderEmail cStringUsingEncoding:NSUTF8StringEncoding], [displayedSenderName cStringUsingEncoding:NSUTF8StringEncoding], [self.messageID cStringUsingEncoding:NSUTF8StringEncoding], [self.messageID cStringUsingEncoding:NSUTF8StringEncoding]];
    
    [message setHTMLBody:bodyString];
    
    
    NSMutableArray* addressees = [NSMutableArray new];
    
    for(EmailRecipientDataStructure* emailRecipient in self.payloadPart.addressees)
    {
        GenericEmailAddressee* addressee = [[GenericEmailAddressee alloc] initWithName:emailRecipient.name emailAddress:emailRecipient.email addresseeType:@(emailRecipient.addresseeType)];
        
        [addressees addObject:addressee];
    }
    
    [message setAddressees:addressees];
    
    
    //set the subject
    if(displayedSenderName.length)
        [message setSubject:[NSString stringWithFormat:NSLocalizedString(@"Safe message from %@", @"Safe message template"), displayedSenderName]];
    else
        [message setSubject:NSLocalizedString(@"Safe message", @"Safe message template")];

    
    // Attach template image
    NSURL* templateImageURL = [[CoreDataHelper bundle] URLForResource:@"MynigmaIconForLetter" withExtension:@"jpg"];
    
    NSData* templateImageData = [NSData dataWithContentsOfURL:templateImageURL];
    
    GenericEmailAttachment* imageAttachment = [GenericEmailAttachment new];
    
    [imageAttachment setData:templateImageData];
    [imageAttachment setSize:@(templateImageData.length)];
    [imageAttachment setContentID:@"TXluaWdtYUljb25Gb3JMZXR0ZXI@mynigma.org"];
    
    [imageAttachment setFileName:@"MynigmaIconForLetter.jpg"];
    
    [imageAttachment setIsInline:@YES];
    [imageAttachment setMIMEType:@"image/jpg"];
    
    [message addAttachment:imageAttachment];
    
    
    // Attach encrypted payload
    GenericEmailAttachment* payloadAttachment = [GenericEmailAttachment new];
    
    [payloadAttachment setData:self.encryptedPayload];
    [payloadAttachment setSize:@(self.encryptedPayload.length)];
    [payloadAttachment setContentID:[MimeHelper generateFreshMessageID]];
    
    [payloadAttachment setFileName:NSLocalizedString(@"Secure message.myn", nil)];
    
    [payloadAttachment setIsInline:@NO];
    [payloadAttachment setMIMEType:@"application/mynigma-payload"];
    
    [message addAttachment:payloadAttachment];
    
    
    // Attach encrypted attachments
    for(int i = 0; i < self.attachmentEncryptionContexts.count; i++)
    {
        MynigmaAttachmentEncryptionContext* attachmentEncryptionContext = self.attachmentEncryptionContexts[i];
        
        [message addAttachment:[attachmentEncryptionContext encryptedAttachmentWithIndex:i+1]];
    }
    
    [message setExtraHeaders:self.extraHeaders];
    
    [message setSentDate:self.sentDate];
    
    [message setMessageID:self.messageID];
    
    return message;
}

- (GenericEmailMessage*)decryptedMessage
{
    GenericEmailMessage* message = [GenericEmailMessage new];
    
    //first set the message body
    [message setHTMLBody:self.payloadPart.HTMLBody.length?self.payloadPart.HTMLBody:nil];
    [message setPlainBody:self.payloadPart.body.length?self.payloadPart.body:nil];
    
    NSMutableArray* addressees = [NSMutableArray new];
    for(EmailRecipientDataStructure* emailRecipient in self.payloadPart.addressees)
    {
        GenericEmailAddressee* addressee = [[GenericEmailAddressee alloc] initWithName:emailRecipient.name emailAddress:emailRecipient.email addresseeType:@(emailRecipient.addresseeType)];
        
        [addressees addObject:addressee];
    }
    
    [message setAddressees:addressees];
    
    
    // Attach decrypted attachments
    for(int i = 0; i < self.attachmentEncryptionContexts.count; i++)
    {
        MynigmaAttachmentEncryptionContext* attachmentEncryptionContext = self.attachmentEncryptionContexts[i];
        
        [message addAttachment:[attachmentEncryptionContext decryptedAttachment]];
    }
    
    //set the main boundary
    [message setSubject:self.payloadPart.subject];
    
    [message setExtraHeaders:self.extraHeaders];
    
    [message setSentDate:self.sentDate];
    
    [message setMessageID:self.messageID];
    
    NSMutableDictionary* extraHeaders = [self.extraHeaders mutableCopy];
    
    if(self.hasErrors)
    {
        NSString* errorCodesList = [self.errors componentsJoinedByString:@","];
        
        [extraHeaders addEntriesFromDictionary:@{ MCryptoDecryptionErrorsHeaderField : errorCodesList }];
    }
    
    [message setExtraHeaders:extraHeaders];
    
    return message;
}






+ (MynigmaMessageEncryptionContext*)contextForDecryptedDeviceMessageWithPayload:(NSData*)payloadData
{
    return nil;
}


#pragma mark - Errors

- (void)pushErrorWithCode:(MynigmaErrorCode)code
{
    if(!self.errors)
        self.errors = [NSMutableArray new];
    
    [self.errors addObject:@(code)];
}

- (BOOL)hasErrors
{
    return self.errors.count > 0;
}

- (NSArray*)errorDescriptions
{
//    NSMutableArray*
    return nil;
}






#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [self.sessionKeys encodeWithCoder:aCoder];
    
    //TODO: add other properties
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if (self) {
        self.sessionKeys = [[SessionKeys alloc] initWithCoder:aDecoder];
    }
    return self;
}




@end
