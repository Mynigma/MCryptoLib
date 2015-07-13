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

#import "MCOAbstractMessage+Convenience.h"

#import "MimeHelper.h"

#import "MimeHelper+MailCore.h"

#import <MProtoBuf/EmailRecipientDataStructure.h>
#import <MProtoBuf/FileAttachmentDataStructure.h>




@implementation MCOAbstractMessage (Convenience)

- (NSArray*)allAttachmentsAsAttachmentDataStructuresWithBasicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine
{
    NSArray* allAttachments = self.allAttachments;
    
    NSMutableArray* allAttachmentDataStructures = [NSMutableArray new];
    
    for(MCOAttachment* attachment in allAttachments)
    {
        NSData* hashedValue = [basicEngine SHA512DigestOfData:attachment.data];
        
        NSString* contentID = [attachment contentIDGeneratingIfNeeded:YES];
        
        FileAttachmentDataStructure* attachmentDataStructure = [[FileAttachmentDataStructure alloc] initWithFileName:attachment.filename contentID:contentID size:attachment.data.length hashedValue:hashedValue partID:nil remoteURL:nil isInline:attachment.isInlineAttachment contentType:attachment.mimeType];
        
        [allAttachmentDataStructures addObject:attachmentDataStructure];
    }
    
    return allAttachmentDataStructures;
}

- (NSArray*)allAttachments
{
    //an MCOMessageBuilder has a simple structure and a convenient method for getting all the attachments
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        return [(MCOMessageBuilder*)self attachments];
    }
    
    if(![self respondsToSelector:@selector(mainPart)])
    {
        NSLog(@"Message does not respond to selector mainPart! %@", self);
        return nil;
    }
    
    MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
    
    return [MimeHelper listAllSubpartsOfPart:mainPart satisfyingCondition:^BOOL(MCOAbstractPart* part)
            {
                if(part.isPlainTextPart || part.isHTMLTextPart)
                    return NO;
                
                return YES;
            }];
}

- (NSArray*)encryptedAttachments
{
    NSMutableArray* encryptedAttachments = [NSMutableArray new];
    
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        for(MCOAttachment* attachment in [(MCOMessageBuilder*)self attachments])
        {
            if([attachment.mimeType.lowercaseString isEqual:@"application/mynigma-attachment"])
                [encryptedAttachments addObject:attachment];
            else if([attachment.mimeType.lowercaseString isEqual:@"application/mynigma"] && ![attachment.filename isEqual:@"Secure message.myn"])
                [encryptedAttachments addObject:attachment];
        }
        
        return encryptedAttachments;
    }
    
    if([self isKindOfClass:[MCOMessageParser class]] || [self isKindOfClass:[MCOIMAPMessage class]])
    {
        MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
        
        if([mainPart isKindOfClass:[MCOAbstractMultipart class]])
        {
            for(MCOAbstractPart* attachment in [(MCOAbstractMultipart*)mainPart parts])
            {
                if([attachment.mimeType.lowercaseString isEqual:@"application/mynigma-attachment"])
                    [encryptedAttachments addObject:attachment];
                else if([attachment.mimeType.lowercaseString isEqual:@"application/mynigma"] && ![attachment.filename isEqual:@"Secure message.myn"])
                    [encryptedAttachments addObject:attachment];
            }
        }
        
        return encryptedAttachments;
    }
    
    return nil;
}


- (NSArray*)inlineAttachments
{
    NSMutableArray* inlineAttachments = [NSMutableArray new];
    
    //an MCOMessageBuilder has a simple structure and a convenient method for getting all the attachments
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        for(MCOAttachment* attachment in [(MCOMessageBuilder*)self attachments])
        {
            if(attachment.inlineAttachment)
                [inlineAttachments addObject:attachment];
        }
        
        return inlineAttachments;
    }
    
    if([self isKindOfClass:[MCOMessageParser class]] || [self isKindOfClass:[MCOIMAPMessage class]])
    {
        MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
        
        return [MimeHelper listAllSubpartsOfPart:mainPart satisfyingCondition:^BOOL(MCOAbstractPart *attachment){
            
            if(attachment.isPlainTextPart || attachment.isHTMLTextPart)
                return NO;

            if(attachment.inlineAttachment)
                return YES;
            
            return NO;
        }];
    }
        
    return nil;
}

- (NSArray*)explicitAttachments
{
    NSMutableArray* explicitAttachments = [NSMutableArray new];
    
    //an MCOMessageBuilder has a simple structure and a convenient method for getting all the attachments
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        for(MCOAttachment* attachment in [(MCOMessageBuilder*)self attachments])
        {
            if(!attachment.inlineAttachment)
                [explicitAttachments addObject:attachment];
        }
        
        return explicitAttachments;
    }
    
    if([self isKindOfClass:[MCOMessageParser class]] || [self isKindOfClass:[MCOIMAPMessage class]])
    {
        //it could be either an MCOMessageParser or an MCIMAPMessage, but both respond to mainPart in the same way
        MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
        
        return [MimeHelper listAllSubpartsOfPart:mainPart satisfyingCondition:^BOOL(MCOAbstractPart *attachment){
            
            if(attachment.inlineAttachment)
                return NO;
            
            if(attachment.isPlainTextPart || attachment.isHTMLTextPart)
                return NO;
            
            return YES;
        }];
    }
    
    return nil;
}

- (NSString*)HTMLBodyString
{
    //an MCOMessageBuilder has a simple structure and a convenient method for getting the body
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        return [(MCOMessageBuilder*)self htmlBody];
    }
    
    if([self isKindOfClass:[MCOMessageParser class]] || [self isKindOfClass:[MCOIMAPMessage class]])
    {
        MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
        
        MCOAttachment* HTMLPartAttachment = [MimeHelper listAllSubpartsOfPart:mainPart satisfyingCondition:^BOOL(MCOAbstractPart *attachment){
            
            if(attachment.isHTMLTextPart)
                return YES;
            
            return NO;
        }].firstObject;
        
        return [HTMLPartAttachment decodedStringForData:HTMLPartAttachment.data];
    }
    
    return nil;
}

- (NSString*)plainBodyString
{
    //an MCOMessageBuilder has a simple structure and a convenient method for getting the body
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        return [(MCOMessageBuilder*)self textBody];
    }
    
    if([self isKindOfClass:[MCOMessageParser class]] || [self isKindOfClass:[MCOIMAPMessage class]])
    {
        MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
        
        MCOAttachment* plainPartAttachment = [MimeHelper listAllSubpartsOfPart:mainPart satisfyingCondition:^BOOL(MCOAbstractPart *attachment){
            
            if(attachment.isPlainTextPart)
                return YES;
            
            return NO;
        }].firstObject;
        
        return [plainPartAttachment decodedStringForData:plainPartAttachment.data];
    }
    
    return nil;
}


- (NSData*)encryptedPayload
{
    if([self isKindOfClass:[MCOMessageBuilder class]])
    {
        for(MCOAttachment* attachment in [(MCOMessageBuilder*)self attachments])
        {
            if([attachment.mimeType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED_PAYLOAD])
                return attachment.data;
        }
    }
    
    if([self isKindOfClass:[MCOMessageParser class]] || [self isKindOfClass:[MCOIMAPMessage class]])
    {
        MCOAbstractPart* mainPart = [(MCOMessageParser*)self mainPart];
        
        if([mainPart isKindOfClass:[MCOAbstractMultipart class]])
        {
            for(MCOAbstractPart* attachment in [(MCOAbstractMultipart*)mainPart parts])
            {
                if([attachment.mimeType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED_PAYLOAD] && [attachment isKindOfClass:[MCOAttachment class]])
                    return [(MCOAttachment*)attachment data];
                
                if([attachment.mimeType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED] && [attachment.filename isEqual:@"Secure message.myn"])
                    return [(MCOAttachment*)attachment data];
            }
        }
    }
    
    return nil;
}

- (MCOAddress*)sender
{
    return self.header.from;
}

- (NSDate*)date
{
    //take the received date first
    //the server is probably more trustworthy, when it comes to setting the correct time
    if(self.header.receivedDate)
        return self.header.receivedDate;
    
    if(self.header.date)
        return self.header.date;
    
    //TODO: get date from other info in the message
    
    return nil;
}

/**
 * Extracts all addressees, including from:, reply-to: and bcc: and lists the email addresses
 * @param message
 * @return
 */
- (NSArray*)allAddressees
{
    NSMutableArray* allAddressees = [NSMutableArray new];
    
    if(self.header.from)
        [allAddressees addObject:self.header.from];
    
    if(self.header.replyTo)
        [allAddressees addObject:self.header.replyTo];
    
    if(self.header.to)
        [allAddressees addObjectsFromArray:self.header.to];
    
    if(self.header.cc)
        [allAddressees addObjectsFromArray:self.header.cc];
    
    if(self.header.bcc)
        [allAddressees addObjectsFromArray:self.header.bcc];
    
    return allAddressees;
}

- (NSArray*)allAddresseesAsRecipientDataStructures
{
    NSMutableArray* allAddressees = [NSMutableArray new];
    
    if(self.header.from)
        [allAddressees addObject:[[EmailRecipientDataStructure alloc] initWithName:self.header.from.displayName emailAddress:self.header.from.mailbox addresseeType:AddresseeTypeFrom]];
    
    for(MCOAddress* address in self.header.replyTo)
    {
        [allAddressees addObject:[[EmailRecipientDataStructure alloc] initWithName:address.displayName emailAddress:address.mailbox addresseeType:AddresseeTypeReplyTo]];
    }

    for(MCOAddress* address in self.header.to)
    {
        [allAddressees addObject:[[EmailRecipientDataStructure alloc] initWithName:address.displayName emailAddress:address.mailbox addresseeType:AddresseeTypeTo]];
    }

    for(MCOAddress* address in self.header.cc)
    {
        [allAddressees addObject:[[EmailRecipientDataStructure alloc] initWithName:address.displayName emailAddress:address.mailbox addresseeType:AddresseeTypeCc]];
    }

    for(MCOAddress* address in self.header.bcc)
    {
        [allAddressees addObject:[[EmailRecipientDataStructure alloc] initWithName:address.displayName emailAddress:address.mailbox addresseeType:AddresseeTypeBcc]];
    }
    
    return allAddressees;
}

/**
 * Extracts all recipients, excluding from: and reply-to: 
 */
- (NSArray*)allRecipients
{
    NSMutableArray* allRecipients = [NSMutableArray new];
    
    if(self.header.to)
        [allRecipients addObjectsFromArray:self.header.to];
    
    if(self.header.cc)
        [allRecipients addObjectsFromArray:self.header.cc];
    
    if(self.header.bcc)
        [allRecipients addObjectsFromArray:self.header.bcc];
    
    return allRecipients;
}

@end
