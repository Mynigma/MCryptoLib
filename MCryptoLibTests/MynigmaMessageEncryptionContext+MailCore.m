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


#import "MynigmaMessageEncryptionContext+MailCore.h"

#import <MailCore/MailCore.h>

#import "AppleEncryptionEngine.h"

#import "MimeHelper.h"
#import "MCOAbstractMessage+Convenience.h"

#import "MynigmaMessageEncryptionContext.h"

#import "MynigmaAttachmentEncryptionContext+MailCore.h"



@implementation PayloadPartDataStructure (MessageParsing)

- (instancetype)initWithMessage:(MCOAbstractMessage*)message withBasicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine
{
    NSString* body = message.plainBodyString;
    NSString* HTMLBody = message.HTMLBodyString;
    NSString* subject = message.header.subject;
    NSDate* date = message.date;
    
    NSArray* addressees = message.allAddresseesAsRecipientDataStructures;
    NSArray* attachments = [message allAttachmentsAsAttachmentDataStructuresWithBasicEncryptionEngine:basicEngine];
    
    return [self initWithBody:body HTMLBody:HTMLBody subject:subject dateSent:date addressees:addressees attachments:attachments];
}

@end





@implementation MynigmaMessageEncryptionContext (MailCore)

+ (MynigmaMessageEncryptionContext*)contextForDecryptedMessage:(MCOAbstractMessage*)message
{
    return [self contextForDecryptedMessage:message withBasicEncryptionEngine:[AppleEncryptionEngine new]];
}

+ (MynigmaMessageEncryptionContext*)contextForDecryptedMessage:(MCOAbstractMessage*)message withBasicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine
{
    MynigmaMessageEncryptionContext* context = [MynigmaMessageEncryptionContext new];
    
    context.senderEmail = message.sender.mailbox;
    
    context.senderName = message.sender.displayName;
    
    context.messageID = message.header.messageID;
    
    context.sentDate = message.date;
    
    context.recipientEmails = [message.allRecipients valueForKey:@"mailbox"];
    
    //first wrap the message data
    context.payloadPart = [[PayloadPartDataStructure alloc] initWithMessage:message withBasicEncryptionEngine:basicEngine];
    
    //now initialise the attachment contexts
    NSMutableArray* newAttachmentContexts = [NSMutableArray new];
    
    NSArray* attachments = message.allAttachments;
    for(MCOAttachment* attachment in attachments)
    {
        MynigmaAttachmentEncryptionContext* attachmentContext = [MynigmaAttachmentEncryptionContext contextForDecryptedAttachment:attachment];
        
        [newAttachmentContexts addObject:attachmentContext];
    }
    
    context.attachmentEncryptionContexts = newAttachmentContexts;
    
    //extra headers
    NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
    for(NSString* extraHeaderName in message.header.allExtraHeadersNames)
    {
        NSString* extraHeaderValue = [message.header extraHeaderValueForName:extraHeaderName];
        
        if(extraHeaderValue)
            extraHeaders[extraHeaderName.lowercaseString] = extraHeaderValue;
    }
    [context setExtraHeaders:extraHeaders];
    
    context.encryptedPayload = message.encryptedPayload;
    
    return context;
}

+ (MynigmaMessageEncryptionContext*)contextForIncomingMessage:(MCOAbstractMessage*)message
{
    return [self contextForDecryptedMessage:message];
}

+ (MynigmaMessageEncryptionContext*)contextForEncryptedMessage:(MCOAbstractMessage*)message
{
    MynigmaMessageEncryptionContext* context = [MynigmaMessageEncryptionContext new];
    
    //take the received date first
    //the server is probably more trustworthy, when it comes to setting the correct time
    context.sentDate = message.date;
    
    context.senderEmail = message.sender.mailbox;
    
    context.senderName = message.sender.displayName;
    
    context.messageID = message.header.messageID;
    
    context.recipientEmails = [message.allRecipients valueForKey:@"mailbox"];
    
    //first wrap the message data
    context.encryptedPayload = message.encryptedPayload;
    
    //now initialise the attachment contexts
    NSMutableArray* newEncryptedAttachmentContexts = [NSMutableArray new];
    
    NSArray* attachments = message.encryptedAttachments;
    
    for(MCOAttachment* attachment in attachments)
    {
        MynigmaAttachmentEncryptionContext* attachmentContext = [MynigmaAttachmentEncryptionContext contextForEncryptedAttachment:attachment];
        
        [newEncryptedAttachmentContexts addObject:attachmentContext];
    }
    
    context.attachmentEncryptionContexts = newEncryptedAttachmentContexts;
    
    //extra headers
    NSMutableDictionary* extraHeaders = [NSMutableDictionary new];
    for(NSString* extraHeaderName in message.header.allExtraHeadersNames)
    {
        NSString* extraHeaderValue = [message.header extraHeaderValueForName:extraHeaderName];
        
        if(extraHeaderValue)
            extraHeaders[extraHeaderName.lowercaseString] = extraHeaderValue;
    }
    [context setExtraHeaders:extraHeaders];
    
    return context;
}



- (MCOAbstractMessage*)encryptedMessage
{
    MCOMessageBuilder* message = [MCOMessageBuilder new];
    
    // Attach Plain Text
    //		MimeBodyPart plainPart = new MimeBodyPart();
    //TODO: handle plain text parts properly
    //		plainPart.setText(plainText);
    //		mainBodyInPlainAndHTML.addBodyPart(plainPart);
    
    NSURL* HTMLTemplateURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"MynigmaMessage" withExtension:@"html"];
    
    NSString* HTMLTemplate = [NSString stringWithContentsOfURL:HTMLTemplateURL encoding:NSUTF8StringEncoding error:nil];
    
    [message setHTMLBody:HTMLTemplate];
    
    
    // Attach template image
    NSURL* templateImageURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"MynigmaIconForLetter" withExtension:@"jpg"];
    
    NSData* templateImageData = [NSData dataWithContentsOfURL:templateImageURL];
    
    MCOAttachment* imageAttachment = [MCOAttachment new];
    
    [imageAttachment setData:templateImageData];
    [imageAttachment setFilename:@"MynigmaIconForLetter.jpg"];
    
    [imageAttachment setInlineAttachment:YES];
    [imageAttachment setMimeType:@"image/jpg"];
    
    [message addRelatedAttachment:imageAttachment];
    
    // Attach encrypted payload
    MCOAttachment* payloadAttachment = [MCOAttachment new];
    
    [payloadAttachment setData:self.encryptedPayload];
    [payloadAttachment setFilename:NSLocalizedString(@"Secure message.myn", nil)];
    
    [payloadAttachment setInlineAttachment:NO];
    [payloadAttachment setMimeType:@"application/mynigma-payload"];
    
    [message addAttachment:payloadAttachment];
    
    
    // Attach encrypted attachments
    for(int i = 0; i < self.attachmentEncryptionContexts.count; i++)
    {
        MynigmaAttachmentEncryptionContext* attachmentEncryptionContext = self.attachmentEncryptionContexts[i];
        
        [message addAttachment:[attachmentEncryptionContext encryptedMimePart:@(i)]];
    }
    
    //set the main boundary
    [message.header setSubject:[NSString stringWithFormat:NSLocalizedString(@"Safe message from %@", nil), self.senderName]];
    
    [message.header setExtraHeaderValue:@"Mynigma Safe Email" forName:@"X-Mynigma-Safe-Message"];
    
    [message.header setDate:[NSDate date]];
    
    //set the main boundary
    
    return message;
}



- (MCOAbstractMessage*)decryptedMessage
{
    MCOMessageBuilder* message = [MCOMessageBuilder new];
    
    // No plain text part
    NSString* plainText = self.payloadPart.body;
    [message setTextBody:plainText];
    
    // Attach HTML Text
    NSString* HTMLText = self.payloadPart.HTMLBody;
    [message setHTMLBody:HTMLText];
    
    
    // Attach decrypted attachments
    for(MynigmaAttachmentEncryptionContext* attachmentContext in self.attachmentEncryptionContexts)
    {
        [message addAttachment:[attachmentContext decryptedMimePart]];
    }
    
    [message.header setDate:self.payloadPart.dateSent];
    
    [message.header setSubject:self.payloadPart.subject];
    
    return message;
}


@end
