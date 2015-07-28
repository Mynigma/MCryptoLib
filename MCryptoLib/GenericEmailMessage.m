//
//  GenericEmailMessage.m
//  Mynigma
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import "GenericEmailMessage.h"

#import "MimeHelper.h"
#import "GenericEmailAttachment.h"
#import "GenericEmailAddressee.h"
#import "MynigmaMessageEncryptionContext.h"


NSString* const extraHeadersKey     = @"MCryptoGenericEmailMessageExtraHeaders";
NSString* const messageIDKey        = @"MCryptoGenericEmailMessageMessageID";
NSString* const subjectKey          = @"MCryptoGenericEmailMessageSubject";
NSString* const sentDateKey         = @"MCryptoGenericEmailMessageSentDate";
NSString* const HTMLBodyKey         = @"MCryptoGenericEmailMessageHTMLBody";
NSString* const plainBodyKey        = @"MCryptoGenericEmailMessagePlainBody";
NSString* const attachmentsKey      = @"MCryptoGenericEmailMessageAttachments";
NSString* const addresseesKey       = @"MCryptoGenericEmailMessageAddressees";



@implementation GenericEmailMessage


- (instancetype)initWithCoder:(NSCoder*)coder
{
    self = [super init];
    if (self){
        
        self.extraHeaders = [coder decodeObjectForKey:extraHeadersKey];
        self.messageID = [coder decodeObjectForKey:messageIDKey];
        self.subject = [coder decodeObjectForKey:subjectKey];
        self.sentDate = [coder decodeObjectForKey:sentDateKey];
        self.HTMLBody = [coder decodeObjectForKey:HTMLBodyKey];
        self.plainBody = [coder decodeObjectForKey:plainBodyKey];
        self.attachments = [coder decodeObjectForKey:attachmentsKey];
        self.addressees = [coder decodeObjectForKey:addresseesKey];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder*)coder
{
    [coder encodeObject:self.extraHeaders forKey:extraHeadersKey];
    [coder encodeObject:self.messageID forKey:messageIDKey];
    [coder encodeObject:self.subject forKey:subjectKey];
    [coder encodeObject:self.sentDate forKey:sentDateKey];
    [coder encodeObject:self.HTMLBody forKey:HTMLBodyKey];
    [coder encodeObject:self.plainBody forKey:plainBodyKey];
    [coder encodeObject:self.attachments forKey:attachmentsKey];
    [coder encodeObject:self.addressees forKey:addresseesKey];
}


- (void)addAttachment:(GenericEmailAttachment*)attachment
{
    if(!self.attachments)
        self.attachments = [NSArray new];
    
    self.attachments = [self.attachments arrayByAddingObject:attachment];
}



- (NSData*)encryptedPayload
{
    for(GenericEmailAttachment* attachment in self.attachments)
    {
        if([attachment.MIMEType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED_PAYLOAD])
        {
            return attachment.data;
        }
        
        if([attachment.MIMEType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED] && [attachment.fileName isEqual:@"Secure message.myn"])
        {
            return attachment.data;
        }
    }
    
    return nil;
}

- (NSArray*)encryptedAttachments
{
    NSMutableArray* encryptedAttachments = [NSMutableArray new];
    
    for(GenericEmailAttachment* attachment in self.attachments)
    {
        if([attachment.MIMEType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED_ATTACHMENTS])
            [encryptedAttachments addObject:attachment];
        else if([attachment.MIMEType.lowercaseString isEqual:MIME_TYPE_ENCRYPTED] && ![attachment.fileName isEqual:@"Secure message.myn"])
            [encryptedAttachments addObject:attachment];
    }
    
    return encryptedAttachments;
}

- (NSString*)senderEmail
{
    for(GenericEmailAddressee* addressee in self.addressees)
    {
        if(addressee.addresseeType == AddresseeTypeFrom)
        {
            return addressee.address;
        }
    }
    
    return nil;
}


@end
