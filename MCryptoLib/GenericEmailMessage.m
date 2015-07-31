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
#import <MProtoBuf/EmailRecipientDataStructure.h>


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
        if(addressee.addresseeType.integerValue == AddresseeTypeFrom)
        {
            return addressee.address;
        }
    }
    
    return nil;
}


- (BOOL)isEqual:(GenericEmailMessage*)object
{
    if(object == self)
        return YES;
    
    if(![object isKindOfClass:[GenericEmailMessage class]])
        return NO;
    
    if((self.extraHeaders && !object.extraHeaders) || (!self.extraHeaders && object.extraHeaders))
        return NO;
    if(self.extraHeaders && ![self.extraHeaders isEqual:object.extraHeaders])
        return NO;
    
    if((self.messageID && !object.messageID) || (!self.messageID && object.messageID))
        return NO;
    if(self.messageID && ![self.messageID isEqual:object.messageID])
        return NO;
    
    if((self.subject && !object.subject) || (!self.subject && object.subject))
        return NO;
    if(self.subject && ![self.subject isEqual:object.subject])
        return NO;
    
    if((self.sentDate && !object.sentDate) || (!self.sentDate && object.sentDate))
        return NO;
    if(self.sentDate && ![self.sentDate isEqual:object.sentDate])
        return NO;
    
    if((self.HTMLBody && !object.HTMLBody) || (!self.HTMLBody && object.HTMLBody))
        return NO;
    if(self.HTMLBody && ![self.HTMLBody isEqual:object.HTMLBody])
        return NO;
    
    if((self.plainBody && !object.plainBody) || (!self.plainBody && object.plainBody))
        return NO;
    if(self.plainBody && ![self.plainBody isEqual:object.plainBody])
        return NO;

    if((self.attachments && !object.attachments) || (!self.attachments && object.attachments))
        return NO;
    if(self.attachments && ![self.attachments isEqual:object.attachments])
        return NO;

    if((self.addressees && !object.addressees) || (!self.addressees && object.addressees))
        return NO;
    if(self.addressees && ![self.addressees isEqual:object.addressees])
        return NO;

    return YES;
}

- (NSUInteger)hash
{
    return self.extraHeaders.hash ^ self.messageID.hash ^ self.subject.hash ^ self.sentDate.hash ^ self.HTMLBody.hash ^ self.plainBody.hash ^ self.attachments.hash ^ self.addressees.hash;
}


@end
