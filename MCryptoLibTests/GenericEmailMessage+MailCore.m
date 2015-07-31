//
//  GenericEmailMessage+MailCore.m
//  MCryptoLib
//
//  Created by Roman Priebe on 30/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import "GenericEmailMessage+MailCore.h"

#import <MailCore/MailCore.h>

#import <MProtoBuf/EmailRecipientDataStructure.h>




@implementation GenericEmailMessage (MailCore)

- (MCOAbstractMessage*)MCOMessage
{
    MCOMessageBuilder* message = [MCOMessageBuilder new];
    
    [message setHTMLBody:self.HTMLBody];
    [message setTextBody:self.plainBody];
    
    [message.header setDate:self.sentDate];
    [message.header setMessageID:self.messageID];
    [message.header setSubject:self.subject];
    
    
    NSMutableArray* replyToAddresses = [NSMutableArray new];
    NSMutableArray* toAddresses = [NSMutableArray new];
    NSMutableArray* ccAddresses = [NSMutableArray new];
    NSMutableArray* bccAddresses = [NSMutableArray new];
    
    for(GenericEmailAddressee* addressee in self.addressees)
    {
        MCOAddress* MCOAddressee = [MCOAddress addressWithDisplayName:addressee.name mailbox:addressee.address];
        
        switch (addressee.addresseeType.integerValue) {
            case AddresseeTypeFrom:
                [message.header setSender:MCOAddressee];
                break;
            case AddresseeTypeReplyTo:
                [replyToAddresses addObject:MCOAddressee];
                break;
            case AddresseeTypeTo:
                [toAddresses addObject:MCOAddressee];
                break;
            case AddresseeTypeCc:
                [ccAddresses addObject:MCOAddressee];
                break;
            case AddresseeTypeBcc:
                [bccAddresses addObject:MCOAddressee];
                break;
            default:
                break;
        }
    }
    
    [message.header setReplyTo:replyToAddresses];
    [message.header setTo:toAddresses];
    [message.header setCc:ccAddresses];
    [message.header setBcc:bccAddresses];
    
    
    for(GenericEmailAttachment* genericAttachment in self.attachments)
    {
        MCOAttachment* attachment  = [MCOAttachment new];
        
        [attachment setContentID:genericAttachment.contentID];
        [attachment setData:genericAttachment.data];
        [attachment setFilename:genericAttachment.fileName];
        [attachment setInlineAttachment:genericAttachment.isInline.boolValue];
        [attachment setMimeType:genericAttachment.MIMEType];
        
        [message addAttachment:attachment];
    }
    
    return message;
}


@end
