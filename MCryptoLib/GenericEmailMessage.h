//
//  GenericEmailMessage.h
//  Mynigma
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import <Foundation/Foundation.h>




@class GenericEmailAttachment;

@interface GenericEmailMessage : NSObject <NSCoding>


@property NSDictionary* extraHeaders;

@property NSString* messageID;

@property NSString* subject;
@property NSDate* sentDate;

@property NSString* HTMLBody;
@property NSString* plainBody;

@property NSArray* attachments;


@property NSArray* addressees;


- (void)addAttachment:(GenericEmailAttachment*)attachment;

- (NSData*)encryptedPayload;
- (NSArray*)encryptedAttachments;

- (NSString*)senderEmail;


@end
