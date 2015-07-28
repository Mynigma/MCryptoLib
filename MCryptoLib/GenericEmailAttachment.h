//
//  GenericEmailAttachment.h
//  Mynigma
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import <Foundation/Foundation.h>


@interface GenericEmailAttachment : NSObject <NSCoding>

- (instancetype)initWithData:(NSData*)data fileName:(NSString*)fileName;


@property NSString* contentID;
@property NSString* fileName;
@property NSString* MIMEType;
@property NSNumber* size;
@property NSData* data;
@property NSNumber* isInline;

@end
