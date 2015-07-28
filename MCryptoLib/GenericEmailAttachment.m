//
//  GenericEmailAttachment.m
//  Mynigma
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import "GenericEmailAttachment.h"


NSString* const contentIDKey    = @"MCryptoGenericAttachmentContentID";
NSString* const fileNameKey     = @"MCryptoGenericAttachmentFileName";
NSString* const MIMETypeKey     = @"MCryptoGenericAttachmentMIMEType";
NSString* const sizeKey         = @"MCryptoGenericAttachmentSize";
NSString* const dataKey         = @"MCryptoGenericAttachmentData";
NSString* const isInlineKey     = @"MCryptoGenericAttachmentIsInline";




@implementation GenericEmailAttachment


- (instancetype)initWithData:(NSData*)data fileName:(NSString*)fileName
{
    self = [super init];
    if (self) {
        self.data = data;
        self.fileName = fileName;
    }
    return self;
}



- (instancetype)initWithCoder:(NSCoder*)coder
{
    self = [super init];
    if (self){
        
        self.contentID = [coder decodeObjectForKey:contentIDKey];
        self.fileName = [coder decodeObjectForKey:fileNameKey];
        self.MIMEType = [coder decodeObjectForKey:MIMETypeKey];
        self.size = [coder decodeObjectForKey:sizeKey];
        self.data = [coder decodeObjectForKey:dataKey];
        self.isInline = [coder decodeObjectForKey:isInlineKey];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder*)coder
{
    [coder encodeObject:self.contentID forKey:contentIDKey];
    [coder encodeObject:self.fileName forKey:fileNameKey];
    [coder encodeObject:self.MIMEType forKey:MIMETypeKey];
    [coder encodeObject:self.size forKey:sizeKey];
    [coder encodeObject:self.data forKey:dataKey];
    [coder encodeObject:self.isInline forKey:isInlineKey];
}


@end
