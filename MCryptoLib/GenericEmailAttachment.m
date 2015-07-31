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



- (BOOL)isEqual:(GenericEmailAttachment*)object
{
    if(object == self)
        return YES;
    
    if(![object isKindOfClass:[GenericEmailAttachment class]])
        return NO;
    
    if((self.contentID && !object.contentID) || (!self.contentID && object.contentID))
        return NO;
    if(self.contentID && ![self.contentID isEqual:object.contentID])
        return NO;
    
    if((self.fileName && !object.fileName) || (!self.fileName && object.fileName))
        return NO;
    if(self.fileName && ![self.fileName isEqual:object.fileName])
        return NO;

    if((self.MIMEType && !object.MIMEType) || (!self.MIMEType && object.MIMEType))
        return NO;
    if(self.MIMEType && ![self.MIMEType isEqual:object.MIMEType])
        return NO;

    if((self.size && !object.size) || (!self.size && object.size))
        return NO;
    if(self.size && ![self.size isEqual:object.size])
        return NO;

    if((self.data && !object.data) || (!self.data && object.data))
        return NO;
    if(self.data && ![self.data isEqual:object.data])
        return NO;

    if((self.isInline && !object.isInline) || (!self.isInline && object.isInline))
        return NO;
    if(self.isInline && ![self.isInline isEqual:object.isInline])
        return NO;

    return YES;
}


- (NSUInteger)hash
{
    return self.contentID.hash ^ self.fileName.hash ^ self.MIMEType.hash ^ self.size.hash ^ self.data.hash ^ self.isInline.hash;
}

@end
