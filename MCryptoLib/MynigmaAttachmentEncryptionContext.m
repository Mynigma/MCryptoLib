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


#import "MynigmaAttachmentEncryptionContext.h"

#import "BasicEncryptionEngineProtocol.h"
#import "GenericEmailAttachment.h"
#import "MimeHelper.h"

#import <MProtoBuf/FileAttachmentDataStructure.h>



@implementation MynigmaAttachmentEncryptionContext


- (instancetype)initWithEncryptedAttachment:(GenericEmailAttachment*)genericEmailAttachment
{
    self = [super init];
    if (self) {
        
        //we are interested in the metadata of the decrypted attachment
        //file name etc. won't be known at this point
        self.attachmentMetaDataStructure = [[FileAttachmentDataStructure alloc] initWithFileName:nil contentID:genericEmailAttachment.contentID size:0 hashedValue:nil partID:nil remoteURL:nil isInline:genericEmailAttachment.isInline.boolValue contentType:genericEmailAttachment.MIMEType];
        
        self.encryptedData = genericEmailAttachment.data;
    }
    return self;
}


- (instancetype)initWithUnencryptedAttachment:(GenericEmailAttachment*)genericEmailAttachment
{
    self = [super init];
    if (self) {
        
        self.attachmentMetaDataStructure = [[FileAttachmentDataStructure alloc] initWithFileName:genericEmailAttachment.fileName contentID:genericEmailAttachment.contentID size:genericEmailAttachment.size.integerValue hashedValue:nil partID:nil remoteURL:nil isInline:genericEmailAttachment.isInline.boolValue contentType:genericEmailAttachment.MIMEType];
        
        self.decryptedData = genericEmailAttachment.data;
    }
    return self;
}



- (instancetype)initWithFileName:(NSString*)fileName contentID:(NSString*)contentID decryptedData:(NSData*)decryptedData hashedValue:(NSData*)hashedValue partID:(NSString*)partID remoteURLString:(NSString*)remoteURLString isInline:(BOOL)isInline contentType:(NSString*)contentType
{
    self = [super init];
    if (self) {
        
        self.attachmentMetaDataStructure = [[FileAttachmentDataStructure alloc] initWithFileName:fileName contentID:contentID size:decryptedData.length hashedValue:hashedValue partID:partID remoteURL:remoteURLString isInline:isInline contentType:contentType];
        
        self.decryptedData = decryptedData;
        
        self.isMissing = NO;
        self.isSuperfluous = NO;
    }
    return self;
}



+ (MynigmaAttachmentEncryptionContext*)contextForMissingAttachment
{
    MynigmaAttachmentEncryptionContext* newContext = [MynigmaAttachmentEncryptionContext new];
    
    newContext.isMissing = YES;
    				
    return newContext;
}

+ (MynigmaAttachmentEncryptionContext*)contextForSuperfluousAttachment
{
    MynigmaAttachmentEncryptionContext* newContext = [MynigmaAttachmentEncryptionContext new];
    
    newContext.isSuperfluous = YES;
    
    return newContext;
}




- (GenericEmailAttachment*)encryptedAttachmentWithIndex:(NSInteger)index
{
    GenericEmailAttachment* genericAttachment = [GenericEmailAttachment new];
    
    [genericAttachment setContentID:self.attachmentMetaDataStructure.contentID];
    [genericAttachment setData:self.encryptedData];
    [genericAttachment setFileName:[NSString stringWithFormat:NSLocalizedString(@"%ld.myn", @"Safe attachment file name"), (long)index]];
    [genericAttachment setIsInline:@(self.attachmentMetaDataStructure.isInline)];
    [genericAttachment setMIMEType:MIME_TYPE_ENCRYPTED_ATTACHMENTS];
    [genericAttachment setSize:@(self.attachmentMetaDataStructure.size)];
    
    return genericAttachment;
}

- (GenericEmailAttachment*)decryptedAttachment
{
    if([self isMissing])
    {
        GenericEmailAttachment* genericAttachment = [GenericEmailAttachment new];
        
        [genericAttachment setContentID:self.attachmentMetaDataStructure.contentID];
        [genericAttachment setData:[NSData new]];
        [genericAttachment setFileName:[NSString stringWithFormat:NSLocalizedString(@"Missing attachment", @"Missing safe attachment replacement name"), (long)index]];
        [genericAttachment setIsInline:@YES];
        [genericAttachment setMIMEType:self.attachmentMetaDataStructure.contentType];
        [genericAttachment setSize:0];
        
        return genericAttachment;
    }
    
    if([self isSuperfluous])
    {
        GenericEmailAttachment* genericAttachment = [GenericEmailAttachment new];
        
        [genericAttachment setContentID:self.attachmentMetaDataStructure.contentID];
        [genericAttachment setData:[NSData new]];
        [genericAttachment setFileName:[NSString stringWithFormat:NSLocalizedString(@"Superfluous attachment", @"Superfluous safe attachment replacement name"), (long)index]];
        [genericAttachment setIsInline:@YES];
        [genericAttachment setMIMEType:self.attachmentMetaDataStructure.contentType];
        [genericAttachment setSize:0];
        
        return genericAttachment;
    }
    
    GenericEmailAttachment* genericAttachment = [GenericEmailAttachment new];
    
    [genericAttachment setContentID:self.attachmentMetaDataStructure.contentID];
    [genericAttachment setData:self.decryptedData];
    [genericAttachment setFileName:self.attachmentMetaDataStructure.fileName];
    [genericAttachment setIsInline:@(self.attachmentMetaDataStructure.isInline)];
    [genericAttachment setMIMEType:self.attachmentMetaDataStructure.contentType];
    [genericAttachment setSize:@(self.attachmentMetaDataStructure.size)];
    
    return genericAttachment;
}

@end
