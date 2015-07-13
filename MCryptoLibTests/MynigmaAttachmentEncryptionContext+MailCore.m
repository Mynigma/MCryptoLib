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

#import "MynigmaAttachmentEncryptionContext+MailCore.h"

#import <MailCore/MailCore.h>


@implementation MynigmaAttachmentEncryptionContext (MailCore)

+ (MynigmaAttachmentEncryptionContext*)contextForDecryptedAttachment:(MCOAttachment*)attachment
{
    NSString* fileName = attachment.filename;
    
    NSString* contentID = attachment.contentID;
    
    NSData* data = attachment.data;
    
    BOOL isInline = attachment.isInlineAttachment;
    
    //se this later
    //    NSData* hashedValue = [basicEngine SHA512DigestOfData:data];
    
    NSString* contentType = attachment.mimeType;
    
    MynigmaAttachmentEncryptionContext* newContext = [[MynigmaAttachmentEncryptionContext alloc] initWithFileName:fileName contentID:contentID decryptedData:data hashedValue:nil partID:nil remoteURLString:nil isInline:isInline contentType:contentType];
    
    return newContext;
}

+ (MynigmaAttachmentEncryptionContext*)contextForEncryptedAttachment:(MCOAttachment*)encryptedAttachment
{
    MynigmaAttachmentEncryptionContext* newContext = [MynigmaAttachmentEncryptionContext new];
    
    newContext.encryptedData = encryptedAttachment.data;
    
    newContext.attachmentMetaDataStructure = [FileAttachmentDataStructure new];
    
    newContext.attachmentMetaDataStructure.contentID = encryptedAttachment.contentID;
    
    if(!newContext.encryptedData)
        return nil;
				
    return newContext;
}


- (MCOAttachment*)encryptedMimePart:(NSNumber*)index
{
    if([self encryptedData].length == 0)
        return nil;
    
    NSString* fileName = [NSString stringWithFormat:@"%@.myn", index];
    
    MCOAttachment* attachment = [MCOAttachment attachmentWithData:[self encryptedData] filename:fileName];
    
    [attachment setContentID:self.attachmentMetaDataStructure.contentID];
    [attachment setInlineAttachment:NO];
    [attachment setMimeType:@"application/mynigma-attachment"];
    
    return attachment;
}


- (MCOAttachment*)decryptedMimePart
{
    if([self decryptedData].length == 0)
        return nil;
    
    MCOAttachment* attachment = [MCOAttachment attachmentWithData:self.decryptedData filename:self.attachmentMetaDataStructure.fileName];
    [attachment setContentID:self.attachmentMetaDataStructure.contentID];
    [attachment setInlineAttachment:self.attachmentMetaDataStructure.isInline];
    [attachment setMimeType:self.attachmentMetaDataStructure.contentType];
    
    return attachment;
}


@end
