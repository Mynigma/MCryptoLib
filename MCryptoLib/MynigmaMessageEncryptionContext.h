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


#import <Foundation/Foundation.h>

#import "MynigmaError.h"


@class SessionKeys, PayloadPartDataStructure, MCOAbstractMessage, GenericEmailMessage;

@interface MynigmaMessageEncryptionContext : NSObject <NSCoding>


- (instancetype)initWithUnencryptedEmailMessage:(GenericEmailMessage*)genericEmailMessage;

- (instancetype)initWithEncryptedEmailMessage:(GenericEmailMessage*)genericEmailMessage;


- (GenericEmailMessage*)encryptedMessage;

- (GenericEmailMessage*)decryptedMessage;



+ (MynigmaMessageEncryptionContext*)contextForDecryptedDeviceMessageWithPayload:(NSData*)payloadData;





//decrypted messages have their payload part set, containing body, subject, attachment meta data, etc...
@property PayloadPartDataStructure* payloadPart;


@property NSData* decryptedData;

@property NSData* signedPayload;

//encrypted messages have this set to the content of outermost HMAC structure
@property NSData* encryptedPayload;

//the attachment encryption contexts keep track of all data needed to encrypt/decrypt attachments
@property NSArray* attachmentEncryptionContexts;


//used to fill the template for safe messages
@property NSString* senderName;
@property NSString* senderEmail;
@property NSString* messageID;
@property NSDate* sentDate;


@property NSDictionary* extraHeaders;


//force particular boundary strings to ensure reproducibility of exact message data for unit tests
@property NSString* alternativePartBoundary;
@property NSString* relatedPartBoundary;
@property NSString* mainBoundary;



//used to generate encrypted session key table
@property NSString* signatureKeyLabel;
@property NSArray* expectedSignatureKeyLabels;
@property NSArray* encryptionKeyLabels;
@property NSArray* recipientEmails;


//remember these for attachment decryption
@property SessionKeys* sessionKeys;

@property NSArray* attachmentHMACValues;


@property NSMutableArray* errors;


- (void)pushErrorWithCode:(MynigmaErrorCode)code;

- (BOOL)hasErrors;


@end
