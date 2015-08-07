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
#import <MCryptoLib/EncryptionEngineProtocol.h>
#import <MCryptoLib/MynigmaKeyManager.h>
#import <MCryptoLib/BasicEncryptionEngineProtocol.h>


#define MCryptoSafeMessageHeaderField @"x-mynigma-safe-message"
#define MCryptoWillBeSentSafelyHeaderField @"x-mynigma-will-be-sent-safely"
#define MCryptoWasSentSafelyHeaderField @"x-mynigma-was-sent-safely"


@class MynigmaMessageEncryptionContext, MynigmaAttachmentEncryptionContext, MCOAbstractMessage, MCOAttachment, GenericEmailMessage;


@interface MynigmaEncryptionEngine : NSObject <EncryptionEngineProtocol>



/**
 *  The shared instance. You typically want to use this.
 *
 *  @return A shared instance of @c MynigmaEncryptionEngine
 */
+ (instancetype)sharedInstance;




@property MynigmaKeyManager* keyManager;
@property id<BasicEncryptionEngineProtocol> basicEngine;

- (instancetype)initWithKeyManager:(MynigmaKeyManager*)keyManager basicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine;
- (instancetype)initWithKeyManager:(MynigmaKeyManager*)keyManager;
- (instancetype)initWithBasicEncryptionEngine:(id<BasicEncryptionEngineProtocol>)basicEngine;



- (BOOL)encryptMessage:(MynigmaMessageEncryptionContext*)context;

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context;
- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context insertHeaderValue:(BOOL)insertHeaderValue;

- (MynigmaAttachmentEncryptionContext*)decryptAttachmentData:(NSData*)attachmentData forMessageID:(NSString*)messageID atIndex:(NSNumber*)index error:(NSError**)error;


- (BOOL)isSenderSafe:(NSString*)senderEmailString;

- (BOOL)isRecipientSafe:(NSString*)recipientEmailString;

- (BOOL)areRecipientsSafe:(NSArray*)recipientEmailStrings;

- (void)ensureValidCurrentKeyForSender:(NSString*)senderEmailString;



- (GenericEmailMessage*)processIncomingMessage:(GenericEmailMessage*)message;

- (GenericEmailMessage*)processOutgoingMessage:(GenericEmailMessage*)message withHeaderField:(BOOL)hasHeaderField didEncrypt:(BOOL*)didEncrypt;

- (GenericEmailMessage*)processOutgoingMessage:(GenericEmailMessage*)message;

@end
