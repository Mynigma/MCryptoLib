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

#import "MynigmaEncryptionEngine+MailCore.h"

#import <MailCore/MailCore.h>

#import "MynigmaMessageEncryptionContext+MailCore.h"




@implementation MynigmaEncryptionEngine (MailCore)


- (MCOAbstractMessage*)processIncomingMessage:(MCOAbstractMessage*)message
{
    MynigmaMessageEncryptionContext* context = [MynigmaMessageEncryptionContext contextForIncomingMessage:message];
    
    [self processIncomingMessageContext:context];
    
    return context.decryptedMessage;
}


- (BOOL)processPublicKeyInHeaders:(MCOAbstractMessage*)message
{
//    PublicKeyData* publicKeyData = [self.keyManager getPublicKeyDataFromHeader:message];
//    
//    if (![self.keyManager addPublicKeyWithData:publicKeyData])
//        return false;
//    
//    NSString* senderAddress = message.sender.mailbox;
//    
//    return [self.keyManager setCurrentKeyForEmailAddress:senderAddress keyLabel:publicKeyData.keyLabel overwrite:NO];
    
    return NO;
}



- (MCOAbstractMessage*)processOutgoingMessage:(MCOAbstractMessage*)message
{
    return nil;
    
    // first check if the message is safe
//    NSString* safeMessageHeaderIndicator = [message.header extraHeaderValueForName:@"X-Mynigma-Safe-Message"];
//    
//    BOOL messageIsSafe = safeMessageHeaderIndicator.length > 0;
//    
//    if (messageIsSafe)
//    {
//        MynigmaMessageEncryptionContext* context = [MynigmaMessageEncryptionContext contextForDecryptedMessage:message];
//        
//        if(![self decryptMessage:context])
//            return nil;
//        
//        return context.decryptedMessage;
//    }
//    else
//    {
//        [self processPublicKeyInHeaders:message];
//        
//        return message;
//    }
}


- (MCOAbstractMessage*)overrideErrorsForMessage:(MCOAbstractMessage*)message
{
    return nil;
}

- (MCOAttachment*)decryptAttachment:(MCOAttachment*)attachment forMessage:(MCOAbstractMessage*)message
{
    return nil;
}

- (MCOAbstractMessage*)overrideErrorsForAttachment:(MCOAttachment*)attachment message:(MCOAbstractMessage*)message
{
    return nil;
}

@end
