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


#import <XCTest/XCTest.h>

#import <MailCore/MailCore.h>

#import "TestHelper.h"

#import "MynigmaEncryptionEngine.h"
#import "UnitTestMynigmaKeyManager.h"
#import "MynigmaMessageEncryptionContext.h"
#import "MCOAbstractMessage+Convenience.h"
#import "AppleEncryptionEngine.h"
#import "OpenSSLEncryptionEngine.h"

#import "MynigmaMessageEncryptionContext+MailCore.h"


@interface MynigmaEncryptionEngine()

- (BOOL)encryptMessage:(MynigmaMessageEncryptionContext*)context;

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context;

@end


@interface EncryptionSmokeTests : XCTestCase

@end

@implementation EncryptionSmokeTests

- (void)testEncryptingMessage1
{
    [self testEncryptingMessageWithIndex:@1];
}

- (void)testEncryptingMessage2
{
    [self testEncryptingMessageWithIndex:@2];
}

- (void)testEncryptingMessage3
{
    [self testEncryptingMessageWithIndex:@3];
}

- (void)testEncryptingMessage4
{
    [self testEncryptingMessageWithIndex:@4];
}

- (void)testEncryptingMessage5
{
    [self testEncryptingMessageWithIndex:@5];
}

- (void)testEncryptingMessage6
{
    [self testEncryptingMessageWithIndex:@6];
}

- (void)testEncryptingMessage7
{
    [self testEncryptingMessageWithIndex:@7];
}

- (void)testEncryptingMessage8
{
    [self testEncryptingMessageWithIndex:@8];
}

- (void)testEncryptingMessage9
{
    [self testEncryptingMessageWithIndex:@9];
}

- (void)testEncryptingMessage10
{
    [self testEncryptingMessageWithIndex:@10];
}

- (void)testEncryptingMessage11
{
    [self testEncryptingMessageWithIndex:@11];
}

- (void)testEncryptingMessage12
{
    [self testEncryptingMessageWithIndex:@12];
}

- (void)testEncryptingMessage13
{
    [self testEncryptingMessageWithIndex:@13];
}

- (void)testEncryptingMessage14
{
    [self testEncryptingMessageWithIndex:@14];
}

- (void)testEncryptingMessage15
{
    [self testEncryptingMessageWithIndex:@15];
}

- (void)testEncryptingMessage16
{
    [self testEncryptingMessageWithIndex:@16];
}

- (void)testEncryptingMessage17
{
    [self testEncryptingMessageWithIndex:@17];
}

- (void)testEncryptingMessage18
{
    [self testEncryptingMessageWithIndex:@18];
}

- (void)testEncryptingMessage19
{
    [self testEncryptingMessageWithIndex:@19];
}

- (void)testEncryptingMessage20
{
    [self testEncryptingMessageWithIndex:@20];
}

- (void)testEncryptingMessage21
{
    [self testEncryptingMessageWithIndex:@21];
}

- (void)testEncryptingMessage22
{
    [self testEncryptingMessageWithIndex:@22];
}

- (void)testEncryptingMessage23
{
    [self testEncryptingMessageWithIndex:@23];
}

- (void)testEncryptingMessage24
{
    [self testEncryptingMessageWithIndex:@24];
}

- (void)testEncryptingMessage25
{
    [self testEncryptingMessageWithIndex:@25];
}

- (void)testEncryptingMessage26
{
    [self testEncryptingMessageWithIndex:@26];
}

- (void)testEncryptingMessage27
{
    [self testEncryptingMessageWithIndex:@27];
}

- (void)testEncryptingMessage28
{
    [self testEncryptingMessageWithIndex:@28];
}

- (void)testEncryptingMessage29
{
    [self testEncryptingMessageWithIndex:@29];
}

- (void)testEncryptingMessage30
{
    [self testEncryptingMessageWithIndex:@30];
}



- (void)testEncryptingMessageWithIndex:(NSNumber*)index
{
    NSData* messageData = [TestHelper dataForResourceWithFileName:[NSString stringWithFormat:@"Message%@.eml", index]];
    XCTAssertNotNil(messageData);
    
    MCOMessageParser* message = [[MCOMessageParser alloc] initWithData:messageData];
    XCTAssertNotNil(message);
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new] basicEncryptionEngine:[[OpenSSLEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]]];
    
    MynigmaMessageEncryptionContext* context = [[MynigmaMessageEncryptionContext alloc] initWithUnencryptedEmailMessage:message.genericMessage];
    

    //encrypt the message with the standard sample keys
    context.signatureKeyLabel = TEST_KEY_LABEL1;
    
    context.encryptionKeyLabels = @[TEST_KEY_LABEL3, TEST_KEY_LABEL1];
    
    context.recipientEmails = @[@"testEmailAddress248253@mynigma.org", @"testEmailAddress2471253@mynigma.org"];
    
    context.expectedSignatureKeyLabels = @[@"TestKeyLabel2", @"TestKeyLabel1"];
    
    XCTAssertTrue([engine encryptMessage:context]);
    XCTAssertFalse(context.hasErrors);
    
    MynigmaMessageEncryptionContext* restoredContext = [[MynigmaMessageEncryptionContext alloc] initWithEncryptedEmailMessage:[context encryptedMessage]];
    
    XCTAssertTrue([engine decryptMessage:restoredContext insertHeaderValue:NO]);
    XCTAssertFalse(context.hasErrors);
        
    //check we got a valid result
    XCTAssertEqualObjects(message.genericMessage, restoredContext.decryptedMessage);
}

//- (void)assertStructuralEqualityOfMessage:(MCOAbstractMessage*)message1 withMessage:(MCOAbstractMessage*)message2
//{
//    NSString* HTMLPart1 = message1.HTMLBodyString;
//    NSString* HTMLPart2 = message2.HTMLBodyString;
//    
//    //not all messages have an HTML part
//    if(HTMLPart1.length || HTMLPart2.length)
//        XCTAssertEqualObjects(HTMLPart1, HTMLPart2);
//    
//    NSString* bodyPart1 = message1.plainBodyString;
//    NSString* bodyPart2 = message2.plainBodyString;
//    XCTAssertEqualObjects(bodyPart1, bodyPart2);
//    
//    NSArray* allAttachments1 = message1.allAttachments;
//    NSArray* allAttachments2 = message2.allAttachments;
//    
//    XCTAssertEqual(allAttachments1.count, allAttachments2.count);
//    
//    for(int i = 0; i < allAttachments1.count; i++)
//    {
//        MCOAttachment* attachmentPart1 = allAttachments1[i];
//        MCOAttachment* attachmentPart2 = allAttachments2[i];
//        
//        XCTAssertEqualObjects(attachmentPart1.filename, attachmentPart2.filename);
//        XCTAssertEqualObjects(attachmentPart1.data, attachmentPart2.data);
//    }
//}


@end
