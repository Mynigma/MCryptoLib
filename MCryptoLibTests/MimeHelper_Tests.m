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
#import "MimeHelper.h"
#import "TestHelper.h"
#import "MCOAbstractMessage+Convenience.h"



@interface MimeHelper_Tests : XCTestCase

@end

@implementation MimeHelper_Tests

- (void)testGenerateMessageIDs
{
    NSString* messageID1 = [MimeHelper generateFreshMessageID];
    XCTAssertNotNil(messageID1);
    
    NSString* messageID2 = [MimeHelper generateFreshMessageID];
    XCTAssertNotNil(messageID2);
    
    XCTAssertNotEqualObjects(messageID1, messageID2);
}

- (void)testMessage1
{
    NSData* data = [TestHelper dataForResourceWithFileName:@"TestMessage1.txt"];
    
    MCOMessageParser* message = [[MCOMessageParser alloc] initWithData:data];

    XCTAssertEqual(4, message.allAttachments.count);
    
    XCTAssertEqual(1, message.inlineAttachments.count);
    
    XCTAssertEqual(3, message.explicitAttachments.count);
    
    NSString* plainBody = message.plainBodyString;
    XCTAssertNotNil(plainBody);
    
    NSString* HTMLBody = message.HTMLBodyString;
    XCTAssertNotNil(HTMLBody);
    
    NSData* payload = message.encryptedPayload;
    XCTAssertNotNil(payload);
    
    MCOAddress* senderEmail = message.sender;
    XCTAssertEqualObjects(@"jakob.sacher@gmx.de", senderEmail.mailbox);
}


- (void)testMessage2
{
    NSData* data = [TestHelper dataForResourceWithFileName:@"TestMessage2.txt"];
    
    MCOMessageParser* message = [[MCOMessageParser alloc] initWithData:data];
    
    XCTAssertEqual(2, message.allAttachments.count);
    
    XCTAssertEqual(0, message.inlineAttachments.count);

    XCTAssertEqual(2, message.explicitAttachments.count);
    
    NSString* plainBody = message.plainBodyString;
    XCTAssertNotNil(plainBody);
    
    NSString* HTMLBody = message.HTMLBodyString;
    XCTAssertNotNil(HTMLBody);
    
    NSData* payload = message.encryptedPayload;
    XCTAssertNil(payload);
    
    MCOAddress* senderEmail = message.sender;
    XCTAssertEqualObjects(@"newsletter@bitmi.de", senderEmail.mailbox);
}


- (void)testMessage3
{
    NSData* data = [TestHelper dataForResourceWithFileName:@"TestMessage3.txt"];
    
    MCOMessageParser* message = [[MCOMessageParser alloc] initWithData:data];
    
    XCTAssertEqual(1, message.allAttachments.count);
    
    XCTAssertEqual(1, message.inlineAttachments.count);
    
    XCTAssertEqual(0, message.explicitAttachments.count);
    
    NSString* plainBody = message.plainBodyString;
    XCTAssertNotNil(plainBody);
    
    NSString* HTMLBody = message.HTMLBodyString;
    XCTAssertNotNil(HTMLBody);
    
    NSData* payload = message.encryptedPayload;
    XCTAssertNil(payload);
    
    MCOAddress* senderEmail = message.sender;
    XCTAssertEqualObjects(@"viola.fechner@coachingbonus.de", senderEmail.mailbox);
}


//- (void)testUnencryptedSampleMessage
//{
//    MCOMessageParser* message = TestHelper.sampleMessage();
//    assertNotNull(message);
//    
//    assertEquals(0, MimeHelper.getAllAttachmentsForMessage(message).size());
//    assertEquals(0, MimeHelper.getEncryptedAttachmentsForMessage(message).size());
//    assertNull(MimeHelper.getEncryptedPayload(message));
//    assertEquals(0, MimeHelper.getExplicitAttachmentsForMessage(message).size());
//}



- (void)testGetMIMETypeForFileName
{
    XCTAssertEqualObjects(@"image/jpeg", [MCOAttachment mimeTypeForFilename:@"someFile.jpg"]);
    XCTAssertEqualObjects(@"image/png", [MCOAttachment mimeTypeForFilename:@"someFile.png"]);
    XCTAssertEqualObjects(@"application/pdf", [MCOAttachment mimeTypeForFilename:@"someFile.pdf"]);
    XCTAssertEqualObjects(@"application/zip", [MCOAttachment mimeTypeForFilename:@"someFile.zip"]);
    XCTAssertEqualObjects(@"text/plain", [MCOAttachment mimeTypeForFilename:@"someFile.txt"]);
    XCTAssertEqualObjects(@"text/html", [MCOAttachment mimeTypeForFilename:@"someFile.html"]);
}

@end
