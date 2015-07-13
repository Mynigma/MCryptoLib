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


#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "MynigmaKeyManager.h"
#import "UnitTestKeychainHelper.h"
#import "TestHelper.h"
#import <MailCore/MailCore.h>
#import "MynigmaEncryptionEngine.h"
#import "MCOAbstractMessage+Convenience.h"



@interface MynigmaKeyManager_Tests : XCTestCase

@end

@implementation MynigmaKeyManager_Tests

/**
 * Test that an attempt to update the expected key with a future anchor date fails
 */
- (void)testThatExpectedKeyUpdateFailsForFutureAnchorDate
{
    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];
    
    NSString* senderEmail = @"senderEmail347284@mynigma.org";
    NSString* recipientEmail = @"senderEmail89927284@mynigma.org";
    NSString* keyLabel = @"testKeyLabel3247348295";
    
    NSDate* date = [NSDate dateWithTimeIntervalSinceNow:10];
    
    [keyManager updateExpectedKeyLabelFrom:senderEmail to:recipientEmail keyLabel:keyLabel date:date];
    
    NSString* expectedKeyLabel = [keyManager expectedKeyLabelFrom:senderEmail to:recipientEmail];
    
    XCTAssertNil(expectedKeyLabel);
}

/**
 * Test that key update without an anchor date uses current date
 */
- (void)testThatUpdatingExpectedKeyFillsInMissingAnchorDate
{
    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];
    
    NSString* senderEmail = @"senderEmail347284@mynigma.org";
    NSString* recipientEmail = @"senderEmail89927284@mynigma.org";
    NSString* keyLabel = @"testKeyLabel3247348295";
    
    [keyManager addPublicKeyWithData:[TestHelper publicKeyData:@1 withKeyLabel:keyLabel]];

    XCTAssertTrue([keyManager updateExpectedKeyLabelFrom:senderEmail to:recipientEmail keyLabel:keyLabel date:nil]);
    
    NSDate* anchorDate = [keyManager anchorDateFrom:senderEmail to:recipientEmail];
    
    XCTAssertNotNil(anchorDate);
}

/**
 * Test that an attempt to update the expected key with an outdated anchor date fails
 */
- (void)testThatKeyWithNewerAnchorDateIsNotOverwritten
{
    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];
    
    NSString* senderEmail = @"senderEmail347284@mynigma.org";
    NSString* recipientEmail = @"senderEmail89927284@mynigma.org";
    NSString* oldKeyLabel = @"testKeyLabel3247348295";
    NSString* newKeyLabel = @"testKeyLabel3482347283717";
    
    [keyManager addPublicKeyWithData:[TestHelper publicKeyData:@1 withKeyLabel:oldKeyLabel]];
    
    [keyManager addPublicKeyWithData:[TestHelper publicKeyData:@2 withKeyLabel:newKeyLabel]];
    
    NSDate* oldDate = [NSDate dateWithTimeIntervalSince1970:1234567];
    
    NSDate* newDate = [NSDate dateWithTimeIntervalSince1970:1000000];
    
    [keyManager setExpectedKeyLabelFrom:senderEmail to:recipientEmail keyLabel:oldKeyLabel date:oldDate overwrite:YES];
    
    NSString* expectedKeyLabel = [keyManager expectedKeyLabelFrom:senderEmail to:recipientEmail];
    NSDate* anchorDate = [keyManager anchorDateFrom:senderEmail to:recipientEmail];
    
    XCTAssertEqualObjects(oldKeyLabel, expectedKeyLabel);
    XCTAssertEqualObjects(oldDate, anchorDate);
    
    XCTAssertFalse([keyManager updateExpectedKeyLabelFrom:senderEmail to:recipientEmail keyLabel:newKeyLabel date:newDate]);
    
    expectedKeyLabel = [keyManager expectedKeyLabelFrom:senderEmail to:recipientEmail];
    anchorDate = [keyManager anchorDateFrom:senderEmail to:recipientEmail];
    
    XCTAssertEqualObjects(oldKeyLabel, expectedKeyLabel);
    XCTAssertEqualObjects(oldDate, anchorDate);
}


/**
 * Test that processing an incoming message causes a key update, if applicable
 */
- (void)testThatReceiptOfMessageCausesExpectationUpdate
{
    NSData* messageData = [TestHelper dataForBase64ResourceWithFileName:@"EncryptedSampleMessage.txt"];
    XCTAssertNotNil(messageData);
    
    MCOMessageParser* message = [[MCOMessageParser alloc] initWithData:messageData];
    XCTAssertNotNil(message);
    
    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];

    XCTAssertTrue([keyManager addPrivateKeyWithData:[TestHelper privateKeyData:@1 withKeyLabel:@"TestKeyLabel1"]]);
    XCTAssertTrue([keyManager addPrivateKeyWithData:[TestHelper privateKeyData:@3 withKeyLabel:@"TestKeyLabel3"]]);
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
    
    XCTAssertNotNil([engine processIncomingMessage:message]);
    
    NSString* senderEmail = message.sender.mailbox;
    NSString* recipientEmail = [message.allRecipients.firstObject mailbox];
    
    NSString* expectedKeyLabel = [keyManager expectedKeyLabelFrom:senderEmail to:recipientEmail];
    XCTAssertNotNil(expectedKeyLabel);
    
    XCTAssertEqualObjects(@"TestKeyLabel3", expectedKeyLabel);
}








/**
 * Test that parsing a valid key introduction updates the current key
 */
- (void)testThatParsedIntroductionWithValidSignatureUpdatesCurrentKey
{
    NSData* messageData = [TestHelper dataForBase64ResourceWithFileName:@"EncryptedSampleMessage.txt"];
    XCTAssertNotNil(messageData);
    
    MCOMessageParser* message = [[MCOMessageParser alloc] initWithData:messageData];
    XCTAssertNotNil(message);
    
    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];

    XCTAssertTrue([keyManager addPrivateKeyWithData:[TestHelper privateKeyData:@1 withKeyLabel:@"TestKeyLabel1"]]);
    XCTAssertTrue([keyManager addPrivateKeyWithData:[TestHelper privateKeyData:@2 withKeyLabel:@"TestKeyLabel2"]]);
    XCTAssertTrue([keyManager addPrivateKeyWithData:[TestHelper privateKeyData:@3 withKeyLabel:@"TestKeyLabel3"]]);
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
    
    XCTAssertNotNil([engine processIncomingMessage:message]);
    
    NSString* senderEmail = message.sender.mailbox;
    XCTAssertNotNil(senderEmail);
    
    NSString* currentKeyLabel = [keyManager currentKeyLabelForEmailAddress:senderEmail];
    XCTAssertEqualObjects(@"TestKeyLabel1", currentKeyLabel);
}


///**
// * Test basic key expectation behaviour
// */
//- (void)testKeyExpectations
//{
//    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];
//    
//    NSString* fromEmail = @"from@example.com";
//    NSString* toEmail = @"to@example.com";
//    
//    XCTAssertNil([keyManager expectedKeyLabelFrom:fromEmail to:toEmail]);
//    
//    NSString* keyLabel = @"keyLabel@mynimga.org";
//    NSDate* date = [NSDate dateWithTimeIntervalSince1970:123456];
//    
//    [keyManager updateExpectedKeyLabelFrom:fromEmail to:toEmail keyLabel:keyLabel date:date];
//    
//    XCTAssertEqualObjects(@", <#expression2, ...#>)
//    
//}



/**
 * Test that easy reading fingerprint generated for sample keys matches expectation
 */
- (void)testEasyReadingFingerprint
{
    MynigmaKeyManager* keyManager = [[MynigmaKeyManager alloc] initWithKeychainHelper:[UnitTestKeychainHelper new]];
    
    PublicKeyData* sampleKey1 = [TestHelper publicKeyData:@3 withKeyLabel:@"TestKeyLabel3"];
    
    [keyManager addPublicKeyWithData:sampleKey1];
    
    NSString* easyReadingFingerprint = [keyManager easyReadingFingerprintForKeyWithLabel:@"TestKeyLabel3"];
    
    XCTAssertNotNil(easyReadingFingerprint);
    XCTAssertNotEqualObjects(easyReadingFingerprint, @"-- error --");
}



@end
