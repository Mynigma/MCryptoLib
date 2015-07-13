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
#import "UnitTestMynigmaKeyManager.h"
#import "MynigmaEncryptionEngine.h"
#import "TestHelper.h"







@interface MynigmaEncryptionEngine()

- (NSData*)introductionDataFromKeyLabel:(NSString*)oldKeyLabel toKeyLabel:(NSString*)newKeyLabel;

- (NSData*)introductionDataFromKeyLabel:(NSString*)oldKeyLabel toKeyLabel:(NSString*)newKeyLabel date:(NSDate*)date version:(NSString*)version;

- (BOOL)processIntroductionData:(NSData*)introductionData fromEmail:(NSString*)senderEmailString;

- (BOOL)encryptMessage:(MynigmaMessageEncryptionContext*)context;

- (BOOL)decryptMessage:(MynigmaMessageEncryptionContext*)context;

@end





@interface MynigmaEncryptionEngine_Tests : XCTestCase

@end

@implementation MynigmaEncryptionEngine_Tests

/**
 * Test that a generated key introduction correctly changes current key when processed
 */
- (void)testGenerateAndProcessKeyIntroduction
{
    NSString* oldKeyLabel = @"TestKeyLabel2";
    NSString* newKeyLabel = @"TestKeyLabel1";
    
    NSString* senderEmail = @"testEmail32742@mynigma.org";
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
    
    NSData* keyIntroduction = [engine introductionDataFromKeyLabel:oldKeyLabel toKeyLabel:newKeyLabel];
    
    XCTAssertNotNil(keyIntroduction);
    
    [keyManager setCurrentKeyForEmailAddress:senderEmail keyLabel:oldKeyLabel overwrite:YES];
    
    XCTAssertEqualObjects(oldKeyLabel, [keyManager currentKeyLabelForEmailAddress:senderEmail]);
    
    XCTAssertTrue([engine processIntroductionData:keyIntroduction fromEmail:senderEmail]);

    XCTAssertEqualObjects(newKeyLabel, [keyManager currentKeyLabelForEmailAddress:senderEmail]);
}


/**
 * Test that key introductions from the current key to another lead to update of the current key
 */
- (void)testProcessValidKeyIntroduction
{
    NSData* keyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel2.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
    
    NSString* testEmail = @"testEmail@ddress.com";
    
    [keyManager setCurrentKeyForEmailAddress:testEmail keyLabel:@"TestKeyLabel1" overwrite:YES];
    
    XCTAssertEqualObjects(@"TestKeyLabel1", [keyManager currentKeyLabelForEmailAddress:testEmail]);
    
    [engine processIntroductionData:keyIntroductionData fromEmail:testEmail];
    
    XCTAssertEqualObjects(@"TestKeyLabel2", [keyManager currentKeyLabelForEmailAddress:testEmail]);
}

/**
 * Test that an introduction from a key that is not the current one has no effect
 */
- (void)testProcessKeyIntroductionFromNonCurrentKey
{
    NSData* keyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel2.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
				
    NSString* testEmail = @"testEmail98726425@random.address.com";
    
    [keyManager setCurrentKeyForEmailAddress:testEmail keyLabel:@"TestKeyLabel3" overwrite:YES];
     
     XCTAssertEqualObjects(@"TestKeyLabel3", [keyManager currentKeyLabelForEmailAddress:testEmail]);
    
    [engine processIntroductionData:keyIntroductionData fromEmail:testEmail];
    
    XCTAssertEqualObjects(@"TestKeyLabel3", [keyManager currentKeyLabelForEmailAddress:testEmail]);
}

/**
 * Test that a key introduction from an address with no current key updates the key
 */
- (void)testProcessKeyIntroductionWithPreviouslyUnknownSender
{
    NSData* keyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel2.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
				
    NSString* testEmail = @"testEmail4352345@random.address.com";
    
    XCTAssertNil([keyManager currentKeyLabelForEmailAddress:testEmail]);
    
    [engine processIntroductionData:keyIntroductionData fromEmail:testEmail];
    
    XCTAssertEqualObjects(@"TestKeyLabel2", [keyManager currentKeyLabelForEmailAddress:testEmail]);
}

/**
 * Test generating key introduction data from TestKeyLabel1 to TestKeyLabel2 and comparing it to expected data
 */
- (void)testGeneratingKeyIntroductionData
{
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]];
    
    NSDate* testDate = [NSDate dateWithTimeIntervalSince1970:12345678];
    
    NSData* keyIntroductionData = [engine introductionDataFromKeyLabel:@"TestKeyLabel1" toKeyLabel:@"TestKeyLabel2" date:testDate version:@"TestVersion"];
    XCTAssertNotNil(keyIntroductionData);
    
    NSData* expectedKeyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel2.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    XCTAssertEqualObjects(expectedKeyIntroductionData, keyIntroductionData);
}

/**
 * Test generating key self-introduction data from TestKeyLabel1 to itself and comparing it to expected data
 */
- (void)testGeneratingKeySelfIntroductionData
{
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]];
    
    NSDate* testDate = [NSDate dateWithTimeIntervalSince1970:12345678];
    
    NSData* keyIntroductionData = [engine introductionDataFromKeyLabel:@"TestKeyLabel1" toKeyLabel:@"TestKeyLabel1" date:testDate version:@"TestVersion"];
    XCTAssertNotNil(keyIntroductionData);
    
    NSData* expectedKeyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel1.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    XCTAssertEqualObjects(expectedKeyIntroductionData, keyIntroductionData);
}

/**
 * Test that self-introduction from a key that is not the current one has no effect
 */
- (void)testProcessKeySelfIntroductionFromNonCurrentKey
{
    NSData* keyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel1.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
				
    NSString* testEmail = @"testEmail92342561425@random.address.com";
    
    [keyManager setCurrentKeyForEmailAddress:testEmail keyLabel:@"TestKeyLabel3" overwrite:YES];
    
    XCTAssertEqualObjects(@"TestKeyLabel3", [keyManager currentKeyLabelForEmailAddress:testEmail]);
    
    [engine processIntroductionData:keyIntroductionData fromEmail:testEmail];
    
    XCTAssertEqualObjects(@"TestKeyLabel3", [keyManager currentKeyLabelForEmailAddress:testEmail]);
}

/**
 * Test that self-introduction updates key if no current one is set
 */
- (void)testProcessKeySelfIntroductionWithoutCurrentKey
{
    NSData* keyIntroductionData = [TestHelper dataForBase64ResourceWithFileName:@"KeyIntroductionFromTestKeyLabel1ToTestKeyLabel1.txt"];
    XCTAssertNotNil(keyIntroductionData);
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    MynigmaEncryptionEngine* engine = [[MynigmaEncryptionEngine alloc] initWithKeyManager:keyManager];
				
    NSString* testEmail = @"testEmail98725436425@random.address.com";
    
    XCTAssertNil([keyManager currentKeyLabelForEmailAddress:testEmail]);
    
    [engine processIntroductionData:keyIntroductionData fromEmail:testEmail];
    
    XCTAssertEqualObjects(@"TestKeyLabel1", [keyManager currentKeyLabelForEmailAddress:testEmail]);
}

@end
