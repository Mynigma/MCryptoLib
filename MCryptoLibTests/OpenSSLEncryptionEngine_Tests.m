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
#import "TestHelper.h"
#import "UnitTestMynigmaKeyManager.h"
#import "OpenSSLEncryptionEngine.h"



@interface OpenSSLEncryptionEngine_Tests : XCTestCase

@end

@implementation OpenSSLEncryptionEngine_Tests


/**
 *  Test that RSA decryption of an encrypted test vector produces the expected result
 */
- (void)testRSADecryption
{
    //load a value from file
    //no point trying to compare this with an encrypted test vector
    //OAEP padding is not deterministic
    //but we can verify that decryption succeeds

    NSData* plainTestVector = [TestHelper dataForBase64ResourceWithFileName:@"108BytesData.txt"];
    XCTAssertNotNil(plainTestVector);

    NSString* keyLabel = @"TestKeyLabel1";

    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    OpenSSLEncryptionEngine* engine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:keyManager];

    NSData* encryptedTestVector = [TestHelper dataForBase64ResourceWithFileName:@"RSAEncrypted108BytesOfData.txt"];
    XCTAssertNotNil(encryptedTestVector);
    
    NSError* error = nil;
    NSData* decryptedVector = [engine RSADecryptData:encryptedTestVector withKeyLabel:keyLabel withSHA512MGF:NO error:&error];
    XCTAssertNotNil(decryptedVector);
    XCTAssertNil(error);
    
    XCTAssertEqualObjects(plainTestVector, decryptedVector);
}


/**
 *  Test that RSA encryption followed by decryption is idempotent
 */
- (void)testRSAEncryptionAndDecryption
{
    NSData* testVector = [TestHelper dataForBase64ResourceWithFileName:@"108BytesData.txt"];
    XCTAssertNotNil(testVector);
    
    NSString* keyLabel = @"TestKeyLabel1";
    
    UnitTestMynigmaKeyManager* keyManager = [UnitTestMynigmaKeyManager new];
    
    OpenSSLEncryptionEngine* engine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:keyManager];
    
    NSError* error = nil;
    NSData* encryptedTestVector = [engine RSAEncryptData:testVector withKeyLabel:keyLabel withSHA512MGF:NO error:&error];
    XCTAssertNotNil(encryptedTestVector);
    XCTAssertNil(error);
    
    NSData* decryptedTestVector = [engine RSADecryptData:encryptedTestVector withKeyLabel:keyLabel withSHA512MGF:NO error:&error];
    XCTAssertNotNil(decryptedTestVector);
    XCTAssertNil(error);
    
    XCTAssertEqualObjects(testVector, decryptedTestVector);
}

/**
 *  Test that AES encryption produces the expected result for both 127 and 128 bytes of data
 */
- (void)testAESEncryption
{
    NSData* IV = [TestHelper dataForBase64ResourceWithFileName:@"16BytesData.txt"];
    XCTAssertNotNil(IV);
    
    NSData* sessionKey = [TestHelper dataForBase64ResourceWithFileName:@"AESSessionKey1.txt"];
    XCTAssertNotNil(sessionKey);
    
    NSData* data = [TestHelper dataForBase64ResourceWithFileName:@"127BytesData.txt"];
    XCTAssertNotNil(data);
    
    OpenSSLEncryptionEngine* engine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]];
    
    NSError* error = nil;
    NSData* encryptedData = [engine AESEncryptData:data withSessionKey:sessionKey IV:IV error:&error];
    XCTAssertNil(error);
    
    NSData* resultVector = [TestHelper dataForBase64ResourceWithFileName:@"AESEncrypted127BytesData.txt"];
    XCTAssertNotNil(resultVector);
    
    XCTAssertEqualObjects(encryptedData, resultVector);
    
    data = [TestHelper dataForBase64ResourceWithFileName:@"128BytesData.txt"];
    XCTAssertNotNil(data);
    
    error = nil;
    encryptedData = [engine AESEncryptData:data withSessionKey:sessionKey IV:IV error:&error];
    XCTAssertNil(error);
    
    resultVector = [TestHelper dataForBase64ResourceWithFileName:@"AESEncrypted128BytesData.txt"];
    XCTAssertNotNil(resultVector);
    
    XCTAssertEqualObjects(encryptedData, resultVector);
}


/**
 *  Test that AES decryption produces the expected result for both 127 and 128 bytes of data
 */
- (void)testAESDecryption
{
    NSData* IV = [TestHelper dataForBase64ResourceWithFileName:@"16BytesData.txt"];
    XCTAssertNotNil(IV);
    
    NSData* sessionKey = [TestHelper dataForBase64ResourceWithFileName:@"AESSessionKey1.txt"];
    XCTAssertNotNil(sessionKey);
    
    NSData* data = [TestHelper dataForBase64ResourceWithFileName:@"AESEncrypted128BytesData.txt"];
    XCTAssertNotNil(data);
    
    OpenSSLEncryptionEngine* engine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]];
    
    NSError* error = nil;
    NSData* encryptedData = [engine AESDecryptData:data withSessionKey:sessionKey error:&error];
    XCTAssertNil(error);
    
    NSData* resultVector = [TestHelper dataForBase64ResourceWithFileName:@"128BytesData.txt"];
    XCTAssertNotNil(resultVector);
    
    XCTAssertEqualObjects(encryptedData, resultVector);
    
    //do the same for 127 bytes of data
    //this needs different padding, so the test is worthwhile
    data = [TestHelper dataForBase64ResourceWithFileName:@"AESEncrypted127BytesData.txt"];
    XCTAssertNotNil(data);
    
    error = nil;
    encryptedData = [engine AESDecryptData:data withSessionKey:sessionKey error:&error];
    XCTAssertNil(error);
    
    resultVector = [TestHelper dataForBase64ResourceWithFileName:@"127BytesData.txt"];
    XCTAssertNotNil(resultVector);
    
    XCTAssertEqualObjects(encryptedData, resultVector);
}

/**
 * Test that a valid HMAC can be verified, an invalid one cannot
 */
- (void)testValidAndInvalidHMAC
{
    NSData* messageToBeHMACed = [TestHelper dataForBase64ResourceWithFileName:@"255BytesData.txt"];
    XCTAssertNotNil(messageToBeHMACed);
    
    NSData* secret = [TestHelper dataForBase64ResourceWithFileName:@"16BytesData.txt"];
    XCTAssertNotNil(secret);
    
    NSData* HMACValue = [TestHelper dataForBase64ResourceWithFileName:@"HMACOf255BytesWith16BytesSecret.txt"];
    XCTAssertNotNil(HMACValue);
    
    OpenSSLEncryptionEngine* engine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]];
    
    XCTAssertTrue([engine verifyHMAC:HMACValue ofMessage:messageToBeHMACed withSecret:secret]);
    
    //try again with different data - the verification should fail
    messageToBeHMACed = [TestHelper dataForBase64ResourceWithFileName:@"256BytesData.txt"];
    
    XCTAssertFalse([engine verifyHMAC:HMACValue ofMessage:messageToBeHMACed withSecret:secret]);
}

/**
 * Test that the SHA512 digest function produces the expected output
 */
- (void)testSHA512Digest
{
    NSData* base64EncodedBytes = [TestHelper dataForBase64ResourceWithFileName:@"255BytesData.txt"];
    XCTAssertNotNil(base64EncodedBytes);
    
    OpenSSLEncryptionEngine* engine = [[OpenSSLEncryptionEngine alloc] initWithKeyManager:[UnitTestMynigmaKeyManager new]];

    NSData* hashValue = [engine SHA512DigestOfData:base64EncodedBytes];
    
    NSData* correctHashValue = [TestHelper dataForBase64ResourceWithFileName:@"SHA512DigestOf255BytesData.txt"];
    XCTAssertNotNil(correctHashValue);
    
    XCTAssertEqualObjects(hashValue, correctHashValue);
    
    base64EncodedBytes = [TestHelper dataForBase64ResourceWithFileName:@"108BytesData.txt"];
    XCTAssertNotNil(base64EncodedBytes);
    
    hashValue = [engine SHA512DigestOfData:base64EncodedBytes];
    
    correctHashValue = [TestHelper dataForBase64ResourceWithFileName:@"SHA512DigestOf108BytesData.txt"];
    XCTAssertNotNil(correctHashValue);
    
    XCTAssertEqualObjects(hashValue, correctHashValue);
}


@end
