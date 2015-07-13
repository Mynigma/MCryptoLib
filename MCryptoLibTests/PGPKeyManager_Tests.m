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

#import "CommonHeader.h"

#import "PGPKeyManager.h"



@interface PGPKeyManager()

+ (NSData*)dataFromHexString:(NSString*)hexString;

@end


@interface PGPKeyManager_Tests : XCTestCase

@end

@implementation PGPKeyManager_Tests





- (void)testDataFromHexString
{
    //unsuitable characters should be stripped
    NSString* testString = @"/:01 23 45 67 89 0a Bc dE ffttg`";
    
    NSData* testData = [PGPKeyManager dataFromHexString:testString];
    
    unsigned char expectedBytes[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xFF };

    NSData* expectedData = [NSData dataWithBytes:expectedBytes length:9];
    
    XCTAssertEqualObjects(testData, expectedData);
}





#pragma mark - Public key import


- (void)performPublicKeyTest:(NSNumber*)index
{
    NSString* fileName = [NSString stringWithFormat:@"PGPPublicKey%@", index];
    
    NSURL* fileURL = [BUNDLE URLForResource:fileName withExtension:@""];
    
    XCTAssertNotNil(fileURL);
    
    PGPKeyManager* keyManager = [PGPKeyManager new];
    
    NSInteger numberOfKeys = [keyManager listKeys].count;
    
    BOOL result = [keyManager importKeyFromFileWithURL:fileURL];
    
    XCTAssertTrue(result);

    NSInteger newNumberOfKeys = [keyManager listKeys].count;
    
    XCTAssertEqual(numberOfKeys + 1, newNumberOfKeys);
}



- (void)performPrivateKeyTest:(NSNumber*)index
{
    NSString* fileName = [NSString stringWithFormat:@"PGPPrivateKey%@", index];
    
    NSURL* fileURL = [BUNDLE URLForResource:fileName withExtension:@""];
    
    XCTAssertNotNil(fileURL);
    
    PGPKeyManager* keyManager = [PGPKeyManager new];
    
    NSInteger numberOfKeys = [keyManager listKeys].count;
    
    BOOL result = [keyManager importKeyFromFileWithURL:fileURL];
    
    XCTAssertTrue(result);

    NSInteger newNumberOfKeys = [keyManager listKeys].count;

    XCTAssertEqual(numberOfKeys + 1, newNumberOfKeys);
}


- (void)testImportPublicKey1
{
    [self performPublicKeyTest:@1];
}

- (void)testImportPublicKey2
{
    [self performPublicKeyTest:@2];
}

- (void)testImportPublicKey3
{
    [self performPublicKeyTest:@3];
}

- (void)testImportPublicKey4
{
    [self performPublicKeyTest:@4];
}

- (void)testImportPublicKey5
{
    [self performPublicKeyTest:@5];
}

- (void)testImportPublicKey6
{
    [self performPublicKeyTest:@6];
}

- (void)testImportPublicKey7
{
    [self performPublicKeyTest:@7];
}

- (void)testImportPublicKey8
{
    [self performPublicKeyTest:@8];
}

- (void)testImportPublicKey9
{
    [self performPublicKeyTest:@9];
}

- (void)testImportPublicKey10
{
    [self performPublicKeyTest:@10];
}

- (void)testImportPublicKey11
{
    [self performPublicKeyTest:@11];
}

- (void)testImportPublicKey12
{
    [self performPublicKeyTest:@12];
}

- (void)testImportPublicKey13
{
    [self performPublicKeyTest:@13];
}

- (void)testImportPublicKey14
{
    [self performPublicKeyTest:@14];
}

- (void)d_testImportPublicKey15
{
    [self performPublicKeyTest:@15];
}

- (void)d_testImportPublicKey16
{
    [self performPublicKeyTest:@16];
}

- (void)testImportPublicKey17
{
    [self performPublicKeyTest:@17];
}




#pragma mark - Private key import




- (void)testImportMynigmaUnittestsPrivateKey
{
    NSString* fileName = @"PrivKey1";
    
    NSURL* fileURL = [BUNDLE URLForResource:fileName withExtension:@"asc"];
    
    XCTAssertNotNil(fileURL);
    
    PGPKeyManager* keyManager = [PGPKeyManager new];
    
    NSInteger numberOfKeys = [keyManager listKeys].count;
    
    BOOL result = [keyManager importKeyFromFileWithURL:fileURL];
    
    XCTAssertTrue(result);
    
    NSInteger newNumberOfKeys = [keyManager listKeys].count;
    
    XCTAssertEqual(numberOfKeys + 2, newNumberOfKeys);
}

- (void)testImportPrivateKey1
{
    [self performPrivateKeyTest:@1];
}

- (void)testImportPrivateKey2
{
    [self performPrivateKeyTest:@2];
}

- (void)testImportPrivateKey3
{
    [self performPrivateKeyTest:@3];
}

- (void)testImportPrivateKey4
{
    [self performPrivateKeyTest:@4];
}

//- (void)testImportPrivateKey5
//{
//    [self performPrivateKeyTest:@5];
//}

- (void)testImportPrivateKey6
{
    [self performPrivateKeyTest:@6];
}



@end
