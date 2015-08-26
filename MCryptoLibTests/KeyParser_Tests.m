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
#import "KeyParser.h"

#import "PublicKeyData.h"
#import "PrivateKeyData.h"





@interface KeyParser_Tests : XCTestCase

@end

@implementation KeyParser_Tests

- (void)testRSAPublicKeyParsing
{
    PublicKeyData* publicKeyData = [TestHelper publicKeyData:@1];
    
    NSData* rawData = publicKeyData.publicKeyEncData;
    
    OpenSSLEncryptionEngine* engine = [OpenSSLEncryptionEngine sharedInstance];
    
    EVP_PKEY* pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:nil];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatDefault];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:nil];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatPKCS12];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatPKCS12 passphrase:nil];
    XCTAssert(pubKey);

    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatPKCS1WithoutOID];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatPKCS1WithoutOID passphrase:nil];
    XCTAssert(pubKey);

    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatPKCS8WithOID];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatPKCS8WithOID passphrase:nil];
    XCTAssert(pubKey);

    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatX509];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatX509 passphrase:nil];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatDefault];
    XCTAssertNotNil(rawData);
    
    XCTAssertEqualObjects(rawData, publicKeyData.publicKeyEncData);
}

- (void)testRSAPublicKeyParsingWithPassphrase
{
    NSString* passphrase = @"Robert'); DROP TABLE Students; --";
    
    PublicKeyData* publicKeyData = [TestHelper publicKeyData:@1];
    
    NSData* rawData = publicKeyData.publicKeyEncData;
    
    EVP_PKEY* pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssert(pubKey);
    
//    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatPKCS12 passphrase:passphrase];
//    XCTAssertNotNil(rawData);
//    
//    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatPKCS12 passphrase:passphrase];
//    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatPKCS1WithoutOID passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatPKCS1WithoutOID passphrase:passphrase];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatPKCS8WithOID passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatPKCS8WithOID passphrase:passphrase];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatX509 passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    pubKey = [KeyParser EVPPublicKeyFromData:rawData format:MynigmaKeyFormatX509 passphrase:passphrase];
    XCTAssert(pubKey);
    
    rawData = [KeyParser dataForEVPPublicKey:pubKey format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    XCTAssertEqualObjects(rawData, publicKeyData.publicKeyEncData);
}


- (void)testRSAPrivateKeyParsing
{
    PrivateKeyData* privateKeyData = [TestHelper privateKeyData:@1];
    
    NSData* rawData = privateKeyData.privateKeyDecData;
    
    EVP_PKEY* privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:nil];
    XCTAssert(privKey);
    
    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatDefault passphrase:nil];
    XCTAssertNotNil(rawData);
  
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:nil];
    XCTAssert(privKey);
    
    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatPKCS12 passphrase:nil];
    XCTAssertNotNil(rawData);
 
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatPKCS12 passphrase:nil];
    XCTAssert(privKey);
    
    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatPKCS1WithoutOID passphrase:nil];
    XCTAssertNotNil(rawData);
   
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatPKCS1WithoutOID passphrase:nil];
    XCTAssert(privKey);
    
    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatPKCS8WithOID passphrase:nil];
    XCTAssertNotNil(rawData);
    
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatPKCS8WithOID passphrase:nil];
    XCTAssert(privKey);

    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatDefault passphrase:nil];
    XCTAssertNotNil(rawData);
    
    XCTAssertEqualObjects(rawData, privateKeyData.privateKeyDecData);
}

- (void)testRSAPrivateKeyParsingWithPassphrase
{
    NSString* passphrase = @"Robert'); DROP TABLE Students; --";
    
    PrivateKeyData* privateKeyData = [TestHelper privateKeyData:@1];
    
    NSData* rawData = privateKeyData.privateKeyDecData;
        
    EVP_PKEY* privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssert(privKey);
    
    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssert(privKey);

    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatPKCS12 passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatPKCS12 passphrase:passphrase];
    XCTAssert(privKey);

    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatPKCS1WithoutOID passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatPKCS1WithoutOID passphrase:passphrase];
    XCTAssert(privKey);

    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatPKCS8WithOID passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    privKey = [KeyParser EVPPrivateKeyFromData:rawData format:MynigmaKeyFormatPKCS8WithOID passphrase:passphrase];
    XCTAssert(privKey);
    
//    SecKeyRef keyRef = [engine tran]

    rawData = [KeyParser dataForEVPPrivateKey:privKey format:MynigmaKeyFormatDefault passphrase:passphrase];
    XCTAssertNotNil(rawData);
    
    XCTAssertEqualObjects(rawData, privateKeyData.privateKeyDecData);
}

@end
