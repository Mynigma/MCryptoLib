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

#import "NSData+Base64.h"
#import "SMIMEEncryptionEngine.h"
#import "SMIMEPublicKey.h"




@interface SMIMEEncryptionEngine_Tests : XCTestCase

@end

@implementation SMIMEEncryptionEngine_Tests

- (SMIMEPublicKey*)importPrivateKey:(NSString*)fileName withEngine:(SMIMEEncryptionEngine*)engine
{
    NSURL* url = [BUNDLE URLForResource:fileName withExtension:@"pri"];
    
    return [engine importKeyFromFileWithURL:url];
}

- (void)d_testVerificationOf_4_8
{
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];

    SMIMEPublicKey* publicKey = [self importPrivateKey:@"AlicePrivRSASign" withEngine:engine];

    XCTAssertNotNil(publicKey);
    
    NSURL* messageDataURL = [BUNDLE URLForResource:@"4.8" withExtension:@"eml"];
    
    XCTAssertNotNil(messageDataURL);
    
    NSData* messageDataInBase64 = [NSData dataWithContentsOfURL:messageDataURL];
    
    XCTAssertNotNil(messageDataInBase64);
    
    NSData* messageData = [NSData dataWithBase64Data:messageDataInBase64];
    
    XCTAssertNotNil(messageData);
    
    NSString* messageString = [[NSString alloc] initWithData:messageData encoding:NSUTF8StringEncoding];
    
    XCTAssertNotNil(messageString);
    
//    
//    NSData* unwrappedData = [OpenSSLWrapper verifySignedData:messageData withPublicKeyLabel:keyLabel error:&error];
//    
//    
//    XCTAssertNil(error);
//    
//    XCTAssertNotNil(unwrappedData);
//    
//    NSData* expectedData = nil;
//    
//    XCTAssertEqualObjects(unwrappedData, expectedData);
}

@end
