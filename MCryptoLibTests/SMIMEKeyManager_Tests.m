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

#import "SMIMEKeyManager.h"

#import "CommonHeader.h"
#import "SMIMEEncryptionEngine.h"



@interface SMIMEKeyManager_Tests : XCTestCase

@end

@implementation SMIMEKeyManager_Tests



#pragma mark - Test import of S/MIME certificates

- (void)testImportOfAliceDSSSignByCarlNoInherit
{
    NSURL* url = [BUNDLE URLForResource:@"AliceDSSSignByCarlNoInherit" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfAliceRSASignByCarl
{
    NSURL* url = [BUNDLE URLForResource:@"AliceRSASignByCarl" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfBobRSASignByCarl
{
    NSURL* url = [BUNDLE URLForResource:@"BobRSASignByCarl" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfCarlDSSSelf
{
    NSURL* url = [BUNDLE URLForResource:@"CarlDSSSelf" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfCarlRSASelf
{
    NSURL* url = [BUNDLE URLForResource:@"CarlRSASelf" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfDianeDSSSignByCarlInherit
{
    NSURL* url = [BUNDLE URLForResource:@"DianeDSSSignByCarlInherit" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfDianeRSASignByCarl
{
    NSURL* url = [BUNDLE URLForResource:@"DianeRSASignByCarl" withExtension:@"cer"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}




#pragma mark - Test import of S/MIME private keys

- (void)testImportOfAlicePrivDSSSign
{
    NSURL* url = [BUNDLE URLForResource:@"AlicePrivDSSSign" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfAlicePrivRSASign
{
    NSURL* url = [BUNDLE URLForResource:@"AlicePrivRSASign" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfBobPrivRSAEncrypt
{
    NSURL* url = [BUNDLE URLForResource:@"BobPrivRSAEncrypt" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfCarlPrivDSSSign
{
    NSURL* url = [BUNDLE URLForResource:@"CarlPrivDSSSign" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfCarlPrivRSASign
{
    NSURL* url = [BUNDLE URLForResource:@"CarlPrivRSASign" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfDianePrivDSSSign
{
    NSURL* url = [BUNDLE URLForResource:@"DianePrivDSSSign" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}

- (void)testImportOfDianePrivRSASignEncrypt
{
    NSURL* url = [BUNDLE URLForResource:@"DianePrivRSASignEncrypt" withExtension:@"pri"];
    
    XCTAssertNotNil(url);
    
    SMIMEEncryptionEngine* engine = [SMIMEEncryptionEngine new];
    
    SMIMEPublicKey* result = [engine importKeyFromFileWithURL:url];
    
    XCTAssertNotNil(result);
}



@end
