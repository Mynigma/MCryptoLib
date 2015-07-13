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




#define BUNDLE [NSBundle bundleForClass:NSClassFromString(@"TestHelper")]


#import <Foundation/Foundation.h>

#define TEST_KEY_LABEL1 @"TestKeyLabel1"
#define TEST_KEY_LABEL2 @"TestKeyLabel2"
#define TEST_KEY_LABEL3 @"TestKeyLabel3"
#define TEST_KEY_LABEL4 @"TestKeyLabel4"
#define TEST_KEY_LABEL5 @"TestKeyLabel5"
#define TEST_KEY_LABEL6 @"TestKeyLabel6"
#define TEST_KEY_LABEL7 @"TestKeyLabel7"
#define TEST_KEY_LABEL8 @"TestKeyLabel8"
#define TEST_KEY_LABEL9 @"TestKeyLabel9"
#define TEST_KEY_LABEL10 @"TestKeyLabel10"



@class MynigmaDevice, PrivateKeyData, PublicKeyData;

@interface TestHelper : NSObject


+ (PrivateKeyData*)privateKeyData:(NSNumber*)index withKeyLabel:(NSString*)keyLabel;
+ (PrivateKeyData*)privateKeyData:(NSNumber*)index;

+ (PublicKeyData*)publicKeyData:(NSNumber*)index withKeyLabel:(NSString*)keyLabel;
+ (PublicKeyData*)publicKeyData:(NSNumber*)index;


+ (NSData*)encData:(NSNumber*)index;
+ (NSData*)verData:(NSNumber*)index;
+ (NSData*)decData:(NSNumber*)index;
+ (NSData*)sigData:(NSNumber*)index;

+ (NSData*)sampleData:(NSNumber*)index;
+ (NSString*)sampleString:(NSNumber*)index;
+ (NSDate*)sampleDate:(NSNumber*)index;

+ (NSData*)dataForResourceWithFileName:(NSString*)fileName;
+ (NSData*)dataForBase64ResourceWithFileName:(NSString*)fileName;


@end