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
#import "NSString+EmailAddresses.h"

@interface NSString_EmailAddresses_Tests : XCTestCase

@end

@implementation NSString_EmailAddresses_Tests

- (void)testEmailAddressValidator
{
    XCTAssertTrue([@"niceandsimple@example.com" isValidEmailAddress]);
    XCTAssertTrue([@"very.common@example.com" isValidEmailAddress]);
    XCTAssertTrue([@"a.little.lengthy.but.fine@dept.example.com" isValidEmailAddress]);
    XCTAssertTrue([@"disposable.style.email.with+symbol@example.com" isValidEmailAddress]);
    XCTAssertTrue([@"other.email-with-dash@example.com" isValidEmailAddress]);
    
    //TODO: find a better way to validate email addresses, which will rightly recognise these addresses as valid
//    XCTAssertTrue([@"\"much.more unusual\"@example.com" isValidEmailAddress]);
//    XCTAssertTrue([@"\"very.unusual.@.unusual.com\"@example.com" isValidEmailAddress]);
//    XCTAssertTrue([@"\"very.(),:;<>[]\\\".VERY.\\\"very@\\\\ \\\"very\\\".unusual\"@strange.example.com" isValidEmailAddress]);
//    XCTAssertTrue([@"admin@mailserver1" isValidEmailAddress]);
//    XCTAssertTrue([@"#!$%&'*+-/=?^_`{}|~@example.org" isValidEmailAddress]);
//    XCTAssertTrue([@"\"()<>[]:,;@\\\"!#$%&'*+-/=?^_`{}| ~.a\"@example.org" isValidEmailAddress]);
//    XCTAssertTrue([@"\" \"@example.org" isValidEmailAddress]);
    
    XCTAssertTrue([@"test.email@t-online.de" isValidEmailAddress]);
    XCTAssertTrue([@"test.email@merton.ox.ac.uk" isValidEmailAddress]);
    XCTAssertTrue([@"test.email@very.longdomainname" isValidEmailAddress]);

    //TODO: look into unicode parsing
    //need an RFC 6530 conforming validator
//    XCTAssertTrue([@"\u00FC\u00F1\u00EE\u00E7\u00F8\u00F0\u00E9@example.com" isValidEmailAddress]);
//    XCTAssertTrue([@"\u00FC\u00F1\u00EE\u00E7\u00F8\u00F0\u00E9@\u00FC\u00F1\u00EE\u00E7\u00F8\u00F0\u00E9.com" isValidEmailAddress]);
    

    //    XCTAssertFalse([@"john.doe@example..com" isValidEmailAddress]);
    //    XCTAssertFalse([@"john..doe@example.com" isValidEmailAddress]);

    
    XCTAssertFalse([@"condition);Abc.example.com" isValidEmailAddress]);
    XCTAssertFalse([@"A@b@c@example.com" isValidEmailAddress]);
    XCTAssertFalse([@"a\"b(c)d,e:f;g<h>i[j\\k]l@example.com" isValidEmailAddress]);
    XCTAssertFalse([@"just\"not\"right@example.com" isValidEmailAddress]);
    XCTAssertFalse([@"this is\"not\\allowed@example.com" isValidEmailAddress]);
    XCTAssertFalse([@"this\\ still\\\"not\\\\allowed@example.com" isValidEmailAddress]);
    XCTAssertFalse([@" leading@space.com" isValidEmailAddress]);
    XCTAssertFalse([@"trailing@space.com " isValidEmailAddress]);
}

- (void)testCanonicalForm
{
    XCTAssertEqualObjects(@"make@lowercase.com", [@"maKe@LoWERcaSE.CoM" canonicalForm]);
    XCTAssertEqualObjects(@"turn-me.com-into@icloud.com", [@"turn-me.com-into@me.com" canonicalForm]);
    XCTAssertEqualObjects(@"turn-me.com-into@icloud.com", [@"turn-me.com-into@mac.com" canonicalForm]);
    XCTAssertEqualObjects(@"turn-googlemail-into@gmail.com", [@"turn-googlemail-into@googlemail.com" canonicalForm]);
    XCTAssertEqualObjects(@"trim@gmail.com", [@"trim+tag+andanothertag@gmail.com" canonicalForm]);
    XCTAssertEqualObjects(@"removedots@gmail.com", [@"r.e.move.dot.s@gmail.com" canonicalForm]);
}

- (void)testInvalidEmailAddress
{
    XCTAssertNil([@"342350912" canonicalForm]);
}
@end
