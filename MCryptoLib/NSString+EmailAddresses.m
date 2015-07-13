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





#import "NSString+EmailAddresses.h"



static NSArray* usersOwnEmailAddresses;


@implementation NSString (EmailAddresses)

- (NSString*)canonicalForm
{
    NSString* returnValue = self.lowercaseString;

    returnValue = [returnValue stringByReplacingOccurrencesOfString:@"@googlemail." withString:@"@gmail." options:0 range:NSMakeRange(0, returnValue.length)];

    returnValue = [returnValue stringByReplacingOccurrencesOfString:@"@mac.com" withString:@"@icloud.com" options:0 range:NSMakeRange(0, returnValue.length)];

    returnValue = [returnValue stringByReplacingOccurrencesOfString:@"@me.com" withString:@"@icloud.com" options:0 range:NSMakeRange(0, returnValue.length)];


    NSArray* components = [returnValue componentsSeparatedByString:@"@"];

    NSString* userPart = [components firstObject];

    NSString* domainPart = [components lastObject];


    if([domainPart hasPrefix:@"gmail."])
    {
        //google ignores dots in email addresses
        userPart = [userPart stringByReplacingOccurrencesOfString:@"." withString:@""];

        //it also ignores anything following a '+' sign
        NSArray* userPartComponents = [userPart componentsSeparatedByString:@"+"];

        userPart = userPartComponents.firstObject;
    }

    returnValue = [NSString stringWithFormat:@"%@@%@", userPart, domainPart];

    if([returnValue isValidEmailAddress])
        return returnValue;

    return nil;
}

- (BOOL)isValidEmailAddress
{
//    NSString *regex1 = @"\\A[a-z0-9]+([-._][a-z0-9]+)*@([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,4}\\z";
//    NSString *regex2 = @"^(?=.{1,64}@.{4,64}$)(?=.{6,100}$).*";
//    NSPredicate *test1 = [NSPredicate predicateWithFormat:@"SELF MATCHES %@", regex1];
//    NSPredicate *test2 = [NSPredicate predicateWithFormat:@"SELF MATCHES %@", regex2];
//    return [test1 evaluateWithObject:self] && [test2 evaluateWithObject:self];

    //pretty permissive, but it doesn't matter if an address slips through
    //we do want to avoid wrongly excluded valid addresses
    NSString *emailRegex =
    @"[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,20}";
//
////    @"(?:[a-z0-9!#$%\\&'*+/=?\\^_`{|}~-]+(?:\\.[a-z0-9!#$%\\&'*+/=?\\^_`{|}"
////    @"~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\"
////    @"x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-"
////    @"z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5"
////    @"]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-"
////    @"9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21"
////    @"-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";
    
    NSPredicate *emailTest = [NSPredicate predicateWithFormat:@"SELF MATCHES [c] %@", emailRegex];

    return [emailTest evaluateWithObject:self];
}


#pragma mark - User's own addresses

+ (void)setUsersAddresses:(NSArray*)usersAddresses
{
    usersOwnEmailAddresses = usersAddresses;
}

+ (NSArray*)usersAddresses
{
    return [usersOwnEmailAddresses copy];
}

- (BOOL)isUsersAddress
{
    NSString* canonicalAddress = [self canonicalForm];
    return [usersOwnEmailAddresses containsObject:canonicalAddress];
}




#pragma mark - MessageID generation

//generates a new message ID - it's a timestamp followed by a random string, followed by "@" and the provider part of the given email address
- (NSString*)generateMessageID
{
    NSString* canonicalEmailAddress = [self canonicalForm];

    NSArray* emailComponents = [canonicalEmailAddress componentsSeparatedByString:@"@"];

    if(emailComponents.count != 2)
    {
        return nil;
    }

    NSDate* currentDate = [NSDate date];

    NSString* timeStamp = [NSString stringWithFormat:@"%f",[currentDate timeIntervalSince1970]];

    NSString *randomString = [NSString stringWithFormat:@"%u",arc4random()];

    return [NSString stringWithFormat:@"%@%@@%@",timeStamp,randomString,[emailComponents objectAtIndex:1]];
}

@end
