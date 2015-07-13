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

#import "PublicKeyData.h"

@implementation PublicKeyData


- (instancetype)initWithKeyLabel:(NSString*)keyLabel encData:(NSData*)encData verData:(NSData*)verData
{
    self = [super init];
    if (self) {
        [self setKeyLabel:keyLabel];
        
        //quick fix to translate from old key format - which had -----BEGIN RSA PUBLIC KEY----- headers
        //it should be -----BEGIN PUBLIC KEY-----
        NSString* encString = [[NSString alloc] initWithData:encData encoding:NSUTF8StringEncoding];
        encString = [encString stringByReplacingOccurrencesOfString:@"RSA PUBLIC" withString:@"PUBLIC"];
        
        NSString* verString = [[NSString alloc] initWithData:verData encoding:NSUTF8StringEncoding];
        verString = [verString stringByReplacingOccurrencesOfString:@"RSA PUBLIC" withString:@"PUBLIC"];
        
        encData = [encString dataUsingEncoding:NSUTF8StringEncoding];
        verData = [verString dataUsingEncoding:NSUTF8StringEncoding];
        
        [self setPublicKeyEncData:encData];
        [self setPublicKeyVerData:verData];
    }
    return self;
}


#pragma mark - Equality

- (NSUInteger)hash
{
    return 3*self.publicKeyEncData.hash + 5*self.publicKeyVerData.hash + 7*self.keyLabel.hash;
}

- (BOOL)isEqual:(PublicKeyData*)object
{
    if(![object isKindOfClass:[PublicKeyData class]])
        return NO;
    
    return [self.publicKeyEncData isEqual:object.publicKeyEncData] && [self.publicKeyVerData isEqual:object.publicKeyVerData] && [self.keyLabel isEqual:object.keyLabel];
}

@end
