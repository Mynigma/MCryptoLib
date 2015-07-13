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

#import "SessionKeys.h"

@implementation SessionKeys

- (instancetype)initWithAESSessionKey:(NSData*)AESSessionKey andHMACSecret:(NSData*)HMACSecret
{
    self = [super init];
    if(self)
    {
        [self setAESSessionKey:AESSessionKey];
        [self setHMACSecret:HMACSecret];
    }
    return self;
}

+ (instancetype)sessionKeysFromData:(NSData*)data
{
    //the data needs to be of length 128 bits (AES) + 1024 bits (HMAC) = 1152 bit/144 bytes
    if(data.length != 144)
        return nil;
    
    NSData* AESSessionKey = [data subdataWithRange:NSMakeRange(0, 16)];
    
    NSData* HMACSecret = [data subdataWithRange:NSMakeRange(16, 128)];
    
    SessionKeys* newSessionKeys = [SessionKeys new];
    
    [newSessionKeys setAESSessionKey:AESSessionKey];
    [newSessionKeys setHMACSecret:HMACSecret];
    
    return newSessionKeys;
}

- (NSData*)concatenatedKeys
{
    if(!self.AESSessionKey.length || !self.HMACSecret.length)
    {
        return nil;
    }
    
    NSMutableData* mutableData = [self.AESSessionKey mutableCopy];
    
    [mutableData appendData:self.HMACSecret];
    
    return mutableData;
}



#define AES_SESSION_KEY_ENCODING_KEY @"AES session key"
#define HMAC_SECRET_KEY_ENCODING_KEY @"HMAC secret"

- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if (self) {
    
        [self setAESSessionKey:[aDecoder decodeObjectForKey:AES_SESSION_KEY_ENCODING_KEY]];
        [self setHMACSecret:[aDecoder decodeObjectForKey:HMAC_SECRET_KEY_ENCODING_KEY]];
    
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    if(self.AESSessionKey)
        [aCoder encodeObject:self.AESSessionKey forKey:AES_SESSION_KEY_ENCODING_KEY];
    if(self.HMACSecret)
        [aCoder encodeObject:self.HMACSecret forKey:HMAC_SECRET_KEY_ENCODING_KEY];
}



@end
