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





#import "NSData+Base64.h"

@implementation NSData (Base64)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

- (NSString*)base64
{
    if([self respondsToSelector:@selector(base64EncodedStringWithOptions:)])
    {
        //available from 10.9
        return [self base64EncodedStringWithOptions:0];
    }
    else
    {
        //available from 10.6, deprecated in 10.9
        return [self base64Encoding];
    }
}

- (NSData*)base64StringData
{
    if([self respondsToSelector:@selector(base64EncodedDataWithOptions:)])
    {
        //available from 10.9
        return [self base64EncodedDataWithOptions:0];
    }
    else
    {
        //available from 10.6, deprecated in 10.9
        return [[self base64Encoding] dataUsingEncoding:NSUTF8StringEncoding];
    }
}


- (NSString*)base64In64ByteChunksWithCarriageReturn:(BOOL)withCarriageReturn
{
    NSString* result = nil;
    if([self respondsToSelector:@selector(base64EncodedStringWithOptions:)])
    {
        //available from 10.9
        NSDataBase64EncodingOptions options = NSDataBase64Encoding64CharacterLineLength|NSDataBase64EncodingEndLineWithLineFeed;
        if(withCarriageReturn)
            options |= NSDataBase64EncodingEndLineWithCarriageReturn;
        result = [self base64EncodedStringWithOptions:options];
    }
    else
    {
        //available from 10.6, deprecated in 10.9
        result = [self base64Encoding];

        //split into 64 character lines
        NSMutableArray* chunks = [NSMutableArray new];

        NSInteger index = 0;

        while(index<self.length)
        {
            NSInteger lengthOfChunk = (index+64<self.length)?64:self.length-index;

            NSString* substring = [result substringWithRange:NSMakeRange(index, lengthOfChunk)];

            [chunks addObject:substring];

            index+= 64;
        }

        NSString* lineDelimiter = @"\n";
        
        if(withCarriageReturn)
            lineDelimiter = @"\r\n";
        
        result = [chunks componentsJoinedByString:lineDelimiter];
    }
    return result;
}

+ (NSData*)dataWithBase64String:(NSString*)base64String
{
    if(!base64String)
        return nil;
    
    //need to remove line breaks first, weirdly...
    NSString* cleanedString = [[base64String stringByReplacingOccurrencesOfString:@"\r" withString:@""] stringByReplacingOccurrencesOfString:@"\n" withString:@""];

    if([NSData instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)])
    {
        return [[NSData alloc] initWithBase64EncodedString:cleanedString options:0];
    }
    else
    {
        return [[NSData alloc] initWithBase64Encoding:cleanedString];
    }
}

+ (NSData*)dataWithBase64Data:(NSData*)base64Data
{
    return [NSData dataWithBase64String:[[NSString alloc] initWithData:base64Data encoding:NSUTF8StringEncoding]];
}

#pragma GCC diagnostic pop


@end


@implementation NSString (Base64Additions)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

+ (NSString*)stringWithBase64String:(NSString*)base64String
{
    if([NSData instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)])
    {
        NSData* data = [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];

        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    else
    {
        NSData* data = [[NSData alloc] initWithBase64Encoding:base64String];
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
}

#pragma GCC diagnostic pop


@end
