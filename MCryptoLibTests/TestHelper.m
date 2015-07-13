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


#import "TestHelper.h"
#import "PublicKeyData.h"
#import "PrivateKeyData.h"
#import "NSData+Base64.h"

#import <MProtoBuf/PlainBackupDataStructure.h>
#import <MProtoBuf/DeviceDiscoveryPayloadDataStructure.h>




@implementation TestHelper


+ (PrivateKeyData*)privateKeyData:(NSNumber*)index withKeyLabel:(NSString*)keyLabel
{
    PrivateKeyData* privateKeyData = [TestHelper privateKeyData:index];
    
    [privateKeyData setKeyLabel:keyLabel];
    
    return privateKeyData;
}

+ (PrivateKeyData*)privateKeyData:(NSNumber*)index
{
    NSData* encData = [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_EncKey%@", index?index:@""] ofType:@"txt"]];
    NSData* verData = [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_VerKey%@", index?index:@""] ofType:@"txt"]];
    NSData* decData = [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_DecKey%@", index?index:@""] ofType:@"txt"]];
    NSData* sigData = [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_SigKey%@", index?index:@""] ofType:@"txt"]];
    
    PrivateKeyData* keyData = [[PrivateKeyData alloc] initWithKeyLabel:@"testLabel" decData:decData sigData:sigData encData:encData verData:verData];
    
    return keyData;
}

+ (PublicKeyData*)publicKeyData:(NSNumber*)index withKeyLabel:(NSString*)keyLabel
{
    PublicKeyData* publicKeyData = [TestHelper publicKeyData:index];
    
    [publicKeyData setKeyLabel:keyLabel];
    
    return publicKeyData;
}

+ (PublicKeyData*)publicKeyData:(NSNumber*)index
{
    NSData* encData = [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_EncKey%@", index?index:@""] ofType:@"txt"]];
    NSData* verData = [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_VerKey%@", index?index:@""] ofType:@"txt"]];
    
    PublicKeyData* keyData = [[PublicKeyData alloc] initWithKeyLabel:@"testLabel" encData:encData verData:verData];
    
    return keyData;
}

+ (NSData*)encData:(NSNumber*)index
{
    return [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_EncKey%@", index?index:@""] ofType:@"txt"]];
}

+ (NSData*)verData:(NSNumber*)index
{
    return [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_VerKey%@", index?index:@""] ofType:@"txt"]];
}

+ (NSData*)decData:(NSNumber*)index;
{
    return [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_DecKey%@", index?index:@""] ofType:@"txt"]];
}

+ (NSData*)sigData:(NSNumber*)index;
{
    return [NSData dataWithContentsOfFile:[BUNDLE pathForResource:[NSString stringWithFormat:@"Sample_SigKey%@", index?index:@""] ofType:@"txt"]];
}


+ (NSData*)sampleData:(NSNumber*)index
{
    NSString* base64DataString = [NSString stringWithContentsOfURL:[BUNDLE URLForResource:[NSString stringWithFormat:@"Sample_Data%@", index?index:@""] withExtension:@"txt"] encoding:NSUTF8StringEncoding error:nil];
    
    NSData* rawData = [[NSData alloc] initWithBase64EncodedString:base64DataString options:0];
    
    return rawData;
}

+ (NSString*)sampleString:(NSNumber*)index;
{
    switch(index.integerValue)
    {
        case 0:
            return @"sampleString#0";
        case 1:
            return @"sampleString#1";
        case 2:
            return @"sampleString#2";
        case 3:
            return @"sampleString#3";
        case 4:
            return @"sampleString#4";
        case 5:
            return @"sampleString#5";
    }
    
    return @"sampleString";
}


+ (NSDate*)sampleDate:(NSNumber*)index
{
    return [NSDate dateWithTimeIntervalSince1970:3243 + 346763*index.integerValue];
}

+ (NSData*)dataForResourceWithFileName:(NSString*)fileName
{
    NSArray* components = [fileName componentsSeparatedByString:@"."];
    
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:components.firstObject withExtension:components.lastObject];
    
    return [NSData dataWithContentsOfURL:fileURL];
}

+ (NSData*)dataForBase64ResourceWithFileName:(NSString*)fileName
{
    NSArray* components = [fileName componentsSeparatedByString:@"."];
    
    NSURL* fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:components.firstObject withExtension:components.lastObject];
    
    NSData* fileData = [NSData dataWithContentsOfURL:fileURL];
    
    if(!fileData.length)
        return nil;
    
    return [NSData dataWithBase64Data:fileData];
}

@end
