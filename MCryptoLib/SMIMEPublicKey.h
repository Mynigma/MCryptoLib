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


#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>
#import "GenericPublicKey.h"

@class EmailAddress;

@interface SMIMEPublicKey : GenericPublicKey

@property (nonatomic, retain) NSData * data;
@property (nonatomic, retain) NSString * issuer;
@property (nonatomic, retain) NSData * keychainRef;
@property (nonatomic, retain) NSString * keyUsage;
@property (nonatomic, retain) NSString * serialNumber;
@property (nonatomic, retain) NSData * signature;
@property (nonatomic, retain) NSString * signatureAlgorithm;
@property (nonatomic, retain) NSString * subject;
@property (nonatomic, retain) NSData * fingerprint;
@property (nonatomic, retain) NSString * fingerprintAlgorithm;
@property (nonatomic, retain) NSDate * validFrom;
@property (nonatomic, retain) NSDate * validUntil;
@property (nonatomic, retain) NSString * version;
@property (nonatomic, retain) NSString * capabilities;
@property (nonatomic, retain) NSSet *activeSigningKeyForEmail;
@property (nonatomic, retain) NSSet *activeEncryptionKeyForEmail;
@end

@interface SMIMEPublicKey (CoreDataGeneratedAccessors)

- (void)addActiveSigningKeyForEmailObject:(EmailAddress *)value;
- (void)removeActiveSigningKeyForEmailObject:(EmailAddress *)value;
- (void)addActiveSigningKeyForEmail:(NSSet *)values;
- (void)removeActiveSigningKeyForEmail:(NSSet *)values;

- (void)addActiveEncryptionKeyForEmailObject:(EmailAddress *)value;
- (void)removeActiveEncryptionKeyForEmailObject:(EmailAddress *)value;
- (void)addActiveEncryptionKeyForEmail:(NSSet *)values;
- (void)removeActiveEncryptionKeyForEmail:(NSSet *)values;

@end
