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

@class EmailAddress, KeyExpectation, MynigmaDevice, MynigmaPublicKey;

@interface MynigmaPublicKey : GenericPublicKey

@property (nonatomic, retain) NSDate * dateCreated;
@property (nonatomic, retain) NSDate * dateObtained;
@property (nonatomic, retain) NSNumber * isCompromised;
@property (nonatomic, retain) NSString * keyLabel;
@property (nonatomic, retain) NSData * publicEncrKeyRef;
@property (nonatomic, retain) NSData * publicVerifyKeyRef;
@property (nonatomic, retain) NSString * version;
@property (nonatomic, retain) NSSet *currentKeyForEmail;
@property (nonatomic, retain) NSSet *expectedBy;
@property (nonatomic, retain) NSSet *introducesKeys;
@property (nonatomic, retain) NSSet *isIntroducedByKeys;
@property (nonatomic, retain) NSSet *syncKeyForDevice;
@end

@interface MynigmaPublicKey (CoreDataGeneratedAccessors)

- (void)addCurrentKeyForEmailObject:(EmailAddress *)value;
- (void)removeCurrentKeyForEmailObject:(EmailAddress *)value;
- (void)addCurrentKeyForEmail:(NSSet *)values;
- (void)removeCurrentKeyForEmail:(NSSet *)values;

- (void)addExpectedByObject:(KeyExpectation *)value;
- (void)removeExpectedByObject:(KeyExpectation *)value;
- (void)addExpectedBy:(NSSet *)values;
- (void)removeExpectedBy:(NSSet *)values;

- (void)addIntroducesKeysObject:(MynigmaPublicKey *)value;
- (void)removeIntroducesKeysObject:(MynigmaPublicKey *)value;
- (void)addIntroducesKeys:(NSSet *)values;
- (void)removeIntroducesKeys:(NSSet *)values;

- (void)addIsIntroducedByKeysObject:(MynigmaPublicKey *)value;
- (void)removeIsIntroducedByKeysObject:(MynigmaPublicKey *)value;
- (void)addIsIntroducedByKeys:(NSSet *)values;
- (void)removeIsIntroducedByKeys:(NSSet *)values;

- (void)addSyncKeyForDeviceObject:(MynigmaDevice *)value;
- (void)removeSyncKeyForDeviceObject:(MynigmaDevice *)value;
- (void)addSyncKeyForDevice:(NSSet *)values;
- (void)removeSyncKeyForDevice:(NSSet *)values;

@end
