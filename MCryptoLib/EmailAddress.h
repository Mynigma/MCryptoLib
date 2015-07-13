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

@class GenericPublicKey, KeyExpectation, MynigmaDevice, MynigmaPublicKey, PGPUserID, SMIMEPublicKey;

@interface EmailAddress : NSManagedObject

@property (nonatomic, retain) NSString * address;
@property (nonatomic, retain) NSDate * dateAdded;
@property (nonatomic, retain) NSDate * dateCurrentKeyAnchored;
@property (nonatomic, retain) NSSet *accountUsesDevices;
@property (nonatomic, retain) NSSet *allKeys;
@property (nonatomic, retain) MynigmaPublicKey *currentMynigmaKey;
@property (nonatomic, retain) SMIMEPublicKey *activeSMIMESignatureKey;
@property (nonatomic, retain) NSSet *expectationsFrom;
@property (nonatomic, retain) NSSet *expectationsTo;
@property (nonatomic, retain) PGPUserID *activePGPUserID;
@property (nonatomic, retain) PGPUserID *allPGPUserIDs;
@property (nonatomic, retain) SMIMEPublicKey *activeSMIMEEncryptionKey;
@end

@interface EmailAddress (CoreDataGeneratedAccessors)

- (void)addAccountUsesDevicesObject:(MynigmaDevice *)value;
- (void)removeAccountUsesDevicesObject:(MynigmaDevice *)value;
- (void)addAccountUsesDevices:(NSSet *)values;
- (void)removeAccountUsesDevices:(NSSet *)values;

- (void)addAllKeysObject:(GenericPublicKey *)value;
- (void)removeAllKeysObject:(GenericPublicKey *)value;
- (void)addAllKeys:(NSSet *)values;
- (void)removeAllKeys:(NSSet *)values;

- (void)addExpectationsFromObject:(KeyExpectation *)value;
- (void)removeExpectationsFromObject:(KeyExpectation *)value;
- (void)addExpectationsFrom:(NSSet *)values;
- (void)removeExpectationsFrom:(NSSet *)values;

- (void)addExpectationsToObject:(KeyExpectation *)value;
- (void)removeExpectationsToObject:(KeyExpectation *)value;
- (void)addExpectationsTo:(NSSet *)values;
- (void)removeExpectationsTo:(NSSet *)values;

@end
