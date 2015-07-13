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

@class PGPBindingSignature, PGPPublicKey, PGPSubkeyBindingSignature, PGPUserID;

@interface PGPPublicKey : GenericPublicKey

@property (nonatomic, retain) NSString * userID;
@property (nonatomic, retain) NSString * version;
@property (nonatomic, retain) NSData * publicKeychainRef;
@property (nonatomic, retain) NSString * algorithm;
@property (nonatomic, retain) NSDate * creationDate;
@property (nonatomic, retain) NSDate * expiryDate;
@property (nonatomic, retain) NSData * keyID;
@property (nonatomic, retain) NSData * fingerprint;
@property (nonatomic, retain) NSData * flags;
@property (nonatomic, retain) NSNumber * usage;
@property (nonatomic, retain) NSSet *userIDs;
@property (nonatomic, retain) PGPUserID *primaryUserID;
@property (nonatomic, retain) NSSet *subkeys;
@property (nonatomic, retain) PGPPublicKey *topLevelKey;
@property (nonatomic, retain) NSSet *activeKeyForUserIDs;
@property (nonatomic, retain) NSSet *signedBindings;
@property (nonatomic, retain) PGPPublicKey *revocationKey;
@property (nonatomic, retain) NSSet *revocableKeys;
@property (nonatomic, retain) NSSet *boundBySubkeyBindings;
@end

@interface PGPPublicKey (CoreDataGeneratedAccessors)

- (void)addUserIDsObject:(PGPUserID *)value;
- (void)removeUserIDsObject:(PGPUserID *)value;
- (void)addUserIDs:(NSSet *)values;
- (void)removeUserIDs:(NSSet *)values;

- (void)addSubkeysObject:(PGPPublicKey *)value;
- (void)removeSubkeysObject:(PGPPublicKey *)value;
- (void)addSubkeys:(NSSet *)values;
- (void)removeSubkeys:(NSSet *)values;

- (void)addActiveKeyForUserIDsObject:(PGPUserID *)value;
- (void)removeActiveKeyForUserIDsObject:(PGPUserID *)value;
- (void)addActiveKeyForUserIDs:(NSSet *)values;
- (void)removeActiveKeyForUserIDs:(NSSet *)values;

- (void)addSignedBindingsObject:(PGPBindingSignature *)value;
- (void)removeSignedBindingsObject:(PGPBindingSignature *)value;
- (void)addSignedBindings:(NSSet *)values;
- (void)removeSignedBindings:(NSSet *)values;

- (void)addRevocableKeysObject:(PGPPublicKey *)value;
- (void)removeRevocableKeysObject:(PGPPublicKey *)value;
- (void)addRevocableKeys:(NSSet *)values;
- (void)removeRevocableKeys:(NSSet *)values;

- (void)addBoundBySubkeyBindingsObject:(PGPSubkeyBindingSignature *)value;
- (void)removeBoundBySubkeyBindingsObject:(PGPSubkeyBindingSignature *)value;
- (void)addBoundBySubkeyBindings:(NSSet *)values;
- (void)removeBoundBySubkeyBindings:(NSSet *)values;

@end
