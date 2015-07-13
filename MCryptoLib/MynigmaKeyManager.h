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





@class KeychainHelper, CoreDataHelper, MCOAbstractMessage, PublicKeyData, PrivateKeyData, MynigmaPublicKey, MynigmaPrivateKey, MynigmaDevice;


@interface MynigmaKeyManager : NSObject


- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper;

- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper coreDataHelper:(CoreDataHelper*)coreDataHelper;




@property KeychainHelper* keychainHelper;
@property CoreDataHelper* coreDataHelper;



#pragma mark - Querying keys

- (BOOL)havePublicKeyWithLabel:(NSString*)keyLabel;
- (BOOL)havePrivateKeyWithLabel:(NSString*)keyLabel;

- (MynigmaPublicKey*)publicKeyWithLabel:(NSString*)keyLabel inContext:(NSManagedObjectContext*)keyContext;
- (MynigmaPrivateKey*)privateKeyWithLabel:(NSString*)keyLabel inContext:(NSManagedObjectContext*)keyContext;

- (PublicKeyData*)dataForPublicKeyWithLabel:(NSString*)keyLabel;
- (PrivateKeyData*)dataForPrivateKeyWithLabel:(NSString*)keyLabel;

- (NSArray*)listAllPrivateKeyLabels;


#pragma mark - Adding keys

- (BOOL)addPublicKeyWithData:(PublicKeyData*)publicKeyData;
- (BOOL)addPrivateKeyWithData:(PrivateKeyData*)privateKeyData;

- (BOOL)generatePrivateKeyWithLabel:(NSString*)keyLabel;


#pragma mark - Current keys

- (BOOL)setCurrentKeyForEmailAddress:(NSString*)emailAddress keyLabel:(NSString*)keyLabel overwrite:(BOOL)overwritePrevious;
- (BOOL)haveCurrentKeyForEmailAddress:(NSString*)emailAddress;
- (BOOL)haveCurrentPrivateKeyForEmailAddress:(NSString*)emailAddress;
- (NSString*)currentKeyLabelForEmailAddress:(NSString*)emailAddress;
- (BOOL)updateCurrentKeyLabel:(NSString*)publicKeyLabel forEmail:(NSString*)emailString ifAnchorDateIsNewerThan:(NSDate*)anchorDate;


#pragma mark - Key expectations

- (BOOL)setExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail keyLabel:(NSString*)keyLabel date:(NSDate*)date overwrite:(BOOL)overwritePrevious;
- (NSString*)expectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail;
- (NSDate*)anchorDateFrom:(NSString*)senderEmail to:(NSString*)recipientEmail;
- (BOOL)haveExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail;
- (BOOL)updateExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail keyLabel:(NSString*)keyLabel date:(NSDate*)date;


#pragma mark - Devices

- (NSString*)currentDeviceUUID;
- (MynigmaDevice*)deviceWithUUID:(NSString*)deviceUUID addIfNotFound:(BOOL)addIfNotFound inContext:(NSManagedObjectContext*)localContext;

- (BOOL)setCurrentKeyForDeviceWithUUID:(NSString*)deviceUUID keyLabel:(NSString*)keyLabel overwrite:(BOOL)overwritePrevious;
- (BOOL)haveCurrentKeyForDeviceWithUUID:(NSString*)deviceUUID;
- (BOOL)haveCurrentPrivateKeyForDeviceWithUUID:(NSString*)deviceUUID;
- (NSString*)currentKeyLabelForDeviceWithUUID:(NSString*)deviceUUID;


- (void)distrustAllDevices;




#pragma mark - Easy reading fingerprint

- (NSString*)easyReadingFingerprintForKeyWithLabel:(NSString*)keyLabel;


- (PublicKeyData*)getPublicKeyDataFromExtraHeaderValues:(NSDictionary*)headerValues;


@end
