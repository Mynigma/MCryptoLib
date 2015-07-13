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


#define DEVICE_DISCOVERY @"DEVICE_DISCOVERY"
#define ANNOUNCE_INFO @"1_ANNOUNCE_INFO"
#define ACK_ANNOUNCE_INFO @"1_ACK_ANNOUNCE_INFO"
#define CONFIRM_CONNECTION @"2_CONFIRM_CONNECTION"
#define ACK_CONFIRM_CONNECTION @"2_ACK_CONFIRM_CONNECTION"
#define SYNC_DATA @"SYNC_DATA"







@class DeviceConnectionThread, DeviceMessage, IMAPAccountSetting, IdleHelper, TrustEstablishmentThread, MynigmaDevice, CoreDataHelper;

@interface DeviceConnectionHelper : NSObject




//an additional timer that checks the folder at regular intervals
@property NSTimer* folderCheckTimer;


//the threadID of the thread in which trust is currently being established
@property NSString* establishingTrustInThreadWithID;


@property MynigmaDevice* targetDeviceForThreadEstablishmentToBeConfirmed;




//only ever need one instance of this
+ (DeviceConnectionHelper*)sharedInstance;






- (void)ensureDeviceKeyGenerated;




- (void)processDeviceMessageWithDownloadedData:(NSData*)downloadedData inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL toBeDeleted))callback;





- (void)initiateTrustEstablishmentWithDeviceUUID:(NSString*)partnerDeviceUUID inAccountWithEmailAddress:(NSString*)emailAddress withCallback:(void(^)(BOOL))callback;




#pragma mark - Trust establishment

+ (BOOL)startEstablishingTrustInThreadID:(NSString*)threadID inAccountWithEmailAddress:(NSString*)emailAddress withDate:(NSDate*)initiationDate deviceUUID:(NSString*)deviceUUID;
+ (BOOL)isEstablishingTrustInThreadWithID:(NSString*)threadID;
+ (BOOL)isEstablishingTrust;
+ (void)stopTrustEstablishment;

- (void)resetAllSyncInfo;


@end
