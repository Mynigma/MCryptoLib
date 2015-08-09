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

#import "SessionKeyCache.h"

#import "CoreDataHelper.h"

#import "CachedSessionKeys.h"
#import "SessionKeys.h"
#import "MynigmaAttachmentEncryptionContext.h"


@implementation SessionKeyCache

+ (void)cacheAttachmentEncryptionContext:(MynigmaAttachmentEncryptionContext*)attachmentContext forUniqueKey:(NSString*)uniqueKey
{
    [[CoreDataHelper sharedInstance] runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
        
        NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"CachedSessionKeys"];
        [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"uniqueKey == %@", uniqueKey]];
        [fetchRequest setFetchLimit:1];
        
        CachedSessionKeys* existingEntry = [localContext executeFetchRequest:fetchRequest error:nil].firstObject;
        
    if(existingEntry)
    {
        existingEntry.encryptionContextData = attachmentContext.serialisedData;
    }
    else
    {
        CachedSessionKeys* addedEntry = [[CachedSessionKeys alloc] initWithEntity:[NSEntityDescription entityForName:@"CachedSessionKeys" inManagedObjectContext:localContext] insertIntoManagedObjectContext:localContext];
        
        addedEntry.encryptionContextData = attachmentContext.serialisedData;
        addedEntry.uniqueKey = uniqueKey;
    }
        
        [localContext save:nil];
        [[CoreDataHelper sharedInstance] save];
    }];
}

+ (MynigmaAttachmentEncryptionContext*)attachmentContextForUniqueKey:(NSString*)uniqueKey
{
    __block MynigmaAttachmentEncryptionContext* returnValue = nil;
    [[CoreDataHelper sharedInstance] runSyncOnKeyContext:^(NSManagedObjectContext *localContext) {

        NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"CachedSessionKeys"];
    [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"uniqueKey == %@", uniqueKey]];
    [fetchRequest setFetchLimit:1];
    
    CachedSessionKeys* sessionKeys = [localContext executeFetchRequest:fetchRequest error:nil].firstObject;
       
        returnValue = [[MynigmaAttachmentEncryptionContext alloc] initWithData:sessionKeys.encryptionContextData];
    }];
    
    return returnValue;
}

+ (void)purgeCache
{
    [[CoreDataHelper sharedInstance] runAsyncFreshLocalChildContext:^(NSManagedObjectContext *localContext) {
    NSFetchRequest *fetchRequest = [[NSFetchRequest alloc] initWithEntityName:@"CachedSessionKeys"];
    [fetchRequest setIncludesPropertyValues:NO];
    
    for (NSManagedObject *object in [localContext executeFetchRequest:fetchRequest error:nil])
    {
        [localContext deleteObject:object];
    }
        
        [localContext save:nil];
        [[CoreDataHelper sharedInstance] save];
    }];
}

@end
