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


#import <CoreData/CoreData.h>

#import "CoreDataHelper.h"
#import "ThreadHelper.h"

#import <objc/runtime.h>





static NSString* dictKey = @"MynManagedObjectContext";

@implementation ThreadHelper


+ (BOOL)ensureMainThread
{
    if(![NSThread isMainThread])
    {
        NSLog(@"Ensuring main thread failed!!");
        NSLog(@"Stack trace: %@", [NSThread callStackSymbols]);
        return NO;
    }
    
    return YES;
}



+ (void)runAsyncFreshLocalChildContext:(void(^)(NSManagedObjectContext* localContext))executionBlock
{
    NSManagedObjectContext* localContext = [[NSManagedObjectContext alloc] initWithConcurrencyType:NSPrivateQueueConcurrencyType];
    [localContext setParentContext:[CoreDataHelper sharedInstance].mainObjectContext];
    [localContext setMergePolicy:NSErrorMergePolicy];
    [localContext setUndoManager:nil];

    [localContext performBlock:^{

        NSThread* currentThread = [NSThread currentThread];

        currentThread.threadDictionary[dictKey] = localContext;

        executionBlock(localContext);

        NSError* error = nil;

        //NSDate* startDate = [NSDate date];

        [localContext save:&error];

        //[ThreadHelper printElapsedTimeSince:startDate withIdentifier:@"local context save"];

        if(error)
        {
            NSLog(@"Error saving local context at end of run async block");
        }

        [currentThread.threadDictionary removeObjectForKey:dictKey];
    }];
}


+ (void)runAsyncOnKeyContext:(void(^)(void))blockToRun
{
    [[CoreDataHelper sharedInstance].keyObjectContext performBlock:^{

        blockToRun();

        NSError* error = nil;

        [[CoreDataHelper sharedInstance].keyObjectContext save:&error];

        if(error)
        {
            NSLog(@"Error saving key context at end of ThreadHelper async block");
        }

        [[CoreDataHelper sharedInstance] save];
    }];
}

+ (void)runSyncOnKeyContext:(void(^)(NSManagedObjectContext* keyContext))blockToRun
{
    //don't call [KEY_CONTEXT performBlockAndWait:] from the main thread
    //it would cause a deadlock if the key context needs to fetch objects from its parent, the main context
    if([NSThread isMainThread])
    {
        [[CoreDataHelper sharedInstance].mainObjectContext performBlockAndWait:^{

            blockToRun([CoreDataHelper sharedInstance].mainObjectContext);

            [[CoreDataHelper sharedInstance] save];
        }];
    }
    else
    {
    [[CoreDataHelper sharedInstance].keyObjectContext performBlockAndWait:^{

        blockToRun([CoreDataHelper sharedInstance].keyObjectContext);

        NSError* error = nil;

        [[CoreDataHelper sharedInstance].keyObjectContext save:&error];

        if(error)
        {
            NSLog(@"Error saving key context at end of ThreadHelper sync block");
        }

        [[CoreDataHelper sharedInstance] save];
}];
    }
}

+ (void)runAsyncOnMain:(void(^)(void))blockToRun
{
    [[CoreDataHelper sharedInstance].mainObjectContext performBlock:^{

        blockToRun();
    }];
}

+ (void)runSyncOnMain:(void(^)(void))blockToRun
{
    [[CoreDataHelper sharedInstance].mainObjectContext performBlockAndWait:^{

        blockToRun();       
    }];
}


///**
//Calls block within an @synchronized(syncObject) statement, unless it is called on the main thread. In this case no synchronisation is enforced. This prevents beach balls for code that should not, but may be executed concurrently on the main and at most one other thread.
//*/
//+ (void)synchronizeIfNotOnMain:(NSObject*)syncObject block:(void(^)(void))blockToExecute
//{
//    if([NSThread isMainThread])
//    {
//        if(blockToExecute)
//            blockToExecute();
//    }
//    else
//    {
//        @synchronized(syncObject)
//        {
//            if(blockToExecute)
//                blockToExecute();
//        }
//    }
//}

@end
