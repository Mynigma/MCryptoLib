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


#define MAIN_CONTEXT ([CoreDataHelper sharedInstance].mainObjectContext)

//the key context
#define KEY_CONTEXT ([CoreDataHelper sharedInstance].keyObjectContext)



@interface CoreDataHelper : NSObject
{
    //store coordinator and managed object contexts
    NSPersistentStoreCoordinator* persistentStoreCoordinator;
    NSManagedObjectModel* managedObjectModel;
    NSManagedObjectContext* mainObjectContext;
    NSManagedObjectContext* storeObjectContext;

    //the object context used for storing and fetching keys
    NSManagedObjectContext* keyObjectContext;
}


//store coordinator and managed object contexts
@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *mainObjectContext;
@property (readonly, strong, nonatomic) NSManagedObjectContext *storeObjectContext;

//the object context used for storing and fetching keys
@property (readonly, strong, nonatomic) NSManagedObjectContext* keyObjectContext;


+ (instancetype)sharedInstance;

- (instancetype)initWithFileName:(NSString*)fileName storeType:(NSString*)storeType;



//+ (NSString*)coreDataStoreType;
//
//+ (NSURL*)coreDataStoreURL;
//


+ (NSURL *)applicationSupportSubDirectory;


- (BOOL)haveInitialisedManagedObjectContext;



#pragma mark - SAVING


- (void)saveOnlyMain;
- (void)saveOnlyMainWithCallback:(void(^)(void))callback;
- (void)save;
- (void)saveAndWait;
- (void)saveWithCallback:(void(^)(void))callback;
- (void)saveOnlyStoreContextWithCallback:(void(^)(void))callback;


#pragma mark - THREADS

- (void)runAsyncFreshLocalChildContext:(void(^)(NSManagedObjectContext* localContext))executionBlock;
- (void)runAsyncOnKeyContext:(void(^)(void))blockToRun;
- (void)runSyncOnKeyContext:(void(^)(NSManagedObjectContext* keyContext))blockToRun;
- (void)runAsyncOnMain:(void(^)(void))blockToRun;
- (void)runSyncOnMain:(void(^)(void))blockToRun;



- (NSManagedObject*)fetchObjectOfClass:(Class)objectClass withPredicate:(NSPredicate*)predicate inContext:(NSManagedObjectContext*)localContext;

- (BOOL)haveObjectOfClass:(Class)objectClass withPredicate:(NSPredicate*)predicate inContext:(NSManagedObjectContext*)localContext;

@end
