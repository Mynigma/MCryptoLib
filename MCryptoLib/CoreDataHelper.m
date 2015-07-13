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





#import "CoreDataHelper.h"



@interface CoreDataHelper()

@property NSURL* coreDataStoreURL;
@property NSString* coreDataStoreType;

@end


@implementation CoreDataHelper

@synthesize persistentStoreCoordinator = _persistentStoreCoordinator;
@synthesize storeObjectContext = _storeObjectContext;
@synthesize managedObjectModel = _managedObjectModel;
@synthesize mainObjectContext = _mainObjectContext;
@synthesize keyObjectContext = _keyObjectContext;





+ (instancetype)sharedInstance
{
    static dispatch_once_t p = 0;

    __strong static id sharedObject = nil;

    dispatch_once(&p, ^{
        sharedObject = [[CoreDataHelper alloc] initWithFileName:@"MCryptoLib.storedata" storeType:NSSQLiteStoreType];
    });

    return sharedObject;
}

- (instancetype)initWithFileName:(NSString*)fileName storeType:(NSString*)storeType
{
    self = [super init];
    if(self)
    {
        NSURL* storeURL = [[CoreDataHelper applicationSupportSubDirectory] URLByAppendingPathComponent:fileName];
            
        [storeURL setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
            
        self.coreDataStoreURL = storeURL;
        self.coreDataStoreType = storeType;
    }
    return self;
}


+ (NSURL*)coreDataDirectory
{
    NSURL* url = [[NSFileManager defaultManager] URLForDirectory:NSApplicationSupportDirectory inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:nil];
    return url;
}


#if TARGET_OS_IPHONE

// Creates if necessary and returns the managed object model for the application.
- (NSManagedObjectModel *)managedObjectModel
{
    if (managedObjectModel != nil) {
        return managedObjectModel;
    }
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    if(!bundle)
    {
        NSLog(@"No bundle!");
        return nil;
    }
    managedObjectModel = [NSManagedObjectModel mergedModelFromBundles:@[bundle]];
    if(!managedObjectModel)
    {
        NSLog(@"No managed object model!!!");
    }
    return managedObjectModel;
}

#else

// Creates if necessary and returns the managed object model for the application.
- (NSManagedObjectModel *)managedObjectModel
{
    if (_managedObjectModel)
    {
        return _managedObjectModel;
    }

    NSURL *modelURL = [[NSBundle bundleForClass:self.class] URLForResource:@"MCryptoLib" withExtension:@"momd"];

    _managedObjectModel = [[NSManagedObjectModel alloc] initWithContentsOfURL:modelURL];
    return _managedObjectModel;
}

#endif


+ (NSURL *)applicationSupportSubDirectory
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *appSupportURL = [[fileManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] lastObject];
    return [appSupportURL URLByAppendingPathComponent:@"MCryptoLib"];
}



// Returns the store object context for the application (which is already bound to the persistent store coordinator for the application.)
- (NSManagedObjectContext *)storeObjectContext
{
    if (_storeObjectContext)
    {
        return _storeObjectContext;
    }

    NSPersistentStoreCoordinator *coordinator = [self persistentStoreCoordinator];
    if (!coordinator)
    {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setValue:@"Failed to initialize the store" forKey:NSLocalizedDescriptionKey];
        [dict setValue:@"There was an error building up the data file." forKey:NSLocalizedFailureReasonErrorKey];

        @throw [NSException exceptionWithName:@"CoreDataInitialisationFailure" reason:@"The MCryptoLib core data store could not be initialised" userInfo:dict];
    }
    _storeObjectContext = [[NSManagedObjectContext alloc] initWithConcurrencyType:NSPrivateQueueConcurrencyType];
    [_storeObjectContext setUndoManager:nil];
    [_storeObjectContext setPersistentStoreCoordinator:coordinator];
    [_storeObjectContext setMergePolicy:NSErrorMergePolicy];

    return _storeObjectContext;
}




//returns the main object context (which is a child of the store context and runs on the main thread)
- (NSManagedObjectContext *)mainObjectContext
{
    if (_mainObjectContext)
    {
        return _mainObjectContext;
    }

    NSPersistentStoreCoordinator *coordinator = [self persistentStoreCoordinator];
    if (!coordinator)
    {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setValue:@"Failed to initialize the store" forKey:NSLocalizedDescriptionKey];
        [dict setValue:@"There was an error building up the data file." forKey:NSLocalizedFailureReasonErrorKey];

        @throw [NSException exceptionWithName:@"CoreDataInitialisationFailure" reason:@"The MCryptoLib core data persistent store coordinator could not be initialised" userInfo:dict];
    }


    _mainObjectContext = [[NSManagedObjectContext alloc] initWithConcurrencyType:NSMainQueueConcurrencyType];

    //Undo Support
    //NSUndoManager* undoManager = [NSUndoManager new];
    [_mainObjectContext setUndoManager:nil];
    //[_mainObjectContext.undoManager disableUndoRegistration];
    [_mainObjectContext setMergePolicy:NSErrorMergePolicy];

    NSManagedObjectContext* storeContext = [self storeObjectContext];

    if(storeContext)
        [_mainObjectContext setParentContext:storeContext];

    return _mainObjectContext;
}

//returns the key object context (which is a child of the main context and is not tied to the main thread)
- (NSManagedObjectContext *)keyObjectContext
{
    if (!_keyObjectContext)
    {
        NSManagedObjectContext* localContext = [[NSManagedObjectContext alloc] initWithConcurrencyType:NSPrivateQueueConcurrencyType];
        [localContext setParentContext:[CoreDataHelper sharedInstance].mainObjectContext];
        [localContext setMergePolicy:NSErrorMergePolicy];
        [localContext setUndoManager:nil];

        _keyObjectContext = localContext;
    }

    return _keyObjectContext;
}

// Returns the persistent store coordinator for the application. This implementation creates and return a coordinator, having added the store for the application to it. (The directory for the store is created, if necessary.)
- (NSPersistentStoreCoordinator *)persistentStoreCoordinator
{
    if(persistentStoreCoordinator)
    {
        return persistentStoreCoordinator;
    }

    NSManagedObjectModel *mom = [self managedObjectModel];
    if(!mom)
    {
        NSLog(@"%@:%@ No model to generate a store from", [self class], NSStringFromSelector(_cmd));
        return nil;
    }

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *applicationFilesDirectory = [CoreDataHelper applicationSupportSubDirectory];
    NSError *error = nil;

    NSDictionary *properties = [applicationFilesDirectory resourceValuesForKeys:@[NSURLIsDirectoryKey] error:&error];

    if(!properties)
    {
        BOOL ok = NO;
        if([error code] == NSFileReadNoSuchFileError)
        {
            ok = [fileManager createDirectoryAtPath:[applicationFilesDirectory path] withIntermediateDirectories:YES attributes:nil error:&error];
        }
        if(!ok)
        {
            NSLog(@"Error creating directory: %@", error);
            return nil;
        }
    }
    else
    {
        if (![[properties valueForKey:NSURLIsDirectoryKey] boolValue]) {
            // Customize and localize this error.
            NSString *failureDescription = [NSString stringWithFormat:NSLocalizedString(@"Expected a folder to store application data, found a file (%@).",@"The filename"), [applicationFilesDirectory path]];

            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setValue:failureDescription forKey:NSLocalizedDescriptionKey];
            error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:101 userInfo:dict];

            NSLog(@"Error creating store: %@", error);
            return nil;
        }
    }

    NSURL *url = [self coreDataStoreURL];
    
    [url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];


    NSPersistentStoreCoordinator *coordinator = [[NSPersistentStoreCoordinator alloc] initWithManagedObjectModel:mom];

    NSDictionary *options = @{NSMigratePersistentStoresAutomaticallyOption:@YES,
                              NSInferMappingModelAutomaticallyOption:@YES};

    if (![coordinator addPersistentStoreWithType:[self coreDataStoreType] configuration:nil URL:url options:options error:&error]) {
        NSLog(@"Error creating persistent store: %@", error);
        return nil;
    }
    _persistentStoreCoordinator = coordinator;
    
    return _persistentStoreCoordinator;
}


- (BOOL)haveInitialisedManagedObjectContext
{
    return _mainObjectContext != nil;
}



#pragma mark -
#pragma mark SAVING


//saves the main context, but not the (parent) store context
- (void)saveOnlyMain
{
    [self saveOnlyMainWithCallback:nil];
}

//saves the main context, but not the store context, then executes the callback
- (void)saveOnlyMainWithCallback:(void(^)(void))callback
{
    //NSLog(@"Saving... ");

    [self runAsyncOnMain:^{

        @try {
            NSError* error = nil;
            [self.mainObjectContext save:&error];
            if(error)
                NSLog(@"Error saving main object context: %@",error);

        }
        @catch (NSException *exception) {
            NSLog(@"Exception while trying to save main context: %@", exception);
        }
        @finally {

        }

        if(callback)
            callback();
    }];
}


//saves the main context and then the store context (asynchronously)
- (void)save
{
    [self saveWithCallback:nil];
}

- (void)saveAndWait
{
    [self runSyncOnMain:^{

        @try {
            NSError* error = nil;
            [self.mainObjectContext save:&error];
            if(error)
                NSLog(@"Error saving main object context: %@",error);

        }
        @catch (NSException *exception) {
            NSLog(@"Exception while trying to save main context: %@", exception);
        }
        @finally {

        }

        [self.storeObjectContext performBlockAndWait:^{

            @try {
                NSError* error = nil;
                [self.storeObjectContext save:&error];
                if(error)
                    NSLog(@"Error saving store object context: %@",error);
            }
            @catch (NSException *exception) {
                NSLog(@"Exception while trying to save main context: %@", exception);
            }
            @finally {

            }
        }];

    }];
}

//saves the main context and then the store context asynchronously and then executes the callback
- (void)saveWithCallback:(void(^)(void))callback
{
    [self saveOnlyMainWithCallback:^{

        if(callback)
            callback();

            [self saveOnlyStoreContextWithCallback:nil];
    }];
}



- (void)saveOnlyStoreContextWithCallback:(void(^)(void))callback
{
    [self.storeObjectContext performBlock:^{
        
    @try {
        NSError* error = nil;
        [self.storeObjectContext save:&error];
        if(error)
            NSLog(@"Error saving store object context: %@",error);
    }
    @catch (NSException *exception) {
        NSLog(@"Exception while trying to save main context: %@", exception);
    }
    @finally {
        
        if(callback)
            callback();
    }
    }];
}






- (void)runAsyncFreshLocalChildContext:(void(^)(NSManagedObjectContext* localContext))executionBlock
{
    NSManagedObjectContext* localContext = [[NSManagedObjectContext alloc] initWithConcurrencyType:NSPrivateQueueConcurrencyType];
    [localContext setParentContext:self.mainObjectContext];
    [localContext setMergePolicy:NSErrorMergePolicy];
    [localContext setUndoManager:nil];
    
    [localContext performBlock:^{
        
        executionBlock(localContext);
        
        NSError* error = nil;
        
        [localContext save:&error];
        
        if(error)
        {
            NSLog(@"Error saving local context at end of run async block");
        }
    }];
}


- (void)runAsyncOnKeyContext:(void(^)(void))blockToRun
{
    [self.keyObjectContext performBlock:^{
        
        blockToRun();
        
        NSError* error = nil;
        
        [self.keyObjectContext save:&error];
        
        if(error)
        {
            NSLog(@"Error saving key context at end of CoreDataHelper async block");
        }
        
        [self save];
    }];
}

- (void)runSyncOnKeyContext:(void(^)(NSManagedObjectContext* keyContext))blockToRun
{
    //don't call [KEY_CONTEXT performBlockAndWait:] from the main thread
    //it would cause a deadlock if the key context needs to fetch objects from its parent, the main context
    if([NSThread isMainThread])
    {
        [self.mainObjectContext performBlockAndWait:^{
            
            blockToRun(self.mainObjectContext);
            
            [self save];
        }];
    }
    else
    {
        [self.keyObjectContext performBlockAndWait:^{
            
            blockToRun(self.keyObjectContext);
            
            NSError* error = nil;
            
            [self.keyObjectContext save:&error];
            
            if(error)
            {
                NSLog(@"Error saving key context at end of CoreDataHelper sync block");
            }
            
            [self save];
        }];
    }
}

- (void)runAsyncOnMain:(void(^)(void))blockToRun
{
    [self.mainObjectContext performBlock:^{

        blockToRun();
    }];
}

- (void)runSyncOnMain:(void(^)(void))blockToRun
{
    [self.mainObjectContext performBlockAndWait:^{
        
        blockToRun();
        
    }];
}


- (NSManagedObject*)fetchObjectOfClass:(Class)objectClass withPredicate:(NSPredicate*)predicate inContext:(NSManagedObjectContext*)localContext
{
    NSFetchRequest* fetchRequest = [[NSFetchRequest alloc] initWithEntityName:NSStringFromClass(objectClass)];
    
    if(predicate)
        [fetchRequest setPredicate:predicate];
    
    NSError* error = nil;
    
    NSArray* results = [localContext executeFetchRequest:fetchRequest error:&error];
    
    if(error)
    {
        NSLog(@"Error fetching object of class %@: %@", objectClass, error);
    }
    
    if(results.count>1)
    {
        NSLog(@"More than one object of class %@ with predicate %@", objectClass, predicate);
    }
    
    return results.firstObject;
}

- (BOOL)haveObjectOfClass:(Class)objectClass withPredicate:(NSPredicate*)predicate inContext:(NSManagedObjectContext*)localContext
{
    NSFetchRequest* fetchRequest = [[NSFetchRequest alloc] initWithEntityName:NSStringFromClass(objectClass)];
    
    if(predicate)
        [fetchRequest setPredicate:predicate];
    
    NSError* error = nil;
    
    NSInteger resultsCount = [localContext countForFetchRequest:fetchRequest error:&error];
                        
    if(error)
    {
        NSLog(@"Error fetching count for object of class %@: %@", objectClass, error);
    }
    
    return resultsCount > 0;
}

@end
