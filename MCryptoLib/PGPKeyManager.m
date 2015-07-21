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


#import "PGPKeyManager.h"

#import "CoreDataHelper.h"
#import "KeychainHelper+PGP.h"
#import "OpenSSLEncryptionEngine.h"
#import "KeyParser.h"

#import "PGPPublicKey.h"

#import "signature.h"
#import "fmemopen.h"
#import "keyring.h"
#import "mj.h"
#import "PGPUserID.h"
#import "EmailAddress.h"
#import "PGPPrivateKey.h"




@interface PGPKeyManager()

@property NSString* userID;

@property netpgp_t* netPGP;

@property NSString* homeDirectoryPath;
@property NSString* publicKeyringPath;
@property NSString* privateKeyringPath;

@property NSString* password;

@end


@implementation PGPKeyManager


- (instancetype)initWithKeychainHelper:(KeychainHelper*)keychainHelper
{
    self = [super init];
    if(self)
    {
        [self setKeychainHelper:keychainHelper];
        
        [self setOpenSSLEngine:[OpenSSLEncryptionEngine new]];

        NSURL* homeDirectory = [[CoreDataHelper applicationSupportSubDirectory] URLByAppendingPathComponent:@"PGP"];
        
        [homeDirectory setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:homeDirectory.path isDirectory:nil])
        {
            [[NSFileManager defaultManager] createDirectoryAtPath:homeDirectory.path withIntermediateDirectories:YES attributes:nil error:nil];
        }
        
        self.homeDirectoryPath = homeDirectory.path;
        self.publicKeyringPath = [homeDirectory URLByAppendingPathComponent:@"public_keyring.pgp"].path;
        self.privateKeyringPath = [homeDirectory URLByAppendingPathComponent:@"private_keyring.pgp"].path;
        
        self.password = @"dummyPassphrase";
        
        [self buildnetpgp];
    }
    return self;
}

- (instancetype) initWithUserID:(NSString *)userID
{
    if (self = [self init])
    {
        self.userID = userID;
    }
    return self;
}

- (instancetype)init
{
    return [self initWithKeychainHelper:[KeychainHelper new]];
}



- (netpgp_t *)buildnetpgp;
{
    @synchronized(self)
    {
        if(!self.netPGP)
        {
            self.netPGP = calloc(0x1, sizeof(netpgp_t));
            
            if (self.userID)
                netpgp_setvar(self.netPGP, "userid", self.userID.UTF8String);
            
            if(self.password)
                netpgp_setvar(self.netPGP, "passphrase", [self.password cStringUsingEncoding:NSUTF8StringEncoding]);
            
            if (self.homeDirectoryPath)
            {
                char *directory_path = calloc(self.homeDirectoryPath.length+1, sizeof(char));
                strcpy(directory_path, self.homeDirectoryPath.UTF8String);
                
                netpgp_set_homedir(self.netPGP, directory_path, NULL, 0);
                
                free(directory_path);
            }
            
            if (self.privateKeyringPath)
            {
                if (![[NSFileManager defaultManager] fileExistsAtPath:self.privateKeyringPath])
                {
                    [[NSFileManager defaultManager] createFileAtPath:self.privateKeyringPath contents:nil attributes:@{NSFilePosixPermissions: [NSNumber numberWithShort:0600]}];
                }
                netpgp_setvar(self.netPGP, "secring", self.privateKeyringPath.UTF8String);
            }
            
            if (self.publicKeyringPath)
            {
                if (![[NSFileManager defaultManager] fileExistsAtPath:self.publicKeyringPath]) {
                    [[NSFileManager defaultManager] createFileAtPath:self.publicKeyringPath contents:nil attributes:@{NSFilePosixPermissions: [NSNumber numberWithShort:0600]}];
                }
                netpgp_setvar(self.netPGP, "pubring", self.publicKeyringPath.UTF8String);
            }
            
            if (self.password)
            {
                const char* cstr = [self.password stringByAppendingString:@"\n"].UTF8String;
                self.netPGP->passfp = fmemopen((void *)cstr, sizeof(char) * (self.password.length + 1), "r");
            }
            
            /* 4 MiB for a memory file */
            netpgp_setvar(self.netPGP, "max mem alloc", "4194304");
            
            //FIXME: use sha1 because sha256 crashing, don't know why yet
            netpgp_setvar(self.netPGP, "hash", "sha1");
            
            // Custom variable
            //netpgp_setvar(netpgp, "dont use subkey to encrypt", "1");
            
#if DEBUG
            netpgp_incvar(self.netPGP, "verbose", 1);
            netpgp_set_debug(NULL);
#endif
            
            if (!netpgp_init(self.netPGP))
            {
                NSLog(@"Can't initialize netpgp stack");
                free(self.netPGP);
                return nil;
            }
        }
        return self.netPGP;
    }
}

- (void) finishnetpgp:(netpgp_t *)netpgp
{
    if (!netpgp) {
        return;
    }
    
    netpgp_end(netpgp);
    free(netpgp);
}








+ (BOOL)stringIsArmoured:(NSString*)string
{
    return [string hasPrefix:@"-----BEGIN"];
}

+ (BOOL)dataIsArmoured:(NSData*)data
{
    if(data.length < 10)
        return NO;
    
    return [[data subdataWithRange:NSMakeRange(0, 10)] isEqual:[@"-----BEGIN" dataUsingEncoding:NSUTF8StringEncoding]];
}


static void
str2keyid(const char *userid, uint8_t *keyid, size_t len)
{
    static const char	*uppers = "0123456789ABCDEF";
    static const char	*lowers = "0123456789abcdef";
    const char		*hi;
    const char		*lo;
    uint8_t			 hichar;
    uint8_t			 lochar;
    size_t			 j;
    int			 i;
    
    for (i = 0, j = 0 ; j < len && userid[i] && userid[i + 1] ; i += 2, j++) {
        if ((hi = strchr(uppers, userid[i])) == NULL) {
            if ((hi = strchr(lowers, userid[i])) == NULL) {
                break;
            }
            hichar = (uint8_t)(hi - lowers);
        } else {
            hichar = (uint8_t)(hi - uppers);
        }
        if ((lo = strchr(uppers, userid[i + 1])) == NULL) {
            if ((lo = strchr(lowers, userid[i + 1])) == NULL) {
                break;
            }
            lochar = (uint8_t)(lo - lowers);
        } else {
            lochar = (uint8_t)(lo - uppers);
        }
        keyid[j] = (hichar << 4) | (lochar);
    }
    keyid[j] = 0x0;
}

- (NSArray*)listKeys
{
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"PGPPublicKey"];
    
    return [MAIN_CONTEXT executeFetchRequest:fetchRequest error:nil];
    
    //    char* json;
    //
    //    int length = netpgp_list_keys_json(self.netPGP, &json, 0);
    //
    //    if(length == 0 || !json)
    //        return nil;
    //
    //    NSData* JSONData = [NSData dataWithBytesNoCopy:json length:length freeWhenDone:YES];
    //
    //    NSError* error = nil;
    //
    //    NSObject* keyDict = [NSJSONSerialization JSONObjectWithData:JSONData options:0 error:&error];
    //
    //    if([keyDict isKindOfClass:[NSArray class]])
    //        return (NSArray*)keyDict;
    //
    //    return nil;
}

- (BOOL)importKeyFromFileWithURL:(NSURL*)fileURL
{
    NSData* data = [NSData dataWithContentsOfURL:fileURL];
    
    //    return 0 != netpgp_import_key(self.netPGP, (void*)data.bytes);
    
    unsigned isArmoured = [PGPKeyManager dataIsArmoured:data];
    
    __ops_keyring_t* keyring = NULL;
    if ((keyring = calloc(1, sizeof(*keyring))) == NULL)
    {
        (void) fprintf(stderr, "readkeyring: bad alloc\n");
        return 0;
    }
    __ops_memory_t* memory = __ops_memory_new();
    __ops_memory_add(memory, data.bytes, data.length);
    
    __ops_io_t* io = self.netPGP->io;
    
    unsigned done = __ops_keyring_read_from_mem(io, keyring, isArmoured, memory);
    
    if (!done)
    {
        NSLog(@"Failed to import key from data! %@", data);
        return 0;
    }
    
    BOOL foundAKey = NO;
    
    __ops_key_t* key = NULL;
    unsigned n;
    for (n = 0, key = keyring->keys; n < keyring->keyc; ++n, ++key)
    {
        foundAKey = YES;
    }
    
    mj_t* mj_JSONObject = malloc(sizeof(mj_t));
    
    done = __ops_keyring_json(io, keyring, mj_JSONObject, 0);
    
    char* buf = NULL;
    
    int size = mj_asprint(&buf, mj_JSONObject);
    
    NSData* JSONData = [[NSData alloc] initWithBytes:buf length:size - 1];
    
    NSError* error = nil;
    
    NSArray* JSONArray = (NSArray*)[NSJSONSerialization JSONObjectWithData:JSONData  options:0 error:&error];
    
    for(NSDictionary* keyProperties in JSONArray)
    {
        NSString* keyID = (NSString*)keyProperties[@"key id"];
        
        uint8_t keyIDRawData[16];
        
        str2keyid([keyID cStringUsingEncoding:NSUTF8StringEncoding], keyIDRawData, 16);
        
        unsigned from = 0;
        
        const __ops_key_t* key = __ops_getkeybyid(io, keyring, keyIDRawData, &from, NULL);
        
        if(__ops_is_key_secret(key))
        {
            [self addPGPPrivateKeyWithProperties:keyProperties opsKey:key];
        }
        else
        {
            [self addPGPPublicKeyWithProperties:keyProperties opsKey:key];
        }
    }
    
    if (keyring != NULL)
    {
        __ops_keyring_free(keyring);
        free(keyring);
    }
    
    return foundAKey;
}

- (PGPPublicKey*)fetchPublicKeyWithFingerprint:(NSData*)fingerprint inContext:(NSManagedObjectContext*)localContext error:(NSError**)error
{
    if(!fingerprint.length)
        return nil;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"PGPPublicKey"];
    [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"fingerprint == %@", fingerprint]];
    
    return [localContext executeFetchRequest:fetchRequest error:error].firstObject;
}

- (PGPPrivateKey*)fetchPrivateKeyWithFingerprint:(NSData*)fingerprint inContext:(NSManagedObjectContext*)localContext error:(NSError**)error
{
    if(!fingerprint.length)
        return nil;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"PGPPrivateKey"];
    [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"fingerprint == %@", fingerprint]];
    
    return [localContext executeFetchRequest:fetchRequest error:error].firstObject;
}


- (PGPUserID*)fetchUserID:(NSString*)userIDString inContext:(NSManagedObjectContext*)localContext error:(NSError**)error
{
    if(!userIDString.length)
        return nil;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"PGPUserID"];
    [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"text == %@", userIDString]];
    
    return [localContext executeFetchRequest:fetchRequest error:error].firstObject;
}

- (EmailAddress*)fetchEmailAddress:(NSString*)emailAddressString inContext:(NSManagedObjectContext*)localContext error:(NSError**)error

{
    if(!emailAddressString.length)
        return nil;
    
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"EmailAddress"];
    [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"address == %@", emailAddressString]];
    
    return [localContext executeFetchRequest:fetchRequest error:error].firstObject;
}

- (EmailAddress*)emailAddressForString:(NSString*)emailAddressString
{
    NSError* error = nil;
    
    EmailAddress* emailAddress = [self fetchEmailAddress:emailAddressString inContext:MAIN_CONTEXT error:&error];
    
    if(emailAddress)
        return emailAddress;
    
    if(error)
        return nil;
    
    emailAddress = [NSEntityDescription insertNewObjectForEntityForName:@"EmailAddress" inManagedObjectContext:MAIN_CONTEXT];
    [emailAddress setAddress:emailAddressString];
    
    [emailAddress setDateAdded:[NSDate date]];
    
    return emailAddress;
}

- (PGPUserID*)userIDForString:(NSString*)userIDString
{
    NSError* error = nil;
    
    PGPUserID* userID = [self fetchUserID:userIDString inContext:MAIN_CONTEXT error:&error];
    
    if(userID)
        return userID;
    
    if(error)
        return nil;
    
    userID = [NSEntityDescription insertNewObjectForEntityForName:@"PGPUserID" inManagedObjectContext:MAIN_CONTEXT];
    [userID setText:userIDString];
    
    //extract the email address
    NSInteger indexOfOpeningBracket = [userIDString rangeOfString:@"<"].location;
    NSInteger indexOfClosingBracket = [userIDString rangeOfString:@">"].location;
    
    if(indexOfOpeningBracket != NSNotFound && indexOfClosingBracket != NSNotFound && indexOfOpeningBracket < indexOfClosingBracket)
    {
        NSString* emailAddressString = [userIDString substringWithRange:NSMakeRange(indexOfOpeningBracket + 1, indexOfClosingBracket - indexOfOpeningBracket - 1)];
        
        EmailAddress* emailAddress = [self emailAddressForString:emailAddressString];
        
        [userID setEmailAddress:emailAddress];
    }
    
    return userID;
}

- (PGPPublicKey*)addPGPPublicKeyWithProperties:(NSDictionary*)keyProperties opsKey:(const __ops_key_t*)opsKey
{
    NSString* fingerprint = (NSString*)keyProperties[@"fingerprint"];
    NSData* fingerprintData = [PGPKeyManager dataFromHexString:fingerprint];
    
    if(!fingerprintData.length)
        return nil;
    
    NSError* error = nil;
    
    PGPPublicKey* publicKey = [self fetchPublicKeyWithFingerprint:fingerprintData inContext:MAIN_CONTEXT error:&error];
    
    if(!publicKey && !error)
    {
        publicKey = [NSEntityDescription insertNewObjectForEntityForName:@"PGPPublicKey" inManagedObjectContext:MAIN_CONTEXT];
        [publicKey setFingerprint:fingerprintData];
        
        NSString* keyID = (NSString*)keyProperties[@"key id"];
        NSData* keyIDData = [PGPKeyManager dataFromHexString:keyID];
        
        [publicKey setKeyID:keyIDData];
        
        NSNumber* UNIXCreationDate = (NSNumber*)keyProperties[@"birthtime"];
        if([UNIXCreationDate isKindOfClass:[NSNumber class]])
            [publicKey setCreationDate:[NSDate dateWithTimeIntervalSince1970:UNIXCreationDate.floatValue]];
        
        NSNumber* duration = (NSNumber*)keyProperties[@"duration"];
        if([duration isKindOfClass:[NSNumber class]] && duration.floatValue > .1 && publicKey.creationDate)
            [publicKey setExpiryDate:[NSDate dateWithTimeInterval:duration.floatValue sinceDate:publicKey.creationDate]];
        
        NSArray* userIDs = (NSArray*)keyProperties[@"uid"];
        
        for(NSString* userIDString in userIDs)
        {
            if([userIDString isKindOfClass:[NSString class]] && userIDString.length)
            {
                PGPUserID* userID = [self userIDForString:userIDString];
                
                [userID addKeysObject:publicKey];
                
                if(!userID.activeKey)
                    [userID setActiveKey:publicKey];
            }
        }
        
        NSData* PKCS8Data = [self PKCS8DataForOpsPGPPublicKey:opsKey];
        
        //now add the actual key to the keychain
        NSData* persistentRef = [self.keychainHelper addPublicPGPKeyWithPKCS8Data:PKCS8Data];
        
        [publicKey setPublicKeychainRef:persistentRef];
    }
    
    return publicKey;
}


- (PGPPrivateKey*)addPGPPrivateKeyWithProperties:(NSDictionary*)keyProperties opsKey:(const __ops_key_t*)opsKey
{
    NSData* PKCS8PublicKeyData = [self PKCS8DataForOpsPGPPublicKey:opsKey];
    NSData* PKCS12PrivateKeyData = [self PKCS12DataForOpsPGPPrivateKey:opsKey];
    
    NSData* persistentPublicRef = [self.keychainHelper addPublicPGPKeyWithPKCS8Data:PKCS8PublicKeyData];
    
    NSData* persistentPrivateRef = [self.keychainHelper addPrivatePGPKeyWithPKCS12Data:PKCS12PrivateKeyData];

    if(!persistentPublicRef || !persistentPrivateRef)
    {
        NSLog(@"Cannot add private key!! Error adding persistent ref to keychain!");
        
        return nil;
    }
    
    
    NSString* fingerprint = (NSString*)keyProperties[@"fingerprint"];
    NSData* fingerprintData = [PGPKeyManager dataFromHexString:fingerprint];
    
    if(!fingerprintData.length)
        return nil;
    
    NSError* error = nil;
    
    PGPPrivateKey* privateKey = [self fetchPrivateKeyWithFingerprint:fingerprintData inContext:MAIN_CONTEXT error:&error];
    
    if(!privateKey && !error)
    {
        PGPPublicKey* publicKey = [self fetchPublicKeyWithFingerprint:fingerprintData inContext:MAIN_CONTEXT error:&error];
        
        if(publicKey || error)
        {
            //TODO: allow addition of private key if public key already exists
            NSLog(@"Addition of private key failed, as public key already exists");
            
            return nil;
        }
        
        privateKey = [NSEntityDescription insertNewObjectForEntityForName:@"PGPPrivateKey" inManagedObjectContext:MAIN_CONTEXT];
        [privateKey setFingerprint:fingerprintData];
        
        NSString* keyID = (NSString*)keyProperties[@"key id"];
        NSData* keyIDData = [PGPKeyManager dataFromHexString:keyID];
        
        [privateKey setKeyID:keyIDData];
        
        NSNumber* UNIXCreationDate = (NSNumber*)keyProperties[@"birthtime"];
        if([UNIXCreationDate isKindOfClass:[NSNumber class]])
            [privateKey setCreationDate:[NSDate dateWithTimeIntervalSince1970:UNIXCreationDate.floatValue]];
        
        NSNumber* duration = (NSNumber*)keyProperties[@"duration"];
        if([duration isKindOfClass:[NSNumber class]] && duration.floatValue > .1 && privateKey.creationDate)
            [privateKey setExpiryDate:[NSDate dateWithTimeInterval:duration.floatValue sinceDate:publicKey.creationDate]];
        
        NSArray* userIDs = (NSArray*)keyProperties[@"uid"];
        
        for(NSString* userIDString in userIDs)
        {
            if([userIDString isKindOfClass:[NSString class]] && userIDString.length)
            {
                PGPUserID* userID = [self userIDForString:userIDString];
                
                [userID addKeysObject:privateKey];
                
                if(!userID.activeKey)
                    [userID setActiveKey:privateKey];
            }
        }
        
        //now add the actual key to the keychain
        [privateKey setPublicKeychainRef:persistentPublicRef];
        [privateKey setPrivateKeychainRef:persistentPrivateRef];
    }
    
    return privateKey;
}



+ (NSData*)dataFromHexString:(NSString*)hexString
{
    hexString = hexString.lowercaseString;
    
    NSCharacterSet *charactersToRemove = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
    hexString = [[hexString componentsSeparatedByCharactersInSet:charactersToRemove] componentsJoinedByString:@""];
    
    if(!hexString.length)
        return NULL;
    
    const char *cString = [hexString cStringUsingEncoding:NSUTF8StringEncoding];
    char twoChars[3]={0,0,0};
    long bytesBlockSize = hexString.length/2;
    long counter = bytesBlockSize;
    Byte *bytesBlock = malloc(bytesBlockSize);
    if(!bytesBlock)
        return NULL;
    Byte *writer = bytesBlock;
    while(counter--)
    {
        twoChars[0]=*cString++;
        twoChars[1]=*cString++;
        *writer++ = strtol(twoChars, NULL, 16);
    }
    return [NSData dataWithBytesNoCopy:bytesBlock length:bytesBlockSize freeWhenDone:YES];
}


//static const __ops_key_t* resolve_userid(netpgp_t *netpgp, const __ops_keyring_t *keyring, const char *userid)
//{
//    const __ops_key_t	*key;
//    __ops_io_t		*io;
//    
//    if (userid == NULL) {
//        userid = netpgp_getvar(netpgp, "userid");
//        if (userid == NULL)
//            return NULL;
//    } else if (userid[0] == '0' && userid[1] == 'x') {
//        userid += 2;
//    }
//    io = netpgp->io;
//    if ((key = __ops_getkeybyname(io, keyring, userid)) == NULL) {
//        (void) fprintf(io->errs, "Can't find key '%s'\n", userid);
//    }
//    return key;
//}

- (PGPPublicKey*)publicVerificationKeyForUserID:(NSString*)userID
{
    //    netpgp_t *netpgp = [self buildnetpgp];
    return NULL; // resolve_userid(netpgp, netpgp->pubring, keyLabel.UTF8String);
}

- (PGPPublicKey*)publicKeyForUserID:(NSString*)userID forEncryption:(BOOL)forEncryption
{
    NSFetchRequest* fetchRequest = [NSFetchRequest fetchRequestWithEntityName:@"PGPPublicKey"];
    
    [fetchRequest setPredicate:[NSPredicate predicateWithFormat:@"ANY userIDs.text == %@", userID]];
    
    PGPPublicKey* result = [MAIN_CONTEXT executeFetchRequest:fetchRequest error:nil].firstObject;
    
    return result;
}

- (__ops_key_t*)opsPublicEncryptionKeyForUserID:(NSString*)userID forEncryption:(BOOL)forEncryption
{
    PGPPublicKey* publicKey = [self publicKeyForUserID:userID forEncryption:forEncryption];
    
    if(!publicKey)
        return nil;
    
    NSData* PKCS8Data = [self.keychainHelper dataForPersistentRef:publicKey.publicKeychainRef isPrivate:NO];
    
    RSA* RSAObject = [self.openSSLEngine RSAPublicKeyFromData:PKCS8Data];
    
    __ops_key_t* key = __ops_keydata_new();
    
    key->key.pubkey.key.rsa.e = RSAObject->e;
    key->key.pubkey.key.rsa.n = RSAObject->n;
    
    key->key.pubkey.alg = OPS_PKA_RSA;
    
    return key;
}

//- (const __ops_key_t*)opsPrivateKeyForUserID:(NSString*)userID
//{
//    return resolve_userid(self.netPGP, [self privateKeyring], [userID cStringUsingEncoding:NSUTF8StringEncoding]);
//}

- (const __ops_keyring_t*)publicKeyring
{
    __ops_keyring_t* publicKeyring = NULL;
    
    __ops_keyring_fileread(publicKeyring, 1, [self.publicKeyringPath cStringUsingEncoding:NSUTF8StringEncoding]);
    
    return (__bridge const __ops_keyring_t *)(CFBridgingRelease(publicKeyring));
}

- (const __ops_keyring_t*)privateKeyring
{
    __ops_keyring_t* privateKeyring = NULL;
    
    __ops_keyring_fileread(privateKeyring, 1, [self.privateKeyringPath cStringUsingEncoding:NSUTF8StringEncoding]);
    
    return (__bridge const __ops_keyring_t *)(CFBridgingRelease(privateKeyring));
}

- (PGPPublicKey*)publicKeyForFingerprint:(NSData*)fingerprint
{
    return nil;
}

- (BOOL)generateKeyForUserID:(NSString*)userID bitLength:(NSInteger)bitLength
{
    return 1 == netpgp_generate_key(self.netPGP, (char*)[userID.copy cStringUsingEncoding:NSUTF8StringEncoding], (int)bitLength);
}




- (NSData*)PKCS8DataForOpsPGPPublicKey:(const __ops_key_t*)opsKey
{
    switch(opsKey->key.pubkey.alg)
    {
        case OPS_PKA_DSA:
        {
            DSA* dsa = DSA_new();
            
            dsa->g = opsKey->key.pubkey.key.dsa.g;
            dsa->p = opsKey->key.pubkey.key.dsa.p;
            dsa->q = opsKey->key.pubkey.key.dsa.q;
            dsa->pub_key = opsKey->key.pubkey.key.dsa.y;
            
            return [[OpenSSLEncryptionEngine sharedInstance] dataForDSAPublicKey:dsa format:MynigmaKeyFormatPKCS8WithOID];
        }
            
        case OPS_PKA_RSA:
        case OPS_PKA_RSA_ENCRYPT_ONLY:
        case OPS_PKA_RSA_SIGN_ONLY:
        {
            RSA* rsa = RSA_new();
            
            rsa->e = opsKey->key.pubkey.key.rsa.e;
            rsa->n = opsKey->key.pubkey.key.rsa.n;
            
            return [[OpenSSLEncryptionEngine sharedInstance] dataForRSAPublicKey:rsa format:MynigmaKeyFormatPKCS8WithOID];
        }
            
        case OPS_PKA_ELGAMAL:
        default:
        {
            //OpenSSL doesn't actually support ElGamal
        }
    }
    
    return nil;
}

- (NSData*)PKCS12DataForOpsPGPPrivateKey:(const __ops_key_t*)opsKey
{
    switch(opsKey->key.pubkey.alg)
    {
        case OPS_PKA_DSA:
        {
            DSA* dsa = DSA_new();
            
            dsa->g = opsKey->key.pubkey.key.dsa.p;
            dsa->p = opsKey->key.pubkey.key.dsa.p;
            dsa->q = opsKey->key.pubkey.key.dsa.q;
            dsa->pub_key = opsKey->key.pubkey.key.dsa.y;
            
            dsa->priv_key = opsKey->key.seckey.key.dsa.x;
            
            NSData* returnValue = [[OpenSSLEncryptionEngine sharedInstance] dataForDSAPrivateKey:dsa format:MynigmaKeyFormatPKCS12 passphrase:@"Mynigma"];
            
            if(dsa)
                DSA_free(dsa);
            
            return returnValue;
        }
            
        case OPS_PKA_RSA:
        case OPS_PKA_RSA_ENCRYPT_ONLY:
        case OPS_PKA_RSA_SIGN_ONLY:
            
        {
            RSA* rsa = RSA_new();
            
            rsa->e = opsKey->key.pubkey.key.rsa.e;
            rsa->n = opsKey->key.pubkey.key.rsa.n;
            
            rsa->d = opsKey->key.seckey.key.rsa.d;
            
            //the other way around(!?)
            rsa->p = opsKey->key.seckey.key.rsa.q;
            rsa->q = opsKey->key.seckey.key.rsa.p;
            
            rsa->iqmp = opsKey->key.seckey.key.rsa.u;
            
            NSData* returnValue = [[OpenSSLEncryptionEngine sharedInstance] dataForRSAPrivateKey:rsa format:MynigmaKeyFormatPKCS12 passphrase:@"Mynigma"];
            
            if(rsa)
                RSA_free(rsa);
            
            return returnValue;
        }
            
        case OPS_PKA_ELGAMAL:
        default:
        {
            //OpenSSL doesn't actually support ElGamal
        }
    }
    
    return nil;
}


- (__ops_key_t*)opsPublicKeyWithData:(NSData*)PKCS8Data
{
    RSA* RSAObject = [self.openSSLEngine RSAPublicKeyFromData:PKCS8Data];
    
    __ops_key_t* key = __ops_keydata_new();
    
    key->key.pubkey.key.rsa.e = RSAObject->e;
    key->key.pubkey.key.rsa.n = RSAObject->n;
    
    key->key.pubkey.alg = OPS_PKA_RSA;
    
    return key;
}

- (__ops_key_t*)opsPrivateKeyWithData:(NSData*)PKCS8Data
{
    RSA* RSAObject = [self.openSSLEngine RSAPublicKeyFromData:PKCS8Data];
    
    if(!RSAObject)
        return nil;
    
    __ops_key_t* key = __ops_keydata_new();
    
    key->key.pubkey.key.rsa.e = RSAObject->e;
    key->key.pubkey.key.rsa.n = RSAObject->n;
    
    key->key.seckey.key.rsa.d = RSAObject->d;
    key->key.seckey.key.rsa.p = RSAObject->q;
    key->key.seckey.key.rsa.q = RSAObject->p;
    key->key.seckey.key.rsa.u = RSAObject->iqmp;
    
    key->key.pubkey.alg = OPS_PKA_RSA;
    
    return key;
}


- (__ops_key_t*)opsPrivateKeyForUserID:(NSString*)userID forEncryption:(BOOL)forEncryption
{
    PGPPublicKey* publicKey = [self publicKeyForUserID:userID forEncryption:forEncryption];
    
    if(![publicKey isKindOfClass:[PGPPrivateKey class]])
        return nil;
    
    NSData* PKCS8Data = [self.keychainHelper dataForPersistentRef:[(PGPPrivateKey*)publicKey privateKeychainRef] isPrivate:YES];
    
    return [self opsPrivateKeyWithData:PKCS8Data];
}


- (__ops_key_t*)opsPublicKeyForUserID:(NSString*)userID forEncryption:(BOOL)forEncryption
{
    PGPPublicKey* publicKey = [self publicKeyForUserID:userID forEncryption:forEncryption];
    
    if(!publicKey)
        return nil;
    
    NSData* PKCS8Data = [self.keychainHelper dataForPersistentRef:publicKey.publicKeychainRef isPrivate:NO];
    
    return [self opsPrivateKeyWithData:PKCS8Data];
}


@end
