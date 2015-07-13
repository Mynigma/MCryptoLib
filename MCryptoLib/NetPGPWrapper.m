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


#import "NetPGPWrapper.h"

#import "KeychainHelper.h"
#import "OpenSSLEncryptionEngine.h"
#import "KeyParser.h"

#import "PGPPublicKey.h"

#import "netpgp.h"
#import "keyring.h"
#import "PGPKeyManager.h"


#define M_PGP_ALG_RSA @"RSA"
#define M_PGP_ALG_RSA_ENCRYPT_ONLY @"RSA_ENCRYPT_ONLY"
#define M_PGP_ALG_RSA_SIGN_ONLY @"RSA_SIGN_ONLY"
#define M_PGP_ALG_ELGAMAL @"ELGAMAL"
#define M_PGP_ALG_DSA @"DSA"
#define M_PGP_ALG_EC @"EC"
#define M_PGP_ALG_ECDSA @"ECDSA"



static PGPKeyManager* _keyManager;


@implementation NetPGPWrapper



+ (void)setKeyManager:(PGPKeyManager*)keyManager
{
    _keyManager = keyManager;
}

+ (PGPKeyManager*)keyManager
{
    return _keyManager;
}






+ (__ops_pubkey_alg_t)netPGPAlgorithmFromString:(NSString*)algorithmString
{
    if([algorithmString isEqual:M_PGP_ALG_RSA])
        return OPS_PKA_RSA;
    if([algorithmString isEqual:M_PGP_ALG_RSA_ENCRYPT_ONLY])
        return OPS_PKA_RSA_ENCRYPT_ONLY;
    if([algorithmString isEqual:M_PGP_ALG_RSA_SIGN_ONLY])
        return OPS_PKA_RSA_SIGN_ONLY;
    if([algorithmString isEqual:M_PGP_ALG_ELGAMAL])
        return OPS_PKA_ELGAMAL;
    if([algorithmString isEqual:M_PGP_ALG_DSA])
        return OPS_PKA_DSA;
    if([algorithmString isEqual:M_PGP_ALG_EC])
        return OPS_PKA_RESERVED_ELLIPTIC_CURVE;
    if([algorithmString isEqual:M_PGP_ALG_ECDSA])
        return OPS_PKA_RESERVED_ECDSA;
    
    return OPS_PKA_NOTHING;
}

+ (NSString*)stringForNetPGPAlgorithm:(__ops_pubkey_alg_t)algorithm
{
    switch(algorithm)
    {
        case OPS_PKA_RSA:
            return M_PGP_ALG_RSA;
        case OPS_PKA_RSA_ENCRYPT_ONLY:
            return M_PGP_ALG_RSA_ENCRYPT_ONLY;
        case OPS_PKA_RSA_SIGN_ONLY:
            return M_PGP_ALG_RSA_SIGN_ONLY;
        case OPS_PKA_ELGAMAL:
            return M_PGP_ALG_ELGAMAL;
        case OPS_PKA_DSA:
            return M_PGP_ALG_DSA;
        case OPS_PKA_RESERVED_ELLIPTIC_CURVE:
            return M_PGP_ALG_EC;
        case OPS_PKA_RESERVED_ECDSA:
            return M_PGP_ALG_ECDSA;
            
        default:
            return nil;
    }
}


+ (__ops_version_t)netPGPVersionFromString:(NSString*)versionString
{
    if([versionString isEqual:@"V2"])
        return OPS_V2;
    if([versionString isEqual:@"V3"])
        return OPS_V3;
    if([versionString isEqual:@"V4"])
        return OPS_V4;
    
    return 0;
}

+ (NSString*)stringForNetPGPVersion:(__ops_version_t)version
{
    switch(version)
    {
        case OPS_V2:
            return @"V2";
        case OPS_V3:
            return @"V3";
        case OPS_V4:
            return @"V4";
            
        default:
            return nil;
    }
}


- (__ops_key_t*)opsKeyForPGPPublicKey:(PGPPublicKey*)publicKey
{
    if(!publicKey)
        return nil;
    
    __ops_key_t* key = __ops_keydata_new();
    key->key.pubkey.alg = [NetPGPWrapper netPGPAlgorithmFromString:publicKey.algorithm];
    
    switch(key->key.pubkey.alg)
    {
        case OPS_PKA_RSA:
        case OPS_PKA_RSA_ENCRYPT_ONLY:
        case OPS_PKA_RSA_SIGN_ONLY:
        {
            NSData* PKCS8Data = [_keyManager.keychainHelper dataForPersistentRef:publicKey.publicKeychainRef isPrivate:NO];
            RSA* RSAObject = [_keyManager.openSSLEngine RSAPublicKeyFromData:PKCS8Data];
            key->key.pubkey.key.rsa.e = RSAObject->e;
            key->key.pubkey.key.rsa.n = RSAObject->n;
        }
            break;
            
            //        case OPS_PKA_DSA:
            //        {
            //            NSData* PKCS8Data = [self.keychainHelper dataForPersistentRef:publicKey.persistentRef isPrivate:NO];
            //            DSA* DSAObject = [self.openSSLEngine DSAPublicKeyFromPKCS8Data:PKCS8Data];
            //        }
            //            break;
            
        default:
            break;
    }
    
    key->key.pubkey.birthtime = [publicKey.creationDate timeIntervalSince1970];
    key->key.pubkey.duration = [publicKey.expiryDate timeIntervalSinceDate:publicKey.creationDate];
    key->key.pubkey.version = [NetPGPWrapper netPGPVersionFromString:publicKey.version];
    
    return key;
}

- (void)updatePGPPublicKey:(PGPPublicKey*)publicKey withProperties:(NSDictionary*)keyProperties opsKey:(__ops_key_t)key
{
//    NSString* fingerprint = [(NSString*)keyProperties[@"fingerprint"] stringByReplacingOccurrencesOfString:@" " withString:@""];
//    
//    uint8_t fingerprintRawData[20];
//    
//    str2keyid([fingerprint cStringUsingEncoding:NSUTF8StringEncoding], fingerprintRawData, 20);
//    
//    NSData* fingerprintData = [[NSData alloc] initWithBytes:fingerprintRawData length:20];
//    
//    PGPPublicKey* publicKey = [self publicKeyForFingerprint:fingerprintData];
    

}


__ops_key_t* key_for_key_id(const uint8_t *keyid, int length)
{
    return NULL;
    
//    NSData* keyID = [NSData dataWithBytes:keyid length:length];
//    
//    return [_keyManager opsPrivateKeyForUserID:i];
}


__ops_key_t* encryption_key_for_user_id(const char* user_id)
{
    NSString* userID = [NSString stringWithCString:user_id encoding:NSUTF8StringEncoding];
    
    return [_keyManager opsPublicKeyForUserID:userID forEncryption:YES];
}

@end
