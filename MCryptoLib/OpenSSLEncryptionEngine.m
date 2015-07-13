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





#import "OpenSSLEncryptionEngine.h"
#import "MynigmaErrorFactory.h"
#import "PublicKeyData.h"
#import "PrivateKeyData.h"
#import "NSData+Base64.h"
#import "KeyParser.h"
#import "MynigmaKeyManager.h"
#import "MynigmaError.h"



#import <openssl/err.h>
#import <openssl/pkcs12.h>
#import <openssl/pkcs7.h>
#import <openssl/x509.h>
#import <openssl/x509v3.h>
#import <openssl/bio.h>
#import <openssl/pem.h>
#import <openssl/stack.h>
#import <openssl/safestack.h>
#import <openssl/evp.h>
#import <openssl/hmac.h>
#import <openssl/rsa.h>
#import <openssl/cms.h>
#import <openssl/ossl_typ.h>
#import <openssl/bn.h>
#import <openssl/rand.h>

#import <pthread.h>


//static BOOL loadedOpenSSL = NO;


static pthread_mutex_t *locks;

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>


#pragma mark - THREAD SAFETY

static void lock_callback(int mode, int type, char *file, int line)
{
    (void)file;
    (void)line;
    if (mode & CRYPTO_LOCK)
    {
        pthread_mutex_lock(&(locks[type]));
    }
    else {
        pthread_mutex_unlock(&(locks[type]));
    }
}

static unsigned long thread_id(void)
{
    unsigned long ret;
    
    ret=(unsigned long)pthread_self();
    return(ret);
}

static void setUpLocks(void)
{
    locks = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    
    for (int i=0; i<CRYPTO_num_locks(); i++)
        pthread_mutex_init(&(locks[i]),NULL);
    
    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))lock_callback);
}

static void tearDownLocks(void)
{
    CRYPTO_set_locking_callback(NULL);
    
    for (int i=0; i<CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(locks[i]));
    
    OPENSSL_free(locks);
}



@interface OpenSSLEncryptionEngine()

@property MynigmaKeyManager* keyManager;

@end



@implementation OpenSSLEncryptionEngine




#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"


#pragma mark - LOADING & ERRORS

+ (instancetype)sharedInstance
{
    static OpenSSLEncryptionEngine* sharedInstance = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        sharedInstance = [OpenSSLEncryptionEngine new];
    });
    
    return sharedInstance;
}


- (instancetype)init
{
    self = [super init];
    if (self) {
        
        [OpenSSLEncryptionEngine loadCrypto];
        self.keyManager = [MynigmaKeyManager new];
    }
    return self;
}

- (instancetype)initWithKeyManager:(MynigmaKeyManager*)newKeyManager
{
    self = [super init];
    if (self) {
        
        [OpenSSLEncryptionEngine loadCrypto];
        self.keyManager = newKeyManager;
    }
    return self;
}

//- (void)dealloc
//{
//    [OpenSSLEncryptionEngine unloadCrypto];
//}

+ (void)loadCrypto
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        setUpLocks();
        
#if defined(OPENSSL_THREADS)
        //        NSLog(@"OpenSSL configured with multi-thread support");
#else
        NSLog(@"OpenSSL configured WITHOUT multi-thread support!!!");
#endif
        
        OPENSSL_config(NULL);
        
        OpenSSL_add_all_algorithms();
        
        ERR_load_crypto_strings();
        ERR_load_ERR_strings();
    });
}

+ (void)unloadCrypto
{
    //currently unused
    tearDownLocks();
}


+ (void*)logErrorAndReturnNil
{
    unsigned long error_code = ERR_get_error();
    
    const char* error_string = ERR_error_string(error_code, NULL);
    
    NSLog(@"Error: %@", [NSString stringWithCString:error_string?error_string:"" encoding:NSUTF8StringEncoding]);
    
    return nil;
}




#pragma mark - RSA key retrieval

- (RSA*)openSSLPublicKeyWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    PublicKeyData* publicKeyData = [self.keyManager dataForPublicKeyWithLabel:keyLabel];
    
    NSData* PEMData = forEncryption?publicKeyData.publicKeyEncData:publicKeyData.publicKeyVerData;
    
    if(!PEMData)
        return nil;
    
    [OpenSSLEncryptionEngine loadCrypto];
    
    BIO* PEMBio = BIO_new_mem_buf((void*)PEMData.bytes, (int)PEMData.length);
    
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(PEMBio, NULL, NULL, NULL);
    
    return rsa;
}


- (RSA*)openSSLPrivateKeyWithLabel:(NSString*)keyLabel forEncryption:(BOOL)forEncryption
{
    [OpenSSLEncryptionEngine loadCrypto];
    
    PrivateKeyData* privateKeyData = [self.keyManager dataForPrivateKeyWithLabel:keyLabel];
    
    NSData* data = forEncryption?privateKeyData.privateKeyDecData:privateKeyData.privateKeySigData;
    
    return [self RSAPrivateKeyFromData:data];
}














#pragma mark - HASHES

/**
 * Hash some data using SHA-512
 */
- (NSData*)SHA512DigestOfData:(NSData*)data
{
    unsigned char digest[SHA512_DIGEST_LENGTH];
    
    SHA512(data.bytes, data.length, (unsigned char*)&digest);
    
    NSData* returnValue = [NSData dataWithBytes:digest length:SHA512_DIGEST_LENGTH];

    return returnValue;
}

/**
 * Hash some data using SHA-256
 */
- (NSData*)SHA256DigestOfData:(NSData*)data
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    
    SHA256(data.bytes, data.length, (unsigned char*)&digest);
    
    NSData* returnValue = [NSData dataWithBytes:digest length:SHA256_DIGEST_LENGTH];
    
    return returnValue;
}





#pragma mark - AES

/**
 * Encrypt data of arbitrary length using AES with 128 bit key in CBC mode with random IV
 * The IV is prepended to the result
 */
- (NSData*)AESEncryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData error:(NSError**)error
{
    //fill IV with random data
    NSData* initialVector = [self randomBytesOfLength:16];
    
    return [self AESEncryptData:data withSessionKey:sessionKeyData IV:initialVector error:error];
}

/**
 * Encrypt data of arbitrary length using AES with 128 bit key in CBC mode with specified IV
 * The IV is prepended to the result
 */
- (NSData*)AESEncryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData IV:(NSData*)initialVector error:(NSError**)error
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertextLength;
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES encryption error" code:1 userInfo:nil];
        return nil;
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, sessionKeyData.bytes, initialVector.bytes))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES encryption error" code:2 userInfo:nil];
        return nil;
    }
    
    unsigned char ciphertext[data.length + EVP_MAX_BLOCK_LENGTH];
    
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data.bytes, (int)data.length))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES encryption error" code:3 userInfo:nil];
        return nil;
    }
    
    ciphertextLength = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES encryption error" code:4 userInfo:nil];
        return nil;
    }
    
    ciphertextLength += len;
    
    NSData* encryptedData = [NSData dataWithBytes:ciphertext length:ciphertextLength];
    
    NSMutableData* returnValue = [[NSMutableData alloc] initWithData:initialVector];
    
    [returnValue appendData:encryptedData];
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return returnValue;
}

/**
 * Decrypts data of arbitrary length containing an IV followed by some data encrypted using AES with 128 bit key in CBC mode
 */
- (NSData*)AESDecryptData:(NSData*)data withSessionKey:(NSData*)sessionKeyData error:(NSError**)error
{
    if(data.length < 32)
        return nil;
    
    
    NSData* initialVector = [data subdataWithRange:NSMakeRange(0, 16)];
    NSData* encryptedData = [data subdataWithRange:NSMakeRange(16, data.length - 16)];
    
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int plaintextLength;
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES decryption error" code:1 userInfo:nil];
        return nil;
    }
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, sessionKeyData.bytes, initialVector.bytes))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES decryption error" code:2 userInfo:nil];
        return nil;
    }
    
    unsigned char plaintext[data.length + EVP_MAX_BLOCK_LENGTH];
    
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, encryptedData.bytes, (int)encryptedData.length))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES decryption error" code:3 userInfo:nil];
        return nil;
    }
    
    plaintextLength = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        if(error)
            *error = [NSError errorWithDomain:@"OpenSSL AES decryption error" code:4 userInfo:nil];
        return nil;
    }
    
    plaintextLength += len;
    
    NSData* returnValue = [NSData dataWithBytes:plaintext length:plaintextLength];
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return returnValue;
}




#pragma mark - RSA

/**
 * Encrypts a single block of data using RSA with OAEP padding
 *
 */
- (NSData*)RSAEncryptData:(NSData*)data withKeyLabel:(NSString*)keyLabel withSHA512MGF:(BOOL)useSHA512MGF error:(NSError**)error
{
    RSA* rsa = [self openSSLPublicKeyWithLabel:keyLabel forEncryption:YES];
    
    if(!rsa)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSANoPublicKeyForLabel];
        return nil;
    }
    
    int resultLength = RSA_size(rsa);
    
    unsigned char encryptedData[resultLength];
    
    RSA_public_encrypt((int)data.length, data.bytes, encryptedData, rsa, RSA_PKCS1_OAEP_PADDING);
    
    return [NSData dataWithBytes:encryptedData length:resultLength];
}

/**
 * Decrypts a single block of data using RSA with OAEP padding
 *
 */
- (NSData*)RSADecryptData:(NSData*)data withKeyLabel:(NSString*)keyLabel withSHA512MGF:(BOOL)useSHA512MGF error:(NSError**)error
{
    RSA* rsa = [self openSSLPrivateKeyWithLabel:keyLabel forEncryption:YES];
    
    if(!rsa)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSANoPublicKeyForLabel];

        return nil;
    }
    
//    int resultLength = RSA_size(rsa);

    unsigned char* plaintext = malloc(RSA_size(rsa));
    
    int plaintextLength = RSA_private_decrypt((int)data.length, data.bytes, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
    
    if(plaintextLength <= 0)
    {
        if(plaintext)
            free(plaintext);
        
        return [OpenSSLEncryptionEngine logErrorAndReturnNil];
    }
    
    NSData* returnValue = [[NSData alloc] initWithBytes:plaintext length:plaintextLength];
    
    if(plaintext)
        free(plaintext);
    
    return returnValue;
}

/**
 * Signs a single block of data using RSA with PKCS#1v1.5 or PSS padding
 *
 */
- (NSData*)RSASignHash:(NSData*)mHash withKeyLabel:(NSString*)keyLabel withPSSPadding:(BOOL)usePSSPadding error:(NSError**)error
{
    @try
    {
        RSA* rsa = [self openSSLPrivateKeyWithLabel:keyLabel forEncryption:NO];
        
        if(!rsa)
        {
            if(error)
                *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaEncryptionErrorRSANoPublicKeyForLabel];
            NSLog(@"Failed to create RSA object for keyLabel %@", keyLabel);
            return nil;
        }
        
        if(usePSSPadding)
        {
            unsigned char EM[RSA_size(rsa)];
            unsigned char signature[RSA_size(rsa)];
            
            //add PSS padding with SHA-512
            //salt length 32 bytes = 256 bits
            int status = RSA_padding_add_PKCS1_PSS(rsa, EM, mHash.bytes, EVP_sha512(), 32);
            if (!status)
            {
                NSLog(@"RSA_padding_add_PKCS1_PSS failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
                if(error)
                    *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotSetPadding];
                
                return nil;
            }
            
            // sign the data
            // no padding required, as it has already been added in the previous step
            status = RSA_private_encrypt(512, EM, signature, rsa, RSA_NO_PADDING);
            if (status == -1)
            {
                NSLog(@"RSA_private_encrypt failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
                if(error)
                    *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSACannotExecuteTransform];
                
                return nil;
            }
            
            NSData* returnValue = [NSData dataWithBytes:signature length:512];
            
            return returnValue;
        }
        else
        {
            unsigned char signature[512];
            
            unsigned int length;
            
            RSA_sign(NID_sha512, mHash.bytes, (unsigned int)mHash.length, signature, &length, rsa);
            
            NSData* returnValue = [NSData dataWithBytes:signature length:512];
            
            return returnValue;
        }
    }
    @catch(NSException* exception)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaSignatureErrorRSAExceptionCaught];
        
        return nil;
    }
}

/**
 * Verifies the signature on a single block of data using RSA with PKCS#1v1.5 or PSS padding
 *
 */
- (BOOL)RSAVerifySignature:(NSData*)signature ofHash:(NSData*)dataHash withPSSPadding:(BOOL)usePSSPadding withKeyLabel:(NSString*)keyLabel error:(NSError**)error
{
    @try
    {
        if(!keyLabel)
        {
            if(error)
                *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorNoKeyLabel];
            return NO;
        }
    
        RSA* rsa = [self openSSLPublicKeyWithLabel:keyLabel forEncryption:NO];
        
        if(!rsa || !signature || !dataHash || !keyLabel)
        {
            if(error)
                *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorNoKey];
            return NO;
        }
        
        if(usePSSPadding)
        {
            
            unsigned char decryptedData[RSA_size(rsa)];
            
            //first step
            
            //the first stage of verification takes no padding
            //that's unwrapped in the second step below
            int status = RSA_public_decrypt((unsigned int)signature.length, signature.bytes, decryptedData, rsa, RSA_NO_PADDING);
            if (status == -1)
            {
                printf("RSA_public_decrypt failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
                if(error)
                    *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSACannotSetPadding];
                return NO;
            }
            
            //second step
            
            // verify the data
            // hashing algorithm set to SHA-512
            // MGF also set to SHA-512
            // salt length is autorecovered from signature
            status = RSA_verify_PKCS1_PSS(rsa, dataHash.bytes, EVP_sha512(), decryptedData, -2);
            if (status == 1)
            {
                return YES;
            }
            else
            {
                NSLog(@"RSA_verify_PKCS1_PSS failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
                if(error)
                    *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorInvalidSignature];
                return NO;
            }
        }
        else
        {
            BOOL result = RSA_verify(NID_sha512, dataHash.bytes, (unsigned int)dataHash.length, (unsigned char*)signature.bytes, (unsigned int)signature.length, rsa);
            
            return result;
        }
    }
    @catch(NSException* exception)
    {
        if(error)
            *error = [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaVerificationErrorRSAExceptionCaught];
        
        return NO;
    }
    
}



#pragma mark - HMAC


/**
 * Computes the SHA512 HMAC of message with secret
 *
 */
- (NSData*)HMACForMessage:(NSData *)message withSecret:(NSData *)secret
{
    [OpenSSLEncryptionEngine loadCrypto];
    
    unsigned int outputLength = 0;
    unsigned char* outputBytes = HMAC(EVP_sha512(), secret.bytes, (int)secret.length, message.bytes, message.length, NULL, &outputLength);
    
    NSData* outputData = [NSData dataWithBytes:outputBytes length:outputLength];
    
    return outputData;
}

/**
 * Coompares HMAC with the SHA512 HMAC of message using secret
 */
- (BOOL)verifyHMAC:(NSData*)HMAC ofMessage:(NSData*)message withSecret:(NSData*)secret
{
    NSData* computedHMAC = [self HMACForMessage:message withSecret:secret];
    
    if(!computedHMAC.length || !HMAC.length)
    {
        return NO;
    }
    
    return [computedHMAC isEqual:HMAC];
}



#pragma mark - KEY GENERATION

/**
 * Return #length cryptographically secure pseudo-random bytes
 */
- (NSData*)randomBytesOfLength:(NSInteger)length
{
    unsigned char* buf = malloc(length);
    
    if(1 != RAND_bytes(buf, (int)length))
    {
        if(buf)
            free(buf);

        return nil;
    }
    
    NSData* returnValue = [NSData dataWithBytes:buf length:length];
    
    if(buf)
        free(buf);
    
    return returnValue;
}

/**
 * Return 128/8 = 16 cryptographically secure pseudo-random bytes
 */
- (NSData*)generateNewAESSessionKeyData
{
    return [self randomBytesOfLength:16];
}

/**
 * Return 1024/8 = 128 cryptographically secure pseudo-random bytes
 */
- (NSData*)generateNewHMACSecret
{
    //1024 bits = 128 bytes
    return [self randomBytesOfLength:128];
}


#pragma clang diagnostic pop






#pragma mark - Key generation

- (void)generateNewPrivateKeyWithCallback:(void(^)(NSData* publicKeyData, NSData* privateKeyData, NSError* error))callback
{
    [OpenSSLEncryptionEngine loadCrypto];
    
    RSA* RSAKey = RSA_new();
    
    BIGNUM* exponent = BN_new();
    
    BN_set_word(exponent, 65537);
    
    int result = 0;
    
//    @synchronized(@"RSA_key_generation_sync")
    {
        result = RSA_generate_key_ex(RSAKey, 4096, exponent, NULL);
    }
    
    if(result != 1)
    {
        NSLog(@"Error generating RSA key!!!");
        
        if(exponent)
            BN_free(exponent);
        
        exponent = nil;
        
        if(RSAKey)
            RSA_free(RSAKey);
        
        RSAKey = nil;
        
        if(callback)
            callback(nil, nil, [NSError errorWithDomain:@"MCryptoLib S/MIME error" code:2 userInfo:nil]);
        return;
    }
    
    if(exponent)
        BN_free(exponent);
    
    exponent = NULL;
    
    NSData* publicKeyData = [self dataForRSAPublicKey:RSAKey];
    
    NSData* privateKeyData = [self dataForRSAPrivateKey:RSAKey];
    
    if(RSAKey)
        RSA_free(RSAKey);
    
    RSAKey = nil;
    
    if(callback)
        callback(publicKeyData, privateKeyData, nil);
}



#pragma mark - PBKDF2

/**
 * PBKDF2 key derivation from password with 5000 iterations and SHA512 hash function
 */
- (NSData*)AES128KeyFromPassword:(NSString*)password withSalt:(NSData*)salt
{
    //5000 iterations
    return [self AES128KeyUsingPBKDF2WithPassword:password salt:salt iterations:5000];
}

/**
 * PBKDF2 key derivation from password with the specified number of iterations and SHA512 hash function
 */
- (NSData*)AES128KeyUsingPBKDF2WithPassword:(NSString*)password salt:(NSData*)salt iterations:(NSUInteger)iterations
{
    const char* cStringPassword = [password cStringUsingEncoding:NSUTF8StringEncoding];
    int cStringPasswordLength = (int)[password lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char* output = malloc(128 / 8);
    if(1 == PKCS5_PBKDF2_HMAC(cStringPassword, cStringPasswordLength, salt.bytes, (int)salt.length, (int)iterations, EVP_sha512(), 128 / 8, output))
    {
        NSData* result = [NSData dataWithBytes:output length:128 / 8];
        
        if(output)
            free(output);
        
        return result;
    }
    
    if(output)
        free(output);
    
    return nil;
    
}


@end
