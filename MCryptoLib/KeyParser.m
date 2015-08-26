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

#import "NSData+Base64.h"
#import "KeyParser.h"

#import "MynigmaKeyManager.h"
#import "KeychainHelper.h"


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





@interface OpenSSLEncryptionEngine()

@property MynigmaKeyManager* keyManager;

@end





@implementation KeyParser




/**
 * Turn a BIO object into NSData
 *
 * @param bio
 */
+ (NSData*)dataFromBIO:(BIO*)bio
{
    int lengthOfData = BIO_pending(bio);
    
    char *dataBuffer = malloc(lengthOfData);
    
    BIO_read(bio, dataBuffer, lengthOfData);
    
    NSData* outputData = [NSData dataWithBytes:dataBuffer length:lengthOfData];
    
    if(dataBuffer)
        free(dataBuffer);
    
    return outputData;
}


+ (void*)logErrorAndReturnNil
{
    unsigned long error_code = ERR_get_error();
    
    const char* error_string = ERR_error_string(error_code, NULL);
    
    NSLog(@"Error: %@", [NSString stringWithCString:error_string?error_string:"" encoding:NSUTF8StringEncoding]);
    
    return nil;
}


#pragma mark - DATA EXPORT

#pragma mark Public keys

#pragma mark specific

+ (NSData*)PKCS1DataForEVPRSAPublicKey:(EVP_PKEY*)publicKey
{
    if(!publicKey)
        return nil;
    
    RSA* RSAKey = EVP_PKEY_get1_RSA(publicKey);
    
    BIO* privateKeyBIO = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSA_PUBKEY(privateKeyBIO, RSAKey);
    
    NSData* outputData = [self dataFromBIO:privateKeyBIO];
    
    BIO_free(privateKeyBIO);
    
    return outputData;
}

+ (NSData*)PKCS8DataForEVPPublicKey:(EVP_PKEY*)publicKey
{
    if(!publicKey)
        return [self logErrorAndReturnNil];
    
    BIO* DERBio = BIO_new(BIO_s_mem());
    
    PEM_write_bio_PUBKEY(DERBio, publicKey);
    
    NSData* outputData = [self dataFromBIO:DERBio];
    
    BIO_free(DERBio);
    
    //no need to replace BEGIN PUBLIC KEY with BEGIN RSA PUBLIC KEY - it's PKCS#8, so the algorithm identifier is included
    return outputData;
}


+ (NSData*)X509CertificateDataForEVPPublicKey:(EVP_PKEY*)publicKey
{
    if(!publicKey)
        return [self logErrorAndReturnNil];
    
    X509* x509 = X509_new();
    
    X509_set_pubkey(x509, publicKey);
    
    //need to set this to avoid mysterious epic fail
    //good to know
    X509_set_notBefore(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]));
    X509_set_notAfter(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]+2*365*24*60*60));
    
    BIO* DERBio = BIO_new(BIO_s_mem());
    
    i2d_X509_bio(DERBio, x509);
    
    NSData* outputData = [self dataFromBIO:DERBio];
    
    BIO_free(DERBio);
    X509_free(x509);
    
    return outputData;
}

+ (NSData*)PKCS12DataFromEVPPublicKey:(EVP_PKEY*)publicKey passphrase:(NSString*)passphrase
{
    if(!publicKey)
        return [self logErrorAndReturnNil];
    
    X509* x509 = X509_new();
    
    X509_set_pubkey(x509, publicKey);
    
    //need to set the dates for this to work
    X509_set_notAfter(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]+2*365*24*60*60));
    
    X509_set_notBefore(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]));
    
    const char* nameString = [@"Mynigma" cStringUsingEncoding:NSUTF8StringEncoding];
    
    const char* passphraseConstChars = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
    
    char* passphraseChars = NULL;
    
    if(passphraseConstChars)
    {
        passphraseChars = (char*)malloc(strlen(passphraseConstChars) + 1);
        strcpy(passphraseChars, passphraseConstChars);
    }
    
    PKCS12* pkcs12 = PKCS12_create(passphraseChars, (char*)nameString, NULL, x509, NULL, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, PKCS12_DEFAULT_ITER, PKCS12_DEFAULT_ITER, 0);
    
    if(passphraseChars)
        free(passphraseChars);
    
    BIO* PKCS12Bio = BIO_new(BIO_s_mem());
    
    i2d_PKCS12_bio(PKCS12Bio, pkcs12);
    
    NSData* outputData = [self dataFromBIO:PKCS12Bio];
    
    X509_free(x509);
    BIO_free(PKCS12Bio);
    
    return outputData;
}



#pragma mark generic


+ (NSData*)dataForRSAPublicKey:(RSA*)RSAKey
{
    return [self dataForRSAPublicKey:RSAKey format:MynigmaKeyFormatDefault];
}

+ (NSData*)dataForRSAPublicKey:(RSA*)RSAKey format:(MynigmaKeyFormat)format
{
    if(!RSAKey)
        return [self logErrorAndReturnNil];
    
    EVP_PKEY* publicKey = EVP_PKEY_new();
    
    EVP_PKEY_set1_RSA(publicKey, RSAKey);
    
    return [self dataForEVPPublicKey:publicKey format:format];
}

+ (NSData*)dataForEVPPublicKey:(EVP_PKEY*)publicKey format:(MynigmaKeyFormat)format
{
    return [self dataForEVPPublicKey:publicKey format:format passphrase:nil];
}

+ (NSData*)dataForEVPPublicKey:(EVP_PKEY*)publicKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    switch (format) {
        case MynigmaKeyFormatDefault:
        case MynigmaKeyFormatPKCS8WithOID:
            return [self PKCS8DataForEVPPublicKey:publicKey];
            
        case MynigmaKeyFormatPKCS1WithoutOID:
            return [self PKCS1DataForEVPRSAPublicKey:publicKey];
            
        case MynigmaKeyFormatX509:
            return [self X509CertificateDataForEVPPublicKey:publicKey];
            
        case MynigmaKeyFormatPKCS12:
            return [self PKCS12DataFromEVPPublicKey:publicKey passphrase:passphrase];
            
        default:
            break;
    }
    
    return nil;
}

+ (NSData*)dataForDSAPublicKey:(DSA*)DSAKey format:(MynigmaKeyFormat)format
{
    if(!DSAKey)
        return [self logErrorAndReturnNil];
    
    EVP_PKEY* publicKey = EVP_PKEY_new();
    
    EVP_PKEY_set1_DSA(publicKey, DSAKey);
    
    return [self dataForEVPPublicKey:publicKey format:format];
}







#pragma mark Private keys

#pragma mark specific

+ (NSData*)PKCS1DataForEVPPrivateKey:(EVP_PKEY*)privateKey
{
    if(!privateKey)
        return nil;
    
    RSA* RSAKey = EVP_PKEY_get1_RSA(privateKey);
    
    BIO* privateKeyBIO = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSAPrivateKey(privateKeyBIO, RSAKey, NULL, NULL, 0, NULL, NULL);
    
    NSData* outputData = [self dataFromBIO:privateKeyBIO];
    
    BIO_free(privateKeyBIO);
    
    return outputData;
}

+ (NSData*)PKCS8DataForEVPPrivateKey:(EVP_PKEY*)privateKey
{
    if(!privateKey)
        return [self logErrorAndReturnNil];
    
    //it's not necessarily an RSA key, so we can't use the RSA methods...
    
    BIO* privateKeyBIO = BIO_new(BIO_s_mem());
    
    PEM_write_bio_PrivateKey(privateKeyBIO, privateKey, NULL, NULL, 0, NULL, NULL);
    
    NSData* outputData = [self dataFromBIO:privateKeyBIO];
    
    BIO_free(privateKeyBIO);
    
    return outputData;
}

+ (NSData*)PKCS12DataFromEVPPrivateKey:(EVP_PKEY*)privateKey withPassphrase:(NSString*)passphrase
{
    if(!privateKey)
        return [self logErrorAndReturnNil];
    
    X509* x509 = X509_new();
    
    X509_set_pubkey(x509, privateKey);
    
    //need to set the dates for this to work
    X509_set_notAfter(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]+2*365*24*60*60));
    
    X509_set_notBefore(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]));
    
    const char* nameString = [@"Mynigma" cStringUsingEncoding:NSUTF8StringEncoding];
    
    const char* passphraseConstChars = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
    
    char* passphraseChars = NULL;
    
    if(passphraseConstChars)
    {
        passphraseChars = (char*)malloc(strlen(passphraseConstChars) + 1);
        strcpy(passphraseChars, passphraseConstChars);
    }
    
    PKCS12* pkcs12 = PKCS12_create(passphraseChars, (char*)nameString, privateKey, x509, NULL, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, PKCS12_DEFAULT_ITER, PKCS12_DEFAULT_ITER, 0);
    
    if(passphraseChars)
        free(passphraseChars);
    
    BIO* PKCS12Bio = BIO_new(BIO_s_mem());
    
    i2d_PKCS12_bio(PKCS12Bio, pkcs12);
    
    NSData* outputData = [self dataFromBIO:PKCS12Bio];
    
    X509_free(x509);
    BIO_free(PKCS12Bio);
    
    return outputData;
}





//
///**
// * Read PKCS8 wrapped private key data encrypted with the given passphrase and return an RSA private key object
// */
//- (RSA*)RSAPrivateKeyFromWrappedPKCS8Data:(NSData*)wrappedPrivateKeyData withPassphrase:(NSString*)passphrase
//{
//    if(!wrappedPrivateKeyData)
//        return nil;
//
//    BIO* PKCS8BIO = BIO_new_mem_buf((void*)wrappedPrivateKeyData.bytes, (int)wrappedPrivateKeyData.length);
//
//    const char* cStringPassphrase = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
//
//    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(PKCS8BIO, NULL, NULL, (void*)cStringPassphrase);
//
//    if(!privKey)
//        return [self logErrorAndReturnNil];
//
//    RSA* rsa = EVP_PKEY_get1_RSA(privKey);
//
//    return rsa;
//}
//
///**
// * Read PKCS12 wrapped private key data encrypted with the given passphrase and return an RSA private key object
// */
//- (RSA*)RSAPrivateKeyFromWrappedPKCS12Data:(NSData*)wrappedPrivateKeyData withPassphrase:(NSString*)passphrase
//{
//    if(!wrappedPrivateKeyData)
//        return nil;
//
//    BIO* PKCS12BIO = BIO_new_mem_buf((void*)wrappedPrivateKeyData.bytes, (int)wrappedPrivateKeyData.length);
//
//    const char* cStringPassphrase = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
//
//    PKCS12* PKCS12Object = PKCS12_new();
//
//    d2i_PKCS12_bio(PKCS12BIO, &PKCS12Object);
//
//    EVP_PKEY* privKey = NULL;
//
//    X509* X509Certs = NULL;
//
//    PKCS12_parse(PKCS12Object, cStringPassphrase, &privKey, &X509Certs, NULL);
//
//    if(!privKey)
//        return [self logErrorAndReturnNil];
//
//    RSA* rsa = EVP_PKEY_get1_RSA(privKey);
//
//    BIO_free(PKCS12BIO);
//    EVP_PKEY_free(privKey);
//    X509_free(X509Certs);
//
//    return rsa;
//}



#pragma mark generic

+ (NSData*)dataForRSAPrivateKey:(RSA*)RSAKey
{
    return [self dataForRSAPrivateKey:RSAKey format:MynigmaKeyFormatDefault passphrase:nil];
}


+ (NSData*)dataForRSAPrivateKey:(RSA*)RSAKey format:(MynigmaKeyFormat)format
{
    return [self dataForRSAPrivateKey:RSAKey format:format passphrase:nil];
}


+ (NSData*)dataForRSAPrivateKey:(RSA*)RSAKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    if(!RSAKey)
        return [self logErrorAndReturnNil];
    
    EVP_PKEY* privateKey = EVP_PKEY_new();
    
    EVP_PKEY_set1_RSA(privateKey, RSAKey);
    
    return [self dataForEVPPrivateKey:privateKey format:format passphrase:passphrase];
}


+ (NSData*)dataForDSAPrivateKey:(DSA*)DSAKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    if(!DSAKey)
        return [self logErrorAndReturnNil];
    
    EVP_PKEY* publicKey = EVP_PKEY_new();
    
    EVP_PKEY_set1_DSA(publicKey, DSAKey);
    
    return [self dataForEVPPrivateKey:publicKey format:format passphrase:passphrase];
}


+ (NSData*)dataForEVPPrivateKey:(EVP_PKEY*)privateKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    switch(format)
    {
        case MynigmaKeyFormatDefault:
        case MynigmaKeyFormatPKCS1WithoutOID:
            return [self PKCS1DataForEVPPrivateKey:privateKey];
            
        case MynigmaKeyFormatPKCS8WithOID:
            return [self PKCS8DataForEVPPrivateKey:privateKey];
            
        case MynigmaKeyFormatPKCS12:
            return [self PKCS12DataFromEVPPrivateKey:privateKey withPassphrase:passphrase];
            
        default:
            break;
    }
    
    return nil;
}








#pragma mark - DATA IMPORT

#pragma mark Public keys

#pragma mark specific

//- (X509*)X509CertificateForData:(NSData*)certData
//{
//    NSString* PEMString = [[NSString alloc] initWithData:certData encoding:NSUTF8StringEncoding];
//
//    PEMString = [PEMString stringByReplacingOccurrencesOfString:@" RSA PUBLIC " withString:@" PUBLIC "];
//
//    NSData* PEMData = [PEMString dataUsingEncoding:NSUTF8StringEncoding];
//
//
//    BIO* PEMBio = BIO_new_mem_buf((void*)PEMData.bytes, (int)PEMData.length);
//
//    EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(PEMBio, NULL, NULL, NULL);
//
//    if(!pubKey)
//    {
//        return [self logErrorAndReturnNil];
//    }
//
//    X509* x509 = X509_new();
//
//    X509_set_pubkey(x509, pubKey);
//
//    X509_set_notAfter(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]+2*365*24*60*60));
//
//    X509_set_notBefore(x509, ASN1_TIME_set(NULL, [[NSDate date] timeIntervalSince1970]));
//
//    return x509;
//}

+ (EVP_PKEY*)EVPRSAPublicKeyFromPKCS1Data:(NSData*)PKCS1Data
{
    if(!PKCS1Data)
        return nil;
    
    BIO* PEMBio = BIO_new_mem_buf((void*)PKCS1Data.bytes, (int)PKCS1Data.length);
    
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(PEMBio, NULL, NULL, NULL);
    
    if(!rsa)
    {
        BIO_free(PEMBio);
        return [self logErrorAndReturnNil];
    }
    
    EVP_PKEY* pubKey = EVP_PKEY_new();
    
    EVP_PKEY_set1_RSA(pubKey, rsa);
    
    BIO_free(PEMBio);
    
    return pubKey;
}


+ (EVP_PKEY*)EVPPublicKeyFromPKCS8Data:(NSData*)PKCS1Data
{
    if(!PKCS1Data)
        return nil;
    
    BIO* PEMBio = BIO_new_mem_buf((void*)PKCS1Data.bytes, (int)PKCS1Data.length);
    
    EVP_PKEY* EVPKey = PEM_read_bio_PUBKEY(PEMBio, NULL, NULL, NULL);
    
    BIO_free(PEMBio);
    
    if(!EVPKey)
        return [self logErrorAndReturnNil];
    
    return EVPKey;
}

+ (EVP_PKEY*)EVPPublicKeyFromX509Data:(NSData*)data
{
    SecKeyRef transientRef = [self transientSecKeyRefForPublicKeyData:data format:MynigmaKeyFormatX509];
    
    return [self EVPPublicKeyFromSecKeyRef:transientRef];
    
//    NSString* armouredDataString = [NSString stringWithFormat:@"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----\n", [data base64In64ByteChunksWithCarriageReturn:NO]];
//    
//    data = [armouredDataString dataUsingEncoding:NSUTF8StringEncoding];
//    
//    BIO* pemBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);
//    
//    X509* cert = PEM_read_bio_X509(pemBIO, NULL, NULL, NULL);
//    
//    if(!cert)
//        return [self logErrorAndReturnNil];
//    
//    return X509_get_pubkey(cert);
    
    //    STACK_OF(X509_INFO)* stackOfCerts = PEM_X509_INFO_read_bio(pemBIO, NULL, NULL, NULL);
    //
    //    if(pemBIO)
    //        BIO_free(pemBIO);
    //
    //    int numberOfCerts = sk_X509_INFO_num(stackOfCerts);
    //
    //    if(numberOfCerts > 0)
    //    {
    //        X509_INFO* x509Info = sk_X509_INFO_value(stackOfCerts, 0);
    //
    //        X509* certificate = x509Info->x509;
    //
    //        return X509_get_pubkey(certificate);
    //    }
    //
    //    return nil;
}

+ (EVP_PKEY*)EVPPublicKeyFromPKCS12Data:(NSData*)data passphrase:(NSString*)passphrase
{
    SecKeyRef transientRef = [self transientSecKeyRefForPublicKeyData:data format:MynigmaKeyFormatPKCS12];
    
    return [self EVPPublicKeyFromSecKeyRef:transientRef];
    
//    if(!PKCS1Data)
//        return nil;
//    
//    BIO* PKCS12BIO = BIO_new_mem_buf((void*)PKCS1Data.bytes, (int)PKCS1Data.length);
//    
//    const char* cStringPassphrase = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
//    
//    PKCS12* PKCS12Object = PKCS12_new();
//    
//    d2i_PKCS12_bio(PKCS12BIO, &PKCS12Object);
//    
//    EVP_PKEY* privKey = NULL;
//    
//    X509* X509Certs = NULL;
//    
//    PKCS12_parse(PKCS12Object, cStringPassphrase, &privKey, &X509Certs, NULL);
//    
//    if(!privKey)
//        return [self logErrorAndReturnNil];
//    
//    EVP_PKEY* pubKey = X509_get_pubkey(X509Certs);
//    
//    BIO_free(PKCS12BIO);
//    EVP_PKEY_free(privKey);
//    X509_free(X509Certs);
//    
//    return pubKey;
}

+ (EVP_PKEY*)EVPPublicKeyFromSecKeyRef:(SecKeyRef)keyRef
{
    NSData* keyData = [[KeychainHelper sharedInstance] dataForSecKeyRef:keyRef isPrivate:NO];
    
    return [self EVPPublicKeyFromPKCS8Data:keyData];
}




#pragma mark generic

+ (EVP_PKEY*)EVPPublicKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    if(!data)
        return nil;
    
    switch(format)
    {
        case MynigmaKeyFormatPKCS12:
            return [self EVPPublicKeyFromPKCS12Data:data passphrase:passphrase];
            break;
            
        case MynigmaKeyFormatDefault:
        case MynigmaKeyFormatPKCS8WithOID:
            return [self EVPPublicKeyFromPKCS8Data:data];
            
            
        case MynigmaKeyFormatPKCS1WithoutOID:
            return [self EVPRSAPublicKeyFromPKCS1Data:data];
            
        case MynigmaKeyFormatX509:
            return [self EVPPublicKeyFromX509Data:data];
            
        default:
            break;
    }
    
    return nil;
}


#pragma mark Private keys

#pragma mark specific

+ (EVP_PKEY*)EVPPrivateKeyFromPKCS1Data:(NSData*)PKCS1Data passphrase:(NSString*)passphrase
{
    if(!PKCS1Data)
        return nil;
    
    BIO* PEMBio = BIO_new_mem_buf((void*)PKCS1Data.bytes, (int)PKCS1Data.length);
    
    const char* cStringPassphrase = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
    
    EVP_PKEY* EVPKey = PEM_read_bio_PrivateKey(PEMBio, NULL, NULL, (void*)cStringPassphrase);
    
    BIO_free(PEMBio);
    
    if(!EVPKey)
        return [self logErrorAndReturnNil];
    
    return EVPKey;
}


+ (EVP_PKEY*)EVPPrivateKeyFromPKCS8Data:(NSData*)PKCS1Data passphrase:(NSString*)passphrase
{
    if(!PKCS1Data)
        return nil;
    
    BIO* PEMBio = BIO_new_mem_buf((void*)PKCS1Data.bytes, (int)PKCS1Data.length);
    
    const char* cStringPassphrase = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
    
    RSA* rsa = PEM_read_bio_RSAPrivateKey(PEMBio, NULL, NULL, (void*)cStringPassphrase);
    
    if(!rsa)
    {
        BIO_free(PEMBio);
        return [self logErrorAndReturnNil];
    }
    
    EVP_PKEY* privKey = EVP_PKEY_new();
    
    EVP_PKEY_set1_RSA(privKey, rsa);
    
    BIO_free(PEMBio);
    
    return privKey;
}

+ (EVP_PKEY*)EVPPrivateKeyFromPKCS12Data:(NSData*)data passphrase:(NSString*)passphrase
{
    SecKeyRef transientRef = [self transientSecKeyRefForPrivateKeyData:data format:MynigmaKeyFormatPKCS12 passphrase:passphrase];
    
    return [self EVPPrivateKeyFromSecKeyRef:transientRef];

//    if(!PKCS12Data)
//        return nil;
//    
//    BIO* PKCS12BIO = BIO_new_mem_buf((void*)PKCS12Data.bytes, (int)PKCS12Data.length);
//    
//    const char* cStringPassphrase = [passphrase cStringUsingEncoding:NSUTF8StringEncoding];
//    
//    PKCS12* PKCS12Object = PKCS12_new();
//    
//    d2i_PKCS12_bio(PKCS12BIO, &PKCS12Object);
//    
//    EVP_PKEY* privKey = NULL;
//    
//    X509* X509Certs = NULL;
//    
//    PKCS12_parse(PKCS12Object, cStringPassphrase, &privKey, &X509Certs, NULL);
//    
//    if(!privKey)
//        return [self logErrorAndReturnNil];
//    
//    BIO_free(PKCS12BIO);
//    
//    return privKey;
}


+ (EVP_PKEY*)EVPPrivateKeyFromSecKeyRef:(SecKeyRef)keyRef
{
    NSData* keyData = [[KeychainHelper sharedInstance] dataForSecKeyRef:keyRef isPrivate:YES];
    
    return [self EVPPrivateKeyFromData:keyData format:MynigmaKeyFormatPKCS1WithoutOID passphrase:nil];
}



#pragma mark generic


+ (EVP_PKEY*)EVPPrivateKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    if(!data)
        return nil;
    
    switch(format)
    {
        case MynigmaKeyFormatDefault:
        case MynigmaKeyFormatPKCS1WithoutOID:
            return [self EVPPrivateKeyFromPKCS1Data:data passphrase:passphrase];
            
        case MynigmaKeyFormatPKCS8WithOID:
            return [self EVPPrivateKeyFromPKCS8Data:data passphrase:passphrase];
            
        case MynigmaKeyFormatPKCS12:
            return [self EVPPrivateKeyFromPKCS12Data:data passphrase:passphrase];
            
        default:
            return nil;
    }
}



#pragma mark - RSA OBJECTS

+ (RSA*)RSAPublicKeyFromData:(NSData*)data
{
    return [self RSAPublicKeyFromData:data format:MynigmaKeyFormatDefault passphrase:nil];
}

+ (RSA*)RSAPublicKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    if(!data)
        return nil;
    
    EVP_PKEY* pubKey = [self EVPPublicKeyFromData:data format:format passphrase:passphrase];
    
    if(!pubKey)
        return [self logErrorAndReturnNil];
    
    RSA* rsa = EVP_PKEY_get1_RSA(pubKey);
    
    EVP_PKEY_free(pubKey);
    
    return rsa;
}

+ (RSA*)RSAPrivateKeyFromData:(NSData*)data
{
    return [self RSAPrivateKeyFromData:data format:MynigmaKeyFormatDefault passphrase:nil];
}

+ (RSA*)RSAPrivateKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase
{
    if(!data)
        return nil;
    
    EVP_PKEY* privKey = [self EVPPrivateKeyFromData:data format:format passphrase:passphrase];
    
    if(!privKey)
        return [self logErrorAndReturnNil];
    
    RSA* rsa = EVP_PKEY_get1_RSA(privKey);
    
    EVP_PKEY_free(privKey);
    
    return rsa;
}



#pragma mark - CROSS-CONVERSION

+ (NSData*)convertPublicKeyData:(NSData*)publicKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat
{
    return [self convertPublicKeyData:publicKeyData fromFormat:inFormat toFormat:outFormat inPassphrase:nil outPassphrase:nil];
}

+ (NSData*)convertPublicKeyData:(NSData*)publicKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat inPassphrase:(NSString *)inPassphrase outPassphrase:(NSString *)outPassphrase
{
    EVP_PKEY* EVPKey = [self EVPPublicKeyFromData:publicKeyData format:inFormat passphrase:inPassphrase];
    return [self dataForEVPPublicKey:EVPKey format:outFormat passphrase:outPassphrase];
}

+ (NSData*)convertPrivateKeyData:(NSData*)privateKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat
{
    return [self convertPrivateKeyData:privateKeyData fromFormat:inFormat toFormat:outFormat inPassphrase:nil outPassphrase:nil];
}

+ (NSData*)convertPrivateKeyData:(NSData*)privateKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat inPassphrase:(NSString*)inPassphrase outPassphrase:(NSString*)outPassphrase
{
    EVP_PKEY* EVPKey = [self EVPPrivateKeyFromData:privateKeyData format:inFormat passphrase:inPassphrase];
    return [self dataForEVPPrivateKey:EVPKey format:outFormat passphrase:outPassphrase];
}


//- (NSData*)PKCS1DataForWrappedPrivateKeyData:(NSData*)PKCS8Data withPassphrase:(NSString*)passphrase
//{
//    return [self dataForEVPPublicKey:[self EVPPrivateKeyFromData:PKCS8Data passphrase:passphrase] format:MynigmaKeyFormatPKCS1WithoutOID];
//}
//
//
//- (NSData*)PKCS12DataFromPKCS1Data:(NSData*)PKCS1Data withPassphrase:(NSString*)passphrase
//{
//    EVP_PKEY* EVPKey = [self EVPPrivateKeyFromData:PKCS1Data passphrase:nil];
//    return [self dataForEVPPrivateKey:EVPKey format:MynigmaKeyFormatPKCS12 passphrase:passphrase];
//}
//
//
//- (NSData*)X509CertificateFromPKCS8Data:(NSData*)PKCS8Data
//{
//    return [self dataForEVPPublicKey:[self EVPPublicKeyFromData:PKCS8Data format:MynigmaKeyFormatDefault passphrase:nil] format:MynigmaKeyFormatX509];
//}






#pragma mark - KEY ARMOUR

+ (NSString*)armourPrivateKeyData:(NSData*)privateKeyData
{
    NSString* outputString = [NSString stringWithFormat:@"-----BEGIN RSA PRIVATE KEY-----\n%@\n-----END RSA PRIVATE KEY-----\n", [privateKeyData base64In64ByteChunksWithCarriageReturn:NO]];
    
    return outputString;
}

+ (NSData*)armourPKCS1PublicKeyData:(NSData*)publicKeyData
{
    //public keys come out of the keychain in PKCS#1 format
    //we need to change the format by appending the object identifier 1.2.840.113549.1.1
    //it's easy: just append some fixed data to the base64 string
    
    NSString* base64edKeyData = [publicKeyData base64];
    
    base64edKeyData = [NSString stringWithFormat:@"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A%@", [base64edKeyData copy]];
    
    //split into 64 character lines
    NSMutableArray* chunks = [NSMutableArray new];
    
    NSInteger index = 0;
    
    while(index<base64edKeyData.length)
    {
        NSInteger lengthOfChunk = (index+64<base64edKeyData.length)?64:base64edKeyData.length-index;
        
        NSString* substring = [base64edKeyData substringWithRange:NSMakeRange(index, lengthOfChunk)];
        
        [chunks addObject:substring];
        
        index+= 64;
    }
    
    NSString* joinedString = [chunks componentsJoinedByString:@"\n"];
    
    NSString* armouredDataString = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----\n", joinedString];
    
    NSData* returnValue = [armouredDataString dataUsingEncoding:NSUTF8StringEncoding];
    
    return returnValue;
}






#pragma mark - KEYCHAIN


+ (SecKeyRef)transientSecKeyRefForPublicKeyData:(NSData*)keyData format:(MynigmaKeyFormat)format
{
#if TARGET_OS_IPHONE
        
    if(format != MynigmaKeyFormatX509)
        keyData = [self convertPublicKeyData:keyData fromFormat:format toFormat:MynigmaKeyFormatX509];
        
        //get a SecKeyRef without adding the key to any keychains
        SecCertificateRef cert = SecCertificateCreateWithData (kCFAllocatorDefault, (__bridge CFDataRef)(keyData));
        CFArrayRef certs = CFArrayCreate(kCFAllocatorDefault, (const void **) &cert, 1, NULL);
        
        SecTrustRef trustRef;
        SecPolicyRef policy = SecPolicyCreateBasicX509();
        SecTrustCreateWithCertificates(certs, policy, &trustRef);
        SecTrustResultType trustResult;
        SecTrustEvaluate(trustRef, &trustResult);
        SecKeyRef publicKeyRef = SecTrustCopyPublicKey(trustRef);
        
        CFRelease(certs);
        
        return publicKeyRef;
        
#else
        
        CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
        CFDictionarySetValue(parameters, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionarySetValue(parameters, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        
        //remove the armour
        NSString* keyString = [[NSString alloc] initWithData:rawKeyData encoding:NSUTF8StringEncoding];
        NSArray* keyComponents = [keyString componentsSeparatedByString:@"-----"];
        if(keyComponents.count<3)
            return nil;
        //we want the middle bit, and we also need to base64 decode it
        NSString* mainDataString = keyComponents[2];
        NSData* mainData = [NSData dataWithBase64String:mainDataString];
        
        CFErrorRef error = NULL;
        SecKeyRef key = SecKeyCreateFromData(parameters, (__bridge CFDataRef)mainData, &error);
        
        return key;
        
#endif
}





+ (SecKeyRef)transientSecKeyRefForPrivateKeyData:(NSData*)keyData format:(MynigmaKeyFormat)format passphrase:(NSString*)inPassphrase
{
#if TARGET_OS_IPHONE
    
    if(!inPassphrase)
    {
        NSLog(@"Cannot currently obtain transient SecKeyRefs for PKCS12 keys without password(!!)");
        return nil;
    }
    
    NSString* outPassphrase = inPassphrase?inPassphrase:@"TEST PASSWORD";
    if(format != MynigmaKeyFormatPKCS12 || !inPassphrase)
        keyData = [self convertPrivateKeyData:keyData fromFormat:format toFormat:MynigmaKeyFormatPKCS12 inPassphrase:inPassphrase outPassphrase:outPassphrase];
    
    NSMutableDictionary *options = [[NSMutableDictionary alloc] init];
    SecKeyRef privateKey = NULL;
    [options setObject:outPassphrase forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = NULL;
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)options, &items);
    
    if (securityError == noErr && CFArrayGetCount(items) > 0)
    {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp =
        (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKey);
        if (securityError != noErr)
        {
            privateKey = NULL;
        }
    }
    else
    {
        NSError* error = [NSError errorWithDomain:NSOSStatusErrorDomain code:securityError userInfo:nil];
        NSLog(@"Error getting transient keychain ref for private key data!! %@", error);
    }
    
    if(items)
        CFRelease(items);
    options = nil;
    
    return privateKey;
    
#else
    
    if(format != MynigmaKeyForma)
    keyData = [self convertDataFrom]
    
    SecItemImportExportKeyParameters params = [KeychainHelper importExportParams:forEncryption];
    
    params.keyUsage = (__bridge CFArrayRef)@[(__bridge id)kSecAttrCanDecrypt, (__bridge id)kSecAttrCanSign];
    
    SecExternalItemType itemType = kSecItemTypePrivateKey;
    SecExternalFormat externalFormat = kSecFormatOpenSSL;
    int flags = 0;
    
    CFArrayRef temparray;
    OSStatus oserr = SecItemImport((__bridge CFDataRef)keyData, NULL, &externalFormat, &itemType, flags, &params, NULL, &temparray);
    
    
    if (oserr != noErr || CFArrayGetCount(temparray)<1)
    {
        NSLog(@"Error importing key! %@", [NSError errorWithDomain:NSOSStatusErrorDomain code:oserr userInfo:nil]);
        
        return nil;
    }
    
    SecKeyRef keyRef = (SecKeyRef)CFArrayGetValueAtIndex(temparray, 0);
    
    //        CFRelease(temparray);
    
    return keyRef;
    
#endif
}

@end
