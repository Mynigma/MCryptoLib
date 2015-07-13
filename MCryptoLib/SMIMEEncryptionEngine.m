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


#import "SMIMEEncryptionEngine.h"

#import <openssl/x509.h>
#import <openssl/cms.h>
#import <openssl/err.h>
#import <openssl/pem.h>

#import "PublicKeyData.h"
#import "OpenSSLEncryptionEngine.h"
#import "KeyParser.h"
#import "SMIMEKeyManager.h"
#import "ASN1Helper.h"

#import "SMIMEPublicKey.h"
#import "NSData+Base64.h"
#import "SMIMEPrivateKey.h"


#import "netpgp.h"
#import "keyring.h"




@implementation SMIMEEncryptionEngine

- (instancetype)init
{
    self = [super init];
    if(self)
    {
        self.keyManager = [SMIMEKeyManager new];
        self.openSSLEngine = [OpenSSLEncryptionEngine new];
    }
    return self;
}




#pragma clang diagnostic pop




#pragma mark - Cryptographic Message Syntax (CMS) & S/MIME

- (NSData*)encryptData:(NSData*)data forEmailAddresses:(NSArray*)emailAddresses error:(NSError**)error
{
    STACK_OF(X509) *sk = sk_X509_new_null();
    
    for(NSString* emailAddress in emailAddresses)
    {
        X509* X509Certificate = [self.keyManager encryptionCertificateForEmailAddress:emailAddress];
        
        if(!X509Certificate)
            continue;
        
        sk_X509_push(sk, X509Certificate);
    }
    
    BIO* dataBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);
    
    BIO* outputBIO = BIO_new(BIO_s_mem());
    
    CMS_ContentInfo* contentInfo = CMS_encrypt(sk, dataBIO, EVP_aes_128_cbc(), 0);
    
    int result = SMIME_write_CMS(outputBIO, contentInfo, dataBIO, 0);
    
    if(result != 1)
    {
        //TO DO: better error feedback
        
        long errorCode = ERR_get_error();
        
        if(error)
            *error = [NSError errorWithDomain:@"S/MIME parse error" code:errorCode userInfo:@{}];
    }
    
    int len = BIO_pending(outputBIO);
    
    char *resultBytes = malloc(len);
    
    BIO_read(outputBIO, resultBytes, len);
    
    NSData* resultData = [NSData dataWithBytes:resultBytes length:len];
    
    free(resultBytes);
    
    return resultData;
}

- (NSData*)decryptData:(NSData*)data forEmailAddress:(NSString*)emailAddress error:(NSError**)error
{
    X509* x509Cert = [self.keyManager encryptionCertificateForEmailAddress:emailAddress];
    
    EVP_PKEY* privKey = NULL; //[self.keyManager decryptionEVPKeyForEmailAddress:emailAddress];
    
    BIO* dataBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);
    
    BIO* outputBIO = BIO_new(BIO_s_mem());
    
    BIO *cont = NULL;
    
    CMS_ContentInfo* contentInfo = SMIME_read_CMS(dataBIO, &cont);
    
    int decryptionResult = CMS_decrypt(contentInfo, privKey, x509Cert, cont, outputBIO, 0);
    
    if(decryptionResult != 1)
    {
        //TO DO: better error feedback
        
        long errorCode = ERR_get_error();
        
        if(error)
            *error = [NSError errorWithDomain:@"S/MIME parse error" code:errorCode userInfo:@{}];
    }
    
    int len = BIO_pending(outputBIO);
    
    char *resultBytes = malloc(len);
    
    BIO_read(outputBIO, resultBytes, len);
    
    NSData* resultData = [NSData dataWithBytes:resultBytes length:len];
    
    free(resultBytes);
    
    return resultData;
}

- (NSData*)signData:(NSData*)data forEmailAddress:(NSString*)emailAddress error:(NSError**)error
{
    STACK_OF(X509) *sk = sk_X509_new_null();
    
    X509* X509Certificate = NULL; // [self.keyManager X509CertificateForEmailAddress:emailAddress];
    
    sk_X509_push(sk, X509Certificate);
    
    EVP_PKEY* privKey = NULL; //[self.keyManager EVP_PKEYForEmailAddress:emailAddress];
    
    BIO* dataBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);
    
    BIO* outputBIO = BIO_new(BIO_s_mem());
    
    CMS_ContentInfo* contentInfo = CMS_sign(X509Certificate, privKey, NULL, dataBIO, 0);
    
    int result = SMIME_write_CMS(outputBIO, contentInfo, dataBIO, 0);
    
    if(result != 1)
    {
        //TO DO: better error feedback
        
        long errorCode = ERR_get_error();
        
        if(error)
            *error = [NSError errorWithDomain:@"S/MIME parse error" code:errorCode userInfo:@{}];
    }
    
    int len = BIO_pending(outputBIO);
    
    char *resultBytes = malloc(len);
    
    BIO_read(outputBIO, resultBytes, len);
    
    NSData* resultData = [NSData dataWithBytes:resultBytes length:len];
    
    free(resultBytes);
    
    return resultData;
}

- (NSData*)verifySignedData:(NSData*)data forEmailAddress:(NSString*)emailAddress error:(NSError**)error
{
    STACK_OF(X509) *sk = sk_X509_new_null();
    
    X509* X509Certificate = NULL; //[self.keyManager X509CertificateForEmailAddress:emailAddress];
    
    sk_X509_push(sk, X509Certificate);
    
    X509_STORE* store = X509_STORE_new();
    
    X509_STORE_add_cert(store, X509Certificate);
    
    BIO* dataBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);
    
    BIO* outputBIO = BIO_new(BIO_s_mem());
    
    BIO *cont = NULL;
    
    CMS_ContentInfo* contentInfo = SMIME_read_CMS(dataBIO, &cont);
    
    if(!contentInfo)
    {
        long errorCode = ERR_get_error();
        
        const char* error_string = ERR_error_string(errorCode, NULL);
        
        NSLog(@"Error: %@", [NSString stringWithCString:error_string?error_string:"" encoding:NSUTF8StringEncoding]);
        
        return nil;
    }
    
    int result = CMS_verify(contentInfo, sk, store, NULL, outputBIO, 0);
    
    if(result != 1)
    {
        //TO DO: better error feedback
        
        long errorCode = ERR_get_error();
        
        const char* error_string = ERR_error_string(errorCode, NULL);
        
        NSLog(@"Error: %@", [NSString stringWithCString:error_string?error_string:"" encoding:NSUTF8StringEncoding]);
        
        if(error)
            *error = [NSError errorWithDomain:@"S/MIME signature verification fail" code:errorCode userInfo:@{}];
        
        return nil;
    }
    
    int len = BIO_pending(outputBIO);
    
    char *resultBytes = malloc(len);
    
    BIO_read(outputBIO, resultBytes, len);
    
    NSData* resultData = [NSData dataWithBytes:resultBytes length:len];
    
    free(resultBytes);
    
    return resultData;
}


#pragma mark - Importing S/MIME keys

- (SMIMEPublicKey*)importKeyFromFileWithURL:(NSURL*)fileURL
{
    return [self importKeyFromFileWithURL:fileURL withPassphraseCallback:nil andResultCallback:nil];
}



- (SMIMEPublicKey*)importKeyFromFileWithURL:(NSURL*)fileURL withPassphraseCallback:(void(^)(NSString* passphrase))passPhraseCallback andResultCallback:(void(^)(NSArray* importedKeyLabels))resultCallback
{
    NSData* fileData = [NSData dataWithContentsOfURL:fileURL];

    //we first need to work out what kind of data it is...
    NSString* dataString = [[NSString alloc] initWithData:fileData encoding:NSUTF8StringEncoding];
    
    //check for an armour
    NSArray* armourComponents = [dataString componentsSeparatedByString:@"-----"];
    
    BOOL isArmoured = armourComponents.count >= 4;
    
    //we want the data to be in base64 and armoured
    //if the provided data is not in this format, we will adjust it
    NSData* armouredBase64Data = fileData;
    
    if(!isArmoured)
    {
        NSString* unarmouredString = nil;
        
        //try base64-decoding the data
        //if this works, we'll assume that it is indeed base64
        NSData* base64DecodedData = [NSData dataWithBase64String:dataString];
        
        if(base64DecodedData.length)
        {
            //dataString is already base64-encoded data
            unarmouredString = dataString;
        }
        else
        {
            //assume it's raw data - encode it in base64
            unarmouredString = [fileData base64In64ByteChunksWithCarriageReturn:YES];
        }
        
        NSString* armourType = @"CERTIFICATE";
        
        //use "RSA PRIVATE KEY" even for DSS keys, just "PRIVATE KEY" won't work
        if([@[@"pri", @"key"] containsObject:fileURL.pathExtension])
            armourType = @"RSA PRIVATE KEY";
        
        NSString* armouredString = [NSString stringWithFormat:@"-----BEGIN %@-----\r\n%@\r\n-----END %@-----\r\n", armourType, dataString, armourType];
        
        armouredBase64Data = [armouredString dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    return [self parseASN1DataIntoImportedCertificate:armouredBase64Data withPasswordCallback:nil];
}


- (NSData*)dataForEVPPrivateKey:(EVP_PKEY*)privateKeyEVP
{
    BIO* privateKeyBIO = BIO_new(BIO_s_mem());
    
    PEM_write_bio_PKCS8PrivateKey(privateKeyBIO, privateKeyEVP, NULL, NULL, 0, NULL, NULL);
    
    int len = BIO_pending(privateKeyBIO);
    
    char *keyBytes = malloc(len);
    
    BIO_read(privateKeyBIO, keyBytes, len);
    
    NSData* privateKeyData = [NSData dataWithBytes:keyBytes length:len];
    
    if(keyBytes)
        free(keyBytes);
    
    return privateKeyData;
}

- (NSData*)dataForEVPPublicKey:(EVP_PKEY*)publicKeyEVP
{
    BIO* publicKeyBIO = BIO_new(BIO_s_mem());
    
    PEM_write_bio_PUBKEY(publicKeyBIO, publicKeyEVP);
    
    
    int len = BIO_pending(publicKeyBIO);
    
    char *keyBytes = malloc(len);
    
    BIO_read(publicKeyBIO, keyBytes, len);
    
    NSData* publicKeyData = [NSData dataWithBytes:keyBytes length:len];
    
    if(keyBytes)
        free(keyBytes);
    
    return publicKeyData;
}


- (SMIMEPublicKey*)parseASN1DataIntoImportedCertificate:(NSData*)pemData withPasswordCallback:(void(^)(pem_password_cb *passwordReturnCallback))passwordCallback
{
    [OpenSSLEncryptionEngine sharedInstance];
    
    BIO* pemBIO = BIO_new_mem_buf((void*)pemData.bytes, (int)pemData.length);
    
    pem_password_cb* pwCallback = objc_unretainedPointer(passwordCallback);
    
    STACK_OF(X509_INFO)* stackOfCerts = PEM_X509_INFO_read_bio(pemBIO, NULL, pwCallback, NULL);
    
    int numberOfCerts = sk_X509_INFO_num(stackOfCerts);
    
    for(int i = 0; i < numberOfCerts; i++)
    {
        X509_INFO* x509Info = sk_X509_INFO_value(stackOfCerts, i);
        
        X509* certificate = x509Info->x509;
        
        X509_PKEY* privateKey = x509Info->x_pkey;
        
        if(privateKey)
        {
            //there is a private key(!!)

            EVP_PKEY* privateKeyEVP = privateKey->dec_pkey;
            
            if(!certificate)
            {
                certificate = X509_new();
            
                X509_set_pubkey(certificate, privateKeyEVP);
            }
            
            unsigned char fingerprintData[256];
            unsigned int fingerprintLength;
            
            int fingerprintCreationResult = X509_digest(certificate, EVP_sha256(), fingerprintData, &fingerprintLength);
            
            if(fingerprintCreationResult != 1)
                continue;

            NSData* fingerprint = [NSData dataWithBytes:fingerprintData length:fingerprintLength];
            
            NSData* PKCS8Data = [self.openSSLEngine dataForEVPPrivateKey:privateKeyEVP format:MynigmaKeyFormatPKCS8WithOID passphrase:nil];
            
            //we can actually use the private key here
            NSData* X509Data = [self.openSSLEngine dataForEVPPublicKey:privateKeyEVP format:MynigmaKeyFormatX509];
            
            SMIMEPrivateKey* addedKey = [self.keyManager addPrivateKeyWithPKCS8Data:PKCS8Data andX509Data:X509Data SHA256Fingerprint:fingerprint];
            
            
            
            
            
            
            
            
            return addedKey;
        }
        else if(certificate)
        {
            //if there is no private key, there should at least be a certificate
            
            //first try to get the public key data
            X509_CINF* certInfo = certificate->cert_info;
            
            X509_PUBKEY* certPublicKey = certInfo->key;
            
            EVP_PKEY* publicKeyEVP = X509_PUBKEY_get(certPublicKey);
            
            NSData* publicKeyData = [self.openSSLEngine dataForEVPPublicKey:publicKeyEVP format:MynigmaKeyFormatX509];
            
            if(!publicKeyData.length)
                return nil;

            unsigned char fingerprintData[256];
                unsigned int fingerprintLength;
                
                int fingerprintCreationResult = X509_digest(certificate, EVP_sha256(), fingerprintData, &fingerprintLength);
                
                if(fingerprintCreationResult != 1)
                    continue;
                
                NSData* fingerprint = [NSData dataWithBytes:fingerprintData length:fingerprintLength];
            
                SMIMEPublicKey* publicKey = [self.keyManager addPublicKeyWithX509Data:publicKeyData SHA256Fingerprint:fingerprint];

                if(!publicKey)
                    continue;
            
            [self updatePropertiesOfSMIMEPublicKey:publicKey withX509Infos:certInfo];

                return publicKey;
        }
        else
        {
            NSLog(@"Error parsing X509 info object!!");
        }
    }
    
    return nil;
}




- (void)updatePropertiesOfSMIMEPublicKey:(SMIMEPublicKey*)publicKey withX509Infos:(X509_CINF*)certInfo
{
    //                @property (nonatomic, retain) NSString * issuer;
    X509_NAME* issuerName = certInfo->issuer;
    
    NSMutableArray* issuerNames = [NSMutableArray new];
    X509_NAME_ENTRY* issuerNameEntry = NULL;
    while((issuerNameEntry = sk_X509_NAME_ENTRY_pop(issuerName->entries)))
    {
        NSString* issuerNameString = [ASN1Helper stringFromASN1String:issuerNameEntry->value];
        if(issuerNameString)
            [issuerNames addObject:issuerNameString];
    }
    
    //TODO: deal with multiple issuer names
    [publicKey setIssuer:issuerNames.firstObject];
    
    //                @property (nonatomic, retain) NSString * keyUsage;
    
    //                @property (nonatomic, retain) NSString * serialNumber;
    
    NSString* serialNumber = [ASN1Helper stringFromASN1Integer:certInfo->serialNumber];
    
    [publicKey setSerialNumber:serialNumber];
    
    //                @property (nonatomic, retain) NSData * signature;
    
    //                X509_ALGOR* signature = certInfo->signature;
    
    //                [publicKey setSignature:signature]
    
    //                @property (nonatomic, retain) NSString * signatureAlgorithm;
    
    //                ASN1_OBJECT* signatureAlgorithm = signature->algorithm;
    
    //                [publicKey setSignatureAlgorithm:signatureAlgorithm->]
    
    //                @property (nonatomic, retain) NSString * subject;
    
    X509_NAME* subjectName = certInfo->subject;
    
    NSMutableArray* subjectNames = [NSMutableArray new];
    X509_NAME_ENTRY* subjectNameEntry = NULL;
    while((subjectNameEntry = sk_X509_NAME_ENTRY_pop(subjectName->entries)))
    {
        NSString* subjectNameString = [ASN1Helper stringFromASN1String:subjectNameEntry->value];
        if(subjectNameString)
            [subjectNames addObject:subjectNameString];
    }
    
    [publicKey setSubject:subjectNames.firstObject];
    
    //                @property (nonatomic, retain) NSData * thumbprint;
    
    //                @property (nonatomic, retain) NSString * thumbprintAlgorithm;
    
    //                @property (nonatomic, retain) NSDate * validFrom;
    
    X509_VAL* validity = certInfo->validity;
    
    ASN1_TIME* notBefore = validity->notBefore;
    
    NSDate* validFromDate = [ASN1Helper dateFromASN1Time:notBefore];
    
    [publicKey setValidFrom:validFromDate];
    
    //                @property (nonatomic, retain) NSDate * validUntil;
    
    ASN1_TIME* notAfter = validity->notAfter;
    
    NSDate* validUntilDate = [ASN1Helper dateFromASN1Time:notAfter];
    
    [publicKey setValidUntil:validUntilDate];
    
    //                @property (nonatomic, retain) NSString * version;
    
    NSString* version = [ASN1Helper stringFromASN1Integer:certInfo->version];
    
    [publicKey setVersion:version];
    
    //                @property (nonatomic, retain) EmailAddress *currentKeyForEmail;
}



- (NSData*)publicKeyDataForOpsKey:(__ops_key_t*)opsKey
{
    __ops_pubkey_t pubKey = opsKey->key.pubkey;
    
    __ops_rsa_pubkey_t rsaPubKey = pubKey.key.rsa;
    
    if(rsaPubKey.e && rsaPubKey.n)
    {
    if(__ops_is_key_secret(opsKey))
    {
        __ops_seckey_t privKey = opsKey->key.seckey;
       
        __ops_rsa_seckey_t rsaPrivKey = privKey.key.rsa;

        if(rsaPrivKey.d && rsaPrivKey.p && rsaPrivKey.q && rsaPrivKey.u)
        {
        //write the secret key
        RSA* RSA = RSA_new();

            RSA->n = BN_dup(rsaPubKey.n);
            RSA->e = BN_dup(rsaPubKey.e);

            RSA->d = rsaPrivKey.d;
            
            //p and q are reversed
            RSA->p = rsaPrivKey.q;
            RSA->q = rsaPrivKey.p;
            
        NSData* returnValue = [self.openSSLEngine dataForRSAPrivateKey:RSA];
        
            RSA_free(RSA);
            
        return returnValue;
        }
    }
    else
    {
        RSA* RSA = RSA_new();
        
        RSA->e = rsaPubKey.e;
        RSA->n = rsaPubKey.n;
        
        NSData* returnValue = [self.openSSLEngine dataForRSAPublicKey:RSA];
        
        RSA_free(RSA);
        
        return returnValue;
    }
    }

    return nil;
}




@end
