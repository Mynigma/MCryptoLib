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




#import <openssl/rsa.h>
#import <openssl/dsa.h>



typedef NS_ENUM(NSUInteger, MynigmaKeyFormat)
{
    
    /**
     * The default format is PKCS#1 for private RSA keys and PKCS#8 for all other keys
     */
    MynigmaKeyFormatDefault = 0,
    
    /**
     * PKCS#8 format for RSA private keys is an RSAPrivateKey ASN.1 object (raw data without OID) in base64 encoded DER with RSA private key armour
     *
     * @code
     * ----BEGIN RSA PRIVATE KEY-----\n
     * [base64 encoded DER representation of RSAPrivateKey]\n
     * ----END RSA PRIVATE KEY-----\n
     * @endcode
     *
     * @see https://tools.ietf.org/html/rfc3447#appendix-A.1 (RFC 3447, PKCS#1, Appendix A.1.2)
     */
    MynigmaKeyFormatPKCS1WithoutOID = 1,
    
    /**
     * PKCS#8 format is a SubjectPublicKeyInfo ASN.1 object (containing an OID as well as the key data) in base64 encoded DER with generic public key armour
     *
     * @code
     * ----BEGIN PUBLIC KEY-----\n
     * [base64 encoded DER representation of SubjectPublicKeyInfo]\n
     * ----END PUBLIC KEY-----\n
     * @endcode
     *
     * @see https://tools.ietf.org/html/rfc5208#appendix-A (RFC 5208, PKCS#8, Appendix A)
     */
    MynigmaKeyFormatPKCS8WithOID = 2,
    
    /**
     * X.509 format
     *
     * @code
     * ----BEGIN CERTIFICATE-----\n
     * [base64 encoded X.509 certificate]\n
     * ----END CERTIFICATE-----\n
     * @endcode
     *
     * @see https://tools.ietf.org/html/rfc5280 (RFC 5280, X.509)
     */
    MynigmaKeyFormatX509 = 3,
    
    /**
     *  PKCS#12 format
     *
     * @code
     * Unarmoured raw PKCS#12 data
     * @endcode
     *
     *  @see http://tools.ietf.org/html/rfc7292 (RFC 7292, PKCS#12)
     */
    MynigmaKeyFormatPKCS12 = 4
};



@interface OpenSSLEncryptionEngine (KeyParsing)



#pragma mark - DATA EXPORT


/**
 *  Export RSA public key in default format
 *
 *  @param RSAKey The RSA public key to export
 *
 *  @return The key data in Mynigma's default format (PKCS#8)
 */
- (NSData*)dataForRSAPublicKey:(RSA*)RSAKey;

/**
 *  Export RSA public key
 *
 *  @param RSAKey The RSA public key to export
 *
 *  @return The key data in the specified format
 */
- (NSData*)dataForRSAPublicKey:(RSA*)RSAKey format:(MynigmaKeyFormat)format;



/**
 *  Export RSA private key in default format
 *
 *  @param RSAKey The RSA private key to export
 *
 *  @return The key data in Mynigma's default format (PKCS#1)
 */
- (NSData*)dataForRSAPrivateKey:(RSA*)RSAKey;

/**
 *  Export RSA private key
 *
 *  @param RSAKey The RSA private key to export
 *
 *  @return The key data in the specified format
 */
- (NSData*)dataForRSAPrivateKey:(RSA*)RSAKey format:(MynigmaKeyFormat)format;

/**
 *  Export a passphrase encrypted RSA private key in the specified format
 *
 *  @param RSAKey The RSA private key to export
 *
 *  @return The key data in the specified format, encrypted with the given passphrase
 */

/**
 *  Export a passphrase encrypted RSA private key
 *
 *  @param RSAKey       The RSA private key to export
 *  @param format       The format (e.g. MynigmaKeyFormatPKCS12)
 *  @param passphrase   The passphrase used to protect the exported key
 *
 *  @return The key data in the specified format, encrypted with the given passphrase
 */
- (NSData*)dataForRSAPrivateKey:(RSA*)RSAKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;

/**
 *  Export an EVP_PKEY object as public key data
 *
 *  @param publicKey  The public key
 *  @param format     The format (e.g. MynigmaFormatDefault)
 *
 *  @return The key data in the specified format
 */
- (NSData*)dataForEVPPublicKey:(EVP_PKEY*)publicKey format:(MynigmaKeyFormat)format;


- (NSData*)dataForEVPPublicKey:(EVP_PKEY*)publicKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;





/**
 *  Export DSA public key
 *
 *  @param DSAKey The DSA key to export
 *  @param format The format (e.g. MynigmaFormatPKCS8WithOID)
 *
 *  @return The key data in the specified format
 */
- (NSData*)dataForDSAPublicKey:(DSA*)DSAKey format:(MynigmaKeyFormat)format;

/**
 *  Export DSA private key
 *
 *  @param DSAKey The DSA key to export
 *  @param format The format (e.g. MynigmaFormatPKCS8WithOID)
 *  @param passphrase An optional passphrase
 *
 *  @return The key data in the specified format
 */
- (NSData*)dataForDSAPrivateKey:(DSA*)DSAKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;


/**
 *  Export an EVP_PKEY object as private key data
 *
 *  @param privateKey The private key
 *  @param format     The format (e.g. MynigmaFormatDefault)
 *  @param passphrase An optional passphrase
 *
 *  @return The key data in the specified format
 */
- (NSData*)dataForEVPPrivateKey:(EVP_PKEY*)privateKey format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;



#pragma mark - DATA IMPORT


///**
// *  Import X.509 certificate
// *
// *  @param certData The certificate data
// *
// *  @return An X509 object containing the imported certificate
// */
//- (X509*)X509CertificateForData:(NSData*)certData;


/**
 *  Import public key
 *
 *  @param data The public key data
 *
 *  @return An EVP_PKEY object containing the imported key
 */
- (EVP_PKEY*)EVPPublicKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;


/**
 *  Import private key
 *
 *  @param data The private key data
 *
 *  @return An EVP_PKEY object containing the imported key
 */
- (EVP_PKEY*)EVPPrivateKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;


#pragma mark - RSA OBJECTS

- (RSA*)RSAPublicKeyFromData:(NSData*)data;

- (RSA*)RSAPrivateKeyFromData:(NSData*)data;

- (RSA*)RSAPublicKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;

- (RSA*)RSAPrivateKeyFromData:(NSData*)data format:(MynigmaKeyFormat)format passphrase:(NSString*)passphrase;


#pragma mark - CROSS-CONVERSION

- (NSData*)convertPublicKeyData:(NSData*)publicKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat;

- (NSData*)convertPublicKeyData:(NSData*)publicKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat inPassphrase:(NSString*)inPassphrase outPassphrase:(NSString*)outPassphrase;

- (NSData*)convertPrivateKeyData:(NSData*)privateKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat;

- (NSData*)convertPrivateKeyData:(NSData*)privateKeyData fromFormat:(MynigmaKeyFormat)inFormat toFormat:(MynigmaKeyFormat)outFormat inPassphrase:(NSString*)inPassphrase outPassphrase:(NSString*)outPassphrase;




#pragma mark - KEY ARMOUR

/**
 *  Base64 encode the input and add -----BEGIN RSA PRIVATE KEY----- armour
 *
 *  @param privateKeyData The raw key data
 *
 *  @return Armoured, base 64 encoded key data
 */
+ (NSString*)armourPrivateKeyData:(NSData*)privateKeyData;

/**
 *  Convert PKCS#1 formatted raw data without armour into armoured PKCS#8 data
 */
+ (NSData*)armourPKCS1PublicKeyData:(NSData*)publicKeyData;



#pragma mark - KEYCHAIN


- (SecKeyRef)transientSecKeyRefForPublicKeyData:(NSData*)keyData format:(MynigmaKeyFormat)format;

- (SecKeyRef)transientSecKeyRefForPrivateKeyData:(NSData*)keyData format:(MynigmaKeyFormat)format passphrase:(NSString*)inPassphrase;


@end
