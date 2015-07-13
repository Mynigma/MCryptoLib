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


#import "ASN1Helper.h"






@implementation ASN1Helper

+ (NSString*)stringFromASN1Integer:(ASN1_INTEGER*)ASN1Integer
{
    BIGNUM *bn = ASN1_INTEGER_to_BN(ASN1Integer, NULL);
    
    char *result;
    result = BN_bn2hex(bn);
    
    return [[NSString alloc] initWithCString:result encoding:NSUTF8StringEncoding];
}

+ (NSString*)stringFromASN1String:(ASN1_STRING*)ASN1String
{
    char *data,*result;
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_STRING_print(bio, ASN1String);
    
    long n = BIO_get_mem_data(bio, &data);
    result = (char *) malloc (n+1);
    result[n]='\0';
    memcpy(result,data,n);
    
    BIO_free(bio);
    bio=NULL;
    return [[NSString alloc] initWithCString:result encoding:NSASCIIStringEncoding];
}

+ (NSDate*)dateFromASN1Time:(ASN1_TIME*)time
{
    char *data,*result;
    BIO *bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, time);
    
    long n = BIO_get_mem_data(bio, &data);
    result = (char *) malloc (n+1);
    result[n]='\0';
    memcpy(result,data,n);
    
    NSString *date = [[NSString alloc] initWithCString:result encoding:NSASCIIStringEncoding];
    
    //Jan 21 10:20:56 2010 GMT
    NSDateFormatter *format=[[NSDateFormatter alloc] init];
    [format setFormatterBehavior: NSDateFormatterBehavior10_4];
    
    [format setDateFormat:@"LLL d HH:mm:ss yyyy z"];
    
    NSDate *cdate=[format dateFromString:date];
    
    BIO_free(bio);
    bio=NULL;
    
    return cdate;
}

@end
