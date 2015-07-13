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


#import "PGPEncryptionEngine.h"

#import "PGPKeyManager.h"

#import "netpgp.h"
#import "keyring.h"
#import "memory.h"
#import "crypto.h"



static dispatch_queue_t _PGPEngineQueue;


@interface PGPKeyManager()

- (__ops_keyring_t*)publicKeyring;
- (__ops_keyring_t*)privateKeyring;

- (NSString*)password;

@end




@implementation PGPEncryptionEngine


- (instancetype)init
{
    self = [super init];
    if(self)
    {
        _PGPEngineQueue = dispatch_queue_create("Mynigma PGP engine dispatch queue", NULL);
        self.keyManager = [PGPKeyManager new];
    }
    return self;
}

- (instancetype)initWithKeyManager:(PGPKeyManager*)keyManager
{
    self = [super init];
    if(self)
    {
        _PGPEngineQueue = dispatch_queue_create("Mynigma PGP engine dispatch queue", NULL);
        self.keyManager = keyManager;
    }
    return self;
}



- (NSData*)encryptData:(NSData*)inData options:(OpenPGPEncryptionOption)options withUserID:(NSString*)userID
{
    __block NSData *result = nil;

    dispatch_sync(_PGPEngineQueue, ^{
        netpgp_t *netpgp = [self.keyManager buildnetpgp];
        if(netpgp)
        {

            if (options & OpenPGPEncryptionOptionDontUseSubkeys)
            {
                netpgp_setvar(netpgp, "dont use subkey to encrypt", "1");
            }

            int insize = (int)inData.length;
            void *inbuf = calloc(inData.length, sizeof(Byte));
            memcpy(inbuf, inData.bytes, inData.length);

            NSNumber* encryptWithArmourOption = [[NSUserDefaults standardUserDefaults] objectForKey:@"OpenPGPWrapper encrypt with armour"];

            unsigned maxsize = (unsigned)atoi(netpgp_getvar(netpgp, "max mem alloc"));
            void *outbuf = calloc(maxsize, sizeof(Byte));
            int outsize = maxsize;
            
            int m = netpgp_encrypt_memory(netpgp, [userID cStringUsingEncoding:NSUTF8StringEncoding], inbuf, insize, outbuf, outsize, encryptWithArmourOption.boolValue?1:0);

            if(m > 0 && outsize > 0)
            {
                result = [NSData dataWithBytesNoCopy:outbuf length:m freeWhenDone:YES];
            }
            else if(outbuf)
                free(outbuf);

            if (inbuf)
                free(inbuf);
        }
    });

    return result;
}


- (NSData*)decryptData:(NSData*)inData options:(OpenPGPEncryptionOption)options withUserID:(NSString*)userID
{
    BOOL dataIsArmoured = [PGPKeyManager dataIsArmoured:inData];
    
    __block NSData *result = nil;
    
    dispatch_sync(_PGPEngineQueue, ^{
        netpgp_t *netpgp = [self.keyManager buildnetpgp];
        if (netpgp) {
            
            if (options & OpenPGPEncryptionOptionDontUseSubkeys)
            {
                netpgp_setvar(netpgp, "dont use subkey to encrypt", "1");
            }
            
            int insize = (int)inData.length;
            void *inbuf = calloc(inData.length, sizeof(Byte));
            memcpy(inbuf, inData.bytes, inData.length);
            
            unsigned maxsize = (unsigned)atoi(netpgp_getvar(netpgp, "max mem alloc"));
            void *outbuf = calloc(maxsize, sizeof(Byte));
            int outsize = maxsize;
                        
            int m = netpgp_decrypt_memory(netpgp, inbuf, insize, outbuf, outsize, dataIsArmoured?1:0);
            
            if(m > 0 && outsize > 0)
            {
                result = [NSData dataWithBytesNoCopy:outbuf length:m freeWhenDone:YES];
            }
            else if(outbuf)
                free(outbuf);
            
            if(inbuf)
                free(inbuf);
        }
    });
    
    return result;
}




- (NSData*)signData:(NSData*)inData withUserID:(NSString*)userID
{
        __block NSData *result = nil;
    
        dispatch_sync(_PGPEngineQueue, ^{
            netpgp_t *netpgp = [self.keyManager buildnetpgp];
            if (netpgp) {
                void *inbuf = calloc(inData.length, sizeof(Byte));
                memcpy(inbuf, inData.bytes, inData.length);
    
                NSInteger maxsize = (unsigned)atoi(netpgp_getvar(netpgp, "max mem alloc"));
                void *outbuf = calloc(sizeof(Byte), maxsize);
                int outsize = netpgp_sign_memory(netpgp, userID.UTF8String, inbuf, inData.length, outbuf, maxsize, 1, 0 /* !cleartext */);
    
                if (outsize > 0) {
                    result = [NSData dataWithBytesNoCopy:outbuf length:outsize freeWhenDone:YES];
                }
                else if(outbuf)
                    free(outbuf);
   
                if (inbuf)
                    free(inbuf);
            }
        });
    
        return result;
}

- (NSData*)verifyData:(NSData*)inData withUserID:(NSString*)userID
{
    __block NSData *result = nil;
    
    dispatch_sync(_PGPEngineQueue, ^{
        netpgp_t *netpgp = [self.keyManager buildnetpgp];
        if (netpgp) {
            void *inbuf = calloc(inData.length, sizeof(Byte));
            memcpy(inbuf, inData.bytes, inData.length);
            
            NSInteger maxsize = (unsigned)atoi(netpgp_getvar(netpgp, "max mem alloc"));
            void *outbuf = calloc(sizeof(Byte), maxsize);
            int outsize = netpgp_verify_memory(netpgp, inbuf, inData.length, outbuf, maxsize, 1);
            
            if(outsize > 0)
            {
                result = [NSData dataWithBytesNoCopy:outbuf length:outsize freeWhenDone:YES];
            }
            else if(outbuf)
                free(outbuf);
            
            if (inbuf)
                free(inbuf);
        }
    });
    
    return result;
}







//+ (NSData*)encryptMessage:(PGPMessage*)message withFeedback:(MynigmaFeedback*)feedback
//{
//    //first collect the data to be signed & encrypted, as well as the keys
//
//    EmailRecipient* sender = [AddressDataHelper senderAsEmailRecipientForMessage:message addIfNotFound:YES];
//
//    NSString* senderKeyLabel = [MynigmaPrivateKey privateKeyLabelForEmailAddress:sender.email];
//
//
//    NSArray* emailRecipients = [AddressDataHelper nonSenderEmailRecipientsForMessage:message];
//
//    NSArray* encryptionKeyLabels = [MynigmaPublicKey encryptionKeyLabelsForRecipients:emailRecipients allowErrors:NO];
//
//
//    MCOMessageBuilder* messageBuilder = [MCOMessageBuilder new];
//
//
//
//
//
//    NSData* dataToBeSigned = [messageBuilder dataForEncryption];
//
//    NSData* signature = [self signData:dataToBeSigned withKeyLabel:senderKeyLabel];
//
//    //then encrypt it
//    NSData* dataToBeEncrypted = [messageBuilder openPGPSignedMessageDataWithSignatureData:signature];
//
//
//    NSData* encryptedData = [self encryptData:dataToBeEncrypted options:0 withKeyLabels:encryptionKeyLabels];
//
//    NSData* encryptedOpenPGPMessageData = [messageBuilder openPGPEncryptedMessageDataWithEncryptedData:encryptedData];
//
//    return encryptedOpenPGPMessageData;
//}

//+ (PGPMessage*)decryptData:(NSData*)data withFeedback:(MynigmaFeedback*)feedback;
//{
//    
//    
//    return nil;
//}

@end
