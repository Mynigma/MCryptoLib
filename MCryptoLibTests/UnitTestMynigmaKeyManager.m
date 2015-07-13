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

#import "UnitTestMynigmaKeyManager.h"
#import "TestHelper.h"
#import "NSString+EmailAddresses.h"

#import "PublicKeyData.h"
#import "PrivateKeyData.h"





@interface UnitTestMynigmaKeyManager()

// dictionary holding PublicKeyData/PrivateKeyData objects, indexed by the keyLabel
@property NSMutableDictionary* allKeys;

// dictionary of current keyLabels, indexed by the canonical form of the email address
@property NSMutableDictionary* currentKeyLabels;

//dictionary of dictionaries
// from => (to => @[expectedLabel, date])
@property NSMutableDictionary* keyExpectations;

@end




@implementation UnitTestMynigmaKeyManager


- (instancetype)init
{
    self = [super init];
    if (self) {
        
        self.allKeys = [NSMutableDictionary new];
        
        self.allKeys[TEST_KEY_LABEL1] = [TestHelper privateKeyData:@1 withKeyLabel:TEST_KEY_LABEL1];
        self.allKeys[TEST_KEY_LABEL2] = [TestHelper privateKeyData:@2 withKeyLabel:TEST_KEY_LABEL2];
        self.allKeys[TEST_KEY_LABEL3] = [TestHelper privateKeyData:@3 withKeyLabel:TEST_KEY_LABEL3];
        self.allKeys[TEST_KEY_LABEL4] = [TestHelper privateKeyData:@4 withKeyLabel:TEST_KEY_LABEL4];
        self.allKeys[TEST_KEY_LABEL5] = [TestHelper privateKeyData:@5 withKeyLabel:TEST_KEY_LABEL5];

        self.allKeys[TEST_KEY_LABEL6] = [TestHelper publicKeyData:@6 withKeyLabel:TEST_KEY_LABEL6];
        self.allKeys[TEST_KEY_LABEL7] = [TestHelper publicKeyData:@7 withKeyLabel:TEST_KEY_LABEL7];
        self.allKeys[TEST_KEY_LABEL8] = [TestHelper publicKeyData:@8 withKeyLabel:TEST_KEY_LABEL8];
        self.allKeys[TEST_KEY_LABEL9] = [TestHelper publicKeyData:@9 withKeyLabel:TEST_KEY_LABEL9];
        self.allKeys[TEST_KEY_LABEL10] = [TestHelper publicKeyData:@10 withKeyLabel:TEST_KEY_LABEL10];
        
        self.currentKeyLabels = [NSMutableDictionary new];
        
        self.keyExpectations = [NSMutableDictionary new];
    }
    return self;
}


- (BOOL)havePublicKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return NO;
    
    return self.allKeys[keyLabel] != nil;
}

- (BOOL)havePrivateKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return NO;
    
    return [self.allKeys[keyLabel] isKindOfClass:[PrivateKeyData class]];
}

- (MynigmaPublicKey*)publicKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    
    return nil;
//    PublicKeyData* 
//    return [(PublicKeyData*)self.allKeys[keyLabel] forEncryption?publicKeyEncData:public;
}

- (MynigmaPrivateKey*)privateKeyWithLabel:(NSString*)keyLabel
{
    return nil;
}


- (PublicKeyData*)dataForPublicKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel)
        return nil;
    
    return self.allKeys[keyLabel];
}



- (PrivateKeyData*)dataForPrivateKeyWithLabel:(NSString*)keyLabel
{
    if(!keyLabel || ![self havePrivateKeyWithLabel:keyLabel])
        return nil;

    return self.allKeys[keyLabel];
}


#pragma mark - Adding keys

- (BOOL)addPublicKeyWithData:(PublicKeyData*)publicKeyData
{
    if(!publicKeyData.keyLabel)
        return NO;
    
    PublicKeyData* existingKeyData = self.allKeys[publicKeyData.keyLabel];
    
    if([existingKeyData isKindOfClass:[PrivateKeyData class]])
        existingKeyData = [(PrivateKeyData*)existingKeyData publicKeyData];
    
    if(existingKeyData && ![existingKeyData isEqual:publicKeyData])
        return NO;
    
    self.allKeys[publicKeyData.keyLabel] = publicKeyData;
    
    return YES;
}

- (BOOL)addPrivateKeyWithData:(PrivateKeyData*)privateKeyData
{
    if(!privateKeyData.keyLabel)
        return NO;
    
    PrivateKeyData* existingKeyData = self.allKeys[privateKeyData.keyLabel];
    
    if(existingKeyData && ![existingKeyData isEqual:privateKeyData])
        return NO;

    self.allKeys[privateKeyData.keyLabel] = privateKeyData;
    
    return YES;
}

- (BOOL)generatePrivateKeyWithLabel:(NSString*)keyLabel
{
    PrivateKeyData* privateKeyData = [TestHelper privateKeyData:@1 withKeyLabel:keyLabel];
    
    return [self addPrivateKeyWithData:privateKeyData];
}


#pragma mark - Current keys

- (BOOL)setCurrentKeyForEmailAddress:(NSString*)emailAddress keyLabel:(NSString*)keyLabel overwrite:(BOOL)overwritePrevious
{
    if(!emailAddress.canonicalForm)
        return NO;
    
    if(!overwritePrevious && self.currentKeyLabels[emailAddress.canonicalForm])
        return NO;
    
    self.currentKeyLabels[emailAddress.canonicalForm] = keyLabel;
    
    return YES;
}

- (BOOL)haveCurrentKeyForEmailAddress:(NSString*)emailAddress
{
    if(!emailAddress.canonicalForm)
        return NO;
    
    return self.currentKeyLabels[emailAddress.canonicalForm] != nil;
}

- (BOOL)haveCurrentPrivateKeyForEmailAddress:(NSString*)emailAddress
{
    if(!emailAddress.canonicalForm)
        return NO;
    
    NSString* keyLabel = self.currentKeyLabels[emailAddress.canonicalForm];
    
    return [self havePrivateKeyWithLabel:keyLabel];
}

- (NSString*)currentKeyLabelForEmailAddress:(NSString*)emailAddress
{
    if(!emailAddress.canonicalForm)
        return nil;
    
    return self.currentKeyLabels[emailAddress.canonicalForm];
}


#pragma mark - Key expectations

- (BOOL)setExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail keyLabel:(NSString*)keyLabel date:(NSDate*)date overwrite:(BOOL)overwritePrevious
{
    if(!senderEmail.canonicalForm || !recipientEmail.canonicalForm || !keyLabel)
        return NO;
    
    NSMutableDictionary* toToExpectationDict = [self.keyExpectations[senderEmail.canonicalForm] mutableCopy];
    
    if(!toToExpectationDict)
        toToExpectationDict = [NSMutableDictionary new];
    
    NSArray* expectation = toToExpectationDict[recipientEmail.canonicalForm];
    
    if(!overwritePrevious && expectation)
        return NO;
    
    if(!date)
        date = [NSDate date];
   
    toToExpectationDict[recipientEmail.canonicalForm] = @[keyLabel, date];
    
    self.keyExpectations[senderEmail.canonicalForm] = toToExpectationDict;
    
    return YES;
}

- (NSString*)getExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail
{
    if(!senderEmail.canonicalForm || !recipientEmail.canonicalForm)
        return nil;
    
    NSMutableDictionary* toToExpectationDict = self.keyExpectations[senderEmail.canonicalForm];
   
    return [toToExpectationDict[recipientEmail.canonicalForm] firstObject];
}

- (BOOL)haveExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail
{
    if(!senderEmail.canonicalForm || !recipientEmail.canonicalForm)
        return NO;
    
    NSMutableDictionary* toToExpectationDict = self.keyExpectations[senderEmail.canonicalForm];
    
    return toToExpectationDict[recipientEmail.canonicalForm] != nil;
}

- (BOOL)updateExpectedKeyLabelFrom:(NSString*)senderEmail to:(NSString*)recipientEmail keyLabel:(NSString*)keyLabel date:(NSDate*)date
{
    if(!senderEmail.canonicalForm || !recipientEmail.canonicalForm || !keyLabel)
        return NO;
    
    NSMutableDictionary* toToExpectationDict = [self.keyExpectations[senderEmail.canonicalForm] mutableCopy];
    
    if(!toToExpectationDict)
        toToExpectationDict = [NSMutableDictionary new];
    
    NSArray* expectation = toToExpectationDict[recipientEmail.canonicalForm];
    
    if(!date)
        date = [NSDate date];
    
    if(expectation && [date compare:expectation.lastObject] == NSOrderedAscending)
        return NO;
    
    toToExpectationDict[recipientEmail.canonicalForm] = @[keyLabel, date];
    
    self.keyExpectations[senderEmail.canonicalForm] = toToExpectationDict;
    
    return YES;
}

@end
