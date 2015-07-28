//
//  GenericEmailAddressee.h
//  MCryptoLib
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import <Foundation/Foundation.h>

#import <MProtoBuf/EmailRecipientDataStructure.h>



@interface GenericEmailAddressee : NSObject <NSCoding>

@property NSString* name;
@property NSString* address;

@property NSNumber* addresseeType;

@end
