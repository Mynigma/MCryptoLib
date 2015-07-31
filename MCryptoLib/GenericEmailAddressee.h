//
//  GenericEmailAddressee.h
//  MCryptoLib
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import <Foundation/Foundation.h>




@interface GenericEmailAddressee : NSObject <NSCoding>


- (instancetype)initWithName:(NSString*)name emailAddress:(NSString*)emailAddress addresseeType:(NSNumber*)addresseeType;



@property NSString* name;
@property NSString* address;

@property NSNumber* addresseeType;

@end
