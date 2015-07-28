//
//  GenericEmailAddressee.m
//  MCryptoLib
//
//  Created by Roman Priebe on 28/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import "GenericEmailAddressee.h"

NSString* const nameKey             = @"MCryptoGenericAddresseeName";
NSString* const addressKey          = @"MCryptoGenericAddresseeAddress";
NSString* const addresseeTypeKey    = @"MCryptoGenericAddresseeAddresseeType";


@implementation GenericEmailAddressee



- (instancetype)initWithCoder:(NSCoder*)coder
{
    self = [super init];
    if (self){
        
        self.name = [coder decodeObjectForKey:nameKey];
        self.address = [coder decodeObjectForKey:addressKey];
        self.addresseeType = [coder decodeObjectForKey:addresseeTypeKey];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder*)coder
{
    [coder encodeObject:self.name forKey:nameKey];
    [coder encodeObject:self.address forKey:addressKey];
    [coder encodeObject:self.addresseeType forKey:addresseeTypeKey];
}



@end
