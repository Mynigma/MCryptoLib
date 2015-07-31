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

- (instancetype)initWithName:(NSString*)name emailAddress:(NSString*)emailAddress addresseeType:(NSNumber*)addresseeType
{
    self = [super init];
    if (self) {
        
        self.name = name?name:@"";
        self.address = emailAddress;
        self.addresseeType = addresseeType;
    }
    return self;
}



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

- (BOOL)isEqual:(GenericEmailAddressee*)object
{
    if(object == self)
        return YES;
    
    if(![object isKindOfClass:[GenericEmailAddressee class]])
        return NO;
    
    if((self.name && !object.name) || (!self.name && object.name))
        return NO;
    if(self.name && ![self.name isEqual:object.name])
        return NO;
    
    if((self.address && !object.address) || (!self.address && object.address))
        return NO;
    if(self.address && ![self.address isEqual:object.address])
        return NO;
    
    if((self.addresseeType && !object.addresseeType) || (!self.addresseeType && object.addresseeType))
        return NO;
    if(self.addresseeType && ![self.addresseeType isEqual:object.addresseeType])
        return NO;
    
    return YES;
}

- (NSUInteger)hash
{
    return self.name.hash ^ self.address.hash ^ self.addresseeType.hash;
}

@end
