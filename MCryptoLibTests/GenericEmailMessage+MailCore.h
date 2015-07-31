//
//  GenericEmailMessage+MailCore.h
//  MCryptoLib
//
//  Created by Roman Priebe on 30/07/2015.
//  Copyright (c) 2015 Mynigma UG (haftungsbeschränkt). All rights reserved.
//

#import <MCryptoLib/MCryptoLib.h>


@class MCOAbstractMessage;

@interface GenericEmailMessage (MailCore)

- (MCOAbstractMessage*)MCOMessage;

@end
