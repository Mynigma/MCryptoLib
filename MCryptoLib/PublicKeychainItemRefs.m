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

#import "PublicKeychainItemRefs.h"
#import "KeychainHelper.h"



@interface PublicKeychainItemRefs()

@property SecKeyRef encKeyRef;
@property SecKeyRef verKeyRef;

@property NSData* persistentEncKeyRef;
@property NSData* persistentVerKeyRef;

@end


@implementation PublicKeychainItemRefs

- (instancetype)initWithEncKeyRef:(SecKeyRef)encKeyRef verKeyRef:(SecKeyRef)verKeyRef
{
    self = [super init];
    if (self) {
        
        self.encKeyRef = encKeyRef;
        self.verKeyRef = verKeyRef;
    }
    return self;
}


- (instancetype)initWithPersistentEncKeyRef:(NSData*)persistentEncKeyRef persistentVerKeyRef:(NSData*)persistentVerKeyRef
{
    self = [super init];
    if (self) {
        
        self.persistentEncKeyRef = persistentEncKeyRef;
        self.persistentVerKeyRef = persistentVerKeyRef;
    }
    return self;
}





- (SecKeyRef)publicSecKeyRefForEncryption:(BOOL)forEncryption
{
    if(forEncryption)
    {
        if(self.encKeyRef)
            return self.encKeyRef;
        
        if(self.persistentEncKeyRef)
        {
            self.encKeyRef = [KeychainHelper secKeyRefFromPersistentKeyRef:self.persistentEncKeyRef];
            
            return self.encKeyRef;
        }
    }
    else
    {
        if(self.verKeyRef)
            return self.verKeyRef;
        
        if(self.persistentVerKeyRef)
        {
            self.verKeyRef = [KeychainHelper secKeyRefFromPersistentKeyRef:self.persistentVerKeyRef];
            
            return self.verKeyRef;
        }
    }
    
    return nil;
}

- (NSData*)persistentPublicKeyRefForEncryption:(BOOL)forEncryption
{
    if(forEncryption)
    {
        if(self.persistentEncKeyRef)
            return self.persistentEncKeyRef;
        
        if(self.encKeyRef)
        {
            self.persistentEncKeyRef = [KeychainHelper persistentKeyRefFromSecKeyRef:self.encKeyRef];
            
            return self.persistentEncKeyRef;
        }
    }
    else
    {
        if(self.persistentVerKeyRef)
            return self.persistentVerKeyRef;
        
        if(self.verKeyRef)
        {
            self.persistentVerKeyRef = [KeychainHelper persistentKeyRefFromSecKeyRef:self.verKeyRef];
            
            return self.persistentVerKeyRef;
        }
    }
    
    return nil;
}


@end
