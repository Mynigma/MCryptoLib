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

#import "PrivateKeychainItemRefs.h"
#import "KeychainHelper.h"



@interface PublicKeychainItemRefs()

@property SecKeyRef encKeyRef;
@property SecKeyRef verKeyRef;

@property NSData* persistentEncKeyRef;
@property NSData* persistentVerKeyRef;

@end


@interface PrivateKeychainItemRefs()

@property SecKeyRef decKeyRef;
@property SecKeyRef sigKeyRef;

@property NSData* persistentDecKeyRef;
@property NSData* persistentSigKeyRef;

@end

@implementation PrivateKeychainItemRefs


- (instancetype)initWithEncKeyRef:(SecKeyRef)encKeyRef verKeyRef:(SecKeyRef)verKeyRef decKeyRef:(SecKeyRef)decKeyRef sigKeyRef:(SecKeyRef)sigKeyRef
{
    self = [super init];
    if (self) {
    
        self.encKeyRef = encKeyRef;
        self.verKeyRef = verKeyRef;
        
        self.decKeyRef = decKeyRef;
        self.sigKeyRef = sigKeyRef;
    }
    return self;
}

- (instancetype)initWithPersistentEncKeyRef:(NSData*)persistentEncKeyRef persistentVerKeyRef:(NSData*)persistentVerKeyRef persistentDecKeyRef:(NSData*)persistentDecKeyRef persistentSigKeyRef:(NSData*)persistentSigKeyRef
{
    self = [super init];
    if (self) {
        
        self.persistentEncKeyRef = persistentEncKeyRef;
        self.persistentVerKeyRef = persistentVerKeyRef;
        
        self.persistentDecKeyRef = persistentDecKeyRef;
        self.persistentSigKeyRef = persistentSigKeyRef;
    }
    return self;
}


- (SecKeyRef)privateSecKeyRefForEncryption:(BOOL)forEncryption
{
    if(forEncryption)
    {
        if(self.decKeyRef)
            return self.decKeyRef;
        
        if(self.persistentDecKeyRef)
        {
            self.decKeyRef = [KeychainHelper secKeyRefFromPersistentKeyRef:self.persistentDecKeyRef];
            
            return self.decKeyRef;
        }
    }
    else
    {
        if(self.sigKeyRef)
            return self.sigKeyRef;
        
        if(self.persistentSigKeyRef)
        {
            self.sigKeyRef = [KeychainHelper secKeyRefFromPersistentKeyRef:self.persistentSigKeyRef];
            
            return self.sigKeyRef;
        }
    }
    
    return nil;
}

- (NSData*)persistentPrivateKeyRefForEncryption:(BOOL)forEncryption
{
    if(forEncryption)
    {
        if(self.persistentDecKeyRef)
            return self.persistentDecKeyRef;
        
        if(self.decKeyRef)
        {
            self.persistentDecKeyRef = [KeychainHelper persistentKeyRefFromSecKeyRef:self.decKeyRef];
            
            return self.persistentDecKeyRef;
        }
    }
    else
    {
        if(self.persistentSigKeyRef)
            return self.persistentSigKeyRef;
        
        if(self.sigKeyRef)
        {
            self.persistentSigKeyRef = [KeychainHelper persistentKeyRefFromSecKeyRef:self.sigKeyRef];
            
            return self.persistentSigKeyRef;
        }
    }
    
    return nil;
}

@end
