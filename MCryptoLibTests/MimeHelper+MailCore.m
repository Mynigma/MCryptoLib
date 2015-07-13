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

#import "MimeHelper+MailCore.h"





@implementation MimeHelper (MailCore)


+ (NSMutableArray*)listAllSubpartsOfPart:(MCOAbstractPart*)part satisfyingCondition:(BOOL(^)(MCOAbstractPart* part))condition
{
    NSMutableArray* collectedParts = [NSMutableArray new];
    
    //iterate through multiparts
    
    if([part respondsToSelector:@selector(parts)])
    {
        for(MCOAbstractPart* subPart in [(MCOAbstractMultipart*)part parts])
        {
            [collectedParts addObjectsFromArray:[self listAllSubpartsOfPart:subPart satisfyingCondition:condition]];
        }
    }
    else if([part isKindOfClass:[MCOAbstractPart class]] && condition(part))
    {
        [collectedParts addObject:part];
    }
    
    return collectedParts;
}


@end

@implementation MCOAbstractPart (Convenience)

- (NSString*)contentIDGeneratingIfNeeded:(BOOL)generateIfNeeded
{
    NSString* contentID = self.contentID;
    
    if(contentID.length || !generateIfNeeded)
        return contentID;
    
    //OK, generate one
    contentID = [MimeHelper generateFreshMessageID];
    
    [self setContentID:contentID];
    
    return contentID;
}

- (BOOL)isPlainTextPart
{
    BOOL isPlainText = [self.mimeType.lowercaseString isEqual:@"text/plain"];
    
    BOOL hasFileName = [self filename].length != 0;
    
    return isPlainText && !hasFileName;
}

- (BOOL)isHTMLTextPart
{
    BOOL isHTMLText = [self.mimeType.lowercaseString isEqual:@"text/html"];
    
    BOOL hasFileName = [self filename].length != 0;
    
    return isHTMLText && !hasFileName;
}


@end