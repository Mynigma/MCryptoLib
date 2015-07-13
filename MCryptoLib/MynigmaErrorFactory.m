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


#import "MynigmaErrorFactory.h"
#import "MynigmaError.h"



@interface MynigmaErrorFactory()

@property NSMutableDictionary* _errorDescriptions;

@property NSMutableDictionary* currentError;
@property NSString* currentKey;
@property NSMutableString* currentValue;


@end

@implementation MynigmaErrorFactory

+ (instancetype)sharedInstance
{
    static dispatch_once_t p = 0;
    
    __strong static id sharedObject = nil;
    
    dispatch_once(&p, ^{
        sharedObject = [MynigmaErrorFactory new];
    });
    
    return sharedObject;
}

- (void)loadXMLFile
{
    NSURL* fileURL = [BUNDLE URLForResource:@"MynigmaErrors" withExtension:@"xml"];
    
    NSXMLParser* parser = [[NSXMLParser alloc] initWithContentsOfURL:fileURL];
    
    [parser setDelegate:self];
    
    if(![parser parse])
        NSLog(@"Failed to parse MynigmaErrors.xml!! %@", parser.parserError);
}

- (NSMutableDictionary*)errorDescriptions
{
    if(!self._errorDescriptions)
    {
        [self loadXMLFile];
    }
    
    return self._errorDescriptions;
}

- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName attributes:(NSDictionary *)attributeDict
{
    if([elementName isEqualToString:@"mynigmaerrors"])
    {
        self._errorDescriptions = [NSMutableDictionary new];
    }
    else if([elementName isEqualToString:@"error"])
    {
        self.currentError = [NSMutableDictionary new];
        self.currentError[@"code"] = attributeDict[@"id"];
    }
    else
    {
        self.currentValue = [NSMutableString new];
    }
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string
{
    [self.currentValue appendString:[string stringByReplacingOccurrencesOfString:@"\n" withString:@""]];
}

- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName
{
    if([elementName isEqualToString:@"mynigmaerrors"])
    {

    }
    else if([elementName isEqualToString:@"error"])
    {
        self._errorDescriptions[@([self.currentError[@"code"] integerValue])] = self.currentError;
    }
    else
    {
        NSString* strippedCurrentValue = [self.currentValue stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        self.currentError[elementName] = strippedCurrentValue;
    }
}

- (NSDictionary*)descriptionForErrorWithCode:(NSInteger)code
{
    return [self errorDescriptions][@(code)];
}

- (MynigmaError*)errorWithCode:(NSInteger)code
{
    return [self errorWithCode:code OSStatus:nil];
}

- (MynigmaError*)errorWithCode:(NSInteger)code OSStatus:(NSNumber*)status
{
    NSDictionary* descriptionDict = [self descriptionForErrorWithCode:code];
    
    //TODO: add recovery options
    
    //TODO: add status
    
    return [MynigmaError errorWithDomain:@"Mynigma encryption error domain" code:code userInfo:@{ NSLocalizedDescriptionKey : NSLocalizedString(descriptionDict[@"description"], @"Error description"), NSLocalizedFailureReasonErrorKey : NSLocalizedString(descriptionDict[@"reason"], nil), NSLocalizedRecoverySuggestionErrorKey : NSLocalizedString(descriptionDict[@"suggestion"], nil)}];
    
}


- (NSDictionary*)headerValuesForErrorCodes:(NSArray*)errorCodes
{
    NSMutableString* errorString = [NSMutableString new];
    NSMutableString* warningString = [NSMutableString new];
    
    for(NSNumber* code in errorCodes)
    {
        MynigmaError* errorOrWarning = [self errorWithCode:code.integerValue];
        
        if([errorOrWarning isError])
        {
            [errorString appendFormat:@"%ld,", (long)code.integerValue];
        }
        else
        {
            [warningString appendFormat:@"%ld,", (long)code.integerValue];
        }
    }
    
    NSMutableDictionary* returnValue = [NSMutableDictionary new];
    
    if(errorString.length)
    {
        [errorString deleteCharactersInRange:NSMakeRange(errorString.length - 1, 1)];
        
        returnValue[@"X-Mynigma-Errors"] = errorString;
    }
    
    if(warningString.length)
    {
        [warningString deleteCharactersInRange:NSMakeRange(warningString.length - 1, 1)];
        
        returnValue[@"X-Mynigma-Warnings"] = warningString;
    }

    return returnValue;
}

- (NSArray*)errorsAndWarningsForHeaderValues:(NSDictionary*)headerValues
{
    NSString* errorString = headerValues[@"x-mynigma-errors"];
    NSString* warningString = headerValues[@"x-mynigma-warnings"];
    
    NSArray* errorCodeStrings = [errorString componentsSeparatedByString:@","];
    NSArray* warningCodeStrings = [warningString componentsSeparatedByString:@","];
    
    NSMutableArray* errors = [NSMutableArray new];
    NSMutableArray* warnings = [NSMutableArray new];
    
    for(NSString* errorCodeString in errorCodeStrings)
    {
        NSInteger errorCode = errorCodeString.integerValue;
        
        if(errorCode)
            [errors addObject:[self errorWithCode:errorCode]];
    }
    
    for(NSString* warningCodeString in warningCodeStrings)
    {
        NSInteger warningCode = warningCodeString.integerValue;
        
        if(warningCode)
            [warnings addObject:[self errorWithCode:warningCode]];
    }

    [errors addObjectsFromArray:warnings];
    
    return errors;
}

@end
