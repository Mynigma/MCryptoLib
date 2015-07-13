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





#import "MynigmaError.h"
#import "MynigmaErrorFactory.h"




#define MynigmaErrorDomain @"MynigmaFeedbackDomain"



@implementation MynigmaError

- (BOOL)isSuccess
{
    //success codes are in the range [3000, 4000)
    return self.code >= 3000 && self.code < 4000;
}

- (BOOL)isWarning
{
    //warning codes are in the range [1000, 2000)
    return self.code >= 1000 && self.code < 2000;
}

- (BOOL)isError
{
    //codes for "proper" errors are in the range (0, 1000)
    return self.code >= 0 && self.code < 1000;
}

- (BOOL)isDownloadOrDecryptionStatus
{
    //codes for "Downloading...", downloaded and decrypted etc. are in this range
    return self.code >= 2000 && self.code < 3000;
}


- (BOOL)showMessage
{
    if([self isError])
        return NO;

    if([self isWarning])
        return YES;

    if([self isSuccess])
        return YES;

    if(self.code == MynigmaStatusDownloadedAndDecrypted)
        return YES;

    return NO;
}

- (BOOL)showFeedbackWindow
{
    if([self isError])
        return YES;
    
    if([self isDownloadOrDecryptionStatus] && ![self showMessage])
        return YES;
    
    return NO;
}

- (BOOL)showAlert
{
    if([self isWarning])
        return YES;
    
    return NO;
}

- (BOOL)showProgressIndicator
{
    if (self.code == MynigmaStatusDownloading)
        return YES;
    
    if (self.code == MynigmaStatusDecrypting)
        return YES;

//    if (self.code == MynigmaStatusNotDownloaded)
//        return YES;
    
    return NO;
}


- (BOOL)canTryAgain
{
    return YES;
}

- (BOOL)canOverride
{
    return [@[@(MynigmaVerificationErrorPreviouslyValidKey), @(MynigmaVerificationErrorNoKey), @(MynigmaDecryptionErrorOldEncryptionFormat), @(MynigmaVerificationErrorInvalidSignature)] containsObject:@(self.code)];
}



- (NSInteger)code
{
    return [super code];
}


#pragma mark - Generic MynigmaFeedback generation

//+ (MynigmaError*)feedbackWithArchivedString:(NSString*)stringValue message:(EmailMessage*)message
//{
//    if([stringValue isEqual:@""] || [stringValue isEqual:@"OK"])
//        return [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaStatusDownloadedAndDecrypted message:message];
//
//    if(![stringValue hasPrefix:@"MF"] || stringValue.length < 3)
//        return [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaErrorUnspecified message:message];
//    
//    NSString* truncatedString = [stringValue substringFromIndex:2];
//
//    NSArray* components = [truncatedString componentsSeparatedByString:@"+"];
//    
//    NSInteger firstComponent = [components.firstObject integerValue];
//    
//    if(firstComponent == MynigmaDecryptionErrorOldEncryptionFormat && components.count > 1)
//    {
//        NSInteger secondComponent = [components[1] integerValue];
//        
//        MynigmaEncryptionEngineError* feedback = [[MynigmaErrorFactory sharedInstance] errorWithCode:firstComponent message:message];
//        
//        [feedback setAdditionalCode:@(secondComponent)];
//        
//        return feedback;
//    }
//
//    return [[MynigmaErrorFactory sharedInstance] errorWithCode:truncatedString.integerValue message:message];
//}

//+ (MynigmaEncryptionEngineError*)feedback:(MynigmaErrorCode)feedbackCode
//{
//    NSMutableDictionary *userInfo = [[MynigmaEncryptionEngineError userInfoForCode:feedbackCode] mutableCopy];
//
//    MynigmaEncryptionEngineError* newError = [MynigmaEncryptionEngineError errorWithDomain:MynigmaErrorDomain code:feedbackCode userInfo:userInfo];
//
//    return newError;
//}
//
//+ (MynigmaEncryptionEngineError*)feedback:(MynigmaErrorCode)feedbackCode withOSStatus:(OSStatus)status
//{
//    NSMutableDictionary *userInfo = [[MynigmaEncryptionEngineError userInfoForCode:feedbackCode andOSStatus:status] mutableCopy];
//
//    //set the message so that error recovery can be performed whenever applicable
//    MynigmaEncryptionEngineError* newError = [MynigmaEncryptionEngineError errorWithDomain:MynigmaErrorDomain code:feedbackCode userInfo:userInfo];
//
//    return newError;
//}
//
//+ (MynigmaEncryptionEngineError*)feedback:(MynigmaErrorCode)feedbackCode message:(EmailMessage*)message
//{
//    NSMutableDictionary *userInfo = [[MynigmaEncryptionEngineError userInfoForCode:feedbackCode] mutableCopy];
//
//    //set the message so that error recovery can be performed whenever applicable
//    MynigmaEncryptionEngineError* newError = [MynigmaEncryptionEngineError errorWithDomain:MynigmaErrorDomain code:feedbackCode userInfo:userInfo];
//    
//    newError.message = message;
//    
//    return newError;
//}





//+ (NSDictionary*)userInfoForCode:(MynigmaErrorCode)feedbackCode
//{
//    return [self userInfoForCode:feedbackCode andOSStatus:0];
//}
//
//
//
//+ (NSDictionary*)userInfoForCode:(MynigmaErrorCode)feedbackCode andOSStatus:(OSStatus)status
//{
//    NSString* localisedDescription = nil;
//
//    NSString* localisedFailureReason = nil;
//
//    NSString* localisedRecoverySuggestion = nil;
//
//    NSArray* localisedRecoveryOptions = nil;
//
//    switch(feedbackCode)
//    {
//        case MynigmaErrorUnspecified:
//            localisedDescription = NSLocalizedString(@"Failed to decrypt message", nil);
//            localisedFailureReason = NSLocalizedString(@"An error occurred.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Would you like to try again?", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//
//
//        case MynigmaDecryptionErrorMessageCorrupt:
//            localisedDescription = NSLocalizedString(@"Failed to decrypt message (message corrupt)", nil);
//            localisedFailureReason = NSLocalizedString(@"The message data is corrupt.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Would you like to try again?", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//
//        case MynigmaDecryptionErrorNoData:
//            localisedDescription = NSLocalizedString(@"Failed to decrypt message (no data)", nil);
//            localisedFailureReason = NSLocalizedString(@"There is no data to decrypt.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Would you like to try again?", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//
//        case MynigmaDecryptionErrorNoKey:
//            localisedDescription = NSLocalizedString(@"Failed to decrypt message (missing key)", nil);
//            localisedFailureReason = NSLocalizedString(@"The decryption key is missing.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Would you like to try again?", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//
//        case MynigmaDecryptionErrorNoKeyLabel:
//            localisedDescription = NSLocalizedString(@"Failed to decrypt message (no key label)", nil);
//            localisedFailureReason = NSLocalizedString(@"The decryption key label is missing.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Would you like to try again?", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//
//        case MynigmaDecryptionErrorNoSessionKey:
//            localisedDescription = NSLocalizedString(@"Failed to decrypt message (no session key)", nil);
//            localisedFailureReason = NSLocalizedString(@"The session key is missing.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Would you like to try again?", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//
//
//        case MynigmaVerificationErrorNoKey:
//            localisedDescription = NSLocalizedString(@"Invalid signature (no key)", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Please exercise care if you choose to ignore this warning!", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
//            break;
//
//        case MynigmaVerificationErrorNoKeyLabel:
//            localisedDescription = NSLocalizedString(@"Invalid signature (no key label)", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"This message may not genuine. Please exercise care if you choose to ignore this warning!", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
//            break;
//
//
//        case MynigmaVerificationErrorRSAInvalidSignature:
//            localisedDescription = NSLocalizedString(@"Invalid signature (RSA)", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"This message may not genuine. Please exercise care if you choose to ignore this warning!", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
//            break;
//            
//        case MynigmaVerificationErrorNotCurrentKeyLabel:
//            localisedDescription = NSLocalizedString(@"Invalid signature (not current key label)", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"This message may not genuine. Please exercise care if you choose to ignore this warning!", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
//            break;
//
//        case MynigmaVerificationErrorInvalidSignature:
//            localisedDescription = NSLocalizedString(@"Invalid signature", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"This message may not genuine. Please exercise care if you choose to ignore this warning!", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
//            break;
//            
//        case MynigmaDecryptionErrorOldEncryptionFormat:
//            localisedDescription = NSLocalizedString(@"Deprecated encryption format", nil);
//            localisedFailureReason = NSLocalizedString(@"This message was sent using an old version of M.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"This message was sent using an old, less secure version of M. You may choose to ignore this warning!", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
//            break;
//            
//        case MynigmaOverriddenErrorWarningOldEncryptionFormat:
//            localisedDescription = NSLocalizedString(@"Deprecated encryption format", nil);
//            localisedFailureReason = NSLocalizedString(@"This message was sent using an old, less secure version of M.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"This message was sent using an old, less secure version of M. You chose to view it anyway.", nil);
//            localisedRecoveryOptions =
//            @[];
//            break;
//
//
////        case ERROR_SIGN_OUTDATED_SIGNATURE:
////            localisedDescription = NSLocalizedString(@"Incorrect signature (outdated)", nil);
////            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
////            localisedRecoverySuggestion = NSLocalizedString(@"Please exercise care if you choose to ignore this warning!", nil);
////            localisedRecoveryOptions =
////            @[NSLocalizedString(@"Verify again", nil), NSLocalizedString(@"Show anyway", nil)];
////            break;
////
////        case WARNING_SIGN_NO_USER_RECIPIENT:
////            localisedDescription = NSLocalizedString(@"Invalid signature (no valid recipient)", nil);
////            localisedFailureReason = NSLocalizedString(@"This may indicate a fraud.", nil);
////            localisedRecoverySuggestion = NSLocalizedString(@"Please exercise care if you choose to ignore this warning!", nil);
////            localisedRecoveryOptions =
////            @[NSLocalizedString(@"OK", nil)];
////            isError = NO;
////            break;
////
////        case WARNING_SIGN_SOME_INVALID_KEYS:
////            localisedDescription = NSLocalizedString(@"Invalid signature (some invalid keys)", nil);
////            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
////            localisedRecoverySuggestion = NSLocalizedString(@"Please exercise care if you choose to ignore this warning!", nil);
////            localisedRecoveryOptions =
////            @[NSLocalizedString(@"OK", nil)];
////            isError = NO;
////            break;
////
////        case WARNING_OVERRIDDEN_ERROR_SIGN_NO_KEY_LABEL:
////            localisedDescription = NSLocalizedString(@"Invalid signature (no key label)", nil);
////            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
////            localisedRecoverySuggestion = NSLocalizedString(@"You may want to delete it, unless you can be sure that it is genuine.", nil);
////            localisedRecoveryOptions = @[NSLocalizedString(@"OK", nil)];
////            isError = NO;
////            break;
////
////        case WARNING_OVERRIDDEN_ERROR_SIGN_NO_KEY:
////            localisedDescription = NSLocalizedString(@"Invalid signature (no key)", nil);
////            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
////            localisedRecoverySuggestion = NSLocalizedString(@"You may want to delete it, unless you can be sure that it is genuine.", nil);
////            localisedRecoveryOptions = @[NSLocalizedString(@"OK", nil)];
////            isError = NO;
////            break;
////
////        case WARNING_OVERRIDDEN_ERROR_SIGN_INVALID_SIGNATURE:
////            localisedDescription = NSLocalizedString(@"Invalid signature", nil);
////            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
////            localisedRecoverySuggestion = NSLocalizedString(@"You may want to delete it, unless you can be sure that it is genuine.", nil);
////            localisedRecoveryOptions =
////            @[NSLocalizedString(@"OK", nil)];
////            isError = NO;
////            break;
//
//        case MynigmaEncryptionSuccess:
//        case MynigmaDecryptionSuccess:
//        case MynigmaVerificationSuccess:
//        case MynigmaSignatureSuccess:
//            localisedDescription = NSLocalizedString(@"Success!", nil);
//            localisedFailureReason = NSLocalizedString(@"No errors occurred. This should never be displayed.", nil);
//            localisedRecoveryOptions =
//            @[];
//            break;
//
//        case MynigmaStatusDecrypting:
//            localisedDescription = NSLocalizedString(@"Decrypting...", nil);
//            localisedFailureReason = NSLocalizedString(@"Decryption in progress...", nil);
//            localisedRecoveryOptions =
//            @[];
//            break;
//
//        case MynigmaStatusDownloadedAndDecrypted:
//            break;
//
//        case MynigmaStatusDownloading:
//            localisedDescription = NSLocalizedString(@"Downloading...", nil);
//            localisedFailureReason = NSLocalizedString(@"Downloading message...", nil);
//            localisedRecoveryOptions =
//            @[];
//            break;
//
//        case MynigmaStatusNotDownloaded:
//            localisedDescription = NSLocalizedString(@"Download failed.", nil);
//            localisedFailureReason = NSLocalizedString(@"This message has not been downloaded", nil);
//            localisedRecoveryOptions =
//            @[NSLocalizedString(@"Try again", nil)];
//            break;
//            
//        case MynigmaOverriddenErrorWarningNoKey:
//            localisedDescription = NSLocalizedString(@"Invalid signature (no key)", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Please exercise care if you choose to ignore this warning!", nil);
//            break;
//            
//        case MynigmaOverriddenErrorWarningPreviouslyValidKey:
//            localisedDescription = NSLocalizedString(@"Invalid signature (invalid key)", nil);
//            localisedFailureReason = NSLocalizedString(@"This message may be a fraud.", nil);
//            localisedRecoverySuggestion = NSLocalizedString(@"Please exercise care if you choose to ignore this warning!", nil);
//            break;
//            
//        default:
//        {
//            localisedDescription = [NSString stringWithFormat:NSLocalizedString(@"Unexpected error with code %ld", nil), (long)feedbackCode];
//            localisedRecoveryOptions = @[NSLocalizedString(@"Try again", nil)];
//        }
//    }
//
//    
//    
//    NSMutableDictionary *userInfo = [NSMutableDictionary new];
//
//    if(localisedDescription)
//        userInfo[NSLocalizedDescriptionKey] = localisedDescription;
//
//    if(localisedFailureReason)
//        userInfo[NSLocalizedFailureReasonErrorKey] = localisedFailureReason;
//
//    if(localisedRecoverySuggestion)
//        userInfo[NSLocalizedRecoverySuggestionErrorKey] = localisedRecoverySuggestion;
//
//    if(localisedRecoveryOptions)
//        userInfo[NSLocalizedRecoveryOptionsErrorKey] = localisedRecoveryOptions;
//
//    return userInfo;
//}

- (MynigmaError*)overrideIfPossible
{
    switch (self.code)
    {
        case MynigmaVerificationErrorPreviouslyValidKey:
            return [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaOverriddenErrorWarningPreviouslyValidKey];
            
        case MynigmaVerificationErrorNoKey:
            return [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaOverriddenErrorWarningNoKey];
            
        case MynigmaDecryptionErrorOldEncryptionFormat:
            return [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaOverriddenErrorWarningOldEncryptionFormat];
            
        case MynigmaVerificationErrorInvalidSignature:
            return [[MynigmaErrorFactory sharedInstance] errorWithCode:MynigmaOverriddenErrorWarningInvalidSignature];
            
        default:
            return self;
    }
}


@end
