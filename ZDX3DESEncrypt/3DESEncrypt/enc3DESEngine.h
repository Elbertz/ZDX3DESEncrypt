//
//  enc3DESEngine.h
//  Launcher
//
//  Created by shangbao on 16/10/11.
//
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>


@interface enc3DESEngine : NSObject{
    NSData *keyData;
}

+(id)sharedInstance;
- (NSString *)encryptByZDX3DESWithStr:(NSString *)originalStr andKey:(NSString *)key;

- (NSString *)decEncryptBy3DESWithStr:(NSString *)originalStr;

@end
