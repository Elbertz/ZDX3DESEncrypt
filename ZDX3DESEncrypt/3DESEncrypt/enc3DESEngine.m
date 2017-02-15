//
//  enc3DESEngine.m
//  Launcher
//
//  Created by shangbao on 16/10/11.
//
//

#import "enc3DESEngine.h"
#import "GTMBase64.h"

#include <stdio.h>
#include <stdlib.h>
#include "openssl/x509.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>


#define ZDX_MD5_PREFIX @"99999999"
#define ZDX_SHA256_DIGEST @"5tS3kdeUhfTtV8CtI22fPQ=="

@implementation enc3DESEngine

- (NSString *)decEncryptBy3DESWithStr:(NSString *)originalStr{
    //把string 转NSData
//    NSData* data = [originalStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData* data = [GTMBase64 decodeData:[originalStr dataUsingEncoding:NSUTF8StringEncoding]];
    //length
    size_t plainTextBufferSize = [data length];
    
    const void *vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = ( const void *) keyData.bytes ;
    //偏移量
    //const void *vinitVec = (const void *) [gIv UTF8String];
    
    //配置CCCrypt
    ccStatus = CCCrypt(kCCDecrypt,
                       kCCAlgorithm3DES, //3DES
                       kCCOptionECBMode|kCCOptionPKCS7Padding, //设置模式
                       vkey,    //key
                       kCCKeySize3DES,
                       nil,     //偏移量，这里不用，设置为nil;不用的话，必须为nil,不可以为@“”
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const char *)bufferPtr length:(NSUInteger)movedBytes];
    
    
    NSString *result = [[NSString alloc] initWithData:myData encoding:NSUTF8StringEncoding];
    return result;
}

- (NSString *)encryptByZDX3DESWithStr:(NSString *)originalStr andKey:(NSString *)keyStr{
    
    //originalStr = @"20926330$5911EEF940F1FBED17F0D9F5237FA632$13454100609$012418006421650$259AF220-1975-4E9D-8605-EAF69521F21B$259AF220-1975-4E9D-8605-EAF69521F21B$$Reserved$CTC";
    keyStr = @"13454100609;751386";
    
    
    NSData *key = [self getSafeKeyWithContent:keyStr];
    keyData = key;
    //
    //--------------------------------
    
    //把string 转NSData
    NSData* data = [originalStr dataUsingEncoding:NSUTF8StringEncoding];
    
    //length
    size_t plainTextBufferSize = [data length];
    
    const void *vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = ( const void *) key.bytes ;
    //偏移量
    //const void *vinitVec = (const void *) [gIv UTF8String];
    
    //配置CCCrypt
    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithm3DES, //3DES
                       kCCOptionECBMode|kCCOptionPKCS7Padding, //设置模式
                       vkey,    //key
                       kCCKeySize3DES,
                       nil,     //偏移量，这里不用，设置为nil;不用的话，必须为nil,不可以为@“”
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const char *)bufferPtr length:(NSUInteger)movedBytes];
    
    //16进制
    NSUInteger          len = [myData length];
    char *              chars = (char *)[myData bytes];
    NSMutableString *   hexString = [[NSMutableString alloc] init];
    
    for(NSUInteger i = 0; i < len; i++ )
        [hexString appendString:[NSString stringWithFormat:@"%0.2hhX", chars[i]]];
    NSLog(@"hexString = %@",hexString);
    
    //base64
    NSString *result = [GTMBase64 stringByEncodingData:myData];
    
    
    return result;
}

- (NSData *)getSafeKeyWithContent:(NSString *)content{
    
    NSString *data = [self getKeyByZDX3DESWithContent:content];
    
    const char *cKey = [[GTMBase64 decodeString:ZDX_SHA256_DIGEST] bytes];
    const char *cData = [data cStringUsingEncoding:NSUTF8StringEncoding];
    
    
    NSMutableData * derivedKey = [NSMutableData dataWithLength:24];
    
    //  PKCS5_PBKDF2_HMAC_SHA1(cData, strlen(cData), cKey, strlen(cKey), 1000, 32, derivedKey.mutableBytes);
    PKCS5_PBKDF2_HMAC_SHA256_C(cData, strlen(cData), cKey, strlen(cKey), 1000, 32, derivedKey.mutableBytes);
    
    
    NSLog(@"PKCS5_PBKDF2_HMAC_SHA1 derivedKeyData======%s\n%s", derivedKey.mutableBytes,[derivedKey subdataWithRange:NSMakeRange(0, 24)].bytes);
    return [derivedKey subdataWithRange:NSMakeRange(0, 24)];
}


- (NSString *)getKeyByZDX3DESWithContent:(NSString *)content{
    
    NSArray *tempArr = [content componentsSeparatedByString:@";"];
    NSString *userId = [tempArr objectAtIndex:0];
    NSString *password = [tempArr objectAtIndex:1];
    NSLog(@"userId = %@----password = %@",userId,password);
    
    NSString *toZDXMD5Str = [self toZDXMD5WithPassword:password];
    NSLog(@"toZDXMD5Str = %@",toZDXMD5Str);
    
    NSMutableString *hexString = [[NSMutableString alloc] initWithString:toZDXMD5Str];
    NSString *source = [hexString substringWithRange:NSMakeRange(0, 8)];
    NSMutableString *Msource = [[NSMutableString alloc] initWithString:userId];
    [Msource appendString:source];
    [Msource appendString:ZDX_MD5_PREFIX];
    NSLog(@"hexString = %@ --source = %@ --- Msource = %@",hexString,source,Msource);
    
    return Msource;
}

- (NSString *)toZDXMD5WithPassword:(NSString *)password{
    
    if (password == nil || [password isEqualToString:@""]) {
        return nil;
    } else {
        
        NSMutableString *tempstr = [NSMutableString stringWithFormat:@"%@",password] ;
        [tempstr appendString:ZDX_MD5_PREFIX];
        NSLog(@"tempstrMD5 = %@",tempstr);
        
        const char* original_str=[tempstr UTF8String];
        
        unsigned char digist[CC_MD5_DIGEST_LENGTH]; //CC_MD5_DIGEST_LENGTH = 16
        
        CC_MD5(original_str, strlen(original_str), digist);
        
        NSMutableString* outPutStr = [NSMutableString stringWithCapacity:10];
        
        for(int i =0; i<CC_MD5_DIGEST_LENGTH;i++){
            
            [outPutStr appendFormat:@"%x", digist[i]];// 小写 x 表示输出的是小写 MD5 ，大写 X 表示输出的是大写 MD5
            
        }
        
        return [outPutStr lowercaseString];
        
        
    }
}

int PKCS5_PBKDF2_HMAC_SHA256_C(const char *pass, int passlen,
                               unsigned char *salt, int saltlen, int iter,
                               int keylen, unsigned char *out)
{
    unsigned char digtmp[SHA256_DIGEST_LENGTH], *p, itmp[4];
    unsigned long cplen, j, k, tkeylen;
    unsigned long i = 1;
    HMAC_CTX hctx;
    p = out;
    tkeylen = keylen;
    if(!pass)
        passlen = 0;
    //  else if(passlen == -1)
    //    passlen =strlen(pass)&0xffffffff;
    while(tkeylen) {
        if(tkeylen > SHA256_DIGEST_LENGTH) cplen = SHA256_DIGEST_LENGTH;
        else cplen = tkeylen;
        /* We are unlikely to ever use more than 256 blocks (5120 bits!)
         * but just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        HMAC_Init(&hctx, pass, passlen, EVP_sha256());
        HMAC_Update(&hctx, salt, saltlen);
        HMAC_Update(&hctx, itmp, 4);
        HMAC_Final(&hctx, digtmp, NULL);
        memcpy((void*)p, (const void*)digtmp, cplen);
        //CRYPTO_memcmp(p, digtmp, cplen);
        //  memcpy((void *)p, (const void *)digtmp, (unsigned long) cplen);
        for(j = 1; j < iter; j++) {
            HMAC(EVP_sha256(), pass, passlen,
                 digtmp, SHA256_DIGEST_LENGTH, digtmp, NULL);
            for(k = 0; k < cplen; k++) p[k] ^= digtmp[k];
        }
        tkeylen-= cplen;
        i++;
        p+= cplen;
    }
    HMAC_cleanup(&hctx);
#ifdef DEBUG_PKCS5V2
    fprintf(stderr, "Password:\n");
    h__dump (pass, passlen);
    fprintf(stderr, "Salt:\n");
    h__dump (salt, saltlen);
    fprintf(stderr, "Iteration count %d\n", iter);
    fprintf(stderr, "Key:\n");
    h__dump (out, keylen);
#endif
    return 1;
}

//IMPLEMENT_SINGLE_INSTANCE


static id DES_instance = nil;
+(id)sharedInstance{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        DES_instance = [[self alloc]init];
    });
    
    return DES_instance;
}

@end
