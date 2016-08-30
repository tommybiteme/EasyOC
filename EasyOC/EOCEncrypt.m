//
//  EOCEncrypt.m
//  EasyOC      2016年08月30日22:10:53   创建——Tommybiteme
//
//  Created by 王楚杰 on 16/8/29.
//  Copyright © 2016年 Tommybiteme. All rights reserved.
//

#import "EOCEncrypt.h"

@implementation EOCEncrypt

#pragma mark AES
-(NSString *)aes256_encrypt:(NSString *)key andStr:(NSString *)str

{
    const char *cstr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:str.length];
    
    //对数据进行加密
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);//必须为kCCOptionPKCS7Padding 其他平台要使用必须使用kCCOptionPKCS7Padding
    if (cryptStatus == kCCSuccess)
    {
        NSData *result = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        //base64
        return [result base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }else
    {
        return nil;
    }
    
}

-(NSString *)aes192_encrypt:(NSString *)key andStr:(NSString *)str

{
    const char *cstr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:str.length];
    
    //对数据进行加密
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCKeySizeAES192,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);//必须为kCCOptionPKCS7Padding 其他平台要使用必须使用kCCOptionPKCS7Padding
    if (cryptStatus == kCCSuccess)
    {
        NSData *result = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        //base64
        return [result base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }else
    {
        return nil;
    }
    
}

-(NSString *)aess128_encrypt:(NSString *)key andStr:(NSString *)str
{
    const char *cstr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:str.length];
    
    //对数据进行加密
    char keyPtr[kCCKeySizeAES128 +1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCKeySizeAES128,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);//必须为kCCOptionPKCS7Padding 其他平台要使用必须使用kCCOptionPKCS7Padding
    if (cryptStatus == kCCSuccess)
    {
        NSData *result = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        //base64
        return [result base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }else
    {
        return nil;
    }
}


#pragma mark MD5

- (NSString *)md5_encrypt:(NSString *)str
{
    const char *cstr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(cstr, (unsigned int)strlen(cstr), result);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", result[i]];
    
    return output.lowercaseString;
    
}


#pragma mark Sha
- (NSString *)sha256HexDigest:(NSString *)str
{
    const char *cstr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:str.length];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA256(data.bytes, (unsigned int)data.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
}
@end
