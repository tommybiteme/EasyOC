//
//  EOCEncrypt.h
//  EasyOC
//
//  Created by 王楚杰 on 16/8/29.
//  Copyright © 2016年 Tommybiteme. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonCryptor.h>//常用加解密算法
#include <CommonCrypto/CommonDigest.h>//摘要算法
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonSymmetricKeywrap.h>

@interface EOCEncrypt : NSObject

@end
