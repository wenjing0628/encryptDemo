//
//  ViewController.m
//  加密解密大全
//
//  Created by zwj on 2017/10/28.
//  Copyright © 2017年 zwj. All rights reserved.
//

#import "ViewController.h"
 #import<CommonCrypto/CommonDigest.h>//  md5加密头文件
#import <CommonCrypto/CommonCrypto.h>// AES加密头文件

static NSString *mPublicKey = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBDpWtlghwO5i3skfcbr8F66AKIkpP31Gw9xAg8HR4XzzgIJx+dsERWbGggY7SgSm0cMY2o+N3r1rC7SdgReTEpZJv+CfQpzqOkkL+eEpy28Dga0MMXwpU2V6ug8dnhxOlZ+a7wlZ0Fs3nsZtt45S51vLrD3qyuXSSePF9wUF/MwIDAQAB-----END PUBLIC KEY-----";

static NSString *mPrivateKey = @"-----BEGIN PRIVATE KEY-----MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMEOla2WCHA7mLeyR9xuvwXroAoiSk/fUbD3ECDwdHhfPOAgnH52wRFZsaCBjtKBKbRwxjaj43evWsLtJ2BF5MSlkm/4J9CnOo6SQv54SnLbwOBrQwxfClTZXq6Dx2eHE6Vn5rvCVnQWzeexm23jlLnW8usPerK5dJJ48X3BQX8zAgMBAAECgYAXfJO/E4KhTM7OglT1v09kA/9rXDKYNv30Popqx3YT8towFieTxxTD7JqMgVaDy4zsU8/5c8THmcC7+CgTMU2cXEBeUiJnax31mhoWrbCyx6uU/c1ioRbjUvZ4JmOSR59/+ZG3ijQKaWobU3VBWckrN5y1zxVnk3Uz1DZ2xVQOgQJBAP8+hp+kVzubepC5hUoSkM83KhlM6XrzweINYtPiUJnfQyz2bSxVWoD0TJKldqJBm7MfhJMrd5m8SiFgJ/U02nMCQQDBoOvNTO/BTnaLa5ZoAFIH94ieHERlmMKepBFBIUVyAwvK04CUzDKdgdyzQCymatBIwLMihxQNbNnPzdwlJ9hBAkA1YlNv0kR4cBVbbaHmEyn8XPJOJlry30aey+PuovfuptZ68fN1gUiTjgTx6u98EjLJbP8idMXn/oyWnHDfBTXnAkEAgEr+Uf37EYrKcuArPOeRcqPpSlGSY/qOYQx2PkAsQjmQc6gllvGhS8lCkSYhL3awYLQFPQhhGfAYdV6B0cCPwQJABt8UUm4xDzeaLoAR5B6X1UeXCs/1++w6kR/5Z+8Of8DYuDsZjZ5GtxCVNYz3OqPt1wvNZPnNhYrEX1HlzI/mXg==-----END PRIVATE KEY-----";

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *jiaMiText;
@property (weak, nonatomic) IBOutlet UILabel *jieMiLabel;
@property (weak, nonatomic) IBOutlet UILabel *jiamiHouText;

@end

@implementation ViewController{
    NSString *base64;
    
    NSData * aesData;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}
#pragma mark - base64加密解密
/*
- 数据加密之后，数据量会变大，变大1/3左右。
- 可进行反向解密。
- 编码后有个非常显著的特点，末尾有个=号。
 */
//使用Base64执行加密操作
- (IBAction)base64Encrypt:(id)sender {
    
    NSData *data = [self.jiaMiText.text dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodeBase64 = [self base64EncodedStringWithData:data];
    base64 = encodeBase64;
    self.jiamiHouText.text = encodeBase64;
}
 //使用Base64执行解密操作
- (IBAction)base64Decrypt:(id)sender {
   
    NSData *decodeData = [self base64DecodeDataWithString:base64];
    NSString * decodeString = [[NSString alloc] initWithData:decodeData
                                         encoding:NSUTF8StringEncoding];
    self.jieMiLabel.text = decodeString;
    
}

#pragma mark - MD5加密解密
/*
- 压缩性 : 任意长度的数据,算出的MD5值长度都是固定的。
- 容易计算 : 从原数据计算出MD5值很容易。
- 抗修改性 : 对原数据进行任何改动，哪怕只修改一个字节，所得到的MD5值都有很大区别。
- 弱抗碰撞 : 已知原数据和其MD5值，想找到一个具有相同MD5值的数据（即伪造数据）是非常困难的。
- 强抗碰撞 : 想找到两个不同数据，使他们具有相同的MD5值，是非常困难的。
*/
//使用MD5执行加密操作
- (IBAction)MD5Encrypt:(id)sender {
    
    NSString *encodeMD5= [self md5SignWithString:self.jiaMiText.text];
    base64 = encodeMD5;
    self.jiamiHouText.text = encodeMD5;
    
}
//MD5为不可逆的操作，使用MD5执行验签操作
- (IBAction)MD5Decrypt:(id)sender {
    
    NSString *verifyString2 = [self md5SignWithString:self.jiaMiText.text];
    if ([verifyString2 isEqualToString:base64]) {
        [self alertStr:@"MD5验证成功"];
    } else {
        [self alertStr:@"MD5验证失败"];
    }
    
}

- (void)alertStr:(NSString *)str{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:str message:@"" preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *quxiao = [UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
        
    }];
    [alert addAction:quxiao];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - AES加密解密
/*
 - AES强安全性、高性能、高效率、易用和灵活。
 - 在软件及硬件上都能快速地加解密且只需要很少的存储资源。
 */
 //使用AES执行加密操作
- (IBAction)AESEncrypt:(id)sender {
   
    NSString *aesKey = @"a1b2c3d4e5f6g7h8";
    NSData *keyData3 = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *sourceData3 = [self.jiaMiText.text dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encodeData3 = [self encryptData:sourceData3 key:keyData3];
    aesData = encodeData3;
}
//使用AES执行解密操作
- (IBAction)AESDecrypt:(id)sender {
    NSString *aesKey = @"a1b2c3d4e5f6g7h8";
    NSData *keyData3 = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *decodeData3 = [self decryptData:aesData
                                              key:keyData3];
    NSString * decodeString3 = [[NSString alloc] initWithData:decodeData3
                                          encoding:NSUTF8StringEncoding];
    self.jieMiLabel.text = decodeString3;
}
#pragma mark - RSA加密解密
/*
- RSA密钥管理的方便，计算量很大速度相对比较慢。
- RSA安全性很高，能够抵抗到目前为止已知的绝大多数密码攻击。
 */
//使用RSA执行加密操作
// http://web.chacuo.net/netrsakeypair 生成公私钥网址。
- (IBAction)RSAEncrypt:(id)sender {
    
    
    NSString *encodeString4 = [self encryptString:self.jiaMiText.text
                                              publicKey:mPublicKey];
    base64 = encodeString4;
    self.jiamiHouText.text = encodeString4;
    
}
//使用RSA执行解密操作
- (IBAction)RSADecrypt:(id)sender {
    
    NSString *decodeString4 = [self decryptString:base64
                                             privateKey:mPrivateKey];
    self.jieMiLabel.text = decodeString4;
}


#pragma mark - base64 加密解密 代码实现
/****************************Base64.m类实现文件内容****************************/
- (NSString *)base64EncodedStringWithData:(NSData *)data
{
    //判断是否传入需要加密数据参数
    if ((data == nil) || (data == NULL)) {
        return nil;
    } else if (![data isKindOfClass:[NSData class]]) {
        return nil;
    }
    
    //判断设备系统是否满足条件
    if ([[[UIDevice currentDevice] systemVersion] doubleValue] <= 6.9) {
        return nil;
    }
    
    //使用系统的API进行Base64加密操作
    NSDataBase64EncodingOptions options;
    options = NSDataBase64EncodingEndLineWithLineFeed;
    return [data base64EncodedStringWithOptions:options];
}

- (NSData *)base64DecodeDataWithString:(NSString *)string
{
    //判断是否传入需要加密数据参数
    if ((string == nil) || (string == NULL)) {
        return nil;
    } else if (![string isKindOfClass:[NSString class]]) {
        return nil;
    }
    
    //判断设备系统是否满足条件
    if ([[[UIDevice currentDevice] systemVersion] doubleValue] <= 6.9) {
        return nil;
    }
    
    //使用系统的API进行Base64解密操作
    NSDataBase64DecodingOptions options;
    options = NSDataBase64DecodingIgnoreUnknownCharacters;
    return [[NSData alloc] initWithBase64EncodedString:string options:options];
}

#pragma mark - MD5 加密解密 代码实现
/****************************MD5.m类实现文件内容****************************/
//对字符串数据进行MD5的签名
- (NSString *)md5SignWithString:(NSString *)string
{
    const char *object = [string UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(object,(CC_LONG)strlen(object),result);
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < 16; i ++) {
        [hash appendFormat:@"%02X", result[i]];
    }
    return [hash lowercaseString];
}

//对二进制数据进行MD5的签名
- (NSData *)md5SignWithData:(NSData *)data
{
    Byte byte[CC_MD5_DIGEST_LENGTH];    //定义一个字节数组来接收结果
    CC_MD5((const void*)([data bytes]), (CC_LONG)[data length], byte);
    return [NSData dataWithBytes:byte length:CC_MD5_DIGEST_LENGTH];
}
/******************************************************************************/

#pragma mark - AES 加密解密 代码实现

//需要导入：#import <CommonCrypto/CommonCrypto.h>库才能使用
/**
 *  AES128 + ECB + PKCS7
 *  @param data 要加密的原始数据
 *  @param key  加密 key
 *  @return  加密后数据
 */
- (NSData *)encryptData:(NSData *)data key:(NSData *)key
{
    //判断解密的流数据是否存在
    if ((data == nil) || (data == NULL)) {
        return nil;
    } else if (![data isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([data length] <= 0) {
        return nil;
    }
    
    //判断解密的Key是否存在
    if ((key == nil) || (key == NULL)) {
        return nil;
    } else if (![key isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([key length] <= 0) {
        return nil;
    }
    
    //setup key
    NSData *result = nil;
    unsigned char cKey[kCCKeySizeAES128];
    bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:kCCKeySizeAES128];
    
    //setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    //do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,
                                          cKey,
                                          kCCKeySizeAES128,
                                          nil,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
    }
    return result;
}

#pragma mark - RSA 加密解密 代码实现
/**
 *  AES128 + ECB + PKCS7
 *  @param data 要解密的原始数据
 *  @param key  解密 key
 *  @return  解密后数据
 */
- (NSData *)decryptData:(NSData *)data key:(NSData *)key
{
    //判断解密的流数据是否存在
    if ((data == nil) || (data == NULL)) {
        return nil;
    } else if (![data isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([data length] <= 0) {
        return nil;
    }
    
    //判断解密的Key是否存在
    if ((key == nil) || (key == NULL)) {
        return nil;
    } else if (![key isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([key length] <= 0) {
        return nil;
    }
    
    //setup key
    NSData *result = nil;
    unsigned char cKey[kCCKeySizeAES128];
    bzero(cKey, sizeof(cKey));
    [key getBytes:cKey length:kCCKeySizeAES128];
    
    //setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    //do decrypt
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,
                                          cKey,
                                          kCCKeySizeAES128,
                                          nil,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
    }
    return result;
}



/****************************RSAEncrypt.m类实现文件内容****************************/
#pragma mark - Class Utils Method
- (BOOL)isEmptyKeyRef:(id)object
{
    if (object == nil) {
        return YES;
    } else if (object == NULL) {
        return YES;
    } else if (object == [NSNull null]) {
        return YES;
    }
    return NO;
}


#pragma mark - Private Method
- (SecKeyRef)getPrivateKeyRefWithFilePath:(NSString *)filePath keyPassword:(NSString *)keyPassword
{
    //读取私钥证书文件的内容
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    if ((certificateData == nil) || (certificateData == NULL)) {
        return nil;
    } else if (![certificateData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([certificateData length] <= 0) {
        return nil;
    }
    
    //拼接密码参数到字典中
    NSString *passwordKey = (__bridge id)kSecImportExportPassphrase;
    NSString *passwordValue = [NSString stringWithFormat:@"%@",keyPassword];
    if ((keyPassword == nil) || (keyPassword == NULL)) {
        passwordValue = @"";
    } else if (![keyPassword isKindOfClass:[NSString class]]) {
        passwordValue = @"";
    } else if ([keyPassword length] <= 0) {
        passwordValue = @"";
    }
    NSMutableDictionary *optionInfo = [[NSMutableDictionary alloc] init];
    [optionInfo setObject:passwordValue forKey:passwordKey];
    
    //获取私钥对象
    SecKeyRef privateKeyRef = NULL;
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    CFDataRef pkcs12Data = (__bridge CFDataRef)certificateData;
    CFDictionaryRef options = (__bridge CFDictionaryRef)optionInfo;
    OSStatus securityStatus = SecPKCS12Import(pkcs12Data, options, &items);
    if (securityStatus == noErr && CFArrayGetCount(items) > 0)
    {
        SecIdentityRef identity;
        const void *secpkey = kSecImportItemIdentity;
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(identityDict,secpkey);
        securityStatus = SecIdentityCopyPrivateKey(identity, &privateKeyRef);
        if (securityStatus != noErr)
        {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    return privateKeyRef;
}

- (SecKeyRef)privateKeyRefWithPrivateKey:(NSString *)privateKey
{
    //判断参数是否正确
    if ((privateKey == nil) || (privateKey == NULL)) {
        return nil;
    } else if (![privateKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKey length] <= 0) {
        return nil;
    }
    
    //解析私钥对象内容
    NSString *pKey = [NSString stringWithFormat:@"%@",privateKey];
    NSRange sposition = [pKey rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
    NSRange eposition = [pKey rangeOfString:@"-----END PRIVATE KEY-----"];
    if (sposition.location != NSNotFound && eposition.location != NSNotFound)
    {
        NSUInteger endposition = eposition.location;
        NSUInteger startposition = sposition.location + sposition.length;
        NSRange range = NSMakeRange(startposition, endposition-startposition);
        pKey = [pKey substringWithRange:range];
    }
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    //This will be base64 encoded, decode it.
    NSData *keyData = [self base64DecodeDataWithString:pKey];
    keyData = [self stripPrivateKeyHeader:keyData];
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];
    
    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);
    
    //Add persistent version of the key to system keychain
    [attributes setObject:keyData forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPrivate
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) {CFRelease(persistKey);}
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }
    
    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    
    //Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&keyRef);
    if (status != noErr)
    {
        return nil;
    }
    return keyRef;
}

- (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 private key header
    if (d_key == nil) return nil;
    
    unsigned long len = [d_key length];
    if (!len) return nil;
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    if (!(c_len & 0x80))
    {
        c_len = c_len & 0x7f;
    }
    else
    {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    //Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

- (SecKeyRef)getPublicKeyRefWithFilePath:(NSString *)filePath
{
    //读取公钥证书文件的内容
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    if ((certificateData == nil) || (certificateData == NULL)) {
        return nil;
    } else if (![certificateData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([certificateData length] <= 0) {
        return nil;
    }
    
    //将公钥证书制作成证书对象
    CFDataRef data = (__bridge CFDataRef)certificateData;
    SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, data);
    
    //获取公钥对象
    SecTrustRef trust = NULL;
    SecKeyRef publicKey = NULL;
    SecPolicyRef policies = SecPolicyCreateBasicX509();
    if (![self  isEmptyKeyRef:(__bridge id)(certificateRef)]
        && ![self  isEmptyKeyRef:(__bridge id)(policies)])
    {
        OSStatus status;
        status = SecTrustCreateWithCertificates((CFTypeRef)certificateRef,
                                                policies, &trust);
        if (status == noErr)
        {
            SecTrustResultType result;
            if (SecTrustEvaluate(trust, &result) == noErr)
            {
                publicKey = SecTrustCopyPublicKey(trust);
            }
        }
    }
    if (certificateRef != NULL) CFRelease(certificateRef);
    if (policies != NULL) CFRelease(policies);
    if (trust != NULL) CFRelease(trust);
    return publicKey;
}

- (SecKeyRef)publicKeyRefWithPublicKey:(NSString *)publicKey
{
    //判断参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }
    
    //解析公钥对象内容
    NSString *pKey = [NSString stringWithFormat:@"%@",publicKey];
    NSRange sposition = [pKey rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange eposition = [pKey rangeOfString:@"-----END PUBLIC KEY-----"];
    if (sposition.location != NSNotFound && eposition.location != NSNotFound)
    {
        NSUInteger startposition = eposition.location;
        NSUInteger endposition = sposition.location + sposition.length;
        NSRange range = NSMakeRange(endposition, startposition-endposition);
        pKey = [pKey substringWithRange:range];
    }
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    //This will be base64 encoded, decode it.
    NSData *keyData = [self  base64DecodeDataWithString:pKey];
    keyData = [self stripPublicKeyHeader:keyData];
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];
    
    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);
    
    //Add persistent version of the key to system keychain
    [attributes setObject:keyData
                   forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPublic
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }
    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    
    //Now fetch the SecKeyRef version of the key
    SecKeyRef publicKeyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&publicKeyRef);
    if (status != noErr)
    {
        return nil;
    }
    return publicKeyRef;
}

- (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 public key header
    if (d_key == nil) {return nil;}
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 0;
    if (c_key[idx++] != 0x30) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx++;
    }
    
    //PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] = {0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00};
    if (memcmp(&c_key[idx], seqiod, 15)) {return nil;}
    idx += 15;
    if (c_key[idx++] != 0x03) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx ++;
    }
    if (c_key[idx++] != '\0') {return nil;}
    
    //Now make a new NSData from this buffer
    return ([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

- (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef, kSecPaddingPKCS1,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

- (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size)
        {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef, kSecPaddingNone,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for (int i = 0; i < outlen; i ++)
            {
                if (outbuf[i] == 0)
                {
                    if (idxFirstZero < 0)
                    {
                        idxFirstZero = i;
                    }
                    else
                    {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            NSUInteger length = idxNextZero-idxFirstZero-1;
            [ret appendBytes:&outbuf[idxFirstZero+1] length:length];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}


#pragma mark - RSA Key File Encrypt/Decrypt Public Method
- (NSString *)encryptString:(NSString *)originString publicKeyPath:(NSString *)publicKeyPath
{
    //判断originString参数是否正确
    if ((originString == nil) || (originString == NULL)) {
        return nil;
    } else if (![originString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([originString length] <= 0) {
        return nil;
    }
    
    //判断publicKeyPath参数是否正确
    if ((publicKeyPath == nil) || (publicKeyPath == NULL)) {
        return nil;
    } else if (![publicKeyPath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKeyPath length] <= 0) {
        return nil;
    }
    
    //获取公钥对象和需要加密的字符串内容编码数据流
    SecKeyRef publicKeyRef = [self getPublicKeyRefWithFilePath:publicKeyPath];
    NSData *originData = [originString dataUsingEncoding:NSUTF8StringEncoding];
    if ([self isEmptyKeyRef:(__bridge id)(publicKeyRef)]) {
        return nil;
    }
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    
    //加密源字符串内容编码数据流的数据
    NSData *resultData = nil;
    resultData = [self encryptData:originData withKeyRef:publicKeyRef];
    return [self base64EncodedStringWithData:resultData];
}

- (NSString *)decryptString:(NSString *)encryptString privateKeyPath:(NSString *)privateKeyPath privateKeyPwd:(NSString *)privateKeyPwd
{
    //判断encryptString参数是否正确
    if ((encryptString == nil) || (encryptString == NULL)) {
        return nil;
    } else if (![encryptString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([encryptString length] <= 0) {
        return nil;
    }
    
    //判断publicKeyPath参数是否正确
    if ((privateKeyPath == nil) || (privateKeyPath == NULL)) {
        return nil;
    } else if (![privateKeyPath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKeyPath length] <= 0) {
        return nil;
    }
    
    //判断密码是否存在
    NSString *keyPassword = [NSString stringWithFormat:@"%@",privateKeyPwd];
    if ((privateKeyPwd == nil) || (privateKeyPwd == NULL)) {
        keyPassword = @"";
    } else if (![privateKeyPwd isKindOfClass:[NSString class]]) {
        keyPassword = @"";
    } else if ([privateKeyPwd length] <= 0) {
        keyPassword = @"";
    }
    
    //获取私钥对象和需要加密的字符串内容编码数据流
    NSData *encryptData = nil, *decryptData = nil;
    SecKeyRef privateKeyRef = [self getPrivateKeyRefWithFilePath:privateKeyPath
                                                     keyPassword:privateKeyPwd];
    encryptData = [self  base64DecodeDataWithString:encryptString];
    if ([self isEmptyKeyRef:(__bridge id)(privateKeyRef)]) {
        return nil;
    }
    if ((encryptData == nil) || (encryptData == NULL)) {
        return nil;
    } else if (![encryptData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([encryptData length] <= 0) {
        return nil;
    }
    NSStringEncoding encoding = NSUTF8StringEncoding;
    decryptData = [self decryptData:encryptData withKeyRef:privateKeyRef];
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
}


#pragma mark - RSA Key String Encrypt/Decrypt Public Method
- (NSData *)encryptData:(NSData *)originData publicKey:(NSString *)publicKey
{
    //判断originData参数是否正确
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    
    //判断publicKeyPath参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }
    
    //获取需要加密的字符串内容编码数据流
    SecKeyRef publicKeyRef = [self publicKeyRefWithPublicKey:publicKey];
    if([self isEmptyKeyRef:(__bridge id)(publicKeyRef)]){
        return nil;
    }
    return [self encryptData:originData withKeyRef:publicKeyRef];
}

- (NSString *)encryptString:(NSString *)originString publicKey:(NSString *)publicKey
{
    //判断publicKey参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }
    
    //判断originString参数是否正确
    if ((originString == nil) || (originString == NULL)) {
        return nil;
    } else if (![originString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([originString length] <= 0) {
        return nil;
    }
    
    //获取需要加密的字符串内容编码数据流
    NSData *originData = nil, *encryptData = nil;
    SecKeyRef publicKeyRef = [self publicKeyRefWithPublicKey:publicKey];
    originData = [originString dataUsingEncoding:NSUTF8StringEncoding];
    if([self isEmptyKeyRef:(__bridge id)(publicKeyRef)]){
        return nil;
    }
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    encryptData = [self encryptData:originData withKeyRef:publicKeyRef];
    return [self base64EncodedStringWithData:encryptData];
}

- (NSString *)decryptString:(NSString *)encryptString privateKey:(NSString *)privateKey
{
    //判断publicKey参数是否正确
    if ((privateKey == nil) || (privateKey == NULL)) {
        return nil;
    } else if (![privateKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKey length] <= 0) {
        return nil;
    }
    
    //判断originString参数是否正确
    if ((encryptString == nil) || (encryptString == NULL)) {
        return nil;
    } else if (![encryptString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([encryptString length] <= 0) {
        return nil;
    }
    
    //获取私钥对象和需要加密的字符串内容编码数据流
    SecKeyRef privateKeyRef;
    NSData *encryptData = nil, *decryptData = nil;
    privateKeyRef = [self privateKeyRefWithPrivateKey:privateKey];
    encryptData = [self base64DecodeDataWithString:encryptString];
    if ([self isEmptyKeyRef:(__bridge id)(privateKeyRef)]) {
        return nil;
    }
    if ((encryptData == nil) || (encryptData == NULL)) {
        return nil;
    } else if (![encryptData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([encryptData length] <= 0) {
        return nil;
    }
    NSStringEncoding encoding = NSUTF8StringEncoding;
    decryptData = [self decryptData:encryptData withKeyRef:privateKeyRef];
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
}
/******************************************************************************/




@end
