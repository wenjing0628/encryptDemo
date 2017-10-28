# encryptDemo
encryptDemo
//使用Base64文件进行Base64加密和解密
/*********************************使用Base64类*********************************/
//使用Base64执行加密操作
NSString *string = @"abcdefghijklmnopqrstuvwxyz";
NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
NSString *encodeString = [Base64 base64EncodedStringWithData:data];
NSLog(@"encodeString : %@", encodeString);

//使用Base64执行解密操作
NSString *decodeString = nil;
NSData *decodeData = [Base64 base64DecodeDataWithString:encodeString];
decodeString = [[NSString alloc] initWithData:decodeData
                                     encoding:NSUTF8StringEncoding];
NSLog(@"decodeString : %@", decodeString);
/******************************************************************************/

//使用MD5文件进行MD5加密和验签
/*********************************使用MD5类*********************************/
//使用MD5执行加密操作
NSString *string2 = @"abcdefghijklmnopqrstuvwxyz";
NSString *encodeString2 = [MD5 md5SignWithString:string2];
NSLog(@"encodeString2 : %@", encodeString2);

//MD5为不可逆的操作，使用MD5执行验签操作
NSString *verifyString2 = [MD5 md5SignWithString:string2];
NSLog(@"verifyString2 : %@", verifyString2);
if ([verifyString2 isEqualToString:encodeString2]) {
    NSLog(@"md5 verify sign success");
} else {
    NSLog(@"md5 verify sign failed");
}
/******************************************************************************/

//使用AES执行加密操作
NSString *aesKey = @"a1b2c3d4e5f6g7h8";
NSString *string3 = @"abcdefghijklmnopqrstuvwxyz";
NSData *keyData3 = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
NSData *sourceData3 = [string3 dataUsingEncoding:NSUTF8StringEncoding];
NSData *encodeData3 = [AESEncrypt encryptData:sourceData3 key:keyData3];
NSLog(@"encodeData3 : %@", encodeData3);

//使用AES执行解密操作
NSString *decodeString3 = nil;
NSData *decodeData3 = [AESEncrypt decryptData:encodeData3
                                          key:keyData3];
decodeString3 = [[NSString alloc] initWithData:decodeData3
                                      encoding:NSUTF8StringEncoding];
NSLog(@"decodeString3 : %@", decodeString3);



//使用RSA执行加密操作
NSString *string4 = @"abcdefghijklmnopqrstuvwxyz";
NSString *encodeString4 = [RSAEncrypt encryptString:string4
                                          publicKey:mPublicKey];
NSLog(@"encodeString4 : %@", encodeString4);

//使用RSA执行解密操作
NSString *decodeString4 = [RSAEncrypt decryptString:encodeString4
                                         privateKey:mPrivateKey];
NSLog(@"decodeString4 : %@", decodeString4);
