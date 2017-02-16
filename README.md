# ZDX3DESEncrypt
iOS
首先，接口简洁，加密只需调用接口- (NSString *)encryptByZDX3DESWithStr:(NSString *)originalStr andKey:(NSString *)key;
解密：- (NSString *)decEncryptBy3DESWithStr:(NSString *)originalStr;

其次，安全性对初始密钥进行了MD5、哈希算法（SHA256）混合加密，生成安全密钥。感兴趣的童鞋也可以略作修改实现自己定制版本的安全密钥。
