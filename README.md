# ctf_tools

Common encoding and decoding tools for CTF, including base64, base32, base16, hex, binary, URL, rot13, and HTML encoding and decoding, as well as MD5, SHA1, SHA256, SHA512, SHA3_256, and SHA3_512 hash calculations, and AES, DES algorithm encryption and decryption.
ctf 常用编码解码工具，包括 base64、base32、base16、hex、binary、url、rot13、html 的编解码，md5、sha1、sha256、sha512、sha3_256、sha3_512 的 hash 计算，aes、des 算法加解密等。

## Usage

```
usage: ctf_tools.py [-h] [-f]
                    (-e {base64,base32,base16,hex,binary,url,rot13,html} | -d {base64,base32,base16,hex,binary,url,rot13,html} | -H {md5,sha1,sha256,sha512,sha3_256,sha3_512} | -c {aes,des})
                    [-m {encrypt,decrypt}] [-k KEY] [-i IV]
                    input
```

1. 字符串编码:
```
python ctf_tools.py "Hello CTF!" -e base64
python ctf_tools.py "flag{test}" -e url
python ctf_tools.py "secret" -e hex
```
2. 文件编码/哈希:
```
python ctf_tools.py data.txt -f -e base64
python ctf_tools.py image.png -f -H sha256
```
3. 字符串解码:
```
python ctf_tools.py "aGVsbG8=" -d base64
python ctf_tools.py "666c61677b746573747d" -d hex
python ctf_tools.py "%3Chtml%3E" -d url
```
4. 加密操作:
```
# AES加密 (ECB模式)
python ctf_tools.py "plaintext" -c aes -m encrypt -k "16bytekey12345678"
# DES解密 (CBC模式)
python ctf_tools.py "ciphertext" -f -c des -m decrypt -k "8bytekey" -i "12345678"
```    
5. 二进制数据处理:
```
python ctf_tools.py "0100100001100101" -d binary
python ctf_tools.py "Hello" -e binary
```
