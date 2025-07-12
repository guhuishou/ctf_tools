import argparse
import base64
import binascii
import hashlib
import codecs
import urllib.parse
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

def handle_encoding(input_data, encoding_type):
    """处理各种编码操作"""
    try:
        if encoding_type == 'base64':
            return base64.b64encode(input_data).decode()
        elif encoding_type == 'base32':
            return base64.b32encode(input_data).decode()
        elif encoding_type == 'base16':
            return base64.b16encode(input_data).decode()
        elif encoding_type == 'hex':
            return binascii.hexlify(input_data).decode()
        elif encoding_type == 'binary':
            return ''.join(format(byte, '08b') for byte in input_data)
        elif encoding_type == 'url':
            return urllib.parse.quote_plus(input_data)
        elif encoding_type == 'rot13':
            return codecs.encode(input_data.decode(), 'rot_13')
        elif encoding_type == 'html':
            return input_data.decode().replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        else:
            return "不支持的编码类型"
    except Exception as e:
        return f"编码错误: {str(e)}"

def handle_decoding(input_data, decoding_type):
    """处理各种解码操作"""
    try:
        if decoding_type == 'base64':
            return base64.b64decode(input_data).decode()
        elif decoding_type == 'base32':
            return base64.b32decode(input_data).decode()
        elif decoding_type == 'base16':
            return base64.b16decode(input_data).decode()
        elif decoding_type == 'hex':
            return bytes.fromhex(input_data.decode()).decode()
        elif decoding_type == 'binary':
            binary_str = input_data.decode().replace(' ', '')
            return ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
        elif decoding_type == 'url':
            return urllib.parse.unquote_plus(input_data.decode())
        elif decoding_type == 'rot13':
            return codecs.decode(input_data.decode(), 'rot_13')
        elif decoding_type == 'html':
            return input_data.decode().replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        else:
            return "不支持的解码类型"
    except Exception as e:
        return f"解码错误: {str(e)}"

def handle_hash(input_data, hash_type):
    """计算各种哈希值"""
    hash_func = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
    }.get(hash_type.lower())
    
    if not hash_func:
        return "不支持的哈希类型"
    
    return hash_func(input_data).hexdigest()

def handle_crypto(input_data, crypto_type, key=None, mode='ecb', iv=None):
    """处理简单加密/解密操作"""
    try:
        # 密钥长度检查
        if crypto_type == 'aes' and len(key) not in [16, 24, 32]:
            return "AES密钥长度必须为16/24/32字节"
        elif crypto_type == 'des' and len(key) != 8:
            return "DES密钥长度必须为8字节"
        
        if crypto_type == 'aes':
            cipher = AES.new(key, AES.MODE_ECB if mode == 'ecb' else AES.MODE_CBC, iv=iv)
        elif crypto_type == 'des':
            cipher = DES.new(key, DES.MODE_ECB if mode == 'ecb' else DES.MODE_CBC, iv=iv)
        else:
            return "不支持的加密类型"
        
        return cipher.decrypt(input_data) if mode == 'decrypt' else cipher.encrypt(pad(input_data, 16))
    except Exception as e:
        return f"加密/解密错误: {str(e)}"

def main():
    # 详细中文帮助信息和示例
    parser = argparse.ArgumentParser(
        description='CTF编解码与哈希工具集',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''使用示例:
        
  1. 字符串编码:
    python ctf_tools.py "Hello CTF!" -e base64
    python ctf_tools.py "flag{test}" -e url
    python ctf_tools.py "secret" -e hex
    
  2. 文件编码/哈希:
    python ctf_tools.py data.txt -f -e base64
    python ctf_tools.py image.png -f -H sha256
    
  3. 字符串解码:
    python ctf_tools.py "aGVsbG8=" -d base64
    python ctf_tools.py "666c61677b746573747d" -d hex
    python ctf_tools.py "%3Chtml%3E" -d url
    
  4. 加密操作:
    # AES加密 (ECB模式)
    python ctf_tools.py "plaintext" -c aes -m encrypt -k "16bytekey12345678"
    
    # DES解密 (CBC模式)
    python ctf_tools.py "ciphertext" -f -c des -m decrypt -k "8bytekey" -i "12345678"
    
  5. 二进制数据处理:
    python ctf_tools.py "0100100001100101" -d binary
    python ctf_tools.py "Hello" -e binary
    
  注意: 
    - 文件操作需添加 -f 参数
    - 密钥可以是字符串或十六进制
    - CBC模式需要提供IV参数'''
    )
    
    # 输入参数
    parser.add_argument(
        'input', 
        help='输入字符串或文件路径'
    )
    
    # 文件标记
    parser.add_argument(
        '-f', '--file', 
        action='store_true', 
        help='从文件读取输入内容'
    )
    
    # 互斥操作组
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-e', '--encode', 
        choices=['base64', 'base32', 'base16', 'hex', 'binary', 'url', 'rot13', 'html'], 
        help='编码操作: base64|base32|base16|hex|binary|url|rot13|html'
    )
    group.add_argument(
        '-d', '--decode', 
        choices=['base64', 'base32', 'base16', 'hex', 'binary', 'url', 'rot13', 'html'], 
        help='解码操作: base64|base32|base16|hex|binary|url|rot13|html'
    )
    group.add_argument(
        '-H', '--hash', 
        choices=['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512'], 
        help='哈希计算: md5|sha1|sha256|sha512|sha3_256|sha3_512'
    )
    group.add_argument(
        '-c', '--crypto', 
        choices=['aes', 'des'], 
        help='加密/解密算法: aes|des'
    )
    
    # 加密相关参数
    parser.add_argument(
        '-m', '--mode', 
        choices=['encrypt', 'decrypt'], 
        help='加密模式: encrypt|decrypt (需配合-c使用)'
    )
    parser.add_argument(
        '-k', '--key', 
        help='加密密钥 (字符串或十六进制)'
    )
    parser.add_argument(
        '-i', '--iv', 
        help='初始化向量 (十六进制格式)'
    )
    
    args = parser.parse_args()

    # 读取输入数据
    if args.file:
        try:
            with open(args.input, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print(f"错误: 文件 '{args.input}' 不存在")
            return
    else:
        data = args.input.encode()

    # 处理操作
    result = ""
    if args.encode:
        result = handle_encoding(data, args.encode)
    elif args.decode:
        result = handle_decoding(data, args.decode)
    elif args.hash:
        result = handle_hash(data, args.hash)
    elif args.crypto:
        if not args.mode or not args.key:
            print("错误: 加密/解密操作需要指定 -m 和 -k 参数")
            return
            
        # 密钥处理
        key = args.key.encode()
        if len(args.key) % 2 == 0:
            try: 
                key = bytes.fromhex(args.key)
            except:
                pass  # 保持为原始字节
        
        # IV处理
        iv = bytes.fromhex(args.iv) if args.iv else b'\0'*16
        
        result = handle_crypto(
            data,
            args.crypto,
            key=key,
            mode=args.mode,
            iv=iv
        )
        
        # 尝试解码或转为十六进制
        try: 
            result = result.decode('utf-8', errors='ignore') 
        except: 
            result = result.hex()
    
    print(f"操作结果:\n{result}")

if __name__ == '__main__':
    main()
