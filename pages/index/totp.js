var CryptoJS = require("crypto-js");
let timeOffset=0
function time(){
  return Math.floor(Date.now() / 1000) + (timeOffset || 0);
}
function TOTP(key) {
  const timeStep = 30; // 默认时间步长为 30 秒
  const timeCounter = Math.floor(time()/ timeStep).toString(16).padStart(16, '0'); // 时间计数器，16位

  // 使用 Base32 解码并返回 WordArray
  const decodedKey = base32Decode(key);
  
  // 使用 HMAC-SHA1 计算哈希值
  const hmacHash = CryptoJS.HmacSHA1(CryptoJS.enc.Hex.parse(timeCounter),decodedKey);

  // 动态截取
  const hmacBytes = hexToBytes(hmacHash.toString());
  const offset = hmacBytes[hmacBytes.length - 1] & 0xf;
  const otp =
    ((hmacBytes[offset] & 0x7f) << 24) |
    (hmacBytes[offset + 1] << 16) |
    (hmacBytes[offset + 2] << 8) |
    hmacBytes[offset + 3];
  
  // 生成 6 位 OTP
  return (otp % 1000000).toString().padStart(6, '0');
}

// Base32 解码函数
function base32Decode(input) {
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  input = input.toUpperCase().replace(/=+$/, ''); // 去掉填充符

  let bits = '';
  for (let i = 0; i < input.length; i++) {
    const val = base32chars.indexOf(input[i]);
    if (val === -1) throw new Error('Invalid Base32 character');
    bits += val.toString(2).padStart(5, '0');
  }

  let hex="";
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    hex+=parseInt(bits.substring(i, i + 8), 2).toString(16).padStart(2, '0');
  }

  return CryptoJS.enc.Hex.parse(hex);
}

// 将十六进制字符串转换为字节数组
function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}
//Steamtotp实现
function SteamTotp(secret) {
  secret = bufferizeSecret(secret); // 确保密钥的处理函数兼容
  // 创建模拟的 8 字节 buffer
  let bytes = new Uint8Array(8).fill(0);
  let timeDiv30 = Math.floor(time() / 30);
  // 将高位写入前 4 字节（为 0）
  bytes[4] = (timeDiv30 >> 24) & 0xff;
  bytes[5] = (timeDiv30 >> 16) & 0xff;
  bytes[6] = (timeDiv30 >> 8) & 0xff;
  bytes[7] = timeDiv30 & 0xff;
  // 使用 CryptoJS 计算 HMAC
  let hmac = CryptoJS.HmacSHA1(CryptoJS.lib.WordArray.create(bytes), secret);
  console.log(hmac)

  // 转换 HMAC 为字节数组
  let hmacBytes = wordArrayToUint8Array(hmac);

  // 获取偏移量
  const start = hmacBytes[19] & 0x0f;

  // 截取 4 字节
  hmacBytes = hmacBytes.slice(start, start + 4);

  // 转换为无符号 32 位整数并取 31 位
  let fullcode =
    ((hmacBytes[0] << 24) | (hmacBytes[1] << 16) | (hmacBytes[2] << 8) | hmacBytes[3]) & 0x7fffffff;

  // 生成验证码
  const chars = '23456789BCDFGHJKMNPQRTVWXY';
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += chars.charAt(fullcode % chars.length);
    fullcode /= chars.length;
  }

  return code;
};
function bufferizeSecret(secret) {
  if (typeof secret === 'string') {
    // 检查是否为 hex 编码
    if (secret.match(/^[0-9a-f]{40}$/i)) {
      return CryptoJS.enc.Hex.parse(secret); // 解析为 WordArray
    } else {
      // 假设是 base64 编码
      return base32Decode(secret); // 解析为 WordArray
    }
  }

  // 如果不是字符串，假设已经是 WordArray 或其他支持的格式
  return secret;
}
// 将 WordArray 转换为字节数组（Uint8Array）
function wordArrayToUint8Array(wordArray) {
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const bytes = new Uint8Array(sigBytes);
  let i = 0;
  let j = 0;
  while (i < sigBytes) {
    bytes[i++] = (words[j] >>> 24) & 0xff;
    bytes[i++] = (words[j] >>> 16) & 0xff;
    bytes[i++] = (words[j] >>> 8) & 0xff;
    bytes[i++] = words[j++] & 0xff;
  }
  return bytes.slice(0, sigBytes);
}

export { TOTP, SteamTotp, timeOffset }