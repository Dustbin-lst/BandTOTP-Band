var CryptoJS = require("crypto-js");
function TOTP(key,currTime = Math.floor(Date.now() / 1000)) {
    key = key.toUpperCase().replace(/\s/g, "");
    // 将Base32编码的密钥解码为二进制
    key = base32Decode(key);
    // 获取当前时间戳
    var timeStep = 30;  // 默认时间步长为30秒
    // 计算基于时间的单次密码
    var message = Math.floor(currTime / timeStep).toString(16);
    message = message.padStart(16, '0');
    var hmacHash = hmacSHA1(key, hexToBytes(message));
    var offset = hmacHash[19] & 0xf;
    var otp =
      ((hmacHash[offset] & 0x7f) << 24) |
      (hmacHash[offset + 1] << 16) |
      (hmacHash[offset + 2] << 8) |
      hmacHash[offset + 3];
    otp = (otp % 1000000).toString().padStart(6, '0');
    return otp
  }

  // Base32解码
  function base32Decode(input) {
    var base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var base32lookup = {};
    for (var i = 0; i < base32chars.length; i++) {
      base32lookup[base32chars.charAt(i)] = i;
    }
    
    input = input.replace(/=+$/, '');
    var bits = '';
    var output = [];
    for (var i = 0; i < input.length; i++) {
      var char = input.charAt(i).toUpperCase();
      var val = base32lookup[char];
      bits += ('00000' + val.toString(2)).slice(-5);
    }
    while (bits.length >= 8) {
      output.push(parseInt(bits.substring(0, 8), 2));
      bits = bits.substring(8);
    }
    
    return new Uint8Array(output);
  }

  // HMAC-SHA1哈希
  function hmacSHA1(key, message) {
    var keyBytes = new Uint8Array(key);
    var messageBytes = new Uint8Array(message);
    var hmacKey = (keyBytes.length > 64) ? sha1(keyBytes) : keyBytes;
    if (hmacKey.length < 64) {
      var padding = new Uint8Array(64 - hmacKey.length);
      hmacKey = concatenateUint8Arrays(hmacKey, padding);
    }

    var innerPad = new Uint8Array(64);
    var outerPad = new Uint8Array(64);
    for (var i = 0; i < 64; i++) {
      innerPad[i] = hmacKey[i] ^ 0x36;
      outerPad[i] = hmacKey[i] ^ 0x5c;
    }

    var innerHash = sha1(concatenateUint8Arrays(innerPad, messageBytes));
    var outerHash = sha1(concatenateUint8Arrays(outerPad, innerHash));

    return outerHash;
  }

  // SHA1哈希
  function sha1(message) {
    var sha1Hash = CryptoJS.SHA1(CryptoJS.lib.WordArray.create(message));
    return hexToBytes(sha1Hash.toString());
  }

  // 将十六进制字符串转换为字节数组
  function hexToBytes(hex) {
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }

  // 合并Uint8Array
  function concatenateUint8Arrays(a, b) {
    var result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
  }
  export{TOTP}