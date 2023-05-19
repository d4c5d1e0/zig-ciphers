# zig-ciphers

## Zig implementation of various ciphers.
### Clefia [src](src/ciphers/clefia.zig) 

Based on [The 128-Bit Blockcipher CLEFIA](https://datatracker.ietf.org/doc/html/rfc6114)
- Usage with a 192-Bit key
```zig
const clefia = @import("ciphers.zig").clefia;

// 128-Bit block size
var ciphertext: [16]u8 = undefined;
const plaintext = [_]u8{
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
};
// 24 bytes key
const cipher = clefia.Clefia192.init(key);
cipher.encrypt(plaintext[0..], ciphertext[0..]);
```
