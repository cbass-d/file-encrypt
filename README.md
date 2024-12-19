### LOCKBOX RUST
CLI only rust version of https://github.com/cbass-d/lockbox_cli

### Usable algorihtms
* AES256-Gcm
* ChaCha20-Poly1305

### Usage
```
Usage: lockbox_rust -o <OUTPUT> <COMMAND> <FILE> <ALGORITHM> <PASSPHRASE>

Arguments:
  <COMMAND>     [possible values: encrypt, decrypt]
  <FILE>        
  <ALGORITHM>   [possible values: aes256-gcm, chacha20-poly]
  <PASSPHRASE>  

Options:
  -o <OUTPUT>      
  -h, --help       Print help
  -V, --version    Print version
```

**Must remember passphrase used as only its hash is stored**

