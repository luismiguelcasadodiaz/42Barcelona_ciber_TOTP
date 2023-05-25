# TOTP
## Time-based One Time Password generator with Graphical User Interface
### Sync it With Google or Microsoft Two Factor Autenticator.

I started the GUI to generate a QRcode in order that Googel and Microsoft 2FA validate it.
In this link https://totp.app you can validat your TOTP. You can copy paste the secretkey 

### About the secret key passed to the program
This program uses as input a file wiht an hexadecimal shared key.

The hexadecimal shared key, embeded in the QR can be used for sync with Microsoft 2F.

THe hexadecimal key at this moment 8th May 2023 is a string suitable for 

```base64.b32decode(secret.decode(),True, map01='l')```

the Key.hex ABCDEFGHIJKLMNOPQRSTUVWXYZ234567= is base32 alfabeth

when readed from the file we got a byte array into text variable
```text = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567='```

We need to check its length is a multiple of 4 and bigger than 64 Hexadecimal char

I use ```text.hex()``` to get 
'4142434445464748494a4b4c4d4e4f505152535455565758595a323334353637'
'0123456789012345678901234567890123456789012345678901234567890123456789'
'         1         2         3         4         5         6

over this view of the secret key i count the hexadecimal chars 

To check if the secret key only uses base32 Alfabet i use this

```base32_alphabet =b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567='```

to chek is each secret's char belongs to the alfabet wiht a 

```if char not in base32_alphabet```


