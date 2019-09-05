# shellcode writer

## apologies
First I have to make some apologies, since there are several unintended parts in this challenge.
- the shellcode length constraint is 25 bytes before this challenge is visible. However we found that the released challenges may be too hard, I decide to make this challenge easier, so the length constraint is release to 40 bytes, yet I forgot to update the given file..., so you may see the length constraint being 25 bytes locally, however the real binary running on the server is 40 bytes...
- the private key leakage should be 304 bits only. Due to some intention to make this challenge easier, I changed something before this challenge is released, and it seems that these changes make the leakage of private key become 432 bits. The final solution shouldn't change, however this DOES is an unintended bug.

## description
The challenge ask an encrypted input using given RSA public key, then decrypt it and run it as shellcode. It seems perfect, however the program didn't call `RSA_free` to release the imported private key, so the whole private key file can be found on heap. To make this challenge harder, a `backup()` function will overwrite some part of the private key file, leaving only least 304 bits (it is 432 bits now due to some bug QAQ) of private key on the heap, the first goal is to leak it.
After getting the least 304 bits of private key, we can now launch a partial key exposure attack against it. There are several papers describe it, and I choose to call the algorithm's name directly in the script so that you can clearly see which algorithm we are using now while launching the attack.

That's all! Ezpz, isn't it?
