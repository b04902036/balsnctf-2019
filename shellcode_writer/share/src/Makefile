all: shellcode_writer.o
	gcc -I/usr/include -z now -fPIE -pie $< -lcrypto -lssl -lseccomp
	rm $<

%.o: %.c
	gcc $< -c -g -z now -fPIE -pie -fstack-protector-all

.PHONY: clean
clean:
	rm -f *.o a.out
