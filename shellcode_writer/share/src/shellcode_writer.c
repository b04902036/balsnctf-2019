#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <seccomp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define RSA_LENGTH (1024/8)
#define BACKUP (55)
#define MAXLEN (40)

char *myDecrypt(const char *ct, const char *key, int len);
void backup(const char *);
void addSeccomp();
void run(const char *code);
void welcome();

RSA *rsa_para;
char *vul;
char exec_code[RSA_LENGTH+1] __attribute__((aligned(0x1000)));

typedef void (*func)();


int main() {
    int len = 0;
    char *pt;
    welcome();

    vul = (char *) malloc(RSA_LENGTH);
    puts("give me :");
    len = read(0, vul, RSA_LENGTH);
    if (len < 0) {
        perror("error!");
        exit(255);
    }
    pt = myDecrypt(vul, "pri.pem", len);

    addSeccomp();

    memset(exec_code, 0, sizeof(exec_code));
    memcpy(exec_code, pt, MAXLEN);
    // to overwrite private key in memory
    backup(pt);

    run(exec_code);
    return 0;
}

void welcome() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("**********************************");
    puts("*        shellcode writer        *");
    puts("* give me your encrypted message *");
    puts("*    I'll write it out 4 you     *");
    puts("**********************************");
    mprotect(exec_code, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    alarm(10);
}

char *myDecrypt(const char *ct, const char *key, int len) {
    FILE *fp;
    size_t rsa_len = 0;
    char *pt;
    int ret = 0;
   
    fp = fopen(key, "rb");
    if (fp == NULL) {
        perror("error!");
        exit(255);
    }

    rsa_para = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (rsa_para == NULL) {
        perror("error!");
        exit(255);
    }

    rsa_len = RSA_size(rsa_para);
    if (rsa_len <= 0) {
        perror("error!");
        exit(255);
    }

    pt = (char *) calloc(1, RSA_LENGTH + 1);
    if (pt == NULL) {
        perror("error!");
        exit(255);
    }

    ret = RSA_private_decrypt(len, ct, pt, rsa_para, RSA_NO_PADDING);
    if (ret < 0) {
        perror("error!");
        exit(255);
    }
    return pt;
}

void run(const char *code) {
    (*((func)code))();
}

void backup(const char *code) {
    // check code length
    int len = 0;
    char *tmp = vul;
    for (int i = RSA_LENGTH; i >= 0; --i)
        if ((int)code[i] != 0) {
            len = i + 1;
            break;
        }
    // service sign
    strncpy(tmp, "*hint* ha, no hint for you! However, we will be 48 hours online while the BalsnCTF take place!!\nFeel free to contact us at discord! Yet beware of phishing! Don't give flag to others!", 182);
    tmp += 182;
   
    if (len < 3) {
       puts("Wow! Your payload is so short!\n"
             "There is no need to backup..., I think?"
             "Just in case, I'll save one...");

        for (int i = 0; i < 1; ++i) {
            strncpy(tmp, code, 128);
            tmp += 128;
        }

        // number of backup
        ((long long int *)tmp)[0] = 1;
        tmp += 0x8;
    }
    else if (len <= MAXLEN) {
        puts("Wow! Your payload is so long!\n"
             "I have to do some heavy backup in case some failure happen...");

        for (int i = 0; i < BACKUP; ++i) {
            strncpy(tmp, code, RSA_LENGTH);
            tmp += RSA_LENGTH;
        }

        strncpy(tmp, "ENDOFBACKUP", 11);
        tmp += RSA_LENGTH;
        // number of backup
        ((long long int *)tmp)[0] = BACKUP;
        tmp += 0x8;
    }
    else {
        puts("Wow! Your payload is too long!\n"
             "I'm so sorry that we cannnot afford it...");
        exit(255);
    }
    strncpy(tmp, "information of challenge provider : \n\tE-mail : balsn2015@gmail.com\n\tteam : Balsn\n\tusername : FWEASD\n\tchallenge type : pwn(?) + crypto(?) + rev(?) + misc(?)\n\thint : do you know what would happen if we combine multiple easy techniques together? It'll end up become an even easier challenge!!!", 0x1000);
    
    puts("Finish! Now we can try your stuff...");
}

void addSeccomp() {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_load(ctx);
}
