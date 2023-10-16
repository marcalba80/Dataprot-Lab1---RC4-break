#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>

#define IVL    3
#define KL    13
#define ML     1
#define KEYL  16
#define ITER 256

unsigned char  IV[IVL + 1];
unsigned char Key[KL + 1];
unsigned char   M[ML + 1];

FILE *f;

void getIV(){
    printf("Enter iv(3B): ");
    for(int i = 0; i < IVL; i++) scanf("%2X", &IV[i]);
    IV[IVL] = '\0';

    printf("IV: 0x");
    for (int i = 0 ; i < IVL; i++) printf("%02X", IV[i]);
    fflush(stdin);
    printf("\n");
}

void getK(){
    printf("Enter Key(13B): ");
    for(int i = 0; i < KL; i++) scanf("%2X", &Key[i]);
    Key[KL] = '\0';

    printf("Key: 0x");
    for (int i = 0 ; i < KL; i++) printf("%02X", Key[i]);
    fflush(stdin);
    printf("\n");
}

void getM(){
    printf("Enter Message(1B): ");
    for(int i = 0; i < ML; i++) scanf("%2X", &M[i]);
    M[ML] = '\0';

    printf("Message: 0x");
    for (int i = 0 ; i < ML; i++) printf("%02X", M[i]);
    fflush(stdin);
    printf("\n");
}

void generate_key(){
    RAND_bytes(Key, KEYL);
    Key[KEYL] = '\0';
    printf("Key: 0x");
    for (int i = 0 ; i < KL; i++) printf("%02X", Key[i]);
    printf("\n");
}

char* hex2str(unsigned char *r, int l){
    char *n = malloc(l * 2 + 1);
    for (int i = 0 ; i < l; i++){
        sprintf(n + i * 2, "%02X", r[i]);
    }
    n[l * 2] = '\0';
    return n;
}

char* int2uchar(unsigned int r, int l){
    char *n = malloc(l + 1);
    for (int i = 0 ; i < l; i++){
        n[i] = r >> 16 - (i*8);
    }
    n[l] = '\0';
    // printf("prov: %06X\n", *n);
    return n;
}

void generate_message(){
    RAND_bytes(M, ML);
    M[ML] = '\0';
    printf("Message: 0x");
    for (int i = 0 ; i < ML; i++) printf("%02X", M[i]);
    printf("\n");
}

FILE* open_file(){
    char name[IVL*2 + 4 + 1];
    sprintf(name, "%s.dat", hex2str(IV, IVL));
    return fopen(name, "w");
}

void close_file(){
    fclose(f);
}

char* concatKey(unsigned char iv[IVL]){
    unsigned char *k = malloc(KEYL + 1);
    for (int i = 0 ; i < IVL; i++) k[i] = iv[i];
    for (int i = 0 ; i < KL; i++) k[3+i] = Key[i];
    k[KEYL] = '\0';
    printf("IVi+Key: ");
    for (int i = 0 ; i < KEYL; i++) printf("%02X", k[i]);
    printf("\n");
    return k;
}

void write_file(char *data){
    if(fwrite(data, sizeof(char), strlen(data), f) != strlen(data)){
        perror("fwrite(): ");
        exit(1);
    }
    fwrite("\n", sizeof(char), 1, f);
}

char* main_process(unsigned char *k){
    unsigned char C[ML + 1];
    RC4_KEY ky;
    RC4_set_key(&ky, KEYL, k);
    RC4(&ky, ML, M, C);
    C[ML] = '\0';

    const int lout = 2+(IVL*2)+1+2+(ML*2)+1;
    char *out = malloc(lout);
    sprintf(out, "0x%02X%02X%02X 0x%02X", k[0], k[1], k[2], C[0]);
    out[lout] = '\0';
    // out[lout+1] = '\n';
    return out;
}

void process_iter(){   
    unsigned int ivint = (0x00 << 24 | IV[0] << 16 | IV[1] << 8 | IV[2]);
    for (int iter = 0; iter < ITER ; iter++){
        unsigned char *k = concatKey(int2uchar(ivint, IVL));
        write_file(main_process(k));    
        ivint++;
    }
}

void process_enc(){
    f = open_file();
    process_iter();
    close_file();
}

void checkOpt(char *opt){
    if(strcmp(opt, "-k") == 0){
        generate_key();
    }
    if(strcmp(opt, "-m") == 0){
        generate_message();
    }
    if(strcmp(opt, "-e") == 0){
        getIV();
        getK();
        getM();
        process_enc();
    }
}

int main (int argc, char *argv[]){
    if (argc > 1) checkOpt(argv[1]);
    else printf("Usage: \n \
                -k(Generates Key 13B) \n \
                -m(generates message 1B) \n \
                -e(RC4 through iterating iv 256 times)\n");
    return 0;
}
