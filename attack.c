#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#define IVL     3
#define KL     13
#define ML      1
#define KEYL   16
#define ITER  256
#define IVITER 14
#define LSIZE 13

const char *pref_p = "bytes_";
const char *iv_names[] = {"01FF00", "03FF00", "04FF00", "05FF00", "06FF00", \
"07FF00", "08FF00", "09FF00", "0AFF00", "0BFF00", "0CFF00", "0DFF00", "0EFF00", "0FFF00"};
const char *iv_names_p[] = {"01FFxx", "03FFxx", "04FFxx", "05FFxx", "06FFxx", \
"07FFxx", "08FFxx", "09FFxx", "0AFFxx", "0BFFxx", "0CFFxx", "0DFFxx", "0EFFxx", "0FFFxx"};

bool custom_files;
int iteration, recordNum;

unsigned char  IV[IVL + 1];
unsigned char Key[KL + 1];
unsigned char   M[ML + 1];

FILE *f;

struct Freq{
    __uint8_t val;
    // unsigned char cval;
    int freq;
};

unsigned int calc[ITER];
struct Freq valsIter[IVITER];

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

struct Freq getMaxRepeatingElement(unsigned int array[], int n) {
    int i, j, count;
    unsigned int maxElement;
    int maxCount = 0;
    struct Freq maxVal;
    for(i = 0; i< n; i++){
        count = 1;
        // for(j = 0; j < n; j++){
        for(j = i+1; j < n; j++){
            if(array[j] == array[i]){
                count++;
                
            }
        }
        if(count > maxCount){
            maxElement = array[i];
            maxCount = count;
        }
    }
    maxVal.val = maxElement;
    maxVal.freq = maxCount;
    return maxVal;
}

void first_iter(unsigned char *iv, unsigned char *c){
    __uint8_t xint = (iv[2]);
    __uint8_t cint = (c[0]);
    calc[recordNum] = cint ^ (xint+2);
    // printf("calc: %02X ", calc[recordNum]);
}

void second_iter(unsigned char *iv, unsigned char *c){
    __uint8_t xint = (iv[2]);
    __uint8_t cint = (c[0]);
    __uint8_t mint = (M[0]);
    calc[recordNum] = (cint ^ mint)-xint-6;
    // printf("calc: %02X ", calc[recordNum]);
}
void third_iter(unsigned char *iv, unsigned char *c){
    __uint8_t xint = (iv[2]);
    __uint8_t cint = (c[0]);
    __uint8_t mint = (M[0]);
    __uint8_t k0int = (Key[0]);
    calc[recordNum] = (cint ^ mint)-xint-10-k0int;
    // printf("calc: %02X ", calc[recordNum]);
}

__uint8_t sumator(){
    __uint8_t suma = 3;
    for(int i = 0 ; i <= iteration-1 ; i++){
        suma += (i+3);
    }
    // printf("sumator: %d", suma);
    return suma;
}

void default_iter(unsigned char *iv, unsigned char *c){
    __uint8_t xint = (iv[2]);
    __uint8_t cint = (c[0]);
    __uint8_t mint = (M[0]);
    
    calc[recordNum] = (cint ^ mint)-xint-sumator();
    for(int i = 0 ; i < iteration-1 ; i++){
        __uint8_t kint = (Key[i]);
        calc[recordNum] -= kint;
    }
    // printf("calc: %02X ", calc[recordNum]);
}

void process_rec(unsigned char *iv, unsigned char *c){
    switch (iteration)
    {
    case 0:
        first_iter(iv, c);
        break;
    case 1:
        second_iter(iv,c);
        break;
    case 2:
        third_iter(iv,c);
        break;
    default:
        default_iter(iv,c);
        break;
    }
}

void print_details(){
    switch (iteration)
    {
    case 0:
        M[0] = valsIter[iteration].val;
        M[ML] = '\0';
        // printf("M[0]: %02X", M[0]);
        printf("Keystream for %s\n", iv_names_p[iteration]);
        printf("Guessed m[0]: %02X (freq: %d)\n", valsIter[iteration].val, valsIter[iteration].freq);
        printf("***************************************************************\n");
        break;
    default:
        Key[iteration-1] = valsIter[iteration].val;
        Key[KL] = '\0';
        // printf("M[0]: %02X", M[0]);
        printf("Keystream for %s\n", iv_names_p[iteration]);
        printf("Guessed k[%d]: %02X (freq: %d)\n", iteration-1, valsIter[iteration].val, valsIter[iteration].freq);
        printf("***************************************************************\n");
        break;
    }
}

void results(){
    struct Freq res = getMaxRepeatingElement(calc, ITER);
    valsIter[iteration] = res;
    print_details();
}

void read_file(FILE *f){
    char buf[LSIZE + 2];
    unsigned char ivc[IVL + 1];
    unsigned char  c[ML + 1];

    recordNum = 0;
    while(fgets(buf, sizeof(buf), f) != NULL && recordNum < ITER){
        unsigned char ivt[IVL*2 +1];
        strncpy(ivt, buf+2, IVL*2);
        ivt[IVL*2] = '\0';
        unsigned char ct[ML*2 +1];
        strncpy(ct, buf+11, ML*2);
        ct[ML*2] = '\0';
        
        // printf("iv: %s + c: %s\n", ivt, ct);
        for(int i = 0 ; i < IVL ; i++) sscanf(ivt + (i*2), "%02X", &ivc[i]);
        ivc[IVL] = '\0';

        for(int i = 0 ; i < ML ; i++) sscanf(ct + (i*2), "%02X", &c[i]);
        c[ML] = '\0';
        process_rec(ivc, c);
        // printf("iv: %02X c: %02X\n", ivc[2], c[0]);
        recordNum++;
    }
    results();
}

void iter(){
    FILE *f;
    char *name = malloc(25);
    if (custom_files) sprintf(name, "%s.dat", iv_names[iteration]);
    else sprintf(name, "%s%s.dat", pref_p, iv_names_p[iteration]);
    // printf("name: %s", name);
    if((f = fopen(name, "r")) == NULL){
        perror("fopen: ");
        exit(1);
    }
    read_file(f);
    fclose(f);
    free(name);
}

void check_option(char *option) {
    
    if(strcmp(option, "-c") == 0) custom_files = true;
    else custom_files = false;
}
void print_final(){
    printf("End: Message is %02X and Key: ", M[0]);
    for (int i = 0 ; i < KL; i++) printf("%02X", Key[i]);
    printf("\n");
    
}

int main(int argc, char *argv[]){
    if (argc > 1){
        check_option(argv[1]);
        for(iteration = 0 ; iteration < IVITER ; iteration++){
            iter();
        }
        print_final();
    }
    else printf("Usage: -c: Use custom files -p: Use provided files\n");
    return 0;
}