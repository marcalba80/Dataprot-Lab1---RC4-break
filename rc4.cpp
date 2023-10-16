//! Example of a simple attack against the RC4 stream cipher.
// J.L. Villar (Sept.2019)
//
// The typical implementation of WEP is assumed.
// There is a 24-bit long IV prepended to the long-term key.
// The keystream is exposed due to the 4-step challenge-response authentication
// handshake.
// The attack uses special values of the IV and only needs the first byte
// of the key streams to guess the first bytes of the long-term key with
// noticeable probability.
//
// There are many known attacks that are far more powerful than this toy example.

extern "C" {
    #include <stdlib.h>
    #include <stdio.h>
    #include <time.h>
    #include <string.h>
}

const int l=8;     // Bitlength of the elements (words)
const int L=1<<l;  // Number of elements
const int M=L-1;   // Binary mask for elements

int S[L];          // RC4 state (permutation)
int K[L];          // RC4 Expanded (repeated) IV+key
int F[L];          // Transposition counters (debug)
int freq[L];       // Frequency counters (attack)
int I,J;           // RC4 indices
int key[L];        // Long-term key
int IV[L];         // Initialization vector

int keylen=5;      // Length (in words) of the long-term key
int IVlen=3;       // Length (in words) od the Initialization Vector

// Tracing functions (for debugging purposes)

void report(const char *name,const int *X) {
    printf(" *** %s = [",name);
    for (int n=0;n<L;n++) {
        if (!(n&0x0F)) printf("\n    ");
        printf("%02X ",X[n]);
    }
    printf("\n]\n");
}

void reportS() {report("PERM",S);}
void reportK() {report("KEY",K);}
void reportF() {report("SWAP FREQ",F);}

// Generate a random long-term key

void randkey() {
    for (int i=0;i<keylen;i++) key[i]=rand()&M;
}

// Restrict to printable (alphanumeric) characters (only valid for l=8)

char makeprintable(int x) {
    x=unsigned(x)%54;
    if (x<='9'-'0') return '0'+x;
    x-='9'-'0'+1;
    if (x<='Z'-'A') return 'A'+x;
    x-='Z'-'A'+1;
    return 'a'+x;
}

void randpkey() {
    for (int i=0;i<keylen;i++) key[i]=makeprintable(rand());
//    printf("[");
//    for (int i=0;i<keylen;i++) printf("%c",key[i]);
//    printf("]");
}

int isprintable(char c) {
    if (c<'0') return 0;
    if (c<='9') return 1;
    if (c<'A') return 0;
    if (c<='Z') return 1;
    if (c<'a') return 0;
    if (c<='z') return 1;
    return 0;
}

// RC4 implementation

void expandkey() {
    int seedlen=keylen+IVlen;
    for (I=0,J=0;I<IVlen;I++,J++) K[J]=IV[I]&M;
    for (I=0;I<keylen;I++,J++) K[J]=key[I]&M;
    for (;J<L;J++) K[J]=K[J%seedlen];
}

void swap() {
//printf("        (%02X,%02X)\n",I,J);
    if (I!=J) {F[I]++;F[J]++;}
    int T=S[I];
    S[I]=S[J];
    S[J]=T;
}
void initperm() {
    for (I=0;I<L;I++) F[I]=0;
    for (I=0;I<L;I++) S[I]=I;
//reportS();
    J=0;
    for (I=0;I<L;I++) {
        J+=S[I]+K[I];J&=M;
        swap();
//reportS();
    }
    I=0;J=0;
}

unsigned char genbyte() {
    I++;I&=M;
    J+=S[I];J&=M;
    swap();
    return S[(S[I]+S[J])&M];
}

// Generate test vectors

int offsets[]={0,16,240,256,496,512,752,768,1008,1024,1520,1536,2032,2048,3056,3072,4080,4096,-1};

void testvector(int len,int *p) {
    IVlen=0;
    keylen=len;
    for (int i=0;i<keylen;i++) key[i]=p[i];
    printf("\nKey length: %d bits.\n",l*keylen);
    printf("key: 0x");
    for (int i=0;i<keylen;i++) printf("%02x",key[i]);
    printf("\n");
    expandkey();
    initperm();
    int lastoffs=0;
    for (int n=0;offsets[n]>=0;n++) {
        for (int i=offsets[n];i>lastoffs;i--) genbyte();
        lastoffs=offsets[n];
        printf("\nDEC %4d HEX %4x: ",lastoffs,lastoffs);
        for (int i=0;i<4;i++) printf("%02x ",genbyte());
        printf(" ");
        for (int i=0;i<4;i++) printf("%02x ",genbyte());
        printf("  ");
        for (int i=0;i<4;i++) printf("%02x ",genbyte());
        printf(" ");
        for (int i=0;i<4;i++) printf("%02x ",genbyte());
        lastoffs+=16;
    }
    printf("\n");
}

int testkey0[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
int testkey5[]={0x83,0x32,0x22,0x77,0x2a};
int testkey7[]={0x19,0x10,0x83,0x32,0x22,0x77,0x2a};
int testkey8[]={
    0x64,0x19,0x10,0x83,0x32,0x22,0x77,0x2a};
int testkey10[]={
    0x8b,0x37,0x64,0x19,0x10,0x83,0x32,0x22,
    0x77,0x2a};
int testkey16[]={
    0xeb,0xb4,0x62,0x27,0xc6,0xcc,0x8b,0x37,
    0x64,0x19,0x10,0x83,0x32,0x22,0x77,0x2a};
int testkey24[]={
    0xc1,0x09,0x16,0x39,0x08,0xeb,0xe5,0x1d,
    0xeb,0xb4,0x62,0x27,0xc6,0xcc,0x8b,0x37,
    0x64,0x19,0x10,0x83,0x32,0x22,0x77,0x2a};
int testkey32[]={
    0x1a,0xda,0x31,0xd5,0xcf,0x68,0x82,0x21,
    0xc1,0x09,0x16,0x39,0x08,0xeb,0xe5,0x1d,
    0xeb,0xb4,0x62,0x27,0xc6,0xcc,0x8b,0x37,
    0x64,0x19,0x10,0x83,0x32,0x22,0x77,0x2a};


void testvectors() {
    printf("\nThis must produce the test vectors in https://tools.ietf.org/html/rfc6229\n");
    testvector(5,testkey0);
    testvector(7,testkey0);
    testvector(8,testkey0);
    testvector(10,testkey0);
    testvector(16,testkey0);
    testvector(24,testkey0);
    testvector(32,testkey0);
    testvector(5,testkey5);
    testvector(7,testkey7);
    testvector(8,testkey8);
    testvector(10,testkey10);
    testvector(16,testkey16);
    testvector(24,testkey24);
    testvector(32,testkey32);
}

// Generate just the first word of the RC4 key stream

int testRC4() {
    expandkey();
//reportK();
    initperm();
//reportS();
//reportF();
    return genbyte();
}

// First word guessing attack, based on special values for the IV.
// From the first word of the key streams for L different IV
// the function outputs a guess based on the most repeated value.
// The ''magic'' IV is (3,-1,x).
// With a meaningful probability, the RC4 key-scheduling produces the following sequence.
// (e.g. for x=2, and the first key-word y)
//  I    J      S
//              0   1   2   3   4  ...  7  ... y+8 ... 255
//  0    3     (3)  1   2  (0)  4  ...  7  ... y+8 ... 255
//  1    3      3  (0)  2  (1)  4  ...  7  ... y+8 ... 255
//  2    7      3   0  (7)  1   4  ... (2) ... y+8 ... 255
//  3   y+8     3   0   7 (y+8) 4  ...  2  ... (1) ... 255
// ...  ...    ... ... ... ... ... ... ... ... ... ... ... ... ...
//
// Likely, the first word in the key stream will be
//  S[S[1]+S[S[1]]] = S[0+S[0]] = S[3] = y+8
// and then, the fist work in the long-term key is revealed.
// The attack only works when the elements at positions 0, 1 and 3 are not swapped again
// in the key expansion procedure.
//
// After guessing the first key word, a similar attack is performed to retrieve the second word.
// This time, the magic IV values are (4,-1,x).
// For instance, using x=2 and the first two key words being y0 and y1:
//  I    J       S
//               0   1   2     3        4      ...  8  ... 11+y0 ... 12+y0+y1 ... 255
//  0    4      (4)  1   2     3       (0)     ...  8  ... 11+y0 ... 12+y0+y1 ... 255
//  1    4       4  (0)  2     3       (1)     ...  8  ... 11+y0 ... 12+y0+y1 ... 255
//  2    8       4   0  (8)    3        1      ... (2) ... 11+y0 ... 12+y0+y1 ... 255
//  3  11+y0     4   0   8  (11+y0)     1      ...  2  ...  (3)  ... 12+y0+y1 ... 255
//  4 12+y0+y1   4   0   8   11+y0  (12+y0+y1) ...  2  ...   3   ...   (1)    ... 255
// ...  ...     ... ... ...   ...      ...     ... ... ...  ...  ...   ...    ... ...
//
// Then, S[S[1]+S[S[1]]] = S[0+S[0]] = S[4] = 12+y0+y1
// and the second key word y1 can be obtained from the previously guessed y0.
//
// The attack can be sequentially extended for all the remaining key words.

bool onlyprintable=false;
int verbosity=0;
bool onlytest=false;
bool onlyhelp=false;

int gk[L]; // Guessed long-term key

void guesskey() {
    int ofs=3;
    for (int n=0;n<keylen;n++) {
        ofs+=n+3;
        for (int i=0;i<L;i++) freq[i]=0;
        for (int i=0;i<L;i++) {
            IV[0]=(n+3)&M;
            IV[1]=(-1)&M;
            IV[2]=i&M;
            freq[(testRC4()-ofs-i)&M]++;
        }
        int fmax=0;
        int fmaxind=0;
        for (int i=0;i<L;i++)
            if ((!onlyprintable || isprintable(i)) && freq[i]>fmax) {
                fmax=freq[i];
                fmaxind=i;
            }
        if (verbosity>0) printf("    Max freq %d detected at %02X (key[%d]=%02X)\n",fmax,fmaxind,n,key[n]);
        gk[n]=fmaxind;
        ofs+=fmaxind;
    }
}

// Test a number of randomly generated keys.
// The first argument (if any is provided) is the number of keys generated.
// The second argument (if more than one are provided) is the length of the long-term key (in words).
// Default number of keys is 1. Default length is 5.
// The IV length is fixed to 3 words, and it is always prepended to the long-term key.

void processoption(const char *opt) {
    for (;;) {
        switch (*opt++) {
            case 'p': if (l==8) onlyprintable=true;
            continue;
            case 'v': verbosity++;
            continue;
            case 't': onlytest=true;
            continue;
            case 'h': onlyhelp=true;
            continue; 
            case 0: return;
        }
        break;
    }
    fprintf(stderr,"Unknown option '-%c'\nThe only valid options are -p -v -t -h.\n",opt[-1]);
    exit(1);
}

void givehelp(const char* appname=0) {
    fprintf(stderr,"RC4 simple attack demo\n");
    fprintf(stderr,"Usage: %s [options] [num_keys [key_length]]\n",appname?appname:"prog_name");
    fprintf(stderr,"num_keys is the number of attacked randomly generated keys (default: 1)\n");
    fprintf(stderr,"key_length is the length of the keys in bytes (default: 5)\n");
    fprintf(stderr,"Valid options:\n");
    fprintf(stderr,"  -p: Use only printable (alphanumeric) bytes in the keys\n");
    fprintf(stderr,"  -v: Be more verbous\n");
    fprintf(stderr,"  -t: Generate test vectors (to check the implementation of RC4)\n");
    fprintf(stderr,"  -h: Print this help text\n");
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    int basearg;
    for (basearg=0;basearg<argc-1 && argv[basearg+1][0]=='-';basearg++) processoption(argv[basearg+1]+1);
    int niter=argc>basearg+1?strtod(argv[basearg+1],NULL):1;
    if (niter<1) niter=1;
    keylen=argc>basearg+2?strtod(argv[basearg+2],NULL):5;
    if (keylen<1) keylen=1;
    if (keylen>L-IVlen) keylen=L-IVlen;
    if (onlyhelp) {
        givehelp(argv[0]);
        exit(0);
    }
    if (onlytest) {
        testvectors();
        exit(0);
    }
    printf("Trying %d random long-term %skeys of length %d words (a word consists of %d bits)\n",niter,onlyprintable?"printable ":"",keylen,l);
    int nok[keylen];
    for (int i=0;i<keylen;i++) nok[i]=0;
    for (int i=0;i<niter;i++) {
        int ok=0;
        if (onlyprintable) randpkey(); else randkey();
        guesskey();
        for (ok=0;ok<keylen && key[ok]==gk[ok];nok[ok++]++);
        printf("%c",ok>keylen-3?'X':'-'); // mark all attempts that retrieve at least the first keylen-2 key words
        fflush(stdout);
    }
    // Some statistics
    int totw=0;
    int maxw;
    for (maxw=0;maxw<keylen && nok[maxw]>0;maxw++) totw+=nok[maxw];
    printf("\n\nStatistics:\n");
    for (int i=0;i<maxw;i++) printf("%c %5.2f%% of the first %d key words correctly guessed\n",i==keylen-3?'*':' ',nok[i]/double(niter)*100,i+1);
    printf("\nAverage length of the guessed key prefix: %.1f out of %d words\n",totw/double(niter),keylen);
    return 0;
}
