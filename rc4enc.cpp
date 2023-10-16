//! Custom implementation of the alleged RC4 stream cipher.
// J.L. Villar (Sept.2022)
//
// (adapted from previous code implementing an attack)
// Motivation: OpenSSL deprecated RC4 from version 3.0 on
//
// You can use the whole or part of this code at your own
// risk. DISCLAIMER: RC4 does not offer nowadays any reasonable
// level of protection of the confidentiality of the information
// encrypted with it. Moreover, there is no guarantee that
// this implementation is bug-free. The author by no means
// can be considered liable or responsible for any errors or 
// omissions in this code, and any possible damage, loss of
// information or any kind of consequences derived from its use.
//

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
int I,J;           // RC4 indices
int key[L];        // Long-term key

int keylen=8;      // Length (in words) of the long-term key
int outlen=256;    // Length (in words) of the output key stream

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

// RC4 implementation

void expandkey() {
    int seedlen=keylen;
    for (I=0;I<keylen;I++) K[I]=key[I]&M;
    for (;I<L;I++) K[I]=K[I%seedlen];
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

void readkey() {
    unsigned char b;
    int i;
    for (i=0;i<keylen;i++)
        if (fread(&b,1,1,stdin)!=1) {
            if (!feof(stdin)) {
                fprintf(stderr,"Input error while reading key from stdin\n");
                exit(1);
            } else break;
        } else key[i]=b;
    if (i<keylen) {
        fprintf(stderr,"Key is too short: padding with null bytes\n");
        for (;i<keylen;i++) key[i]=0;
    } else if (fread(&b,1,1,stdin)==1) fprintf(stderr,"Key is too long: ignoring extra bytes\n");
}

int hexval(char c) {
    if (c<'0') return -1;
    if (c<='9') return c-'0';
    if (c<'A') return -1;
    if (c<='F') return c-'A'+10;
    if (c<'a') return -1;
    if (c<='f') return c-'a'+10;
    return -1;
}

void read_hexkey(const char *k) {
    if (!k) {
        fprintf(stderr,"Missing hexkey string\n");
        exit(1);
    }
    int i;
    for (i=0;i<keylen;i++) {
        if (!*k) break;
        int x0,x1;
        if ((x0=hexval(*k++))<0 || !*k || (x1=hexval(*k++))<0) {
            fprintf(stderr,"Badly formed hexkey string\n");
            exit(1);
        }
        key[i]=x0*16+x1;
    }
    if (i<keylen) {
        fprintf(stderr,"Key is too short: padding with null bytes\n");
        for (;i<keylen;i++) key[i]=0;
    } else if (*k) fprintf(stderr,"Key is too long: ignoring extra bytes\n");
}

void initRC4() {
    expandkey();
//reportK();
    initperm();
//reportS();
//reportF();
}

void outkeystream() {
    unsigned char o;
    for (int i=0;i<outlen;i++)
        if (fwrite((o=genbyte(),&o),1,1,stdout)!=1) {
            fprintf(stderr,"Output error while writing key stream to stdout\n");
            exit(1);
        }
}

void encrypt() {
    unsigned char i,o;
    while (1) {
        if (fread(&i,1,1,stdin)!=1) {
            if (feof(stdin)) break;
            fprintf(stderr,"Input error while reading plaintext stream from stdin\n");
            exit(1);
        }
        if (fwrite((o=genbyte()^i,&o),1,1,stdout)!=1) {
            fprintf(stderr,"Output error while writing ciphettext stream to stdout\n");
            exit(1);
        }
    }
}

// Generate test vectors

int offsets[]={0,16,240,256,496,512,752,768,1008,1024,1520,1536,2032,2048,3056,3072,4080,4096,-1};

void testvector(int len,int *p) {
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

int verbosity=0;
bool onlystream=false;
bool keyfromargs=false;
bool onlytest=false;
bool onlyhelp=false;

int processoption(const char *opt,const char *arg) {
    bool consumearg=false; 
    for (;;) {
        switch (*opt++) {
            case 'v': verbosity++;
            continue;
            case 'K': keyfromargs=true;
                if (consumearg) {
                    fprintf(stderr,"Two options conflict because both are trying to consume next argument\n");
                    exit(1);
                }
                consumearg=true;
                read_hexkey(arg);
            continue;
            case 'L':
                if (consumearg) {
                    fprintf(stderr,"Two options conflict because both are trying to consume next argument\n");
                    exit(1);
                }
                if (arg && *arg && arg[0]!='-') {
                    consumearg=true;
                    keylen=strtod(arg,NULL);
                    if (keylen<1) {
                        fprintf(stderr,"Key length must be positive: Assuming value 1\n");
                        keylen=1;
                    }
                    if (keylen>L) {
                        fprintf(stderr,"Key length too large: Assuming maximum value %d\n",L);
                        keylen=L;
                    }
                } else keylen=8;
            continue;
            case 'S': onlystream=true;
                if (consumearg) {
                    fprintf(stderr,"Two options conflict because both are trying to consume next argument\n");
                    exit(1);
                }
                if (arg && *arg && arg[0]!='-') {
                    consumearg=true;
                    outlen=strtod(arg,NULL);
                    if (outlen<1) {
                        fprintf(stderr,"Keystream length must be positive: Assuming value 1\n");
                        outlen=1;
                    }
                } else outlen=256;
            continue;
            case 't': onlytest=true;
            continue;
            case 'h': onlyhelp=true;
            continue; 
            case 0: return consumearg? 1 : 0;
        }
        break;
    }
    fprintf(stderr,"Unknown option '-%c'\nThe only valid options are: -L -S -K -t -v -h.\n",opt[-1]);
    exit(1);
    return 0;
}

void givehelp(const char* appname=0) {
    fprintf(stderr,"RC4 encryption and keystream generation program.\n");
    fprintf(stderr,"(J.L.Villar 2022. No warranties. RC4 encryption gives no real data protection. Use with care.)\n");
    fprintf(stderr,"Usage: %s [options]\n",appname?appname:"prog_name");
    fprintf(stderr,"Valid options (can be combined, order matters):\n");
    fprintf(stderr,"  -L <LEN>: Set key length to <LEN> bytes (default: 8)\n");
    fprintf(stderr,"  -S <LEN>: Don't encrypt and generate <LEN> keystream bytes (default: 256)\n");
    fprintf(stderr,"  -K <HEX>: Use key given by the hexadecimal string <HEX>\n");
    fprintf(stderr,"  -t: Only generate test vectors (to check the RC4 implementation)\n");
    fprintf(stderr,"  -v: Be more verbous\n");
    fprintf(stderr,"  -h: Print this help text\n");
    fprintf(stderr,"Do not combine two options accepting arguments in the same string, like -LS.\n");
    fprintf(stderr,"Example of use:\n   cat message.dat | %s -L 5 -K '000102' > cipher.bin\n",appname?appname:"prog_name");
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    int basearg;
//    for (basearg=0;basearg<argc-1 && argv[basearg+1][0]=='-';basearg++) basearg+=processoption(argv[basearg+1]+1,argv[basearg+2]);
//    keylen=argc>basearg+1?strtod(argv[basearg+1],NULL):8;
//    if (keylen<1) keylen=1;
//    if (keylen>L) keylen=L;
//    outlen=argc>basearg+2?strtod(argv[basearg+2],NULL):256;
//    if (outlen<1) outlen=1;
    for (basearg=0;basearg<argc-1;basearg++)
        if (argv[basearg+1][0]=='-') basearg+=processoption(argv[basearg+1]+1,argv[basearg+2]);
        else fprintf(stderr,"Ignoring non-option argument \"%s\"\n",argv[basearg+1]);
    if (onlyhelp) {
        givehelp(argv[0]);
        exit(0);
    }
    if (onlytest) {
        testvectors();
        exit(0);
    }
    if (!keyfromargs) {
        fprintf(stderr,"No key specified. Option -K is mandatory except for generating test vectors.\n");
        exit(1);
//        readkey();
    }
    if (verbosity>0) {
        fprintf(stderr,"Key length: %d bits.\n",l*keylen);
        fprintf(stderr,"key: 0x");
        for (int i=0;i<keylen;i++) fprintf(stderr,"%02x",key[i]);
        fprintf(stderr,"\n");
    }
    if (verbosity>0) {
        if (onlystream) fprintf(stderr,"Producing %d keystream bytes.\n",outlen);
        else fprintf(stderr,"Encrypting/decrypting stdin.\n");
    }
    initRC4();
    if (onlystream) outkeystream();
    else encrypt(); 
    return 0;
}
