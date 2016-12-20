#include <stdio.h>
#include <stdlib.h>

#define typeof __typeof__

#define Pointer(T) typeof(T *)
#define Array(T, N) typeof(T [N])
#define TYPE int

#define Func_msg2(functype, type1, type2)                         \
    struct Func_container2 {                                      \
        functype funcptr;                                         \
        type1 argu1;                                              \
        type2 argu2;                                              \
    }

#define Func_msg3(functype, type1, type2, type3)                        \
    struct Func_container3 {                                            \
        functype funcptr;                                               \
        type1 argu1;                                                    \
        type2 argu2;                                                    \
        type3 argu3;                                                    \
    }

int printi3(int a, int b, int c) {
    printf("%d, %d, %d\n", a, b, c);
    return 0;
}

int printi2(int a, int b) {
    printf("%d, %d\n", a, b);
    return 0;
}

int printc3(char a, char b, char c) {
    printf("%c, %c, %c\n", a, b, c);
    return 0;
}

int printc2(char a, char b) {
    printf("%c, %c\n", a, b);
    return 0;
}

void store(void *p) {
    *(long *)p = 1;
}


int main() {
    /*
    Func_msg2(typeof(int (*)(int, int)), int, int) fmi2;
    Func_msg3(typeof(int (*)(int, int, int)), int, int, int) fmi3;
    fmi2.funcptr = printi2;
    fmi2.argu1 = 1;
    fmi2.argu2 = 2;
    fmi3.funcptr = printi3;
    fmi3.argu1 = 1;
    fmi3.argu2 = 2;
    fmi3.argu3 = 3;
    fmi2.funcptr(fmi2.argu1, fmi2.argu2);
    fmi3.funcptr(fmi3.argu1, fmi3.argu2, fmi3.argu3);
    {
        Func_msg2(typeof(int (*)(char, char)), char, char) fmc2;
        Func_msg3(typeof(int (*)(char, char, char)), char, char, char) fmc3;
        fmc2.funcptr = printc2;
        fmc2.argu1 = 'a';
        fmc2.argu2 = 'b';
        fmc3.funcptr = printc3;
        fmc3.argu1 = 'a';
        fmc3.argu2 = 'b';
        fmc3.argu3 = 'c';
        fmc2.funcptr(fmc2.argu1, fmc2.argu2);
        fmc3.funcptr(fmc3.argu1, fmc3.argu2, fmc3.argu3);
    }
    */
    int a = 0;
    store(&a);
    printf("%d\n", a);
    return 0;
}
