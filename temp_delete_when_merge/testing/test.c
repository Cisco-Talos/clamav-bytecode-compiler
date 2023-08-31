#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>


int getBufferLen(const char * const buffer){
    int j;
                for (j = 0; 0 != buffer[j]; j++)
                    ;
                return j;
}


#if 0
char* encodeUInt_getridofthis(int inval, char buffer[1024], int * size){
    int bufferSize = sizeof(buffer);

    int i;
    int idx = bufferSize - 1;
    *size = 0;

    for (i = 0; i < bufferSize; i++){
        buffer[i] = 0;
    }

    while (inval){
        buffer[idx--] = '0' + (inval - (10 * (inval / 10)));
        (*size)++;

        inval /= 10;
    }

    idx++;

    return &(buffer[idx]);
}
#endif




char* encodeUInt(int inval, char * buffer, int bufferSize, int * size){

    int i;
    int idx = bufferSize - 1;
    *size = 0;

    for (i = 0; i < bufferSize; i++){
        buffer[i] = 0;
    }

    while (inval){
        buffer[idx--] = '0' + (inval - (10 * (inval / 10)));
        (*size)++;

        inval /= 10;
    }

    idx++;

    return &(buffer[idx]);
}


void andyprintf(const char * const formatStr, ...) __attribute__((always_inline)) {
    int i;
    char buffer[1024];

    // Declaring pointer to the
    // argument list
    va_list ptr;

    // Initializing argument to the
    // list pointer
    va_start(ptr, formatStr);

    for (i = 0; 0 != formatStr[i]; ){
        if ('%' == formatStr[i]){
            i++;
            if ('d' == formatStr[i]){
                int tmp  = va_arg(ptr, int);
                int len;
                char * cp = encodeUInt(tmp, buffer, sizeof(buffer), &len);
                write(1, cp, len);
            } else if ('s' == formatStr[i]){
                const char * const tmp = va_arg(ptr, char*);
                int len = getBufferLen(buffer);
                write(1, buffer, len);
            }
        } else {
            write(1, &(formatStr[i]), 1);
        }




        i++;
    }

    // Ending argument list traversal
    va_end(ptr);



}

#define PRINTSTR(__str__) { \
    int i = 0; \
    while (0 != __str__[i]) { \
        write(1, &(__str__[i]), 1) ; \
    } \
}

#define PRINTINT(__val__) { \
                int len; \
                char * cp = encodeUInt(__val__, buffer, sizeof(buffer), &len); \
                write(1, cp, len); \
}

void func(int val){
#if 0
    andyprintf("%s::%d\n", __FUNCTION__, __LINE__);
#else
    PRINTSTR(__FUNCTION__);
    PRINTSTR("\n");
#endif
}


typedef struct s *sp;

static sp func2(){
    return NULL;
}

const char * const CONST_CP = "hi there";

void func3(const char * const val) {

    if (CONST_CP == val){
    PRINTSTR("val = 'CP'\n");
    } else {
    PRINTSTR("val NOT = CP\n");
    }

}


#if 0

typedef void (*fc)();

void fptestfunc1(){ PRINTSTR(__FUNCTION__); PRINTSTR("\n");}
void fptestfunc2(){ PRINTSTR(__FUNCTION__); PRINTSTR("\n");}
int fptest(int argc, char ** argv){

    fc func = fptestfunc1;

    if (argc > 1){
        func = fptestfunc2;
    }

    func();

    return 0;
}
#endif








int main(int argc, char ** argv){

    const char * val = CONST_CP;

    if (argc > 2){
        func(1);
    } else if (1 == argc){
        val = argv[0];
    }

    func3(val);

#if 0
    fptest(argc, argv);
#endif

    return 0;


}
