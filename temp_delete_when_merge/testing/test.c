#include <stdio.h>


void func(int val){
    printf("%s::%d\n", __FUNCTION__, __LINE__);
}


typedef struct s *sp;

static sp func2(){
    return NULL;
}

const char * const CONST_CP = "hi there";

void func3(const char * const val) {

    if (CONST_CP == val){
    printf("val = 'CP'\n");
    } else {
    printf("val = '%p'\n", val);
    }

}


int main(int argc, char ** argv){

    const char * val = CONST_CP;

    if (argc > 2){
        func(1);
    } else if (1 == argc){
        val = argv[0];
    }

    func3(val);

    return 0;


}
