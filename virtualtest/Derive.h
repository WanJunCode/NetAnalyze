#ifndef DERIVE_H
#define DERIVE_H
#include "Base.h"

class Derive: public Base{
private:

public:
    Derive();
    virtual ~Derive();

    virtual void funcA(){
        printf("derive class function funcA invoke\n");
    }
}

#endif // DERIVE_H