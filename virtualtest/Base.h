#ifndef BASE_H
#define BASE_H

class Base
{
private:
    /* data */
public:
    Base();
    virtual ~Base();
    // 纯虚函数
    virtual void funcA() = 0; 

    void parse();
};

#endif // BASE_H