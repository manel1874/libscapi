//
// Created by moriya on 01/10/17.
//

#include "libscapi/include/primitives/Mersenne.hpp"


ZpMersenneIntElement::ZpMersenneIntElement(int elem) {

    this->elem = elem;

    if(this->elem<p){
        return;
    }
    this->elem -=p;

    if(this->elem<p){
        return;
    }

    this->elem -=p;

}

ZpMersenneIntElement ZpMersenneIntElement::operator-(const ZpMersenneIntElement& f2) {

    ZpMersenneIntElement answer;

    int temp =  (int)elem - (int)f2.elem;

    if(temp<0){
        answer.elem = temp + p;
    }
    else{
        answer.elem = temp;
    }

    return answer;
}

ZpMersenneIntElement ZpMersenneIntElement::operator+(const ZpMersenneIntElement& f2){

    ZpMersenneIntElement answer;

    answer.elem = (elem + f2.elem);

    if(answer.elem>=p)
        answer.elem-=p;

    return answer;
}

ZpMersenneIntElement ZpMersenneIntElement::operator*(const ZpMersenneIntElement& f2){

    ZpMersenneIntElement answer;

    long multLong = (long)elem * (long) f2.elem;

    //get the bottom 31 bit
    unsigned int bottom = multLong & p;

    //get the top 31 bits
    unsigned int top = (multLong>>31);

    answer.elem = bottom + top;

    //maximim the value of 2p-2
    if(answer.elem>=p)
        answer.elem-=p;

    //return ZpMersenneIntElement((bottom + top) %p);
    return answer;
}

ZpMersenneIntElement& ZpMersenneIntElement::operator*=(const ZpMersenneIntElement& f2){

    long multLong = (long)elem * (long) f2.elem;

    //get the bottom 31 bit
    unsigned int bottom = multLong & p;

    //get the top 31 bits
    unsigned int top = (multLong>>31) ;

    elem = bottom + top;

    //maximim the value of 2p-2
    if(elem>=p)
        elem-=p;

    return *this;

}

ZpMersenneIntElement ZpMersenneIntElement::operator/(const ZpMersenneIntElement& f2) {

    //code taken from NTL for the function XGCD
    int a = f2.elem;
    int b = p;
    long s;

    int  u, v, q, r;
    long u0, v0, u1, v1, u2, v2;

    int aneg = 0, bneg = 0;

    if (a < 0) {
        if (a < -NTL_MAX_LONG) Error("XGCD: integer overflow");
        a = -a;
        aneg = 1;
    }

    if (b < 0) {
        if (b < -NTL_MAX_LONG) Error("XGCD: integer overflow");
        b = -b;
        bneg = 1;
    }

    u1=1; v1=0;
    u2=0; v2=1;
    u = a; v = b;

    while (v != 0) {
        q = u / v;
        r = u % v;
        u = v;
        v = r;
        u0 = u2;
        v0 = v2;
        u2 =  u1 - q*u2;
        v2 = v1- q*v2;
        u1 = u0;
        v1 = v0;
    }

    if (aneg)
        u1 = -u1;


    s = u1;

    if (s < 0)
        s =  s + p;

    ZpMersenneIntElement inverse(s);

    return inverse* (*this);
}

ZpMersenneLongElement::ZpMersenneLongElement(unsigned long elem) {

    this->elem = elem;
    if(this->elem>=p){

        this->elem = (this->elem & p) + (this->elem>>61);

        if(this->elem >= p)
            this->elem-= p;

    }
}

ZpMersenneLongElement ZpMersenneLongElement::operator-(const ZpMersenneLongElement& f2) {

    ZpMersenneLongElement answer;

    long temp =  (long)elem - (long)f2.elem;

    if(temp<0){
        answer.elem = temp + p;
    }
    else{
        answer.elem = temp;
    }



    return answer;
}

ZpMersenneLongElement ZpMersenneLongElement::operator+(const ZpMersenneLongElement& f2){

    ZpMersenneLongElement answer;

    answer.elem = (elem + f2.elem);

    if(answer.elem>=p)
        answer.elem-=p;

    return answer;
}


ZpMersenneLongElement& ZpMersenneLongElement::operator+=(const ZpMersenneLongElement& f2){

    elem = (elem + f2.elem);

    if(elem>=p)
        elem-=p;

    return *this;

}

ZpMersenneLongElement ZpMersenneLongElement::operator*(const ZpMersenneLongElement& f2){

    ZpMersenneLongElement answer;

    unsigned long long high;
    unsigned long low = _mulx_u64(elem, f2.elem, &high);


    unsigned long low61 = (low & p);
    unsigned long low61to64 = (low>>61);
    unsigned long highShift3 = (high<<3);

    unsigned long res = low61 + low61to64 + highShift3;

    if(res >= p)
        res-= p;

    answer.elem = res;

    return answer;


}

ZpMersenneLongElement& ZpMersenneLongElement::operator*=(const ZpMersenneLongElement& f2){

    unsigned long long high;
    unsigned long low = _mulx_u64(elem, f2.elem, &high);


    unsigned long low61 = (low & p);
    unsigned long low61to64 = (low>>61);
    unsigned long highShift3 = (high<<3);

    unsigned long res = low61 + low61to64 + highShift3;

    if(res >= p)
        res-= p;

    elem = res;

    return *this;

}

ZpMersenneLongElement ZpMersenneLongElement::operator/(const ZpMersenneLongElement& f2){

    ZpMersenneLongElement answer;
    mpz_t d;
    mpz_t result;
    mpz_t mpz_elem;
    mpz_t mpz_me;
    mpz_init_set_str (d, "2305843009213693951", 10);
    mpz_init(mpz_elem);
    mpz_init(mpz_me);

    mpz_set_ui(mpz_elem, f2.elem);
    mpz_set_ui(mpz_me, elem);

    mpz_init(result);

    mpz_invert ( result, mpz_elem, d );

    mpz_mul (result, result, mpz_me);
    mpz_mod (result, result, d);


    answer.elem = mpz_get_ui(result);

    return answer;
}

template <>
TemplateField<ZpMersenneIntElement>::TemplateField(long fieldParam) {

    this->fieldParam = 2147483647;
    this->elementSizeInBytes = 4;//round up to the next byte
    this->elementSizeInBits = 31;

    auto randomKey = prg.generateKey(128);
    prg.setKey(randomKey);

    m_ZERO = new ZpMersenneIntElement(0);
    m_ONE = new ZpMersenneIntElement(1);
}

template <>
TemplateField<ZpMersenneLongElement>::TemplateField(long fieldParam) {

    this->elementSizeInBytes = 8;//round up to the next byte
    this->elementSizeInBits = 61;

    auto randomKey = prg.generateKey(128);
    prg.setKey(randomKey);

    m_ZERO = new ZpMersenneLongElement(0);
    m_ONE = new ZpMersenneLongElement(1);
}


template <>
ZpMersenneIntElement TemplateField<ZpMersenneIntElement>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZpMersenneIntElement element(b);
        return element;
    }
}


template <>
ZpMersenneLongElement TemplateField<ZpMersenneLongElement>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZpMersenneLongElement element(b);
        return element;
    }
}

template <>
void TemplateField<ZpMersenneIntElement>::elementToBytes(unsigned char* elemenetInBytes, ZpMersenneIntElement& element){

    memcpy(elemenetInBytes, (byte*)(&element.elem), 4);
}

template <>
void TemplateField<ZpMersenneLongElement>::elementToBytes(unsigned char* elemenetInBytes, ZpMersenneLongElement& element){

    memcpy(elemenetInBytes, (byte*)(&element.elem), 8);
}

template <>
ZpMersenneIntElement TemplateField<ZpMersenneIntElement>::bytesToElement(unsigned char* elemenetInBytes){

    return ZpMersenneIntElement((unsigned int)(*(unsigned int *)elemenetInBytes));
}


template <>
ZpMersenneLongElement TemplateField<ZpMersenneLongElement>::bytesToElement(unsigned char* elemenetInBytes){

    return ZpMersenneLongElement((unsigned long)(*(unsigned long *)elemenetInBytes));
}
