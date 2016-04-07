#include "../../include/primitives/HashOpenSSL.hpp"
#include <iostream>

int mainSha1()
{
        string input_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        auto hash = make_shared<OpenSSLSHA1>();
        const char *cstr = input_msg.c_str();
        int len = input_msg.size();
        vector<byte> vec(cstr, cstr + len);
        hash->update(vec, 0, len);
        vector<byte> out;
        hash->hashFinal(out, 0);
        string actual = hexStr(out);
        cout << "using sha1 on input: " <<input_msg<< " got result(in hexa): " << actual << endl;
		return 0;
}
