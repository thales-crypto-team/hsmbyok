/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent in SafeNet.
*
*****************************************************************************/

#include "Base64.h"

using namespace std;

// implement BASE64URL, not BASE64
const char *Base64::bstr = "ABCDEFGHIJKLMNOPQ"
                           "RSTUVWXYZabcdefgh"
                           "ijklmnopqrstuvwxy"
                           "z0123456789-_";

char Base64::rstr[] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                        0, 62,  0,  0, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,
                        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                        23, 24, 25, 0,  0,  0,  0, 63,  0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0,  0,  0,  0,  0 };

Base64::Base64() {}

void Base64::encodeURL(unsigned char *input, size_t l, string &output, bool add_crlf) {
    size_t i = 0;
    size_t o = 0;

    output = "";

    if (input == NULL) {
        return;
    }
    while (i < l) {
        size_t remain = l - i;
        if (add_crlf && o && o % 76 == 0)
            output += "\n";
        switch (remain) {
        case 1:
            output += bstr[((input[i] >> 2) & 0x3f)];
            output += bstr[((input[i] << 4) & 0x30)];
            // base64url: no padding: output += "==";
            break;
        case 2:
            output += bstr[((input[i] >> 2) & 0x3f)];
            output += bstr[((input[i] << 4) & 0x30) + ((input[i + 1] >> 4) & 0x0f)];
            output += bstr[((input[i + 1] << 2) & 0x3c)];
            // base64url: no padding: output += "=";
            break;
        default:
            output += bstr[((input[i] >> 2) & 0x3f)];
            output += bstr[((input[i] << 4) & 0x30) + ((input[i + 1] >> 4) & 0x0f)];
            output += bstr[((input[i + 1] << 2) & 0x3c) + ((input[i + 2] >> 6) & 0x03)];
            output += bstr[(input[i + 2] & 0x3f)];
        }
        o += 4;
        i += 3;
    }
}

#define VALID_INPUT_CHAR(_x)  ( ((_x) != '=') && ((_x) != '\0') )

void Base64::decodeURL(const string &input, unsigned char *output, size_t &sz) {
    size_t i = 0;
    size_t l = input.size();
    size_t j = 0;

    while (i < l) {
        while (i < l && (input[i] == '\r' || input[i] == '\n'))
            i++;
        if (i < l) {
            unsigned char b1 =
                    (unsigned char)((rstr[(int)input[i]] << 2 & 0xfc) + (rstr[(int)input[i + 1]] >> 4 & 0x03));
            if (output) {
                output[j] = b1;
            }
            j++;

            if (VALID_INPUT_CHAR(input[i + 1])) {
                if (VALID_INPUT_CHAR(input[i + 2])) {
                    unsigned char b2 =
                            (unsigned char)((rstr[(int)input[i + 1]] << 4 & 0xf0) + (rstr[(int)input[i + 2]] >> 2 & 0x0f));
                    if (output) {
                        output[j] = b2;
                    }
                    j++;

                    if (VALID_INPUT_CHAR(input[i + 3])) {
                        unsigned char b3 = (unsigned char)((rstr[(int)input[i + 2]] << 6 & 0xc0) + rstr[(int)input[i + 3]]);
                        if (output) {
                            output[j] = b3;
                        }
                        j++;
                    }
                }
            }

            i += 4;
        }
    }
    sz = j;
}

// to compile: g++ -DTEST_BASE64 -DDEBUG Base64.cpp

#ifdef TEST_BASE64

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_fill(unsigned char *in, size_t inLen) {
    for (size_t i = 0; i < inLen; i++) {
        in[i] = (unsigned char)rand();
    }
}

static void test_base64() {
    unsigned char in[256] = {0};
    unsigned char out[256] = {0};
    std::string str;
    for (;;) {
        size_t inLen = sizeof(in) - ((unsigned)rand() % 4); // randomize inLen
        assert(inLen <= sizeof(in));
        test_fill(in, inLen); // randomize in
        Base64::encodeURL(in, inLen, str, false);
        cout << "base64url = " << str << endl;
        size_t outLen = 0;
        Base64::decodeURL(str, NULL, outLen);
        assert(outLen <= sizeof(out));
        Base64::decodeURL(str, out, outLen);
        assert(outLen == inLen);
        assert(memcmp(in, out, inLen) == 0);
    }
}

int main() {
    test_base64();
    return 0;
}

#endif // TEST_BASE64
