/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent in SafeNet.
*
*****************************************************************************/

#ifndef _BASE64_H
#define _BASE64_H

#include <string>

class Base64 {
public:
    Base64();

public:
    static void encodeURL(unsigned char *, size_t, std::string &, bool add_crlf = true);
    static void decodeURL(const std::string &, unsigned char *, size_t &);

private:
    static const char *bstr;
    static char rstr[128];
};

#endif // _BASE64_H
