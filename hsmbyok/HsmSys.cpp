/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#include "HsmSys.h"

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#else
#include <string.h>
#include <stdio.h>
#include <termios.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <ctype.h>
#endif

#if defined(_WIN32)

HsmSys::HLIBRARY HsmSys::dlopen(const char *filename) { return ::LoadLibrary(filename); }
char *HsmSys::dlerror(void) { return "(HsmSys::dlerror)"; }
void *HsmSys::dlsym(HsmSys::HLIBRARY handle, const char *symbol) { return (void *)::GetProcAddress(handle, symbol); }
void HsmSys::dlclose(HsmSys::HLIBRARY handle) { (void)::FreeLibrary(handle); }
int HsmSys::strcasecmp(const char *s1, const char *s2) { return ::_stricmp(s1, s2); }
char *HsmSys::strtok_r(char *str, const char *delim, char **saveptr) { return ::strtok_s(str, delim, saveptr); }

#else // _WIN32

HsmSys::HLIBRARY HsmSys::dlopen(const char *filename) { return ::dlopen(filename, RTLD_NOW); }
char *HsmSys::dlerror(void) { return ::dlerror(); }
void *HsmSys::dlsym(HsmSys::HLIBRARY handle, const char *symbol) { return ::dlsym(handle, symbol); }
void HsmSys::dlclose(HsmSys::HLIBRARY handle) { (void)::dlclose(handle); }
int HsmSys::strcasecmp(const char *s1, const char *s2) { return ::strcasecmp(s1, s2); }
char *HsmSys::strtok_r(char *str, const char *delim, char **saveptr) { return ::strtok_r(str, delim, saveptr); }

#endif // _WIN32

static int isrvalue0(int c) {
    return c == '_' || isalpha(c);
}

static int isrvalue(int c) {
    return c == '_' || isalnum(c);
}

// find needle within haystack (case-insensitive)
// needle must consist of rvalue chars
// if needle appears in haystack then it must be delimited by non-rvalue chars
// and/or it can appear at beginning of haystack or at end of haystack
const char *HsmSys::strcasestrrvalue(const char *haystack, const char *needle) {
    const char *p;
    int i;
    if (!haystack || !needle || !haystack[0] || !isrvalue0(needle[0]))
        return NULL;
    for (p = needle; *p; p++) {
        if (!isrvalue(*p))
            return NULL;
    }
    for (p = haystack; *p; p++) {
        for (i = 0; needle[i]; i++) {
            if (tolower(p[i]) != tolower(needle[i]))
                break;
        }
        if (!needle[i]) {
            if ( (p == haystack || !isrvalue(p[-1])) &&
                 (!p[i] || !isrvalue(p[i])) ) {
                return p;
            }
        }
    }
    return NULL;
}

// read password string securely
// return length of password on success
// return 0 or negative value on error
int HsmSys::ReadPassword(char *buffer, unsigned bufferLen) {
    char *cursor = buffer;
    unsigned cursorOffset = 0;

    fflush(stdout);
    fflush(stderr);

#if defined(_WIN32)
    {
        DWORD mode = 0;
        char currentChar = 0;

        if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) {
            return -1;
        }

        // disable terminal echo
        if (!SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode & (~(DWORD)ENABLE_ECHO_INPUT))) {
            return -1;
        }

        // loop until enter is pressed
        do {
            while (!_kbhit())
                Sleep(100);
            currentChar = _getch();
            if (currentChar != '\r') {
                if (currentChar != '\b') {
                    if ((cursorOffset + 1) < bufferLen) {
                        fprintf(stdout, "*");
                        fflush(stdout);
                        *cursor++ = currentChar;
                        cursorOffset++;
                    }
                } else {
                    // backspace is pressed
                    if (cursorOffset > 0) {
                        cursor--;
                        cursorOffset--;
                        fprintf(stdout, "\b \b");
                        fflush(stdout);
                    }
                }
            }
        } while (currentChar != '\r');

        // null terminate string
        *cursor = '\0';

        // restore terminal state
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
    }

#else // _WIN32
    {
        char termbuff[256];
        int fd = -1;
        int rc = -1;
        struct termios tio;
        cc_t old_min;
        cc_t old_time;
        char currentChar = 0;

        fd = open(ctermid(termbuff), O_RDONLY);
        if (fd == -1) {
            return -1;
        }

        rc = tcgetattr(fd, &tio);
        if (rc == -1) {
            close(fd);
            return -1;
        }

        // disable terminal echo, canonical mode
        old_min = tio.c_cc[VMIN];
        old_time = tio.c_cc[VTIME];
        tio.c_lflag = tio.c_lflag & ~ICANON & ~ECHO;
        tio.c_cc[VMIN] = 1;
        tio.c_cc[VTIME] = 0;

        rc = tcsetattr(fd, TCSADRAIN, &tio);
        if (rc == -1) {
            close(fd);
            return -1;
        }

        // loop until enter is pressed
        do {
            rc = read(fd, &currentChar, 1);
            if (rc <= 0) {
                close(fd);
                return -1;
            }
            if (currentChar != '\n') {
                if ((currentChar != '\b') && ((int)currentChar != 127)) {
                    if ((cursorOffset + 1) < bufferLen) {
                        fprintf(stdout, "*");
                        fflush(stdout);
                        *cursor++ = currentChar;
                        cursorOffset++;
                    }
                } else {
                    // backspace is pressed
                    if (cursorOffset > 0) {
                        cursor--;
                        cursorOffset--;
                        fprintf(stdout, "\b \b");
                        fflush(stdout);
                    }
                }
            }
        } while (currentChar != '\n');

        // null terminate string
        *cursor++ = '\0';

        // restore terminal state
        tio.c_lflag = tio.c_lflag | ICANON | ECHO;
        tio.c_cc[VMIN] = old_min;
        tio.c_cc[VTIME] = old_time;
        rc = tcsetattr(fd, TCSADRAIN, &tio);
        if (rc == -1) {
            close(fd);
            return -1;
        }

        close(fd);
    }
#endif // _WIN32

    // obscure password length
    for (unsigned i = cursorOffset; i < bufferLen; i++) {
        fprintf(stdout, "*");
    }
    fprintf(stdout, "\n");
    fflush(stdout);

    // final consistency check
    if ((cursorOffset >= bufferLen) || (cursorOffset < 7) || (cursorOffset != strlen(buffer))) {
        return -1;
    }

    return cursorOffset;
}

// read value string from INI file
// return length of string on success
// return 0 or negative value on error
int HsmSys::ReadIni(char *buffer, unsigned bufferLen, const char *fileName, const char *sectionName,
                            const char *valueName) {
    int returnCount = 0;

    if (!buffer || !bufferLen || !fileName || !sectionName || !valueName)
        return 0;

    if (!fileName[0] || !sectionName[0] || !valueName[0])
        return 0;

    buffer[0] = '\0';

#if defined(_WIN32)
    const char *errorName = "##ERROR##";
    DWORD dwrc = 0;

    dwrc = GetPrivateProfileStringA(sectionName, valueName, errorName, buffer, bufferLen, (char *)fileName);

    if ((dwrc < 1) || (strcmp(buffer, errorName) == 0)) {
        buffer[0] = '\0';
        returnCount = 0;
    } else {
        returnCount = (int)dwrc;
    }

#else // _WIN32
    FILE *infile = 0;
    char *p = 0;
    char inbuf[256] = { 0 };

    char *outp = 0;
    char outbuf[256] = { 0 };

    int found_section = 0;

    infile = fopen(fileName, "r");
    if (infile == NULL)
        return 0;

    // for all lines in file
    for (;;) {
        int is_section = 0;
        int is_sectionEnd = 0;
        int is_rvalue = 0;
        int is_quote = 0;
        int is_quoteEnd = 0;
        char *rvalue = 0;

        // read next line
        p = fgets(inbuf, sizeof(inbuf), infile);
        if (p == NULL)
            goto done;

        // strip away comment, end-of-line, extra space, delimiters
        for (p = inbuf, outp = outbuf; *p != '\0'; p++) {
            if (*p == ';' || *p == '\r' || *p == '\n') {
                *p = '\0';
                break;
            } else if (*p == '[') {
                if (is_rvalue || is_section)
                    goto done; // syntax error
                is_section = 1;
            } else if (*p == ']') {
                if (is_rvalue || !is_section)
                    goto done; // syntax error
                p++;
                is_sectionEnd = 1;
                break; // end section
            } else if (*p == '=') {
                if (is_section || is_rvalue)
                    goto done; // syntax error
                *outp++ = '\0';
                rvalue = outp;
                is_rvalue = 1;
            } else if (*p == '\"') {
                if (!is_rvalue)
                    goto done; // syntax error
                if (is_quote) {
                    p++;
                    is_quoteEnd = 1;
                    break; // end quote
                }
                is_quote = 1;
            } else if (isspace(*p)) {
                if (is_rvalue && is_quote) {
                    *outp++ = *p;
                }
            } else {
                *outp++ = *p;
            }
        }

        *outp = '\0';

        // any extra character (that is not a space) is a syntax error
        for (; *p != '\0'; p++) {
            if (!isspace(*p))
                goto done;
        }

        if (is_section) {
            // fprintf(stderr, "outbuf = \"%s\"\n", outbuf);
            if (!is_sectionEnd)
                goto done; // syntax error
            if (found_section)
                goto done; // sectionName was previously found but valueName was not found
            if (!HsmSys::strcasecmp(outbuf, sectionName))
                found_section = 1;
        } else if (is_rvalue) {
            // fprintf(stderr, "outbuf = \"%s\", rvalue = \"%s\"\n", outbuf, rvalue);
            if (is_quote && !is_quoteEnd)
                goto done; // syntax error
            if (found_section && !HsmSys::strcasecmp(outbuf, valueName)) {
                returnCount = (int)strlen(rvalue);
                strncpy(buffer, rvalue, bufferLen - 1);
                break;
            }
        } else if (outbuf[0] == '\0') {
            // fprintf(stderr, "empty line\n");
            // empty line
        } else {
            // fprintf(stderr, "syntax error\n");
            goto done;
        }

    } // for all lines in file

done:
    fclose(infile);
#endif // _WIN32

    HSM_INFO(("ReadIni: %s: %s: %s: \"%s\": %d", fileName, sectionName, valueName, buffer, (int)returnCount));
    return returnCount;
}
