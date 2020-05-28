##############################################################################
#
# Copyright (c) 2019 SafeNet. All rights reserved.
#
# This file contains information that is proprietary to SafeNet and may not be
# distributed or copied without written consent from SafeNet.
#
##############################################################################

APPNAME=hsmbyok

CC=cl
CCDEFS=-DWIN32 -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE
CCINCLUDES=-I win64-x86/include
CCFLAGS=/MD /Ox /O2 /Ob2 /W3 /WX /Gs0 /GF /Gy /nologo /EHsc $(CCDEFS) $(CCINCLUDES)

LD=LINK
LDFLAGS=/machine:amd64
LDFLAGS_END=user32.lib gdi32.lib advapi32.lib win64-x86/lib/libeay32.lib

all: prep HsmByok.obj HsmKeyPair.obj HsmSecretKey.obj HsmConfig.obj HsmUtils.obj Base64.obj HsmSys.obj
	$(LD) $(LDFLAGS) HsmByok.obj HsmKeyPair.obj HsmSecretKey.obj HsmConfig.obj HsmUtils.obj Base64.obj HsmSys.obj /out:$(APPNAME).exe $(LDFLAGS_END)
	if exist $(APPNAME).exe.manifest mt.exe -nologo -manifest $(APPNAME).exe.manifest -outputresource:$(APPNAME).exe;1

HsmByok.obj: HsmByok.cpp
	$(CC) $(CCFLAGS) /c HsmByok.cpp

HsmKeyPair.obj: HsmKeyPair.cpp
	$(CC) $(CCFLAGS) /c HsmKeyPair.cpp

HsmSecretKey.obj: HsmSecretKey.cpp
	$(CC) $(CCFLAGS) /c HsmSecretKey.cpp

HsmConfig.obj: HsmConfig.cpp
	$(CC) $(CCFLAGS) /c HsmConfig.cpp

HsmUtils.obj: HsmUtils.cpp
	$(CC) $(CCFLAGS) /c HsmUtils.cpp

Base64.obj: Base64.cpp
	$(CC) $(CCFLAGS) /c Base64.cpp

HsmSys.obj: HsmSys.cpp
	$(CC) $(CCFLAGS) /c HsmSys.cpp

clean:
	rm -f $(APPNAME).exe
	if exist $(APPNAME).exe.manifest rm -f $(APPNAME).exe.manifest
	rm -f HsmByok.obj HsmKeyPair.obj HsmSecretKey.obj HsmConfig.obj HsmUtils.obj Base64.obj HsmSys.obj

cleanall: clean
	rm -rf win64-x86

prep:
	if not exist win64-x86 tar xzvf ..\openssl\win64-x86-openssl-1.0.2m.tar.gz
