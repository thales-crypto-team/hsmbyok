##############################################################################
#
# Copyright (c) 2019-2020 SafeNet. All rights reserved.
#
# This file contains information that is proprietary to SafeNet and may not be
# distributed or copied without written consent from SafeNet.
#
##############################################################################

CC=g++
CCDEFS=
#CCDEFS=-DLUNA_HAVE_MASTER_KEY -DLUNA_NO_SESSION_OBJECTS
CCINCLUDES=-I linux64-x86/include
CCFLAGS=-m64 -Wall -Werror $(CCDEFS) $(CCINCLUDES)

LD=g++
LDFLAGS=-m64
LDFLAGS_END=-ldl linux64-x86/lib/libcrypto.a

all: prep HsmByok.o HsmKeyPair.o HsmSecretKey.o HsmConfig.o HsmUtils.o Base64.o HsmSys.o
	$(LD) $(LDFLAGS) -o hsmbyok HsmByok.o HsmKeyPair.o HsmSecretKey.o HsmConfig.o HsmUtils.o Base64.o HsmSys.o $(LDFLAGS_END)
	file hsmbyok
	ldd -r hsmbyok

HsmByok.o: HsmByok.cpp
	$(CC) $(CCFLAGS) -c -o HsmByok.o HsmByok.cpp

HsmKeyPair.o: HsmKeyPair.cpp
	$(CC) $(CCFLAGS) -c -o HsmKeyPair.o HsmKeyPair.cpp

HsmSecretKey.o: HsmSecretKey.cpp
	$(CC) $(CCFLAGS) -c -o HsmSecretKey.o HsmSecretKey.cpp

HsmConfig.o: HsmConfig.cpp
	$(CC) $(CCFLAGS) -c -o HsmConfig.o HsmConfig.cpp

HsmUtils.o: HsmUtils.cpp
	$(CC) $(CCFLAGS) -c -o HsmUtils.o HsmUtils.cpp

Base64.o: Base64.cpp
	$(CC) $(CCFLAGS) -c -o Base64.o Base64.cpp

HsmSys.o: HsmSys.cpp
	$(CC) $(CCFLAGS) -c -o HsmSys.o HsmSys.cpp

clean:
	rm -f hsmbyok
	rm -f HsmByok.o HsmKeyPair.o HsmSecretKey.o HsmConfig.o HsmUtils.o Base64.o HsmSys.o

cleanall: clean
	rm -rf linux64-x86

prep:
	if [ ! -d linux64-x86 ]; then tar xzvf ../openssl/linux64-x86-openssl-1.0.2m.tar.gz ; fi

