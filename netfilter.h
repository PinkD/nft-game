#ifndef _NF_H_
#define _NF_H_

#define _C_API

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>

#include "nfapi.h"
#include "nfdriver.h"
#include "nfevents.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef const char cchar_t;
typedef const unsigned char cuc_t;
typedef ENDPOINT_ID EID;

int initDriver(cchar_t* name, u_short port);
void freeDriver();

void addFilterForProcess(cchar_t* name);
void writeTCPData(EID id, cchar_t* buf, int len);
// TODO: support ipv6
void writeUDPData(EID id, cchar_t* ip, u_short port, cuc_t* buf, int len);
void tcpConnected(EID id);

#ifdef __cplusplus
}
#endif

#endif
