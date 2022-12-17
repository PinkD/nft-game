#include "netfilter.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <regex>
#include <string>
#include <vector>

extern "C" void _handleICMP(cchar_t* buf, int len);
extern "C" void _handleUDP(EID id, cchar_t* ip, u_short port, cchar_t* buf,
                           int len);
extern "C" void _handleCloseUDP(EID id);
extern "C" void _handleDialTCP(EID id, u_short localPort, cchar_t* ip,
                               u_short port);
extern "C" void _handleTCP(EID id, cchar_t* buf, int len);
extern "C" void _handleCloseTCP(EID id, u_short localPort);

std::vector<std::string> processNames;
std::vector<NF_RULE_EX> processNameRules;
std::vector<NF_RULE_EX> portRules;
std::mutex ruleLock;
std::mutex udpOptionLock;
std::map<EID, PNF_UDP_OPTIONS> udpOptions;
std::mutex udpInfoLock;
std::map<EID, PNF_UDP_CONN_INFO> udpInfo;
std::mutex tcpInfoLock;
std::map<EID, PNF_TCP_CONN_INFO> tcpInfo;

DWORD currentPid = 0;
u_short tcpProxyPort = 0;

inline u_short convert_port(u_short port) { return port >> 8 | port << 8; }

void addRule(NF_RULE_EX rule) {
    std::lock_guard<std::mutex> l(ruleLock);
    processNameRules.push_back(rule);
}

void addTCPFilterForProcess(cchar_t* name) {
    NF_RULE_EX rule;
    memset(&rule, 0, sizeof(NF_RULE_EX));
    rule.protocol = IPPROTO_TCP;
    rule.direction = NF_D_OUT;
    rule.filteringFlag = NF_INDICATE_CONNECT_REQUESTS;
    // mbstowcs(rule.processName, name, strlen(name));
    // printf("add tcp filter for process %s\n", name);
    printf("add tcp filter\n");
    addRule(rule);
}

void addUDPFilterForProcess(cchar_t* name) {
    NF_RULE_EX rule;
    memset(&rule, 0, sizeof(NF_RULE_EX));
    rule.protocol = IPPROTO_UDP;
    rule.direction = NF_D_OUT;
    rule.filteringFlag = NF_FILTER;
    // mbstowcs(rule.processName, name, strlen(name));
    // printf("add udp filter for process %s\n", name);
    printf("add udp filter\n");
    addRule(rule);
}

void addConnectionFilterForProcess(cchar_t* name) {
    processNames.push_back(name);
    addTCPFilterForProcess(name);
    addUDPFilterForProcess(name);
    fflush(stdout);
}

void addICMPFilterForProcess(cchar_t* name) {
    NF_RULE_EX rule;
    memset(&rule, 0, sizeof(NF_RULE_EX));
    rule.protocol = IPPROTO_ICMP;
    rule.direction = NF_D_OUT;
    rule.filteringFlag = NF_FILTER_AS_IP_PACKETS;
    mbstowcs(rule.processName, name, strlen(name));
    printf("add icmp filter for process %s\n", name);
    fflush(stdout);
    addRule(rule);
}

void addFilterForLoopback() {
    NF_RULE_EX rule;
    memset(&rule, 0, sizeof(NF_RULE_EX));
    rule.ip_family = AF_INET;
    auto size = 0;
    WSAStringToAddressA((LPSTR)"127.0.0.1", AF_INET, NULL,
                        (LPSOCKADDR)rule.remoteIpAddress, &size);
    WSAStringToAddressA((LPSTR)"255.0.0.0", AF_INET, NULL,
                        (LPSOCKADDR)rule.remoteIpAddressMask, &size);
    rule.filteringFlag = NF_ALLOW;
    addRule(rule);
}

void addFilterForReservedAddress() {
    auto size = 0;
    {
        /* 10.0.0.0/8 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"10.0.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.0.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }
    {
        /* 100.64.0.0/10 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"100.64.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.192.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }
    { /* 169.254.0.0/16 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"169.254.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.255.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }

    { /* 172.16.0.0/12 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"100.64.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.240.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }

    { /* 192.0.0.0/24 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"192.0.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.255.255.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }

    { /* 192.168.0.0/16 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"192.168.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.255.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }

    { /* 198.18.0.0/15 */
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.ip_family = AF_INET;
        WSAStringToAddressA((LPSTR)"198.18.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddress, &size);
        WSAStringToAddressA((LPSTR)"255.254.0.0", AF_INET, NULL,
                            (LPSOCKADDR)rule.remoteIpAddressMask, &size);
        rule.filteringFlag = NF_ALLOW;
        addRule(rule);
    }
}

void flushRules() {
    // always filter loopback and reserved address
    addFilterForLoopback();
    addFilterForReservedAddress();

    std::lock_guard<std::mutex> l(ruleLock);
    std::vector<NF_RULE_EX> rules;
    std::for_each(processNameRules.begin(), processNameRules.end(),
                  [&rules](const auto& rule) { rules.push_back(rule); });
    std::for_each(portRules.begin(), portRules.end(),
                  [&rules](const auto& rule) { rules.push_back(rule); });
    nf_setRulesEx(rules.data(), rules.size());
}

void addFilterForProcess(cchar_t* name) {
    addConnectionFilterForProcess(name);
    addICMPFilterForProcess(name);
    flushRules();
}

void operateFilterForPort(u_short port, int protocol, bool add) {
    if (port == 0) {
        printf("skip port 0\n");
        fflush(stdout);
        return;
    }
    if (add) {
        NF_RULE_EX rule;
        memset(&rule, 0, sizeof(NF_RULE_EX));
        rule.direction = NF_D_OUT;
        rule.protocol = protocol;
        rule.localPort = port;
        rule.filteringFlag = NF_FILTER_AS_IP_PACKETS;
        std::lock_guard<std::mutex> l(ruleLock);
        nf_addRuleEx(&rule, FALSE);
        portRules.push_back(rule);
        printf("add ip filter for port %d\n", port);
    } else {
        auto oldSize = portRules.size();
        {
            std::lock_guard<std::mutex> l(ruleLock);
            std::remove_if(portRules.begin(), portRules.end(),
                           [port, protocol](const auto& rule) {
                               return rule.localPort == port &&
                                      rule.protocol == protocol;
                           });
        }
        if (oldSize != portRules.size()) {
            printf("remove ip filter for port %d\n", port);
            flushRules();
        }
    }
    fflush(stdout);
}

void addFilterForPort(u_short port, int protocol) {
    operateFilterForPort(port, protocol, true);
}

void removeFilterForPort(u_short port, int protocol) {
    operateFilterForPort(port, protocol, false);
}

std::string getProcessName(DWORD id) {
    if (id == 0) {
        return "Idle";
    }

    if (id == 4) {
        return "System";
    }

    wchar_t name[MAX_PATH];
    if (!nf_getProcessNameFromKernel(id, name, MAX_PATH)) {
        if (!nf_getProcessNameW(id, name, MAX_PATH)) {
            return "Unknown";
        }
    }

    auto to_str = [](wchar_t* s) {
        auto ws = std::wstring(s);
        return std::string(ws.begin(), ws.end());
    };

    wchar_t data[MAX_PATH];
    if (GetLongPathNameW(name, data, MAX_PATH)) {
        return to_str(data);
    }
    return to_str(name);
}

bool checkProcessName(DWORD pid) {
    auto targetName = getProcessName(pid);
    // printf("name of %d is %s\n", pid, targetName.data());
    auto match = false;
    for (auto& name : processNames) {
        if (regex_search(targetName, std::regex(name))) {
            return true;
        }
    }
    return false;
}

// API events handler
void threadStart() {
    printf("threadStart\n");
    fflush(stdout);
}

void threadEnd() { printf("threadEnd\n"); }

// TCP events
void tcpConnectRequest(EID id, PNF_TCP_CONN_INFO pConnInfo) {
    auto pid = pConnInfo->processId;
    if (currentPid == pid || !checkProcessName(pid)) {
        nf_tcpDisableFiltering(id);
        return;
    }
    auto loccalAddr = (struct sockaddr_in*)pConnInfo->localAddress;
    u_short localPort = convert_port(loccalAddr->sin_port);
    printf("local ip: %d.%d.%d.%d:%d\n", loccalAddr->sin_addr.S_un.S_un_b.s_b1,
           loccalAddr->sin_addr.S_un.S_un_b.s_b2,
           loccalAddr->sin_addr.S_un.S_un_b.s_b3,
           loccalAddr->sin_addr.S_un.S_un_b.s_b4, localPort);
    struct in_addr remoteAddr;
    auto addr = (struct sockaddr_in*)pConnInfo->remoteAddress;
    memcpy(&remoteAddr, &addr->sin_addr, sizeof(remoteAddr));
    auto port = convert_port(addr->sin_port);
    printf("remote ip: %d.%d.%d.%d:%d\n", addr->sin_addr.S_un.S_un_b.s_b1,
           addr->sin_addr.S_un.S_un_b.s_b2, addr->sin_addr.S_un.S_un_b.s_b3,
           addr->sin_addr.S_un.S_un_b.s_b4, port);
    printf("tcpConnectRequest id=%I64u\n", id);
    fflush(stdout);

    if (pConnInfo->ip_family == AF_INET) {
        auto addr = (struct sockaddr_in*)pConnInfo->remoteAddress;
        addr->sin_family = AF_INET;
        addr->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
        addr->sin_port = tcpProxyPort;
        printf("redirect to 127.0.0.1:%d\n", tcpProxyPort);
    }

    if (pConnInfo->ip_family == AF_INET6) {
        auto addr = (struct sockaddr_in6*)pConnInfo->remoteAddress;
        IN6ADDR_SETLOOPBACK(addr);
        addr->sin6_port = tcpProxyPort;
        printf("redirect to [::1]:%d\n", tcpProxyPort);
    }
    fflush(stdout);
    {
        std::lock_guard<std::mutex> l(tcpInfoLock);
        tcpInfo[id] = pConnInfo;
    }
    _handleDialTCP(id, localPort, (cchar_t*)&remoteAddr, port);
}

void tcpConnected(EID id, PNF_TCP_CONN_INFO pConnInfo) {
    printf("tcpConnected id=%I64u\n", id);
    fflush(stdout);
}

void tcpClosed(EID id, PNF_TCP_CONN_INFO pConnInfo) {
    printf("tcpClosed id=%I64u\n", id);
    fflush(stdout);

    {
        std::lock_guard<std::mutex> l(tcpInfoLock);
        tcpInfo.erase(id);
    }
    struct sockaddr_in* loccalAddr =
        (struct sockaddr_in*)pConnInfo->localAddress;
    u_short localPort = convert_port(loccalAddr->sin_port);
    _handleCloseTCP(id, localPort);
}

void tcpReceive(EID id, const char* buf, int len) {
    printf("tcpReceive id=%I64u len=%d\n", id, len);
    fflush(stdout);
    nf_tcpPostReceive(id, buf, len);
}

void tcpSend(EID id, const char* buf, int len) {
    printf("tcpSend id=%I64u len=%d\n", id, len);
    fflush(stdout);
    nf_tcpPostSend(id, buf, len);
}

void tcpCanReceive(EID id) {
    // printf("tcpCanReceive id=%I64d\n", id);
    // fflush(stdout);
}

void tcpCanSend(EID id) {
    // printf("tcpCanSend id=%I64d\n", id);
    // fflush(stdout);
}

// UDP events
void udpCreated(EID id, PNF_UDP_CONN_INFO pConnInfo) {
    auto pid = pConnInfo->processId;
    if (currentPid == pid || !checkProcessName(pid)) {
        nf_udpDisableFiltering(id);
        return;
    }
    auto addr = (struct sockaddr_in*)pConnInfo->localAddress;
    auto port = convert_port(addr->sin_port);
    printf("local ip: %d.%d.%d.%d:%d\n", addr->sin_addr.S_un.S_un_b.s_b1,
           addr->sin_addr.S_un.S_un_b.s_b2, addr->sin_addr.S_un.S_un_b.s_b3,
           addr->sin_addr.S_un.S_un_b.s_b4, port);
    {
        std::lock_guard<std::mutex> l(udpInfoLock);
        udpInfo[id] = pConnInfo;
    }
    printf("udpCreated id=%I64d\n", id);
    fflush(stdout);
}

void udpConnectRequest(EID id, PNF_UDP_CONN_REQUEST pConnReq) {
    printf("udpConnectRequest id=%I64u\n", id);
    fflush(stdout);
}

void udpClosed(EID id, PNF_UDP_CONN_INFO pConnInfo) {
    printf("udpClosed id=%I64d\n", id);
    fflush(stdout);
    {
        std::lock_guard<std::mutex> l(udpOptionLock);
        auto option = udpOptions[id];
        if (option != nullptr) {
            delete option;
            udpOptions.erase(id);
        }
    }
    {
        std::lock_guard<std::mutex> l(udpInfoLock);
        udpInfo.erase(id);
    }
    _handleCloseUDP(id);
}

void udpReceive(EID id, const unsigned char* remoteAddress, const char* buf,
                int len, PNF_UDP_OPTIONS options) {
    printf("udpReceive id=%I64d\n", id);
    fflush(stdout);
    nf_udpPostReceive(id, remoteAddress, buf, len, options);
}

void udpSend(EID id, const unsigned char* remoteAddress, const char* buf,
             int len, PNF_UDP_OPTIONS options) {
    printf("udpSend id=%I64d\n", id);
    struct sockaddr_in* addr = (struct sockaddr_in*)remoteAddress;
    // ignore broadcast
    if (addr->sin_port == 0) {
        nf_udpPostSend(id, remoteAddress, buf, len, options);
        return;
    }
    {
        std::lock_guard<std::mutex> l(udpInfoLock);
        if (udpInfo.find(id) == udpInfo.end()) {
            nf_udpPostSend(id, remoteAddress, buf, len, options);
            return;
        }
    }
    u_short port = convert_port(addr->sin_port);
    {
        std::lock_guard<std::mutex> l(udpOptionLock);
        if (udpOptions.find(id) == udpOptions.end()) {
            printf("nf udp send to: %d.%d.%d.%d:%d\n",
                   addr->sin_addr.S_un.S_un_b.s_b1,
                   addr->sin_addr.S_un.S_un_b.s_b2,
                   addr->sin_addr.S_un.S_un_b.s_b3,
                   addr->sin_addr.S_un.S_un_b.s_b4, port);

            auto option = (PNF_UDP_OPTIONS) new char[sizeof(NF_UDP_OPTIONS) +
                                                     options->optionsLength]();
            memcpy(option, options,
                   sizeof(NF_UDP_OPTIONS) + options->optionsLength - 1);
            udpOptions[id] = option;
        }
    }
    _handleUDP(id, (cchar_t*)&addr->sin_addr, port, buf, len);
    fflush(stdout);
}

void udpCanReceive(EID id) {
    // printf("udpCanReceive id=%I64d\n", id);
    // fflush(stdout);
}

void udpCanSend(EID id) {
    // printf("udpCanSend id=%I64d\n", id);
    // fflush(stdout);
}

// the ip packet won't change, we only need one
PNF_IP_PACKET_OPTIONS globalOption;

// API events handler for IP packets
void ipReceive(const char* buf, int len, PNF_IP_PACKET_OPTIONS options) {
    nf_ipPostReceive(buf, len, options);
}

void ipSend(const char* buf, int len, PNF_IP_PACKET_OPTIONS options) {
    if (globalOption == NULL) {
        globalOption = options;
    }

    printf("ipSend: packet from nf\n");
    fflush(stdout);
    _handleICMP(buf, len);
}

NF_EventHandler eh = {
    threadStart, threadEnd,  tcpConnectRequest, tcpConnected,
    tcpClosed,   tcpReceive, tcpSend,           tcpCanReceive,
    tcpCanSend,  udpCreated, udpConnectRequest, udpClosed,
    udpReceive,  udpSend,    udpCanReceive,     udpCanSend,
};

NF_IPEventHandler ipeh = {
    ipReceive,
    ipSend,
};

int initDriver(cchar_t* name, u_short port) {
    printf("loading driver %s\n", name);
    NF_STATUS status = nf_init(name, &eh);
    if (status != NF_STATUS_SUCCESS) {
        printf("load return status: %d\n", status);
        return 1;
    }
    nf_setIPEventHandler(&ipeh);
    currentPid = GetCurrentProcessId();
    // convert to network port
    tcpProxyPort = convert_port(port);
    return 0;
}

void freeDriver() { nf_free(); }

void writeTCPData(EID id, cchar_t* buf, int len) {
    printf("wg write tcp to eid: %d\n", id);
    nf_tcpPostReceive(id, buf, len);
}

void writeUDPData(EID id, cchar_t* ip, u_short port, cuc_t* buf, int len) {
    printf("wg write udp to eid: %d, len is %d\n", id, len);
    fflush(stdout);
    std::lock_guard<std::mutex> l(udpOptionLock);
    auto option = udpOptions.find(id);
    if (option != udpOptions.end()) {
        struct sockaddr_in addr;
        addr.sin_addr.S_un.S_addr = inet_addr(ip);
        addr.sin_port = convert_port(port);
        printf("wg udp from ip: %d.%d.%d.%d:%d\n",
               addr.sin_addr.S_un.S_un_b.s_b1, addr.sin_addr.S_un.S_un_b.s_b2,
               addr.sin_addr.S_un.S_un_b.s_b3, addr.sin_addr.S_un.S_un_b.s_b4,
               convert_port(addr.sin_port));
        // printf("data: %02x%02x%02x%02x%02x%02x%02x%02x\n", buf[0], buf[1],
        //        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        // fflush(stdout);
        nf_udpPostReceive(id, (cuc_t*)&addr, (cchar_t*)buf, len,
                          option->second);
    }
}
