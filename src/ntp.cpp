/* Copyright (c) 2015 NovaCoin Developers
 * Copyright (c) 2018 John Doering <ghostlander@orbitcoin.org>
 */

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include "netbase.h"
#include "net.h"
#include "ui_interface.h"

using namespace std;

extern int GetRandInt(int nMax);

/*
 * NTP uses two fixed point formats.  The first (l_fp) is the "long"
 * format and is 64 bits long with the decimal between bits 31 and 32.
 * This is used for time stamps in the NTP packet header (in network
 * byte order) and for internal computations of offsets (in local host
 * byte order). We use the same structure for both signed and unsigned
 * values, which is a big hack but saves rewriting all the operators
 * twice. Just to confuse this, we also sometimes just carry the
 * fractional part in calculations, in both signed and unsigned forms.
 * Anyway, an l_fp looks like:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Integral Part                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Fractional Part                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * REF http://www.eecis.udel.edu/~mills/database/rfc/rfc2030.txt
 */

typedef struct {
    union {
        uint32_t Xl_ui;
        int32_t Xl_i;
    } Ul_i;
    union {
        uint32_t Xl_uf;
        int32_t Xl_f;
    } Ul_f;
} l_fp;

/* Converts NTP time value to UNIX time value;
 * NTP time base is 01-Jan-1900, UNIX time base is 01-Jan-1970 */
inline void Ntp2Unix(const uint32_t &n, time_t &u) {
    u = n - 0x83AA7E80;
}

inline void ntohl_fp(l_fp *n, l_fp *h) {
    (h)->Ul_i.Xl_ui = ntohl((n)->Ul_i.Xl_ui);
    (h)->Ul_f.Xl_uf = ntohl((n)->Ul_f.Xl_uf);
}

struct pkt {
    uint8_t li_vn_mode;       /* leap indicator, version and mode */
    uint8_t stratum;          /* peer stratum */
    uint8_t ppoll;            /* peer poll interval */
    int8_t precision;         /* peer clock precision */
    uint32_t rootdelay;       /* distance to primary clock */
    uint32_t rootdispersion;  /* clock dispersion */
    uint32_t refid;           /* reference clock ID */
    l_fp ref;                 /* time peer clock was last updated */
    l_fp org;                 /* originate time stamp */
    l_fp rec;                 /* receive time stamp */
    l_fp xmt;                 /* transmit time stamp */
    uint32_t exten[1];        /* unused */
    uint8_t mac[5 * sizeof(uint32_t)];
};

const uint nServersCount = 135;

std::string NtpServers[nServersCount] = {

    "time.apple.com",
    "time.windows.com",
    "time1.google.com",
    "time2.google.com",
    "time3.google.com",
    "time4.google.com",
    "clock.sjc.he.net",
    "clock.nyc.he.net",

    /* Russia */
    "0.ru.pool.ntp.org",
    "1.ru.pool.ntp.org",
    "2.ru.pool.ntp.org",
    "3.ru.pool.ntp.org",
    "ntp1.stratum1.ru",
    "ntp2.stratum1.ru",
    "ntp3.stratum1.ru",
    "ntp4.stratum1.ru",
    "ntp5.stratum1.ru",
    "ntp1.stratum2.ru",
    "ntp2.stratum2.ru",
    "ntp3.stratum2.ru",
    "ntp4.stratum2.ru",
    "ntp5.stratum2.ru",
    "ntp1.vniiftri.ru",
    "ntp2.vniiftri.ru",
    "ntp3.vniiftri.ru",
    "ntp4.vniiftri.ru",
    "ntp21.vniiftri.ru",
    "ntp1.niiftri.irkutsk.ru",
    "ntp2.niiftri.irkutsk.ru",
    "vniiftri.khv.ru",
    "vniiftri2.khv.ru",
    "ntp.ix.ru",

    /* United States */
    "0.us.pool.ntp.org",
    "1.us.pool.ntp.org",
    "2.us.pool.ntp.org",
    "3.us.pool.ntp.org",
    "time.nist.gov",
    "time-a.nist.gov",
    "time-b.nist.gov",
    "time-c.nist.gov",
    "time-d.nist.gov",
    "time-nw.nist.gov",
    "ntp1.bu.edu",
    "ntp2.bu.edu",
    "ntp3.bu.edu",
    "ntp-1.ece.cmu.edu",
    "ntp-2.ece.cmu.edu",
    "ntp-3.ece.cmu.edu",
    "ntp1.cs.wisc.edu",
    "ntp2.cs.wisc.edu",
    "ntp3.cs.wisc.edu",
    "ntp4.cs.wisc.edu",
    "ntp-01.caltech.edu",
    "ntp-02.caltech.edu",
    "ntp-03.caltech.edu",
    "ntp-04.caltech.edu",
    "utcnist.colorado.edu",
    "utcnist2.colorado.edu",
    "tick.cs.unlv.edu",
    "tock.cs.unlv.edu",
    "tick.cs.columbia.edu",
    "tock.cs.columbia.edu",
    "otc1.psu.edu",
    "otc2.psu.edu",
    "now.okstate.edu",
    "ntp.colby.edu",
    "bonehed.lcs.mit.edu",
    "ntp-s1.cise.ufl.edu",

    /* South Africa */
    "0.za.pool.ntp.org",
    "1.za.pool.ntp.org",
    "2.za.pool.ntp.org",
    "3.za.pool.ntp.org",
    "tick.meraka.csir.co.za",
    "tock.meraka.csir.co.za",
    "ntp1.meraka.csir.co.za",
    "ntp2.meraka.csir.co.za",
    "ntp.is.co.za",
    "ntp2.is.co.za",

    /* United Kingdom */
    "0.uk.pool.ntp.org",
    "1.uk.pool.ntp.org",
    "2.uk.pool.ntp.org",
    "3.uk.pool.ntp.org",
    "ntppub.le.ac.uk",
    "ntp.cis.strath.ac.uk",
    "ntp.exnet.com",

    /* Canada */
    "0.ca.pool.ntp.org",
    "1.ca.pool.ntp.org",
    "2.ca.pool.ntp.org",
    "3.ca.pool.ntp.org",
    "tick.utoronto.ca",
    "tock.utoronto.ca",
    "chime.utoronto.ca",
    "time.nrc.ca",
    "timelord.uregina.ca",

    /* Japan */
    "0.jp.pool.ntp.org",
    "1.jp.pool.ntp.org",
    "2.jp.pool.ntp.org",
    "3.jp.pool.ntp.org",
    "ntp.nict.jp",

    /* Australia */
    "0.au.pool.ntp.org",
    "1.au.pool.ntp.org",
    "2.au.pool.ntp.org",
    "3.au.pool.ntp.org",
    "ntp.unimelb.edu.au",
    "ntp.adelaide.edu.au",

    /* Italy */
    "0.it.pool.ntp.org",
    "1.it.pool.ntp.org",
    "2.it.pool.ntp.org",
    "3.it.pool.ntp.org",
    "ntp0.inrim.it",
    "ntp1.inrim.it",
    "ntp2.inrim.it",

    /* Netherlands */
    "0.nl.pool.ntp.org",
    "1.nl.pool.ntp.org",
    "2.nl.pool.ntp.org",
    "3.nl.pool.ntp.org",
    "ntp.utwente.nl",

    /* Austria */
    "0.at.pool.ntp.org",
    "1.at.pool.ntp.org",
    "2.at.pool.ntp.org",
    "3.at.pool.ntp.org",

    /* Germany */
    "0.de.pool.ntp.org",
    "1.de.pool.ntp.org",
    "2.de.pool.ntp.org",
    "3.de.pool.ntp.org",

    /* Poland */
    "0.pl.pool.ntp.org",
    "1.pl.pool.ntp.org",
    "2.pl.pool.ntp.org",
    "3.pl.pool.ntp.org",

    /* Mexico */
    "0.mx.pool.ntp.org",
    "1.mx.pool.ntp.org",
    "2.mx.pool.ntp.org",

    /* Brazil */
    "0.br.pool.ntp.org",
    "1.br.pool.ntp.org",
    "2.br.pool.ntp.org",

};

bool InitWithHost(const std::string &strHostName, SOCKET &sockfd, socklen_t &servlen,
  struct sockaddr *pcliaddr) {
    uint i;

    sockfd = INVALID_SOCKET;

    std::vector<CNetAddr> vIP;
    bool fRet = LookupHost(strHostName.c_str(), vIP, 10, true);
    if(!fRet) return(false);

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(123);

    bool found = false;
    for(i = 0; i < vIP.size(); i++) {
        if((found = vIP[i].GetInAddr(&servaddr.sin_addr)) != false)
          break;
    }

    if(!found) return(false);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd == INVALID_SOCKET)
      return(false);

    if(connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1)
      return(false);

    *pcliaddr = *((struct sockaddr *) &servaddr);
    servlen = sizeof(servaddr);

    return(true);
}

bool InitWithRandom(SOCKET &sockfd, socklen_t &servlen, struct sockaddr *pcliaddr) {
    uint i;

    for(i = 0; i < nServersCount; i++) {
        int nServerNum = GetRandInt(nServersCount);
        if(InitWithHost(NtpServers[nServerNum], sockfd, servlen, pcliaddr))
          return(true);
    }

    return(false);
}

int64 DoReq(SOCKET sockfd, socklen_t servlen, struct sockaddr cliaddr) {

#ifdef WIN32
    u_long nOne = 1;
    if(ioctlsocket(sockfd, FIONBIO, &nOne) == SOCKET_ERROR) {
        printf("ConnectSocket() : ioctlsocket non-blocking setting failed, error %d\n",
          WSAGetLastError());
#else
    if(fcntl(sockfd, F_SETFL, O_NONBLOCK) == SOCKET_ERROR) {
        printf("ConnectSocket() : fcntl non-blocking setting failed, error %d\n", errno);
#endif
        return(-2);
    }

    struct timeval timeout = {10, 0};
    struct pkt *msg = new pkt;
    struct pkt *prt = new pkt;
    int ret, len = 48;
    time_t seconds;

    msg->li_vn_mode = 227;
    msg->stratum = 0;
    msg->ppoll = 4;
    msg->precision = 0;
    msg->rootdelay = 0;
    msg->rootdispersion = 0;

    msg->ref.Ul_i.Xl_i = 0;
    msg->ref.Ul_f.Xl_f = 0;
    msg->org.Ul_i.Xl_i = 0;
    msg->org.Ul_f.Xl_f = 0;
    msg->rec.Ul_i.Xl_i = 0;
    msg->rec.Ul_f.Xl_f = 0;
    msg->xmt.Ul_i.Xl_i = 0;
    msg->xmt.Ul_f.Xl_f = 0;

    ret = sendto(sockfd, (char *) msg, len, 0, &cliaddr, servlen);
    if(ret < 0) {
        printf("sendto() failed: %d\n", ret);
        delete(msg);
        delete(prt);
        return(-3);
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);

    ret = select(sockfd + 1, &fdset, NULL, NULL, &timeout);
    if(ret <= 0) {
        printf("select() failed: %d\n", ret);
        delete(msg);
        delete(prt);
        return(-4);
    }

    recvfrom(sockfd, (char *) msg, len, 0, NULL, NULL);
    ntohl_fp(&msg->xmt, &prt->xmt);
    Ntp2Unix(prt->xmt.Ul_i.Xl_ui, seconds);

    delete(msg);
    delete(prt);
    return(seconds);
}

int64 NtpGetTime(CNetAddr &ip) {
    int64 nTime;
    SOCKET sockfd;
    socklen_t servlen;
    struct sockaddr cliaddr;

    if(!InitWithRandom(sockfd, servlen, &cliaddr))
      return(-1);

    ip = CNetAddr(((sockaddr_in *) &cliaddr)->sin_addr);

    printf("NtpGetTime() : querying an NTP server %s\n", ip.ToStringIP().c_str());

    nTime = DoReq(sockfd, servlen, cliaddr);

    closesocket(sockfd);

    if((nTime > 0) && (nTime != 2085978496)) {
        printf("NtpGetTime() : time sample %" PRI64d " offset %+" PRI64d " received from %s\n",
          nTime, nTime - GetTime(), ip.ToStringIP().c_str());
    }

    return(nTime);
}

int64 NtpGetTime(const std::string &strHostName) {
    int64 nTime;
    SOCKET sockfd;
    socklen_t servlen;
    struct sockaddr cliaddr;

    if(!InitWithHost(strHostName, sockfd, servlen, &cliaddr))
      return(-1);

    CNetAddr ip = ((sockaddr_in *) &cliaddr)->sin_addr;
    printf("NtpGetTime() : querying an NTP server %s\n", ip.ToStringIP().c_str());

    nTime = DoReq(sockfd, servlen, cliaddr);

    closesocket(sockfd);

    if((nTime > 0) && (nTime != 2085978496)) {
        printf("NtpGetTime() : time sample %" PRI64d " offset %+" PRI64d " received from %s\n",
          nTime, nTime - GetTime(), ip.ToStringIP().c_str());
    }

    return(nTime);
}

/* The trusted NTP server */
std::string strTrustedNTP = "localhost";

/* Current NTP to system time difference */
int64 nNtpOffset = INT64_MAX;

/* Critical NTP to system time mismatch */
bool fNtpWarning = false;

void ThreadNtpPoller(void *parg) {
    int i;
    int64 nTime, nSystemTime;

    printf("ThreadNtpPoller started\n");
    vnThreadsRunning[THREAD_NTP]++;

    /* Make this thread recognisable */
    RenameThread("orb-ntppoll");

    while(!fShutdown) {
        if(strTrustedNTP != "localhost") {

            /* Obtain a time sample from a trusted NTP server */
            nTime = NtpGetTime(strTrustedNTP);

            nSystemTime = GetTime();

            /* Calculate a time offset */
            if((nTime > 0) && (nTime != 2085978496))
              nNtpOffset = nTime - nSystemTime;
            else {
                printf("ThreadNtpPoller() : invalid response from the trusted NTP server %s, "
                  "fail over to a random NTP server\n", strTrustedNTP.c_str());
                nNtpOffset = INT64_MAX;
                strTrustedNTP = "localhost";
                continue;
            }

        } else {

            CNetAddr ip;

            /* Obtain a time sample from a random NTP server */
            nTime = NtpGetTime(ip);

            nSystemTime = GetTime();

            /* Calculate a time offset */
            if((nTime > 0) && (nTime != 2085978496))
              nNtpOffset = nTime - nSystemTime;
            else {
                int nSleepMinutes = 1 + GetRandInt(9);
                for(i = 0; (i < nSleepMinutes * 60) && !fShutdown; i++)
                  MilliSleep(1000);
                continue;
            }

        }

        /* Issue a warning if the system time is way off */
        if(!fNtpWarning && (abs64(nNtpOffset) > 5 * 60)) {
            fNtpWarning = true;
            string strMessage = _("Warning: Please check your date and time! Halcyon will not work properly if they are incorrect.");
            strMiscWarning = strMessage;
            printf("*** %s\n", strMessage.c_str());
            uiInterface.ThreadSafeMessageBox(strMessage+" ", string("Halcyon"),
              CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION);
        }

        /* Remove the warning if back to normal */
        if(fNtpWarning && (abs64(nNtpOffset) <= 5 * 60)) {
            strMiscWarning.clear();
            fNtpWarning = false;
        }

        int nSleepHours = 1 + GetRandInt(5);

        printf("ThreadNtpPoller() : nNtpOffset = %+" PRI64d " seconds, "
          "the next sync in %d hours\n", nNtpOffset, nSleepHours);

        for(i = 0; (i < nSleepHours * 60 * 60) && !fShutdown; i++)
          MilliSleep(1000);

    }

    vnThreadsRunning[THREAD_NTP]--;
    printf("ThreadNtpPoller exited\n");
}
