//
// Created by sma11case on 2022/12/27.
//

#include <string>



#include <sys/socket.h>  
#include <netinet/in.h>  
#include <netdb.h>       
#include <arpa/inet.h>   
#include <unistd.h>      


//#include "SCE_socks5.h"
#if __has_include(<sys/ioctl.h>)
#include <sys/ioctl.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#if defined(DEBUG)|| defined(_DEBUG)
#define socket_dbg_printf(...) printf(__VA_ARGS__)
#else
#define socket_dbg_printf(...)
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (SOCKET)(-1)
#endif

typedef int SOCKET;
typedef struct hostent * LPHOSTENT;


#define SCE_clang_diagPush()
#define SCE_clang_diagIgnore(...)
#define SCE_clang_diagPop()


class SCE_socketapi
{
public:
    decltype(::socket) *socket = ::socket;
    decltype(::connect) *connect = ::connect;
//    decltype(::listen) *listen = ::listen;
//    decltype(::accept) *accept = ::accept;
//    decltype(::bind) *bind = ::bind;
    decltype(::close) *close = ::close;
    decltype(::shutdown) *shutdown = ::shutdown;
    decltype(::send) *send = ::send;
    decltype(::recv) *recv = ::recv;
#if defined(WIN32) || defined(_WIN32)
    decltype(::closesocket) *closesocket = ::closesocket;
#endif
};

class SCE_socks5
{
public:
    SOCKET socketfd = INVALID_SOCKET;
    SCE_socketapi socketapi;

public:
    inline ssize_t send(const void *buffer, size_t len, int flags = 0) const
    {
        return this->socketapi.send(this->socketfd, (const char *)buffer, (int)len, flags);
    }

    inline ssize_t recv(void *buffer, size_t len, int flags = 0) const
    {
        return this->socketapi.recv(this->socketfd, (char *)buffer, (int)len, flags);
    }

    inline std::string recv(size_t maxlen, int flags = 0) const
    {
        std::string res;
        res.resize(maxlen);
        auto len1 = this->recv(&res.front(), res.size(), flags);
        if (len1 <= 0) return "";
        res.resize(len1);
        return res;
    }

    inline size_t available() const
    {
#if defined(WIN32) || defined(_WIN32)
        {
            unsigned long n = 0;
            if (ioctlsocket(this->socketfd, FIONREAD, &n) < 0)
            {
                /* look in WSAGetLastError() for the error code */
                socket_dbg_printf("ioctlsocket FIONREAD failed\n");
                return 0;
            }
            return n;
        }
#else
        {
            int count = 0;
            if (ioctl(this->socketfd, FIONREAD, &count) < 0)
            {
                socket_dbg_printf("ioctl FIONREAD failed\n");
                return 0;
            }

            return count;
        }
#endif
    }

public:
    template<typename ... T>
    inline void setError(const char *fmt, T ... args)
    {
        SCE_clang_diagPush()
        SCE_clang_diagIgnore("-Wformat-security")
        socket_dbg_printf(fmt, std::forward<T>(args)...);
        socket_dbg_printf("\n");
        SCE_clang_diagPop()
    }

    template<typename ... T>
    inline void setMessage(const char *fmt, T ... args)
    {
        SCE_clang_diagPush()
        SCE_clang_diagIgnore("-Wformat-security")
        socket_dbg_printf(fmt, std::forward<T>(args)...);
        socket_dbg_printf("\n");
        SCE_clang_diagPop()
    }

public:
    void set_timeout(size_t read_timeout_ms, size_t write_timeout_ms)
    {
        {
            struct timeval timeout = {0};
            timeout.tv_sec = (decltype(timeout.tv_sec))(read_timeout_ms / 1000U);
            timeout.tv_usec = (decltype(timeout.tv_usec))((read_timeout_ms % 1000U) * 1000);

            if (::setsockopt(this->socketfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
                setError("setsockopt SO_RCVTIMEO failed");
        }

        {
            struct timeval timeout = {0};
            timeout.tv_sec = (decltype(timeout.tv_sec))(write_timeout_ms / 1000U);
            timeout.tv_usec = (decltype(timeout.tv_usec))((write_timeout_ms % 1000U) * 1000);
            if (::setsockopt(this->socketfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
                setError("setsockopt SO_SNDTIMEO failed");
        }
    }

public:
    inline bool socket_close()
    {
#if defined(WIN32) || defined(_WIN32)
        closesocket(this->socketfd);
#else
        ::shutdown(this->socketfd, SHUT_RDWR);
        ::close(this->socketfd);
#endif

        this->socketfd = INVALID_SOCKET;
        return true;
    }

    inline bool socket_new(int af = AF_INET, int type = SOCK_STREAM, int protocol = 0)
    {
        this->socketfd = this->socketapi.socket(af, type, protocol);
        socket_dbg_printf("new socket: %zd\n", (ssize_t)this->socketfd);
        return this->socketfd != INVALID_SOCKET;
    }

    bool socket_connect(const char *server, uint16_t port)
    {
        // The port and server must be specified before we can connect
        if (port <= 0)
        {
            setError("Port not set for Socket_Connect_Socks5 Object");
            return false;
        }

        if (NULL == server || 0 == *server)
        {
            setError("Server Not Set for Socket_Connect_Socks5 Object");
            return false;
        }


        // we are expecting a socket that is already connected...
        // and we expect destip and destport to be valid....
        if (INVALID_SOCKET == this->socketfd)
        {
            setError("Socket is not connected yet! for Socket_Connect_Socks5 object");
            return false;
        }

#if defined(WIN32) || defined(_WIN32)
        // disable nagles algorithm
        char on[1];
        on[0] = 1;
        setsockopt(this->socketfd, IPPROTO_TCP, TCP_NODELAY, on, sizeof(on));
#endif

        struct sockaddr_in peer = {0};
        LPHOSTENT he = gethostbyname(server);
        if (he == NULL)
        {
            setError("Could not resolve domain");
            return false;
        }
        peer.sin_family = AF_INET;
        peer.sin_port = htons(port);
        peer.sin_addr = *(struct in_addr *)he->h_addr_list[0];
        auto rc = this->socketapi.connect(this->socketfd, (const struct sockaddr *)&peer, sizeof(peer));
        if (rc != 0)
        {
            setError("Could not connect server");
            return false;
        }

        socket_dbg_printf("socket with socket: %zd, dest: %s:%u\n", (ssize_t)this->socketfd, server, port);
        return true;
    }

public:
    bool socks5_connect(const char *server, uint16_t port, const char *s5_server, uint16_t s5_port, const char *s5_user, const char *s5_password)
    {
        decltype(this->socketfd)& s = this->socketfd;
        socket_dbg_printf("socks5 with socket: %zd, dest: %s:%u\n", (ssize_t)s, server, port);

        // The port and server must be specified before we can connect
        if (port <= 0)
        {
            setError("Port not set for Socket_Connect_Socks5 Object");
            return false;
        }

        if (NULL == server || 0 == *server)
        {
            setError("Server Not Set for Socket_Connect_Socks5 Object");
            return false;
        }


        // we are expecting a socket that is already connected...
        // and we expect destip and destport to be valid....
        if (INVALID_SOCKET == s)
        {
            setError("Socket is not connected yet! for Socket_Connect_Socks5 object");
            return false;
        }

        if (false == this->socket_connect(s5_server, s5_port)) return false;
        setMessage("Socks 5 establishing connection");

        // configure communication object
//        d_socketcomm.bind(s);
//        d_socketcomm.setTimeout(getTimeoutSecs(), getTimeoutMicroSecs());

        // Negotiate with Socks Server
        // see RFC 1928
        setMessage("Socks 5 sending version method");

        /*
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        */

        uint8_t d_buffer[1024];
        // STEP 1. send version ID and Method selections
        d_buffer[0] = 0x05;    // version 5
        d_buffer[1] = 0x02;    // we're including two methods
        d_buffer[2] = 0x00;    // no auth required method
        d_buffer[3] = 0x02;    // username / password method

        // ALLOWED METHODS
        //    o  X'00' NO AUTHENTICATION REQUIRED
        //    o  X'01' GSSAPI (RFC 1961)
        //    o  X'02' USERNAME/PASSWORD (RFC 1929)
        //    o  X'03' to X'7F' IANA ASSIGNED
        //    o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        //	   o  X'FF' NO ACCEPTABLE METHODS


//        int rc = d_socketcomm.send(d_buffer, 4);
        auto rc = this->send(d_buffer, 4, MSG_NOSIGNAL);
        if (rc <= 0)
        {
            setError("Socket_Connect_Socks5::simpleConnect() failed. Could not send version/method");
            return false;
        }

        setMessage("Socks5 reading response");

        /*
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        */

        // STEP 2. The server selects from one of the methods given in METHODS, and
        // sends a METHOD selection message (2 octets):
//        rc = d_socketcomm.read(d_buffer, 2);
        rc = this->recv(d_buffer, 2, MSG_NOSIGNAL | MSG_WAITALL);
        if (rc < 2)
        {
            setError("invalid socks5 response");
            return false;
        }


        // check version
        if (d_buffer[0] != 0x05)
        {
            setError("Socks Server returned bad version");
            return false;
        }

        // check method
        if (d_buffer[1] == 0xff)
        {
            setError("Socks Server rejected our suggested methods");
            return false;
        }


        // check for username/password
        if (d_buffer[1] == 0x02)
        {
            /*
            +----+------+----------+------+----------+
            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            +----+------+----------+------+----------+
            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            +----+------+----------+------+----------+
            */

            // perform username / password authentication
            // described in RFC 1929
            std::string d_username = (s5_user ? s5_user : "");
            std::string d_password = (s5_password ? s5_password : "");

            int x = 0;
            auto ulen = d_username.size();
            auto plen = d_password.size();
            d_buffer[x++] = 0x01;    // version 1
            d_buffer[x++] = ulen;
            for (int y = 0; y < ulen; y++)
            {
                d_buffer[x++] = d_username.c_str()[y];
            }
            d_buffer[x++] = plen;
            for (int y = 0; y < plen; y++)
            {
                d_buffer[x++] = d_password.c_str()[y];
            }

            setMessage("Socks5 sending username/ password authentication");

//            int rc = d_socketcomm.send(d_buffer, x);
            rc = this->send(d_buffer, x, MSG_NOSIGNAL);
            if (rc <= 0)
            {
                setError("Socket_Connect_Socks5::simpleConnect() failed. Could not send username/password");
                return false;
            }

            // STEP 2. The server returns 0 if username/password are correct
            // (2 octets):
            //
            setMessage("Socks5 reading authentication response");

            /*
            +----+--------+
            |VER | STATUS |
            +----+--------+
            | 1  |   1    |
            +----+--------+
            */

//            rc = d_socketcomm.read(d_buffer, 2);
            rc = this->recv(d_buffer, 2, MSG_NOSIGNAL | MSG_WAITALL);
            if (rc < 2)
            {
                char status[80];
                snprintf(status, sizeof(status), "Could not read authentication response, received %zd bytes instead of 2", rc);
                setError(status);
                return false;
            }

            // check status
            if (d_buffer[1] != 0x00)
            {
                setError("Socks Server rejected username / password");
                return false;
            }
        }

        // STEP 3
        // we've been authenticated, now send connection instructions...
        setMessage("Socks5 sending connection instructions");

        /*
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */

        int x = 0;
        auto servlen = strlen(server);
        d_buffer[x++] = 0x05;    // version 5
        d_buffer[x++] = 0x01;    // Connect
        d_buffer[x++] = 0x00;    // reserved
        d_buffer[x++] = 0x03;    // address type


        //       o  IP V4 address: X'01'
        //       o  DOMAINNAME: X'03'
        //       o  IP V6 address: X'04'
        d_buffer[x++] = servlen;
        for (int y = 0; y < servlen; y++)
        {
            d_buffer[x++] = server[y];
        }
        d_buffer[x++] = (port / 256); // high bits of port
        d_buffer[x++] = (port % 256); // low bits of port


//        rc = d_socketcomm.send(d_buffer, x);
        rc = this->send(d_buffer, x, MSG_NOSIGNAL);
        if (rc <= 0)
        {
            setError("Socket_Connect_Socks5::simpleConnect() failed. Could not send connection instructions");
            return false;
        }


        // STEP 4. The server returns evaluation results

        /*
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */


//        rc = d_socketcomm.read(d_buffer, 2);
        rc = this->recv(d_buffer, 2, MSG_NOSIGNAL | MSG_WAITALL);
        if (rc < 2)
        {
//            setError(d_socketcomm.getError());
            // error ....
            setError("Could not read Socks Cap servers evaluation response 1 (timed out?)");
            return false;
        }

        auto reponsecode = d_buffer[1];
        //       o  X'00' succeeded
        //       o  X'01' general SOCKS server failure
        //       o  X'02' connection not allowed by ruleset
        //       o  X'03' Network unreachable
        //       o  X'04' Host unreachable
        //       o  X'05' Connection refused
        //       o  X'06' TTL expired
        //       o  X'07' Command not supported
        //       o  X'08' Address type not supported
        //       o  X'09' to X'FF' unassigned

//        rc = d_socketcomm.read(d_buffer, 2);
        rc = this->recv(d_buffer, 2, MSG_NOSIGNAL | MSG_WAITALL);
        if (rc < 2)
        {
            // error ....
            setError("Could not read Socks Cap servers evaluation response 2 (timed out?)");
            return false;
        }

        // now we need to read in the rest of the server's response data
        // X'00' |  1   | Variable |    2
        // o  IP V4 address: X'01'
        // o  DOMAINNAME: X'03'
        // o  IP V6 address: X'04'

        if (d_buffer[1] == 0x01)
        {
//            d_socketcomm.read(d_buffer, 6);
            this->recv(d_buffer, 6, MSG_NOSIGNAL | MSG_WAITALL);
        }
        else if (d_buffer[1] == 0x03)
        {
//            d_socketcomm.read(d_buffer, 1);
//            d_socketcomm.read(d_buffer, (d_buffer[0] + 2));

            this->recv(d_buffer, 1, MSG_NOSIGNAL | MSG_WAITALL);
            this->recv(d_buffer, (d_buffer[0] + 2), MSG_NOSIGNAL | MSG_WAITALL);
        }
        else if (d_buffer[1] == 0x04)
        {
            // read in 18
//            d_socketcomm.read(d_buffer, 18);
            this->recv(d_buffer, 18, MSG_NOSIGNAL | MSG_WAITALL);
        }

        switch (reponsecode)
        {
        case 0x00:setMessage("Socks 5 Connected!");
            return true;
        case 0x01:setError("general SOCKS server failure");
            return false;
        case 0x02:setError("connection not allowed by ruleset");
            return false;
        case 0x03:setError("Network unreachable");
            return false;
        case 0x04:setError("Host unreachable");
            return false;
        case 0x05:setError("Connection refused");
            return false;
        case 0x06:setError("TTL expired");
            return false;
        case 0x07:setError("Command not supported");
            return false;
        case 0x08:setError("Address type not supported");
            return false;
        default:setError("Unknown Error");
            return false;
        }
    }
};

