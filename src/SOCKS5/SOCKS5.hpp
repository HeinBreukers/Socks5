#pragma once

#include "spdlog/sinks/stdout_color_sinks.h"

#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>

namespace SOCKS5
{
    class SocketAddress
    {
    public:
        SocketAddress() = default;

        [[nodiscard]] constexpr sockaddr_in GetAddressIPv4()const noexcept {return m_v4;}
        [[nodiscard]] constexpr sockaddr_in6 GetAddressIPv6()const noexcept {return m_v6;}
        [[nodiscard]] constexpr int GetDomain()const noexcept {return m_domain;}

        constexpr void SetAddressIPv4(sockaddr_in v4)noexcept {m_v4 = std::move(v4);}
        constexpr void SetAddressIPv6(sockaddr_in6 v6)noexcept {m_v6 = std::move(v6);}
        constexpr void SetDomain(int domain)noexcept {m_domain = std::move(domain);}

    private:
        sockaddr_in m_v4;
        sockaddr_in6 m_v6;
        int m_domain;
    };

    class SOCKS5Server
    {
    public:
        SOCKS5Server(const SOCKS5Server& ) = delete;
        static SOCKS5Server& Get()
        {
            return s_Instance;
        }

        static int SelectMethod(uint8_t* input, int& clientSocket) {return Get().pSelectMethod(input, clientSocket);}
        static int HandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket) {return Get().pHandleRequest(input, inputSize, clientSocket, hostSocket);}
        static void DataTransfer(int clientsocket, int hostSocket, uint8_t* buffer) {return Get().pDataTransfer(clientsocket, hostSocket, buffer);}
        static int HandleClient(int socket) {return Get().pHandleClient(socket);}
        static void SetLogger(std::shared_ptr<spdlog::logger> logger) {Get().m_logger = std::move(logger);}
        
    private:
        
        int pSelectMethod(uint8_t* input, int& clientSocket);
        int pHandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket);
        void pDataTransfer(int clientsocket, int hostSocket, uint8_t* buffer);
        int pHandleClient(int socket);

        uint8_t SetBnd(uint8_t cmd, uint8_t* output, int& outputSize);
        uint8_t SetupClient(SocketAddress& serv_addr, int& hostSocket);
        uint8_t GetDst(uint8_t* input, int inputSize, SocketAddress& serv_addr);
        const int m_bufferLength = 1024;

        std::shared_ptr<spdlog::logger> m_logger;
        SOCKS5Server():m_logger(spdlog::stdout_color_mt("SOCKS5")){m_logger->set_level(spdlog::level::info);}
        static SOCKS5Server s_Instance;
    };
}