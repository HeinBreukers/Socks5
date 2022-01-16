#ifndef SOCKS5_H
#define SOCKS5_H

#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>
#include "spdlog/sinks/stdout_color_sinks.h"


#define BUFFER_LENGTH 1024


class SOCKS5
{
public:
    SOCKS5(const SOCKS5& ) = delete;
    static SOCKS5& Get()
    {
        return s_Instance;
    }

    static int SelectMethod(uint8_t* input, int& clientSocket) {return Get().pSelectMethod(input, clientSocket);}
    static int HandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket) {return Get().pHandleRequest(input, inputSize, clientSocket, hostSocket);}
    static void DataTransfer(int clientsocket, int hostSocket, uint8_t* buffer) {return Get().pDataTransfer(clientsocket, hostSocket, buffer);}
    static int HandleClient(int socket) {return Get().pHandleClient(socket);}
    static void SetLogger(std::shared_ptr<spdlog::logger> logger) {Get().m_logger = logger;}
    
    

private:
    
    int pSelectMethod(uint8_t* input, int& clientSocket);
    int pHandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket);
    void pDataTransfer(int clientsocket, int hostSocket, uint8_t* buffer);
    int pHandleClient(int socket);

    uint8_t SetBnd(uint8_t cmd, uint8_t* output, int& outputSize);
    uint8_t SetupClient(sockaddr_in& serv_addr, int& hostSocket);
    uint8_t GetDst(uint8_t* input, int inputSize, sockaddr_in& serv_addr);
    bool linearSearch( uint8_t array[], uint8_t size, uint8_t value );

    std::shared_ptr<spdlog::logger> m_logger;
    SOCKS5():m_logger(spdlog::stdout_color_mt("SOCKS5")){m_logger->set_level(spdlog::level::info);}
    static SOCKS5 s_Instance;
};

#endif //SOCKS5_H