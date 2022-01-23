#include "SOCKS5.hpp"

namespace SOCKS5
{
    SOCKS5Server SOCKS5Server::s_Instance;

    // TODO make return consistent with other methods
    uint8_t SOCKS5Server::SetupClient(SocketAddress& serv_addr, int& hostSocket)
    {
        // Connect with destination address
        if(serv_addr.GetDomain() == AF_INET)
        {
            if ((hostSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                m_logger->error("ThreadID {0}: Unable to create socket to connect to host", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return 0x01;
            }   
            auto addr = serv_addr.GetAddressIPv4();
            if (connect(hostSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
            {
                m_logger->error("ThreadID {0}: IPv4 Socket unable to connect to host", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return 0x05;
            }
        }
        else if (serv_addr.GetDomain() == AF_INET6)
        {
            if ((hostSocket = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
            {
                m_logger->error("ThreadID {0}: Unable to create socket to connect to host", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return 0x01;
            }  
            auto addr = serv_addr.GetAddressIPv6();
            if (connect(hostSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
            {		
                m_logger->error("ThreadID {0}: IPv6 Socket unable to connect to host", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return 0x05;
            }
        }
        return 0x00;
    }

    // TODO make return consistent with other methods
    uint8_t SOCKS5Server::SetBnd(uint8_t cmd, uint8_t* output, int& outputSize)
    {
        // Currently only CMD Connect 0x01 is supported
        if(cmd == 0x01)
        {
            // 
            std::memset(&output[4], 0 , 6);
            outputSize = 10;
            return 0x00;
        }
        
        m_logger->error("ThreadID {0}: Currently only CONNECT cmd supported", std::hash<std::thread::id>{}(std::this_thread::get_id()));
        return 0x07;
    }

    // TODO make return consistent with other methods
    uint8_t SOCKS5Server::GetDst(uint8_t* input, int inputSize, SocketAddress& serv_addr)
    {
        // IPv4     
        if(input[3]==0x01)
        {
            sockaddr_in ipv4Address;
            //m_logger->info("ThreadID {0}: IPv4", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            if(inputSize != 10)
            {
                m_logger->error("ThreadID {0}: Invalid IPv4 address", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return 0x01;
            }
            ipv4Address.sin_family = AF_INET;
            std::memcpy(&(ipv4Address.sin_port), &input[inputSize-2], 2);
            std::memcpy(&(ipv4Address.sin_addr), &input[4], 4);  
            serv_addr.SetAddressIPv4(std::move(ipv4Address));
            serv_addr.SetDomain(AF_INET);
            return 0x00;
        }
        // DNS
        // TODO review
        if(input[3]==0x03)
        {
            m_logger->error("ThreadID {0}: DNS request currenlty not supported", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return 0x08;
        }
        // IPv6
        if(input[3] == 0x04)
        {
            sockaddr_in6 ipv6Address;
            if(inputSize != 22)
            {
                m_logger->error("ThreadID {0}: Invalid IPv6 address", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return 0x01;
            }
            ipv6Address.sin6_family = AF_INET6;
            std::memcpy(&(ipv6Address.sin6_port), &input[inputSize-2], 2);
            std::memcpy(&(ipv6Address.sin6_addr), &input[4], 16);  
            serv_addr.SetAddressIPv6(std::move(ipv6Address));
            serv_addr.SetDomain(AF_INET6);
            return 0x00;
        }
        // TODO investigate what value of atyp reaches this stage
        m_logger->error("ThreadID {0}: Invalid Atyp", std::hash<std::thread::id>{}(std::this_thread::get_id()));
        return 0x08;
    }

    int SOCKS5Server::pSelectMethod(uint8_t* input, int& clientSocket)
    {
        //std::array<uint8_t, 2> arr;
        uint8_t sendArray[2];
        int sendSize = 2;
        sendArray[0] = 0x05;
        sendArray[1] = 0xFF;

    //      Input:
    //      +----+----------+----------+
    //      |VER | NMETHODS | METHODS  |
    //      +----+----------+----------+
    //      | 1  |    1     | 1 to 255 |
    //      +----+----------+----------+

    //      Output:
    //      +----+--------+
    //      |VER | METHOD |
    //      +----+--------+
    //      | 1  |   1    |
    //      +----+--------+

        // Check if SOCKS VER = 5
        if(input[0] != 0x05)
        {
            send(clientSocket, sendArray, sendSize, 0 );
            m_logger->error("ThreadID {0}: Socks method request version is not 5", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return -1;
        }

    //      Currently available Socks Methods
    //      o  X'00' NO AUTHENTICATION REQUIRED

        // Search METHODS and Select Preffered Method
        // Preffered method = no authentication
        auto *methodBegin = &input[2];
        auto *mehodEnd = methodBegin + input[1];
        auto *method = std::find(methodBegin, mehodEnd, 0x00);
        if(method != mehodEnd)
        {
            sendArray[1] = 0x00;
            send(clientSocket, sendArray, sendSize, 0 );
            return 0;
        }
    
        send(clientSocket, sendArray, sendSize, 0 );
        m_logger->error("ThreadID {0}: Only NO AUTHENTICATION REQUIRED supported", std::hash<std::thread::id>{}(std::this_thread::get_id()));
        return -1;    
    }

    int SOCKS5Server::pHandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket){
        // TODO check if array has to be bufferlength
        // maybe use vector instead, or dynamically allocate
        // for now since Only Ipv4 and IPv6 are supported, max length = 22 (see reply format below, max BND Addr = 16 ipv6 length)
        uint8_t sendArray[22];

        //default size, can change
        int sendArraySize = 7;

        // SOCKS ver5
        sendArray[0] = 0x05;
        // RSV Byte
        sendArray[2] = 0x00;
        // Only IPv4 support for now
        sendArray[3] = 0x01;
        

    //      The SOCKS request is formed as follows:
    //      +----+-----+-------+------+----------+----------+
    //      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //      +----+-----+-------+------+----------+----------+
    //      | 1  |  1  | X'00' |  1   | Variable |    2     |
    //      +----+-----+-------+------+----------+----------+

        // Check if SOCKS VER = 5
        if(input[0] != 0x05)
        {
            sendArray[1] = 0x02;
            sendArray[3] = 0x00;
            sendArray[4] = 0x00;
            sendArray[5] = 0x00;
            sendArray[6] = 0x00;
            send(clientSocket, sendArray, 7, 0 );
            m_logger->error("ThreadID {0}: Socks request version is not 5", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return -1;
        } 

    //      The SOCKS reply is formed as follows:
    //      +----+-----+-------+------+----------+----------+
    //      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //      +----+-----+-------+------+----------+----------+
    //      | 1  |  1  | X'00' |  1   | Variable |    2     |
    //      +----+-----+-------+------+----------+----------+

        // Retreive the destination address from the request
        SocketAddress serv_addr;
        if ((sendArray[1] = GetDst(input, inputSize, serv_addr))!=0x00)
        {
            sendArray[3] = 0x00;
            sendArray[4] = 0x00;
            sendArray[5] = 0x00;
            sendArray[6] = 0x00;
            send(clientSocket, sendArray, 7, 0 );
            m_logger->error("ThreadID {0}: Unable to retreive destination address from socks request", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return -1;
        }

        // Setup Client 
        if ((sendArray[1] = SetupClient(serv_addr, hostSocket))!=0x00)
        {
            sendArray[3] = 0x00;
            sendArray[4] = 0x00;
            sendArray[5] = 0x00;
            sendArray[6] = 0x00;
            send(clientSocket, sendArray, 7, 0 );
            m_logger->error("ThreadID {0}: Unable to connect to host", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return -1;
        }

        // Set the Bind Address in the reply
        if ((sendArray[1] = SetBnd(input[1], sendArray, sendArraySize))!=0x00)
        {
            sendArray[3] = 0x00;
            sendArray[4] = 0x00;
            sendArray[5] = 0x00;
            sendArray[6] = 0x00;
            send(clientSocket, sendArray, 7, 0 );
            m_logger->error("ThreadID {0}: Unable to set BND", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return -1;
        }
        send(clientSocket, sendArray, sendArraySize, 0 );
        return 0;
    }

    void SOCKS5Server::pDataTransfer(int clientsocket, int hostSocket, uint8_t* buffer)
    {
        fd_set fdset, fdsetclear;
        timeval timeout;
        ssize_t recvn, sentn;
        int sent;
        bool run = true;

        FD_ZERO(&fdsetclear);
        FD_SET(clientsocket,  &fdsetclear);
        FD_SET(hostSocket, &fdsetclear);
        int nfds = std::max(clientsocket, hostSocket) + 1;
        while (run)
        {
            timeout.tv_sec = 60 * 15; // fifteen minutes before timeout

            // fdset will be altered during select, thus a copy is needed every loop 
            memcpy(&fdset, &fdsetclear, sizeof(fdset));
            
            switch (select(nfds, &fdset, nullptr, nullptr, &timeout))
            {
            case -1:
                m_logger->error("ThreadID {0}: Error during data transfer", std::hash<std::thread::id>{}(std::this_thread::get_id())); 
                run = false;
                break;
            case 0:
                m_logger->error("ThreadID {0}: Connection timed out", std::hash<std::thread::id>{}(std::this_thread::get_id()));    
                run = false;
                break;
            default:
                if (FD_ISSET(hostSocket, &fdset))
                {
                    if ((recvn = recv(hostSocket, buffer, m_bufferLength, 0)) > 1)
                    {                   
                        send(clientsocket, buffer, recvn, 0);              
                    }
                    else
                    {
                        m_logger->debug("ThreadID {0}: Host closed connection", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                        run = false;
                        // FIN recv'd
                        if (recvn == 0)
                        {         
                            break;
                        }                       
                    }
                }
                if (FD_ISSET(clientsocket, &fdset))
                {
                    if ((recvn = recv(clientsocket, buffer, m_bufferLength, 0)) > 1)
                    {
                        send(hostSocket, buffer, recvn, 0);                 
                    }
                    else
                    {
                        m_logger->debug("ThreadID {0}: Client closed connection", std::hash<std::thread::id>{}(std::this_thread::get_id()));
                        run = false;
                        // FIN recv'd
                        if (recvn == 0)
                        {
                            break;
                        }
                    }
                }
            }
        }
        close(clientsocket);
        close(hostSocket);
    }

    int SOCKS5Server::pHandleClient(int socket)
    {
        m_logger->debug("ThreadID {0}: Handling new request", std::hash<std::thread::id>{}(std::this_thread::get_id()));
        uint8_t buffer[m_bufferLength];
        int readSize;

        // Get method from client
        if((read(socket, buffer, m_bufferLength)) == 0)
        {
            m_logger->error("ThreadID {0}: Could not receive method from client", std::hash<std::thread::id>{}(std::this_thread::get_id()));  
            close(socket);
            return -1;
        }
        
        // Select Method and send response
        if (SOCKS5Server::SelectMethod(buffer, socket)!=0)
        {
            m_logger->error("ThreadID {0}: Unable to select method for communication", std::hash<std::thread::id>{}(std::this_thread::get_id()));  
            close(socket);
            return -1;
        }

        // Get request from client
        if((readSize = read(socket, buffer, m_bufferLength))==0)
        {
            m_logger->error("ThreadID {0}: Could not receive request from client", std::hash<std::thread::id>{}(std::this_thread::get_id()));  
            close(socket);
            return -1;
        }

        // Handle Request and send response 
        int hostSocket;
        if (SOCKS5Server::HandleRequest(buffer, readSize, socket, hostSocket)!=0)
        {
            m_logger->error("ThreadID {0}: Unable to handle request", std::hash<std::thread::id>{}(std::this_thread::get_id()));
            close(socket);
            return -1;
        }

        // Start Data Transfer
        SOCKS5Server::DataTransfer(socket, hostSocket, buffer);
        m_logger->debug("ThreadID {0}: Finished request", std::hash<std::thread::id>{}(std::this_thread::get_id()));
        return 0;  
    }
}