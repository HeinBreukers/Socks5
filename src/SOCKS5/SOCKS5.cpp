#include "SOCKS5.h"

#include <cstring>
#define BUFFER_LENGTH 1024

// TODO replace namespace by static class to make functions private
namespace SOCKS5
{
    uint8_t SetupClient(sockaddr_in& serv_addr, int& hostSocket)
    {
        // Connect with destination address
        if ((hostSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            return 0x01;
        }   
        if (connect(hostSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            return 0x05;
        }

        return 0x00;
    }

    uint8_t SetBnd(uint8_t cmd, uint8_t* output, int& outputSize)
    {
        // Currently only CMD Connect 0x01 is supported
        if(cmd == 0x01)
        {
            // 
            std::memset(&output[4], 0 , 6);
            outputSize = 10;
            return 0x00;
        }
        else 
        {
            return 0x07;
        }

        return 0x01;
    }

    uint8_t GetDst(uint8_t* input, int inputSize, sockaddr_in& serv_addr)
    {
        // IPv4
        if(input[3]==0x01)
        {
            serv_addr.sin_family = AF_INET;
            std::memcpy(&(serv_addr.sin_port), &input[inputSize-2], 2);
            std::memcpy(&(serv_addr.sin_addr), &input[4], inputSize-6);  
            return 0x00;
        }
        // DNS
        // TODO review
        else if(input[3]==0x03)
        {
            return 0x08;
 /*           addrinfo hints = {0};
	        addrinfo *result = NULL;

            char domain[256] = {0};
            // change for IPv6?
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags = AI_PASSIVE;

            std::memcpy(domain, &input[4], inputSize-6);
            if (int ret = getaddrinfo(domain, NULL, &hints, &result) != 0)
            {
                return 0x03;
            }

            memcpy(&serv_addr, result->ai_addr, sizeof(sockaddr_in));
            memcpy(&(serv_addr.sin_port), &input[inputSize-3], 2);
            return 0x00;*/
        }
        // IPv6
        // TODO implement
        else if(input[3] == 0x04)
        {
            return 0x08;
        }
        else
        {
            return 0x08;
        }

        return 0x01;
    }

    bool linearSearch( uint8_t array[], uint8_t size, uint8_t value )
    {
        uint8_t i = 0;

        while ( i < size && array[i] != value ) i++;

        return ( i != size );
    }

    int SelectMethod(uint8_t* input, int& clientSocket)
    {
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
            return -1;
        }

//      Currently available Socks Methods
//      o  X'00' NO AUTHENTICATION REQUIRED

        // Search METHODS and Select Desired Method
        // TODO replace linearSearch by stl version
        if(!linearSearch(&input[2], input[1], 0x00)){
            send(clientSocket, sendArray, sendSize, 0 );
            return -1;    
        }
        sendArray[1] = 0x00;
        send(clientSocket, sendArray, sendSize, 0 );
        return 0;
        
    }

    int HandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket){
        uint8_t sendArray[BUFFER_LENGTH];
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
            return -1;
        } 

//      The SOCKS reply is formed as follows:
//      +----+-----+-------+------+----------+----------+
//      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//      +----+-----+-------+------+----------+----------+
//      | 1  |  1  | X'00' |  1   | Variable |    2     |
//      +----+-----+-------+------+----------+----------+

        // Retreive the destination address from the request
        sockaddr_in serv_addr;
        if ((sendArray[1] = GetDst(input, inputSize, serv_addr))!=0x00)
        {
            sendArray[3] = 0x00;
            sendArray[4] = 0x00;
            sendArray[5] = 0x00;
            sendArray[6] = 0x00;
            send(clientSocket, sendArray, 7, 0 );
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
            return -1;
        }
        send(clientSocket, sendArray, sendArraySize, 0 );
        return 0;
    }

    void DataTransfer(int clientsocket, int hostSocket, uint8_t* buffer)
    {
        fd_set fdset, fdsetclear;
        timeval timeout;
        ssize_t recvn, sentn;
        int sent;
        bool run = true;

        FD_ZERO(&fdsetclear);
        FD_SET(clientsocket,  &fdsetclear);
        FD_SET(hostSocket, &fdsetclear);
        while (run)
        {
            timeout.tv_sec = 60 * 5;
            timeout.tv_usec = 0;
            memcpy(&fdset, &fdsetclear, sizeof(fdset));
            switch (select(1024, &fdset, 0, 0, &timeout))
            {
            case -1:
                run = false;
                break;
            case 0:
                run = false;
                break;
            default:
                if (FD_ISSET(hostSocket, &fdset))
                {
                    if ((recvn = recv(hostSocket, buffer, BUFFER_LENGTH, 0)) > 1)
                    {
                        sentn = send(clientsocket, buffer, recvn, 0);
                        /*
                        sent = 0;
                        while (sent < recvn) {
                            if ((sentn = send(clientsocket, hostBuffer + sent, recvn - sent, 0)) > 1)
                            {
                                sent += sentn;
                            }
                            else
                            {
                                run = false;
                                break;
                            }
                        }
                        */
                    }
                    else
                    {
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
                    if ((recvn = recv(clientsocket, buffer, BUFFER_LENGTH, 0)) > 1)
                    {
                        sentn = send(hostSocket, buffer, recvn, 0);
                        /*
                        sent = 0;
                        while (sent < recvn) {
                            if ((sentn = send(hostSocket, clientBuffer + sent, recvn - sent, 0)) > 1)
                            {
                                sent += sentn;
                            }
                            else
                            {
                                run = false;
                                break;
                            }
                        }
                        */
                    }
                    else
                    {
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
}
