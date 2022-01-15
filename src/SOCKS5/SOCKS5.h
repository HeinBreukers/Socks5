#ifndef SOCKS5_H
#define SOCKS5_H


#include <stdint.h>
#include <string>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>


namespace SOCKS5
{

    //bool linearSearch( uint8_t array[], uint8_t size, uint8_t value );

    int SelectMethod(uint8_t* input, int& clientSocket);

    int HandleRequest(uint8_t* input, int inputSize, int& clientSocket, int& hostSocket);

    void DataTransfer(int clientsocket, int hostSocket, uint8_t* buffer);
}
#endif //SOCKS5_H