#include  "SOCKS5.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <thread>
#include <mutex>
#include <arpa/inet.h>

#define BUFFER_LENGTH 1024

//TODO move DataTransfer to Socks5 namespace


void SetupSocket(int& server_fd, sockaddr_in& address, int opt, int port)
{
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
       
    // Forcefully attache socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );
       
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

}

int HandleClient(int socket)
{
    uint8_t buffer[BUFFER_LENGTH];
    int readSize, sendSize;

    // Get method from client
    if((read(socket, buffer, BUFFER_LENGTH)) == 0) // Add timeout?
    {
        return -1;
    }
    
    // Select Method and send response
    if (SOCKS5::SelectMethod(buffer, socket)!=0)
    {
        close(socket);
        return -1;
    }

    // Get request from client
    if((readSize = read(socket, buffer, BUFFER_LENGTH))==0)
    {
        close(socket);
        return -1;
    }

    // Handle Request and send response 
    int hostSocket;
    if (SOCKS5::HandleRequest(buffer, readSize, socket, hostSocket)!=0)
    {
        close(socket);
        return -1;
    }

    // Start Data Transfer
    SOCKS5::DataTransfer(socket, hostSocket, buffer);
    return 0;  
}


int main() {
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    // Initialize socket config   
    SetupSocket(server_fd, address, opt, 8080);
    

    while(true){
        new_socket = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen);
        std::thread thread_object(HandleClient, new_socket);
        thread_object.detach();
    }
    return 0;
}
