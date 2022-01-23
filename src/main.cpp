#include "SOCKS5.hpp"
#include "main.hpp"


int SetupSocket(int& server_fd, sockaddr_in& address, int opt, int port, std::shared_ptr<spdlog::logger> logger)
{
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        logger->error("Main server socket failed");
        return -1;
    }
    logger->debug("Main server socket Created from fd");
       
    // Forcefully attache socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
    {
        logger->error("Main server setsocketopt failed");
        return -1;
    }
    logger->debug("Main server socket options set ");
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );
       
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0)
    {
        logger->error("Main server socket bind failed");
        return -1;
    }
    logger->debug("Main server socket bound");

    if (listen(server_fd, 3) < 0)
    {
        spdlog::error("Main server socket listen failed");
        return -1;
    }
    logger->debug("Main server socket listning");

    return 0;
}

int main() {  
    int server_fd;
    int new_socket;
    sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // ignore sigpipe signal to continue program in case of remote socket close
    signal(SIGPIPE, SIG_IGN);

    // Setup Logging
    auto console = spdlog::stdout_color_mt("console");
    console->debug("DebugTest");
    console->set_level(spdlog::level::debug);
    SOCKS5::SOCKS5Server::SetLogger(console);
  
    // Initialize socket  
    static const int port = 8080;
    if(SetupSocket(server_fd, address, opt, port, console)!=0)
    {
        console->error("Server is unable to create listening socket");
        return 0;
    }

    console->info("Server listening socket created");   
    console->info("Server accepting new connections");
    while(true){
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    
        console->debug("Accepted new connection");
        std::thread thread_object(SOCKS5::SOCKS5Server::HandleClient, new_socket);
        thread_object.detach();
    }
    return 0;
}
