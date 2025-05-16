#include "OpenSSLManager.h"
#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

constexpr int PORT = 12345;
constexpr int BACKLOG = 10;
constexpr int BUFFER_SIZE = 2048;

void handleClient(int clientSock, sockaddr_in clientAddr, OpenSSLManager& opensslManager) {
    char buffer[BUFFER_SIZE] = {0};
    int bytesReceived = recv(clientSock, buffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived <= 0) {
        std::cerr << "Receive failed or client disconnected." << std::endl;
        close(clientSock);
        return;
    }

    std::string received(buffer, bytesReceived);
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);

    std::cout << "Received from " << clientIP << ": " << received << std::endl;

    std::string response;
    if (received == "getCert") {
        response = opensslManager.getCertificatePem();
    } else if (received.compare(0, 4, "----") == 0) {
        response = opensslManager.signCSR(received);
    } else {
        response = "Unknown request";
    }

    send(clientSock, response.c_str(), response.length(), 0);
    close(clientSock);
}

int main(int argc, char* argv[]) {
    bool shouldInit = (argc == 2 && std::string(argv[1]) == "-init");
    OpenSSLManager opensslManager;

    if (shouldInit) {
        if (!opensslManager.generateAndSave()) {
            std::cerr << "Failed to generate certificate and key." << std::endl;
            return 1;
        }
    } else {
        if (!opensslManager.loadFromFile()) {
            std::cerr << "Certificate files not found. Run with -init to generate them." << std::endl;
            return 1;
        }
    }

    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        close(serverSock);
        return 1;
    }

    if (listen(serverSock, BACKLOG) < 0) {
        perror("listen");
        close(serverSock);
        return 1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);

        int clientSock = accept(serverSock, (sockaddr*)&clientAddr, &clientLen);
        if (clientSock < 0) {
            perror("accept");
            continue;
        }

        std::thread(handleClient, clientSock, clientAddr, std::ref(opensslManager)).detach();
    }

    close(serverSock);
    return 0;
}
