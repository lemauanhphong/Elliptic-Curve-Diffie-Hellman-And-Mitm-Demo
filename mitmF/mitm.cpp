#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "cryptopp/cryptlib.h"
#include "cryptopp/xed25519.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/gcm.h"
constexpr int BUFFER_SIZE = 1024;

using namespace CryptoPP;
using namespace std;

AutoSeededRandomPool rnd;

class SocketClient 
{
private:
    int socketDescriptor;

public:
    SocketClient() : socketDescriptor(-1) {}

    void create() 
    {
        socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
        if (socketDescriptor == -1) 
        {
            throw runtime_error("Failed to create socket.");
        }
    }

    void connect(const string& host, int port) 
    {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* serverInfo = nullptr;
        if (getaddrinfo(host.c_str(), to_string(port).c_str(), &hints, &serverInfo) != 0) 
        {
            throw runtime_error("Failed to resolve host.");
        }

        // Iterate over the available addresses and try connecting
        for (addrinfo* p = serverInfo; p != nullptr; p = p->ai_next) 
        {
            if (::connect(socketDescriptor, p->ai_addr, p->ai_addrlen) == 0) 
            {
                // Connection successful
                freeaddrinfo(serverInfo);
                return;
            }
        }

        freeaddrinfo(serverInfo);
        throw runtime_error("Connection failed.");
    }

    ssize_t send(const string& message) {
        ssize_t bytesSent = ::send(socketDescriptor, message.c_str(), message.size(), 0);
        if (bytesSent == -1) 
        {
            throw runtime_error("Failed to send data.");
        }

        return bytesSent;
    }

    string receive() 
    {
        char buffer[BUFFER_SIZE];
        ssize_t bytesRead = ::recv(socketDescriptor, buffer, BUFFER_SIZE, 0);
        if (bytesRead == -1) {
            throw runtime_error("Failed to receive data.");
        }

        return string(buffer, bytesRead);
    }

    void close() 
    {
        ::close(socketDescriptor);
        socketDescriptor = -1;
    }

    ~SocketClient() 
    {
        if (socketDescriptor != -1) {
            close();
        }
    }
};

void print(SecByteBlock a, string message = "", bool el = 1)
{
    cout << message;
    HexEncoder encoder(new FileSink(cout));
    StringSource(a, a.size(), true, new Redirector(encoder));
    if (el) cout << endl;
}

string SecByteBlockToHex(const SecByteBlock& block)
{
    string hex;
    HexEncoder encoder(new StringSink(hex));
    encoder.Put(block.data(), block.size());
    encoder.MessageEnd();
    return hex;
}

SecByteBlock HexToSecByteBlock(const string& hex)
{
    SecByteBlock block(hex.size() / 2);
    HexDecoder decoder;
    decoder.Put((const byte*)hex.data(), hex.size());
    decoder.MessageEnd();
    decoder.Get(block, block.size());
    return block;
}

SecByteBlock calcSessionKey(SecByteBlock shared)
{
    SHA256 sha256;
    SecByteBlock digest(sha256.DigestSize());
    sha256.Update(shared, shared.size());
    sha256.Final(digest);
    SecByteBlock aeskey(digest, digest.size() / 2);
    return aeskey;
}

class SocketServer 
{
private:
    int serverSocket;
    int clientSocket;
    sockaddr_in serverAddress;
    sockaddr_in clientAddress;

public:
    SocketServer() : serverSocket(-1), clientSocket(-1) {}

    void create(int port) 
    {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) 
        {
            throw runtime_error("Failed to create server socket.");
        }

        int reuseAddr = 1;
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr)) == -1) 
        {
            throw runtime_error("Failed to set socket option for reusing address.");
        }

        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = INADDR_ANY;
        serverAddress.sin_port = htons(port);

        if (bind(serverSocket, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress)) < 0) 
        {
            throw runtime_error("Failed to bind server socket.");
        }

        if (listen(serverSocket, 1) < 0) 
        {
            throw runtime_error("Failed to listen on server socket.");
        }
    }

    void accept() 
    {
        socklen_t clientAddressLength = sizeof(clientAddress);
        clientSocket = ::accept(serverSocket, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddressLength);
        if (clientSocket == -1) 
        {
            throw runtime_error("Failed to accept client connection.");
        }
    }

    ssize_t send(const string& message) {
        ssize_t bytesSent = ::send(clientSocket, message.c_str(), message.size(), 0);
        if (bytesSent == -1) {
            throw runtime_error("Failed to send data.");
        }

        return bytesSent;
    }

    string receive() 
    {
        char buffer[BUFFER_SIZE];
        ssize_t bytesRead = ::recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytesRead == -1) 
        {
            throw runtime_error("Failed to receive data.");
        }

        return string(buffer, bytesRead);
    }

    void closeClient()
    {
        ::close(clientSocket);
        clientSocket = -1;
    }

    void closeServer() {
        ::close(serverSocket);
        serverSocket = -1;
    }

    ~SocketServer() {
        if (clientSocket != -1) 
        {
            closeClient();
            closeServer();
        }
    }
};

string encrypt(string plain, SecByteBlock key, SecByteBlock iv) 
{
    GCM<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv, AES::BLOCKSIZE);

    string cipher;
    StringSource(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher)));
    return cipher;
}

string decrypt(string cipher, SecByteBlock key, SecByteBlock iv) 
{
    GCM<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv, AES::BLOCKSIZE);
    string plain;
    StringSource(cipher, true, new AuthenticatedDecryptionFilter(d, new StringSink(plain)));
    return plain;
}

string stringToHex(string text) 
{
    string ret;
    StringSource(text, true, new HexEncoder(new StringSink(ret)));
    return ret;
}

string HexToString(string text) 
{
    string ret;
    StringSource(text, true, new HexDecoder(new StringSink(ret)));
    return ret;
}

int main(int argc, char* argv[])
{
    if (argc < 4) 
    {
        cout << "Usage: ./mitm port1 hostname port2 ..." << endl;
        return 1;
    }

    SocketServer server;
    server.create(stoi(argv[1]));
    cout << "Server started. Listening on port " << argv[1] << endl;

    // Use x25519
    x25519 ecdhC(rnd);

    while (1)
    {

        // Accept the connection
        server.accept();

        SocketClient client;
        client.create();
        client.connect(argv[2], 2808);

        cout << "Client connected." << endl;

        // Generate key pair
        SecByteBlock privC(x25519::SECRET_KEYLENGTH);
        SecByteBlock pubC(x25519::PUBLIC_KEYLENGTH);
        ecdhC.GeneratePrivateKey(rnd, privC);
        ecdhC.GeneratePublicKey(rnd, privC, pubC);

        // Print keys
        print(privC, "Private key: ");
        print(pubC, "Public key: ");

        // Receive pubic key to client
        SecByteBlock pubA = HexToSecByteBlock(server.receive());
        server.send(SecByteBlockToHex(pubC));
        print(pubA, "Received public key from client: ");

        // Calculate key shared with client
        SecByteBlock sharedAC(ecdhC.AgreedValueLength());
        if(!ecdhC.Agree(sharedAC, privC, pubA))
            throw runtime_error("Failed to reach shared secret");
        print(sharedAC, "Client shared secret: ");

        // Send public key to server
        client.send(SecByteBlockToHex(pubC));
        SecByteBlock pubB = HexToSecByteBlock(client.receive());
    
        print(pubB, "Received public key from server: ");
        
        // Calculate key shared with server
        SecByteBlock sharedBC(ecdhC.AgreedValueLength());
        if(!ecdhC.Agree(sharedBC, privC, pubB))
            throw runtime_error("Failed to reach shared secret");
        print(sharedBC, "server Shared secret: ");  

        // Calculate sessionkey
        SecByteBlock clientaeskey = calcSessionKey(sharedAC);    
        print(clientaeskey, "Client AES key: ");
        SecByteBlock serveraeskey = calcSessionKey(sharedBC);    
        print(serveraeskey, "Server AES key: ");
        cout << endl;

        {
            // Get iv + ciphertext and decrypt message from client
            {
                string recv_msg = server.receive();
                string iv_hex = recv_msg.substr(0, 32);
                string iv_string = HexToString(iv_hex);
                string cipher_hex = recv_msg.substr(32, recv_msg.size());
                string cipher_string = HexToString(cipher_hex);
                SecByteBlock iv((const byte*)iv_string.data(), 16);
                cout << "Received IV: " << iv_hex << endl;
                cout << "Received ciphertext: " << cipher_hex << endl;
                cout << "Received from client: " << decrypt(cipher_string, clientaeskey, iv) << endl;
            }

            // Generate iv, encrypt msg and then send to client
            {
                SecByteBlock iv(AES::BLOCKSIZE);
                rnd.GenerateBlock(iv, iv.size());
                string msg = string("I hate you", 10);
                string hexIV = SecByteBlockToHex(iv);
                string hexCipher = stringToHex(encrypt(msg, clientaeskey, iv));
                server.send(hexIV + hexCipher);
                cout << "IV: " << hexIV << endl;
                cout << "Ciphertext: " << hexCipher << endl;
                cout << "Sent to client: " << msg << endl << endl;
            }
        }

        {
            // Generate iv, encrypt msg and then send to server
            {
                SecByteBlock iv(AES::BLOCKSIZE);
                rnd.GenerateBlock(iv, iv.size());
                string msg = string("I hate you more", 15);
                string hexIV = SecByteBlockToHex(iv);
                string hexCipher = stringToHex(encrypt(msg, serveraeskey, iv));
                client.send(hexIV + hexCipher);
                cout << "IV: " << hexIV << endl;
                cout << "Ciphertext: " << hexCipher << endl;
                cout << "Sent to server: " << msg << endl << endl;
            }
            
            // Get iv + ciphertext and decrypt message from server
            {
                string recv_msg = client.receive();
                string iv_hex = recv_msg.substr(0, 32);
                string iv_string = HexToString(iv_hex);
                string cipher_hex = recv_msg.substr(32, recv_msg.size());
                string cipher_string = HexToString(cipher_hex);
                SecByteBlock iv((const byte*)iv_string.data(), 16);
                cout << "Received IV: " << iv_hex << endl;
                cout << "Received ciphertext: " << cipher_hex << endl;
                cout << "Received from server: " << decrypt(cipher_string, serveraeskey, iv) << endl;
            }
        }

        // Close sockets
        server.closeClient();
        
        cout << "-------------------------------------" << endl;
    }

    // Close server
    server.closeServer();
    return 0;
}