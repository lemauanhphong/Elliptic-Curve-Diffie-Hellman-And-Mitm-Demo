#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

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

AutoSeededRandomPool rnd;

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
    if (argc < 2) 
    {
        cout << "Usage: ./server port ..." << endl;
        return 1;
    }

    SocketServer server;
    server.create(stoi(argv[1]));
    cout << "Server started. Listening on port " << argv[1] << endl;

    // Use x25519
    x25519 ecdhB(rnd);

    while (1)
    {
        // Accept the connection
        server.accept();
        cout << "Client connected." << endl;

        SecByteBlock privB(x25519::SECRET_KEYLENGTH);
        SecByteBlock pubB(x25519::PUBLIC_KEYLENGTH);
        ecdhB.GeneratePrivateKey(rnd, privB);
        ecdhB.GeneratePublicKey(rnd, privB, pubB);

        // Print keys
        print(privB, "Private key: ");
        print(pubB, "Public key: ");

        // Receive data from client
        SecByteBlock pubA = HexToSecByteBlock(server.receive());
        print(pubA, "Received public key: ");
        
        // Send public key
        server.send(SecByteBlockToHex(pubB));

        // Calculate share key
        SecByteBlock sharedB(ecdhB.AgreedValueLength());
        if(!ecdhB.Agree(sharedB, privB, pubA))
            throw runtime_error("Failed to reach shared secret");

        print(sharedB, "Shared secret: ");
    
        // Calculate sessionkey
        SecByteBlock aeskey = calcSessionKey(sharedB);    
        print(aeskey, "AES key: ");
        cout << endl;

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
            cout << "Received from client: " << decrypt(cipher_string, aeskey, iv) << endl << endl;
        }

        // Generate iv, encrypt msg and then send to client
        {
            SecByteBlock iv(AES::BLOCKSIZE);
            rnd.GenerateBlock(iv, iv.size());
            string msg = string("See you soon", 12);
            string hexIV = SecByteBlockToHex(iv);
            string hexCipher = stringToHex(encrypt(msg, aeskey, iv));
            server.send(hexIV + hexCipher);
            cout << "IV: " << hexIV << endl;
            cout << "Ciphertext: " << hexCipher << endl;
            cout << "Sent to client: " << msg << endl;
        }

        // Close sockets
        server.closeClient();
        
        cout << "-------------------------------------" << endl;
    }

    // Close server
    server.closeServer();
    return 0;
}