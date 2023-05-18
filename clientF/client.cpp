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
            throw std::runtime_error("Failed to create socket.");
        }
    }

    void connect(const std::string& host, int port) 
    {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* serverInfo = nullptr;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &serverInfo) != 0) 
        {
            throw std::runtime_error("Failed to resolve host.");
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
        throw std::runtime_error("Connection failed.");
    }

    ssize_t send(const std::string& message) {
        ssize_t bytesSent = ::send(socketDescriptor, message.c_str(), message.size(), 0);
        if (bytesSent == -1) 
        {
            throw std::runtime_error("Failed to send data.");
        }

        return bytesSent;
    }

    std::string receive() 
    {
        char buffer[BUFFER_SIZE];
        ssize_t bytesRead = ::recv(socketDescriptor, buffer, BUFFER_SIZE, 0);
        if (bytesRead == -1) {
            throw std::runtime_error("Failed to receive data.");
        }

        return std::string(buffer, bytesRead);
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

void print(SecByteBlock a, std::string message = "", bool el = 1)
{
    std::cout << message;
    HexEncoder encoder(new FileSink(std::cout));
    StringSource(a, a.size(), true, new Redirector(encoder));
    if (el) std::cout << std::endl;
}

std::string SecByteBlockToHex(const SecByteBlock& block)
{
    std::string hex;
    HexEncoder encoder(new StringSink(hex));
    encoder.Put(block.data(), block.size());
    encoder.MessageEnd();
    return hex;
}

SecByteBlock HexToSecByteBlock(const std::string& hex)
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
    if (argc < 3) 
    {
        std::cout << "Usage: ./client hostname port ..." << std::endl;
        return 1;
    }

    // Use x25519
    x25519 ecdhA(rnd);

    // Generate key pair
    SecByteBlock privA(x25519::SECRET_KEYLENGTH);
    SecByteBlock pubA(x25519::PUBLIC_KEYLENGTH);
    ecdhA.GeneratePrivateKey(rnd, privA);
    ecdhA.GeneratePublicKey(rnd, privA, pubA);

    // Print keys
    print(privA, "Private key: ");
    print(pubA, "Public key: ");

    // Create socket
    SocketClient client;
    client.create();
    client.connect(argv[1], stoi(argv[2]));

    // Send public key
    client.send(SecByteBlockToHex(pubA));

    // Receive data from server
    CryptoPP::SecByteBlock pubB(HexToSecByteBlock(client.receive()));
    print(pubB, "Received public key: ");
    
    // Calulate share key
    SecByteBlock sharedA(ecdhA.AgreedValueLength());
    if(!ecdhA.Agree(sharedA, privA, pubB))
        throw std::runtime_error("Failed to reach shared secret");
    print(sharedA, "Shared secret: ");

    // Calculate sessionkey
    SecByteBlock aeskey = calcSessionKey(sharedA);    
    print(aeskey, "AES key: ");
    cout << endl;
    
    // Generate iv, encrypt msg and then send to server
    {
        SecByteBlock iv(AES::BLOCKSIZE);
        rnd.GenerateBlock(iv, iv.size());
        string msg = string("See you at 7am", 14);
        string hexIV = SecByteBlockToHex(iv);
        string hexCipher = stringToHex(encrypt(msg, aeskey, iv));
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
        cout << "Received from server: " << decrypt(cipher_string, aeskey, iv) << endl;
    }

    client.close();

    return 0;
}