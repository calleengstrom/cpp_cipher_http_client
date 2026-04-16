// ============================================================
//  Cipher CTF — student starter template
//
//  HOW THIS FILE IS ORGANISED
//  --------------------------
//  1. sendRequest()  — opens a TCP socket, sends the request,
//                      reads the full response, closes the socket.
//                      Real Winsock calls are shown; pseudocode
//                      sections are marked with  /* PSEUDO: ... */
//
//  2. main()         — calls sendRequest() for every endpoint,
//                      parses the JSON body, and prints the
//                      raw cipher text.  Decryption is left for you.
//
//  BUILD (Windows / MinGW or MSVC):
//    cmake -S . -B build && cmake --build build
//    build\cipher_client.exe
// ============================================================

#include <iostream>
#include <string>
#include <optional>
#include <vector>
#include <algorithm>
#include <map>
#include <bits/stdc++.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else // POSIX
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "http/Request.h"
#include "http/Response.h"
#include "json/JsonParser.h"

std::optional<std::string> sendRequest(const std::string &host,
                                       int port,
                                       const std::string &path)
{

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        std::cout << "Failed to setup socket" << WSAGetLastError() << std::endl;
        WSACleanup();
        return std::nullopt;
    }

    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    InetPtonA(AF_INET, "172.20.203.149", &server.sin_addr.S_un.S_addr);

    if (connect(sock, (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        std::cout << "FAiled to connect " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup;
        return std::nullopt;
    }

    // const std::string request = "GET /test HTTP/1.1\r\nHost: 172.20.203.149\r\nConnection: close\r\n\r\n";
    Request request(host, port, path);
    std::string raw_request = request.build();

    if (send(sock, raw_request.c_str(), (int)raw_request.length(), 0) == SOCKET_ERROR)
    {
        std::cout << "Failed to send request" << WSAGetLastError() << std::endl;
        WSACleanup();
        return nullptr;
    }

    char buffer[2048];

    std::string raw_response;

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (bytesReceived > 0)
        {
            raw_response.append(buffer, bytesReceived);
        }
        else if (bytesReceived == 0)
        {
            break;
        }
        else
        {
            std::cout << "Failed to receive response " << WSAGetLastError() << std::endl;
            break;
        }
    }
    Response response = parseResponse(raw_response);

    /**
     * ----------------------------------------------------------
     * STEP 1 - Create a TCP Socket
     * This is a file descriptor that the OS use to represent our
     * end of a network connection.
     * ----------------------------------------------------------
     */

    /**
     * ----------------------------------------------------------
     * STEP 2 - Fill in the server address struct
     * The sockaddr_in struct describes and IPv4 endpoint, with
     * some cryptic functions:
     * - inet_pton()    converts IP-string to 4 bytes.
     * - htons()        converts the port to network byte order
     * ----------------------------------------------------------
     */

    /**
     * ----------------------------------------------------------
     * STEP 3 - Connect to the server
     * connect() performs the TCP three-way handshake, when this
     * succeeds - the socket is ready for I/O.
     * ----------------------------------------------------------
     */

    /**
     * ----------------------------------------------------------
     * STEP 4 - Build and send the HTTP request
     * Use the Request class to build a HTTP request, then use
     * send() to write raw bytes from a buffer into the TCP
     * stream.
     * ----------------------------------------------------------
     */

    /**
     * ----------------------------------------------------------
     * STEP 5 - Read the response
     * recv() reads the bytes from the TCP stream into a buffer.
     * You can expect the following from recv():
     * - returns > 0 = there are more bytes to be read.
     * - returns 0 = all bytes have been read
     * - else = something went wrong.
     */

    /**
     * ----------------------------------------------------------
     * STEP 6 - Close the socket
     * Always clean up the - remember to close the socket!
     */

    closesocket;
    // std::cout << "Request sent to: " << host << ":" << port << path << std::endl;
    return response.body;
}

std::string invert(std::string text)
{
    reverse(std::begin(text), std::end(text));
    return text;
}


#define SIZE 100

/* char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ
abcdefghijklmnopqrstuvwxyz0123456789+/" */
char* base64Decoder(std::string encoded, int len_str)
{
    char* decoded_string;

    decoded_string = (char*)malloc(sizeof(char) * SIZE);

    int i, j, k = 0;

    // stores the bitstream.
    int num = 0;

    // count_bits stores current
    // number of bits in num.
    int count_bits = 0;

    // selects 4 characters from
    // encoded string at a time.
    // find the position of each encoded
    // character in char_set and stores in num.
    for (i = 0; i < len_str; i += 4) 
    {
        num = 0, count_bits = 0;
        for (j = 0; j < 4; j++)
        {
            
            // make space for 6 bits.
            if (encoded[i + j] != '=') 
            {
                num = num << 6;
                count_bits += 6;
            }

            /* Finding the position of each encoded 
            character in char_set 
            and storing in "num", use OR 
            '|' operator to store bits.*/

            // encoded[i + j] = 'E', 'E' - 'A' = 5
            // 'E' has 5th position in char_set.
            if (encoded[i + j] >= 'A' && encoded[i + j] <= 'Z')
                num = num | (encoded[i + j] - 'A');

            // encoded[i + j] = 'e', 'e' - 'a' = 5,
            // 5 + 26 = 31, 'e' has 31st position in char_set.
            else if (encoded[i + j] >= 'a' && encoded[i + j] <= 'z')
                num = num | (encoded[i + j] - 'a' + 26);

            // encoded[i + j] = '8', '8' - '0' = 8
            // 8 + 52 = 60, '8' has 60th position in char_set.
            else if (encoded[i + j] >= '0' && encoded[i + j] <= '9')
                num = num | (encoded[i + j] - '0' + 52);

            // '+' occurs in 62nd position in char_set.
            else if (encoded[i + j] == '+')
                num = num | 62;

            // '/' occurs in 63rd position in char_set.
            else if (encoded[i + j] == '/')
                num = num | 63;

            // ( str[i + j] == '=' ) remove 2 bits
            // to delete appended bits during encoding.
            else {
                num = num >> 2;
                count_bits -= 2;
            }
        }

        while (count_bits != 0)
        {
            count_bits -= 8;

            // 255 in binary is 11111111
            decoded_string[k++] = (num >> count_bits) & 255;
        }
    }

    // place NULL character to mark end of string.
    decoded_string[k] = '\0';

    return decoded_string;
}

std::string xorShift(std::string message){
    std::string readableMsg;
    char nc;
    for(char &c : message){
        if(c == ' '){
            readableMsg.push_back(c);
        }
        else{
        nc = c ^=(3);
        readableMsg.push_back(nc);
        }
    }
    return message;
}

std::string rail_fence(std::string message,int key)
{
    // create the matrix to cipher plain text
    // key = rows , length(text) = columns
    char rail[key][message.length()];

    // filling the rail matrix to distinguish filled
    // spaces from blank ones
    for (int i=0; i < key; i++)
        for (int j=0; j < message.length(); j++)
            rail[i][j] = '\n';

    // to find the direction
    bool dir_down;

    int row = 0, col = 0;

    // mark the places with '*'
    for (int i=0; i < message.length(); i++)
    {
        // check the direction of flow
        if (row == 0)
            dir_down = true;
        if (row == key-1)
            dir_down = false;

        // place the marker
        rail[row][col++] = '*';

        // find the next row using direction flag
        dir_down?row++ : row--;
    }

    // now we can construct the fill the rail matrix
    int index = 0;
    for (int i=0; i<key; i++)
        for (int j=0; j<message.length(); j++)
            if (rail[i][j] == '*' && index<message.length())
                rail[i][j] = message[index++];


    // now read the matrix in zig-zag manner to construct
    // the resultant text
    std::string result;

    row = 0, col = 0;
    for (int i=0; i< message.length(); i++)
    {
        // check the direction of flow
        if (row == 0)
            dir_down = true;
        if (row == key-1)
            dir_down = false;

        // place the marker
        if (rail[row][col] != '*')
            result.push_back(rail[row][col++]);

        // find the next row using direction flag
        dir_down?row++: row--;
    }
    return result;
}

std::string decryptRot13(std::string message)
{
    std::string decipher;

    for (char &s : message)
    {
        if (s >= 'a' && s <= 'z')
        {
            decipher.push_back('a' + (s - 'a' + 13) % 26);
        }
        else if (s >= 'A' && s <= 'Z')
        {
            decipher.push_back('A' + (s - 'A' + 13) % 26);
        }
        else{
            decipher.push_back(s);
        }
    }
    return decipher;
}

std::string decryptCeasar5(std::string message)
{
    std::string decipher;

    for (char &s : message)
    {
        if (s >= 'a' && s <= 'z')
        {
            decipher.push_back('a' + (s - 'a' - 5) % 26);
        }
        else if (s >= 'A' && s <= 'Z')
        {
            decipher.push_back('A' + (s - 'A' - 5) % 26);
        }
        else{
            decipher.push_back(s);
        }
    }
    return decipher;
}

std::string base64(std::string message)
{
    std::string decipher;

    for (char &s : message)
    {
       s+=64;
       decipher.push_back(s);
    }
    return decipher;
}

std::string subi(std::string message){
std::string decipher;
    std::string subitext = "qwertyuiopasdfghjklzxcvbnm";
    std::array<char, 26> inv;
    for (int i =0; i < 26;i++){
        inv[subitext[i]-'a'] = 'a' + i;
    }
    char nc;
    std::transform(message.begin(),message.end(),message.begin(),::tolower);
    for (char &c : message)
    {
        if(c == ' ' ){
            decipher.push_back(c);
        }
        else{
        int i = c-'a' ;
        decipher.push_back(inv[i]);
        std::cout << i << std::endl;
        }
       
    }
    return decipher;
}

std::string atbash(std::string message)
{
    std::string decipher;

    for (char &s : message)
    {
        if (s >= 'a' && s <= 'z')
        {
            decipher.push_back('z' - (s - 'a') );
        }
        else if (s >= 'A' && s <= 'Z')
        {
            decipher.push_back('Z' - (s - 'A') );
        }
        else{
            decipher.push_back(s);
        }
    }
    return decipher;
}


int main()
{

    const std::string HOST = "172.20.203.149";
    const int PORT = 8080;

// Initialise Winsock (Windows only — must be done before any socket call).
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "[error] WSAStartup failed\n";
        return 1;
    }
#endif

    /**
     * ----------------------------------------------------------
     * STEP 1 - Implement the sendRequest() function
     * Start off by implementing the sendRequest() function and
     * then try it by using "/clear-text" endpoint.
     *
     * Parse the response and then print out the result!
     * ----------------------------------------------------------
     */

    /**
     * ----------------------------------------------------------
     * STEP 2 - Decrypt the ciphertext!
     * Start trying to decrypt the ciphertext by sending requests
     * the the endpoints down below and decrypt them using the
     * KEY and CIPHERTEXT in the payload.
     *
     * You can expect a payload in JSON format like this:
     * { "key": "...", "cipherText": "..." }
     *
     * Suggested workflow:
     *      1. Send a GET request to the related endpoint
     *      2. Parse the Response to get the body
     *      3. Parse the body through JsonParser to extract the key + cipher text
     *      4. Decrypt the ciphertext and save the result in a file with the endpoint name
     */

    const std::vector<std::string> endpoints = {
        "/inverse-cipher",
        "/rot13-cipher",
        "/atbash-cipher",
        "/ceasar-cipher",
        "/base64-cipher",
        "/xor-cipher",
        "/rail-fence-cipher",
        "/substitution-cipher",
        "/columnar-transposition-cipher",
        "/vigenere-cipher",
        "/affine-cipher",
        "/monome-cipher",
        "/playfair-cipher",
    };

    std::vector<std::string> craked;
    for (const auto &path : endpoints)
    {
        // std::string p = "/ceasar-cipher";
        auto r_response = sendRequest(HOST, PORT, path);

        if (r_response.has_value())
        {
            // std::cout << r_response.value() << std::endl;

            JsonParser json(r_response.value());
            auto key = json.get("key");
            auto ciphertext = json.get("cipherText");
            if (key.has_value())
            {
               // std::cout << "Cipher: \n" << path <<"  "<<key.value() << "\nChipher : " << ciphertext.value() << std::endl<<std::endl;
            }
            if (path == "/inverse-cipher")
            {
                craked.push_back(invert(ciphertext.value()));
            }
            if (path == "/rot13-cipher")
            {
                craked.push_back(decryptRot13(ciphertext.value()));
            }
            if (path == "/ceasar-cipher")
            {
                craked.push_back(decryptCeasar5(ciphertext.value()));
            }
            if (path == "/atbash-cipher")
            {
                craked.push_back(atbash(ciphertext.value()));
            }
            if(path == "/base64-cipher"){
                craked.push_back(base64Decoder(ciphertext.value(),(ciphertext.value().length())));
            }
            if(path == "/xor-cipher"){
                craked.push_back(xorShift(ciphertext.value()));
            }if(path == "/rail-fence-cipher"){
                craked.push_back(rail_fence(ciphertext.value(),7));
            }
            if(path == "/substitution-cipher"){
                craked.push_back(subi(ciphertext.value()));
            }
            
        }
    }
    for (std::string &s : craked)
    {
        std::cout << s <<"\n" << std::endl;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
