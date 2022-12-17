/**
 * @file main.cpp
 *
 * @brief solution to CTF https://play.fe-ctf.dk/challenges#15-Hash%20Uppers%20Downers
 *
 *
 * @author Jianqiao Mo
 * Contact: jqmo@nyu.edu
 *
 */

#include <iostream>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <algorithm>
#ifdef __WIN32__
#include <winsock2.h> // -lws2_32
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  // Functions for manipulating numeric IP addresses.
#include <netdb.h>      // Name resolution
#endif

#include "progressbar.hpp"
#include "hash-uppers-downers/sha1.h"

/**** /hash-uppers-downers/sha1.c *****************************************************************************************/
void
digest_to_hex(const uint8_t digest[SHA1_DIGEST_SIZE], char *output)
{
    int i, j;
    char *c = output;

    for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++) {
        for (j = 0; j < 4; j++) {
            sprintf(c, "%02X", digest[i * 4 + j]);
            c += 2;
        }
        sprintf(c, " ");
        c += 1;
    }
    *(c - 1) = '\0';
}
/**************************************************************************************************************************/

/**
 * Connect "nc uppers-downers.hack.fe-ctf.dk 1337"
 * @return int socket ID
 */
int ConnectSocket(){  // nc uppers-downers.hack.fe-ctf.dk 1337
    // socket
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client == -1) {
        std::cout << "Error: socket" << std::endl;
        return 0;
    }
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(1337);
    serverAddr.sin_addr.s_addr = inet_addr("34.154.114.69"); 
    if (connect(client, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cout << "Error: connect" << std::endl;
        return -1;
    }
    return client;
}

const char passw_lib[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; // password char list
struct timeval t_start;  // global time cost
unsigned int ServerReqCount = 0, SHA1count = 0;  // server call count, hash preparation count 

/**
 * Implementation of a 
 * dict{
 *   password: hash_digest
 * }
 * strlen(passw) := 5
 */
typedef struct {
    char passw[6] = {0};
    char userh[SHA1_DIGEST_SIZE] = {0};
} HASHATTEMPT;  // 26 Bytes

/**
 * 3 digits, mod 62 counter for look-up
 *   MSB[base4, base3, base2]LSB
 */
class mod62counter3{
public:
    uint8_t base2 = 0;  // 0 ~ 61
    uint8_t base3 = 0;  // 0 ~ 61
    uint8_t base4 = 0;  // 0 ~ 61

    mod62counter3(void){
        base2 = base3 = base4 = 0;  // init
    };

    // increase, carry
    void increase(void){
        if(61 == base2){
            base2 = 0;
            if(61 == base3){
                base3 = 0;
                if(61 == base4){
                    base4 = 0;
                }
                else{
                    ++base4;
                }
            }
            else{
                ++base3;
            }
        }
        else{
            ++base2;
        }
    };
};

/**
 * Compare two HASHATTEMPT object, by memcmp their->userh
 * @param[in] a: pointer to a HASHATTEMPT object a
 * @param[in] b: pointer to a HASHATTEMPT object b
 * @return memcmp userhash a and b
 */
int HASHATTEMPTcmpfunc (const void * a, const void * b){
    HASHATTEMPT* pa = (HASHATTEMPT*)a;
    HASHATTEMPT* pb = (HASHATTEMPT*)b;
    return memcmp(pa->userh, pb->userh, sizeof(pa->userh));
}

/**
 * Request server to compare a password payload
 * Server return '>' or '<', or flag
 * @param[in] client: client socket ID
 * @param[in] password: password string payload that sent to server to compare
 * @return '>', '<', or exit(0)
 */
char ServerCmp(const int client, const char* password){
    assert(strlen(password) == 5);
    char payload_password[6] = {0, 0, 0, 0, 0, '\n'};
    memcpy(payload_password, password, 5);
    int sendlen = send(client, payload_password, 6, 0), recvlen = 0;

    char SocketBuf[255];
    recvlen = recv(client, SocketBuf, sizeof(SocketBuf), 0);
    SocketBuf[recvlen] = 0;
    char cmp = SocketBuf[0];  // server return '>' or '<'

    if(cmp != '>' && cmp != '<'){  // server return flag
        std::cout << SocketBuf << std::endl;
        std::cout << "* Real Password       = " << password << std::endl;
        struct timeval t_end;
        gettimeofday(&t_end, NULL);
        std::cout << "* Time cost           = " << t_end.tv_sec - t_start.tv_sec << "s" << std::endl;
        std::cout << "# Server call         = " << ServerReqCount << std::endl;
        std::cout << "# Local hash prepare  = " << SHA1count << std::endl;
        close(client);
        exit(0);
        return 0;
    }

    recvlen = recv(client, SocketBuf, sizeof(SocketBuf), 0);  // recv "Password:"
    SocketBuf[recvlen] = 0;

    ++ServerReqCount;
    return cmp;
}

/**
 * Prepare a group of potential password payloads
 * Sorted by their hash digests
 * Drop the out-of-range hash digests
 * The high 3 digits of the passwords are fixed by *base*
 * Only the low 2 digits of the passwords are sweep in passw_lib
 * @param[out] HashSampleArray: pointer to a HASHATTEMPT array
 * @param[in] HashSampleArrayLen: length of HASHATTEMPT array
 * @param[in] low: lower bound of the hash digest
 * @param[in] high: upper bound of the hash digest
 * @param[in, out] base: high 3 digits of the passwords
 * @param[in, out] ctx: powerter to SHA1_CTX object
 * @param[in] salt: powerter to salt string
 * @return number of potential password payloads
 */
unsigned int GenerateHashSample(HASHATTEMPT* HashSampleArray, const unsigned int HashSampleArrayLen, 
                        unsigned char* low, unsigned char* high, mod62counter3 &base, SHA1_CTX* ctx, const char* salt){

    unsigned int HashSampleArrayCounter = 0;
    char password_tmp[6] = {0};
    char userhash_tmp[SHA1_DIGEST_SIZE] = {0};
    // generate hashes in passw_lib order
    assert(HashSampleArrayLen == 62 * 62);
    for(unsigned int j = 0; j < 62; ++j){
        for(unsigned int k = 0; k < 62; ++k){
            password_tmp[0] = passw_lib[k];
            password_tmp[1] = passw_lib[j];
            password_tmp[2] = passw_lib[base.base2];
            password_tmp[3] = passw_lib[base.base3];
            password_tmp[4] = passw_lib[base.base4];
            SHA1_Init(ctx);
            SHA1_Update(ctx, (uint8_t*)salt, strlen(salt));
            SHA1_Update(ctx, (uint8_t*)password_tmp, strlen(password_tmp));
            SHA1_Final(ctx, (uint8_t*)userhash_tmp);

            // only save the password which is in the range, omit out-of-range passwords
            if(memcmp(userhash_tmp, low, sizeof(userhash_tmp)) > 0 && memcmp(userhash_tmp, high, sizeof(userhash_tmp)) < 0){
                memcpy(HashSampleArray[HashSampleArrayCounter].passw, password_tmp, sizeof(password_tmp));
                memcpy(HashSampleArray[HashSampleArrayCounter].userh, userhash_tmp, sizeof(userhash_tmp));
                ++HashSampleArrayCounter;
            }            
        }
    }
    base.increase();

    // sort them by their hash
    memset(HashSampleArray + HashSampleArrayCounter, 0, HashSampleArrayLen - HashSampleArrayCounter);
    qsort(HashSampleArray, HashSampleArrayCounter, sizeof(HASHATTEMPT), HASHATTEMPTcmpfunc);
    SHA1count += HashSampleArrayCounter;
    return HashSampleArrayCounter;
}

/**
 * Binary search: Access server to compare the password hash
 * Lower and upper bound will be updated
 * @param[in] SortedHashSampleArray: pointer to a HASHATTEMPT array (potential passwords)
 * @param[in] ArrayLen: length of HASHATTEMPT array
 * @param[in] client: client socket ID
 * @param[in, out] low: lower bound of the hash digest
 * @param[in, out] high: upper bound of the hash digest
 */
void CheckNewRange(const HASHATTEMPT* SortedHashSampleArray, const unsigned int ArrayLen, const int client, 
                    unsigned char* low, unsigned char* high){

    unsigned int low_idx = 0, high_idx = ArrayLen-1;
    unsigned int mid_idx = (low_idx + high_idx) / 2;
    char cmp = 0;
    // compare and find a new hash range [low, high]
    if(ArrayLen == 0){
        return;
    }
    if(ServerCmp(client, SortedHashSampleArray[0].passw) == '>'){  // good < user[0]
        memcpy(high, SortedHashSampleArray[0].userh, sizeof(high));
        return;
    }
    else if(ServerCmp(client, SortedHashSampleArray[ArrayLen-1].passw) == '<'){  // user[largest] < good
        memcpy(low, SortedHashSampleArray[ArrayLen-1].userh, sizeof(low));
        return;
    }
    else{
        while(mid_idx > low_idx){
            cmp = ServerCmp(client, SortedHashSampleArray[mid_idx].passw);
            if(cmp == '>'){ // good < user[mid]
                high_idx = mid_idx;
            }
            else if(cmp == '<'){  // user[mid] < good
                low_idx = mid_idx;
            }
            mid_idx = (high_idx + low_idx) / 2;  // a new middle point
        }
        // update
        memcpy(low, SortedHashSampleArray[mid_idx].userh, sizeof(low));
        memcpy(high, SortedHashSampleArray[mid_idx + 1].userh, sizeof(high));
    }
}

int main() {
	SHA1_CTX ctx;
	unsigned char goodhash[SHA1_DIGEST_SIZE] = {0};
	unsigned char userhash[SHA1_DIGEST_SIZE] = {0};
	char password[256] = {0};
    uint8_t digest[20] = {0};

	char salt[16] = "pkDHTxmMR18N2l9";  // My static salt
    salt[15] = 0;
    
    // socket
    int client = ConnectSocket();
    char SocketBuf[255] = {0};
    int recvlen = 0; 

    // get salt
    for(unsigned j = 0; j < 3; ++j){
        recvlen = recv(client, SocketBuf, sizeof(SocketBuf), 0);
        SocketBuf[recvlen] = 0;
        std::cout << SocketBuf;
        if(j == 1){
            if(memcmp(SocketBuf + 6, salt, sizeof(salt) - 1) != 0){  // get your salt
                memcpy(salt, SocketBuf + 6, strlen(salt));
            }
        }
        if(j == 2){
            std::cout << std::endl << "* Your salt           = " << salt << std::endl;
        }
        fflush(stdout);
    }

    HASHATTEMPT HashSamples[62*62] = {0};
    mod62counter3 HashSamplesBase;

    // init range for hash (160 bits): hashlo ~ hashhi
	unsigned char hashlo[SHA1_DIGEST_SIZE] = {0};
	unsigned char hashhi[SHA1_DIGEST_SIZE] = {0};
    for(unsigned j = 0; j < SHA1_DIGEST_SIZE; ++j){
        hashhi[j] = 0 - 1;
    }

    unsigned int HashSampleLen = 0;
    progressbar bar(62 * 62 * 62);
    gettimeofday(&t_start, NULL);
    for(unsigned j = 0; j < 62 * 62 * 62; ++j){
        bar.update();
        // prepare potential passwords in range [hashlo, hashhi]
        HashSampleLen = GenerateHashSample(HashSamples, sizeof(HashSamples)/sizeof(HASHATTEMPT), hashlo, hashhi, HashSamplesBase, &ctx, salt);
        // access server to compare the passwords, get new range
        CheckNewRange(HashSamples, HashSampleLen, client, hashlo, hashhi);
    }

    close(client);
	return 0;
}

