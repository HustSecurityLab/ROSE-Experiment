#ifndef UTILITIES_H
#define UTILITIES_H
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <chrono>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <math.h>
#include "Bid.h"
#include "ORAM.hpp"
#include "PRFORAM.hpp"

class Utilities {
private:
    static int parseLine(char* line);
public:
    Utilities();
    static std::string base64_encode(const char* bytes_to_encode, unsigned int in_len);
    static std::string base64_decode(std::string const& enc);
    static std::string XOR(std::string value, std::string key);
    static void startTimer(int id);
    static double stopTimer(int id);
    static std::map<int, std::chrono::time_point<std::chrono::high_resolution_clock> > m_begs;
    static std::map<std::string, std::ofstream*> handlers;
    static void logTime(std::string filename, std::string content);
    static void initializeLogging(std::string filename);
    static void finalizeLogging(std::string filename);
    static std::array<uint8_t, 16> convertToArray(std::string value);
    static int getMem();
    static double getTimeFromHist(int id);
    static int getBid(std::string srchIndex);
    static std::array<uint8_t, 16> encode(std::string keyword);
    static std::string decode(std::array<uint8_t, 16> data);
    static unsigned char key[16], iv[16];
    static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
    static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
    static void handleErrors(void);

    static void save_map_data(FILE *f_out, const std::map<std::string, int> &m);

    static void load_map_data(FILE *f_in, std::map<std::string, int> &m);

    static void save_map_data(FILE *f_out, const std::map<std::string, std::string> &m);

    static void load_map_data(FILE *f_in, std::map<std::string, std::string> &m);

    static void save_map_data(FILE *f_out, std::map<Bid, Node *> &m);

    static void load_map_data(FILE *f_in, std::map<Bid, Node *> &m);

    static void save_string(FILE *f_out, const std::string &s);

    static std::string load_string(FILE *f_in);

    static void save_int(FILE *f_out, int i);

    static int load_int(FILE *f_in);

    static void save_bid(FILE *f_out, const Bid &bid);

    static Bid load_bid(FILE *f_in);

    static void save_vector_data(FILE *f_out, vector<int> &v);

    static void load_vector_data(FILE *f_in, vector<int> &v);

    static void save_map_data(FILE *f_out, map<Bid, Box *> &m);

    static void load_map_data(FILE *f_in, map<Bid, Box *> &m);



    virtual ~Utilities();
};

#endif /* UTILITIES_H */

