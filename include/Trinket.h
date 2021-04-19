//
// Created by yaroslav on 19.04.2021.
//

#ifndef ASYNC_CRYPT_DZ5__TRINKET_H
#define ASYNC_CRYPT_DZ5__TRINKET_H

#include "Utils.h"
#include <iostream>
#include <utility>
#include "crypto++/rsa.h"
#include <crypto++/osrng.h>

class Trinket {
public:
    explicit Trinket(CryptoPP::RSA::PrivateKey private_key);

    std::string get_command(char command);
    size_t challenge(const std::string &response);

private:
    CryptoPP::RSA::PrivateKey _private_key;

    size_t decoding(const std::string &cipher);
};

#endif //ASYNC_CRYPT_DZ5__TRINKET_H
