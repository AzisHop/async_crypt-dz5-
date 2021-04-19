//
// Created by yaroslav on 19.04.2021.
//

#ifndef ASYNC_CRYPT_DZ5__CAR_H
#define ASYNC_CRYPT_DZ5__CAR_H

#include <iostream>
#include <utility>
#include "crypto++/rsa.h"
#include <crypto++/osrng.h>
#include <random>
#include <sstream>
#include "Utils.h"

#define ERROR "ERROR"

class Car {
public:
    explicit Car(CryptoPP::RSA::PublicKey public_key);

    std::string get_message(const std::string &command);
    std::string challenge(const size_t &response);

private:
    CryptoPP::RSA::PublicKey _public_key;
    std::string _command;
    size_t _hash_message;

    std::string encrypt(const std::string &mes);

};
#endif //ASYNC_CRYPT_DZ5__CAR_H
