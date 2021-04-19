//
// Created by yaroslav on 19.04.2021.
//

#include "Car.h"


Car::Car(CryptoPP::RSA::PublicKey public_key) : _public_key(std::move(public_key)) {}

std::string Car::get_message(const std::string &command) {
    if (command != Commands.open && command != Commands.close) {
        return ERROR;
    }
    _command = command;
    std::random_device rd;
    std::mt19937 generator(rd());
    unsigned long mes1 = generator();
    std::ostringstream oss;

    oss << mes1;

    return encrypt(oss.str());
}

std::string Car::challenge(const size_t &response) {
    if (response != _hash_message) {
        return ERROR;
    }

    if (_command == Commands.open) {
        return "car open";
    }

    if (_command == Commands.close) {
        return "car close";
    }

    return ERROR;
}

std::string Car::encrypt(const std::string &mes) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string cipher;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(_public_key);

    CryptoPP::StringSource ss1(mes, true,
                               new CryptoPP::PK_EncryptorFilter(rng, e,
                                                                new CryptoPP::StringSink(cipher)
                               ) // PK_EncryptorFilter
    ); // StringSource
    std::hash<std::string> hash;
    _hash_message = hash(mes);
    return cipher;
}