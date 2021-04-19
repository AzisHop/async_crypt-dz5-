//
// Created by yaroslav on 19.04.2021.
//

#include "Trinket.h"

Trinket::Trinket(CryptoPP::RSA::PrivateKey private_key)
: _private_key(std::move(private_key)) {}


size_t Trinket::decoding(const std::string &cipher) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string recovered;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(_private_key);

    CryptoPP::StringSource ss2(cipher, true,
                               new CryptoPP::PK_DecryptorFilter(rng, d,
                                                                new CryptoPP::StringSink(recovered)
                               ) // PK_DecryptorFilter
    ); // StringSource
    std::hash<std::string> hash;
    return hash(recovered);
}

size_t Trinket::challenge(const std::string &response) {
    return decoding(response);
}

std::string Trinket::get_command(char command) {
    switch (command) {
        case 'o':
            return Commands.open;
        case 'c':
            return Commands.close;
        default:
            std::cout << "НЕИЗВЕСТНАЯ КОМАНДА";
            return "";
    }
}