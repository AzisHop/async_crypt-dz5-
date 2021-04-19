#include <iostream>
#include <utility>
#include "crypto++/rsa.h"
#include <crypto++/osrng.h>
#include <random>
#include <sstream>

#define ERROR "ERROR"

static struct Commands {
    std::string open = "open";
    std::string close = "close";
} Commands;

class Trinket {
public:
    explicit Trinket(CryptoPP::RSA::PrivateKey private_key)
            : _private_key(std::move(private_key)) {}

    std::string get_command(char command) {
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

    size_t challenge(const std::string &response) {
        return decoding(response);
    }


private:
    CryptoPP::RSA::PrivateKey _private_key;


    size_t decoding(const std::string &cipher) {
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


};

class Car {
public:
    explicit Car(CryptoPP::RSA::PublicKey public_key) : _public_key(std::move(public_key)) {}

    std::string get_message(const std::string &command) {
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

    std::string challenge(const size_t &response) {
        if (response != _hash_message) {
            return ERROR;
        }

        if (_command == Commands.open) {
            return "машина открыта";
        }

        if (_command == Commands.close) {
            return "машина закрыта";
        }

        return ERROR;
    }

private:
    CryptoPP::RSA::PublicKey _public_key;
    std::string _command;
    size_t _hash_message;

    std::string encrypt(const std::string &mes) {
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

};

int main() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey private_key;
    private_key.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PublicKey public_key(private_key);

    Car car(public_key);
    Trinket trinket(private_key);

    std::cout << trinket.get_command('c') << '\n';
    std::string tr_com = trinket.get_command('c');
    std::string car_mes = car.get_message(tr_com);
    std:: cout << car_mes << '\n';
    size_t tr_ch = trinket.challenge(car_mes);
    std::cout << tr_ch << '\n';
    std::string car_resp = car.challenge(tr_ch);
    std::cout << car_resp << '\n';


//    std::cout << "Hello, World!" << std::endl;
    return 0;
}
