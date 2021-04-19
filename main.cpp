#include <iostream>
#include "crypto++/rsa.h"
#include <crypto++/osrng.h>
#include "Car.h"
#include "Trinket.h"

using std::cout;

int main() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey private_key;
    private_key.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PublicKey public_key(private_key);

    Car car(public_key);
    Trinket trinket(private_key);

    cout << "(handshake) trinket -> car: ";
    std::string tr_com = trinket.get_command('o');
    std::cout << tr_com << '\n';

    cout << "(challenge)  car -> trinket: ";
    std::string car_mes = car.get_message(tr_com);
    std:: cout << car_mes << '\n';

    cout << "(response)  trinket -> car: ";
    size_t tr_ch = trinket.challenge(car_mes);
    std::cout << tr_ch << '\n';

    cout << "(action)  car: ";
    std::string car_resp = car.challenge(tr_ch);
    std::cout << car_resp << '\n';

    return EXIT_SUCCESS;
}
