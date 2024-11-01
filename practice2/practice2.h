#pragma once
#include "openfhe.h"

using namespace lbcrypto;

class Practice2 {
  public:
    static Ciphertext<DCRTPoly>
    computeAverage(const CryptoContext<DCRTPoly> cc,
                   const Ciphertext<DCRTPoly> vector);

    static Ciphertext<DCRTPoly>
    computeDotProduct(const CryptoContext<DCRTPoly> cc,
                      const Ciphertext<DCRTPoly> vector1,
                      const Ciphertext<DCRTPoly> vector2);

    static std::vector<double>
    decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                       const Ciphertext<DCRTPoly> &ciphertext,
                       const PrivateKey<DCRTPoly> &sk);
};