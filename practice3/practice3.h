#pragma once
#include "openfhe.h"

using namespace lbcrypto;

class Practice3 {
  public:
    static Ciphertext<DCRTPoly> customRotate(const CryptoContext<DCRTPoly> cc,
                                             const Ciphertext<DCRTPoly> input,
                                             int32_t index);

    static Ciphertext<DCRTPoly>
    permutateVector(const CryptoContext<DCRTPoly> cc,
                    const Ciphertext<DCRTPoly> input);

    static Ciphertext<DCRTPoly>
    efficientCubicPolynomial(const CryptoContext<DCRTPoly> cc,
                             const Ciphertext<DCRTPoly> x);

    static std::vector<double>
    decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                       const Ciphertext<DCRTPoly> &ciphertext,
                       const PrivateKey<DCRTPoly> &sk);
};