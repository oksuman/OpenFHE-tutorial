#pragma once

#include "openfhe.h"

using namespace lbcrypto;

class Practice1 {
  public:
    static Ciphertext<lbcrypto::DCRTPoly>
    evaluateLinearPolynomial(const CryptoContext<DCRTPoly> cc,
                             const Ciphertext<lbcrypto::DCRTPoly> X,
                             const Ciphertext<lbcrypto::DCRTPoly> Y);

    static Ciphertext<DCRTPolyImpl<BigVector>>
    computeTriangleArea(const CryptoContext<DCRTPoly> cc,
                        const Ciphertext<lbcrypto::DCRTPoly> base,
                        const Ciphertext<lbcrypto::DCRTPoly> height);

    static Ciphertext<lbcrypto::DCRTPoly>
    evaluateCubicPolynomial(const CryptoContext<DCRTPoly> cc,
                            const Ciphertext<lbcrypto::DCRTPoly> x);

    static std::vector<double>
    decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                       const Ciphertext<DCRTPoly> &ciphertext,
                       const PrivateKey<DCRTPoly> &sk);
};