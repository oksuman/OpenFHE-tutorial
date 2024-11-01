#include "practice1.h"

Ciphertext<DCRTPoly>
Practice1::evaluateLinearPolynomial(const CryptoContext<DCRTPoly> cc,
                                    const Ciphertext<DCRTPoly> x,
                                    const Ciphertext<DCRTPoly> y) {

    auto twice_x = cc->EvalMult(x, 2.0);
    return cc->EvalAdd(twice_x, y);
}

Ciphertext<DCRTPoly>
Practice1::computeTriangleArea(const CryptoContext<DCRTPoly> cc,
                               const Ciphertext<DCRTPoly> base,
                               const Ciphertext<DCRTPoly> height) {
    auto area = cc->EvalMultAndRelinearize(base, height);
    return cc->EvalMult(area, 0.5);
}

Ciphertext<DCRTPoly>
Practice1::evaluateCubicPolynomial(const CryptoContext<DCRTPoly> cc,
                                   const Ciphertext<DCRTPoly> x) {

    auto const_term = cc->EvalMult(x, 0.0);
    const_term = cc->EvalAdd(const_term, 1.0);

    auto linear_term = cc->EvalMult(x, 3.0);

    auto x_squared = cc->EvalMultAndRelinearize(x, x);
    auto x_cubed = cc->EvalMultAndRelinearize(x_squared, x);
    auto cubic_term = cc->EvalMult(x_cubed, 0.2);

    auto result = cc->EvalAdd(const_term, linear_term);
    return cc->EvalAdd(result, cubic_term);
}

std::vector<double>
Practice1::decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                              const Ciphertext<DCRTPoly> &ciphertext,
                              const PrivateKey<DCRTPoly> &sk) {
    Plaintext plaintext;
    cc->Decrypt(sk, ciphertext, &plaintext);
    plaintext->SetLength(4);
    return plaintext->GetRealPackedValue();
}