#include "practice1.h"

Ciphertext<lbcrypto::DCRTPoly>
Practice1::evaluateLinearPolynomial(const CryptoContext<DCRTPoly> cc,
                                    const Ciphertext<lbcrypto::DCRTPoly> x,
                                    const Ciphertext<lbcrypto::DCRTPoly> y) {
    /**
     * TODO: Evaluate 2x + y using encrypted values
     *
     * Example:
     * x = {1, 2, 3, 4}
     * y = {2, 1, 1, 2}
     * output = {4, 5, 7, 10}
     */
    return nullptr;
}

Ciphertext<lbcrypto::DCRTPoly>
Practice1::computeTriangleArea(const CryptoContext<DCRTPoly> cc,
                               const Ciphertext<lbcrypto::DCRTPoly> base,
                               const Ciphertext<lbcrypto::DCRTPoly> height) {
    /**
     * TODO: Compute triangle areas from encrypted base and height values
     *
     * Formula: area = (base * height) / 2
     *
     * Example:
     * base = {2, 3, 4, 5}
     * height = {3, 4, 5, 6}
     * output = {3, 6, 10, 15}
     */
    return nullptr;
}

Ciphertext<lbcrypto::DCRTPoly>
Practice1::evaluateCubicPolynomial(const CryptoContext<DCRTPoly> cc,
                                   const Ciphertext<lbcrypto::DCRTPoly> x) {
    /**
     * TODO: Evaluate 1 + 3x + 0.2x³ using encrypted x values
     *
     * Example:
     * x = {1, 2, 3, 4}
     * output = {4.2, 11.6, 25.4, 49.2}
     */
    return nullptr;
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