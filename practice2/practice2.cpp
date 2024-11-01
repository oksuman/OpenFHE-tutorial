#include "practice2.h"

Ciphertext<lbcrypto::DCRTPoly>
Practice2::computeAverage(const CryptoContext<DCRTPoly> cc,
                          const Ciphertext<lbcrypto::DCRTPoly> vector) {
    /**
     * TODO: Compute the average of encrypted vector values
     * The result should be a vector where all elements are the average
     *
     * Example:
     * vector = {2, 4, 6, 8}
     * output = {5, 5, 5, 5}  // (2+4+6+8)/4 = 5
     *
     * Hint:
     * - Rotation operation is available
     * - Rotation keys for {-4,-3,-2,-1,1,2,3,4} are provided
     */
    return nullptr;
}

Ciphertext<lbcrypto::DCRTPoly>
Practice2::computeDotProduct(const CryptoContext<DCRTPoly> cc,
                             const Ciphertext<lbcrypto::DCRTPoly> vector1,
                             const Ciphertext<lbcrypto::DCRTPoly> vector2) {
    /**
     * TODO: Compute the dot product of two encrypted vectors
     * The result should be a vector where all elements are the dot product
     *
     * Example:
     * vector1 = {1, 2, 3, 4}
     * vector2 = {2, 3, 4, 5}
     * output = {40, 40, 40, 40}  // 1*2 + 2*3 + 3*4 + 4*5 = 40
     */
    return nullptr;
}

std::vector<double>
Practice2::decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                              const Ciphertext<DCRTPoly> &ciphertext,
                              const PrivateKey<DCRTPoly> &sk) {
    Plaintext plaintext;
    cc->Decrypt(sk, ciphertext, &plaintext);
    plaintext->SetLength(4);
    return plaintext->GetRealPackedValue();
}