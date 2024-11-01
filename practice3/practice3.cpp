#include "practice3.h"

Ciphertext<DCRTPoly> Practice3::customRotate(const CryptoContext<DCRTPoly> cc,
                                             const Ciphertext<DCRTPoly> input,
                                             int32_t index) {
    /**
     * TODO: Implement arbitrary rotation using only available rotation keys
     *
     * Given:
     * - Batch size is 8
     * - Available rotation keys are {-4,-2,-1,1,2,4}
     *
     * Task:
     * - Implement a function that can perform any rotation amount
     * - Example: rotation by 7 should be possible using combination of given
     * keys
     *
     * Example:
     * input = {1, 2, 3, 4, 5, 6, 7, 8}
     * index = 3
     * output = {6, 7, 8, 1, 2, 3, 4, 5}
     */
    return nullptr;
}

Ciphertext<DCRTPoly>
Practice3::permutateVector(const CryptoContext<DCRTPoly> cc,
                           const Ciphertext<DCRTPoly> input) {
    /**
     * TODO: Implement specific permutation using rotations
     *
     * Given vector [a b c d e f g h], create [b c d a f g h e]
     *
     * Example:
     * input = {1, 2, 3, 4, 5, 6, 7, 8}
     * output = {2, 3, 4, 1, 6, 7, 8, 5}
     */
    return nullptr;
}

Ciphertext<DCRTPoly>
Practice3::efficientCubicPolynomial(const CryptoContext<DCRTPoly> cc,
                                    const Ciphertext<DCRTPoly> x) {
    /**
     * TODO: Compute 1 + 3x + 0.2x³ using only depth 2
     *
     * Challenge:
     * - Implement the same cubic polynomial as in Practice1
     * - Use only multiplicative depth 2 (optimize the multiplication chain)
     *
     * Example:
     * x = {1, 2, -1.5, 0.5}
     * output = {4.2, 11.6, -2.325, 1.525}
     */
    return nullptr;
}

std::vector<double>
Practice3::decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                              const Ciphertext<DCRTPoly> &ciphertext,
                              const PrivateKey<DCRTPoly> &sk) {
    Plaintext plaintext;
    cc->Decrypt(sk, ciphertext, &plaintext);
    plaintext->SetLength(8); // Note: batch size is 8 for Practice3
    return plaintext->GetRealPackedValue();
}