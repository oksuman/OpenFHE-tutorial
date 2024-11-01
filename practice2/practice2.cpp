#include "practice2.h"

Ciphertext<DCRTPoly>
Practice2::computeAverage(const CryptoContext<DCRTPoly> cc,
                          const Ciphertext<DCRTPoly> vector) {
    auto sum = vector;

    for (int i = 1; i < 4; i++) {
        auto rotated = cc->EvalRotate(vector, i);
        sum = cc->EvalAdd(sum, rotated);
    }

    return cc->EvalMult(sum, 0.25);
}

Ciphertext<DCRTPoly>
Practice2::computeDotProduct(const CryptoContext<DCRTPoly> cc,
                             const Ciphertext<DCRTPoly> vector1,
                             const Ciphertext<DCRTPoly> vector2) {
    auto product = cc->EvalMultAndRelinearize(vector1, vector2);

    for (int i = 1; i <= log2(4); i++) {
        cc->EvalAddInPlace(product, cc->EvalRotate(product, 4 / (1 << i)));
    }

    return product;
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