#include "practice3.h"

Ciphertext<DCRTPoly> Practice3::customRotate(const CryptoContext<DCRTPoly> cc,
                                             const Ciphertext<DCRTPoly> input,
                                             int32_t index) {
    if (index == 0)
        return input;

    auto result = input->Clone();
    int l = abs(index);

    while (l > 0) {
        int largestPowerOf2 = 1 << static_cast<int>(log2(l));
        if (largestPowerOf2 > 4) {
            largestPowerOf2 = 4;
        }

        result = cc->EvalRotate(result, (index > 0) ? largestPowerOf2
                                                    : -largestPowerOf2);
        l -= largestPowerOf2;
    }

    return result;
}

Ciphertext<DCRTPoly>
Practice3::permutateVector(const CryptoContext<DCRTPoly> cc,
                           const Ciphertext<DCRTPoly> input) {
    auto mask1 = cc->MakeCKKSPackedPlaintext(
        std::vector<double>{1, 1, 1, 0, 1, 1, 1, 0});
    auto part1 = customRotate(cc, input, 1);
    part1 = cc->EvalMult(part1, mask1);

    auto mask2 = cc->MakeCKKSPackedPlaintext(
        std::vector<double>{0, 0, 0, 1, 0, 0, 0, 1});
    auto part2 = customRotate(cc, input, -3);
    part2 = cc->EvalMult(part2, mask2);

    return cc->EvalAdd(part1, part2);
}

Ciphertext<DCRTPoly>
Practice3::efficientCubicPolynomial(const CryptoContext<DCRTPoly> cc,
                                    const Ciphertext<DCRTPoly> x) {
    auto const_term = cc->EvalMult(x, 0.0);
    const_term = cc->EvalAdd(const_term, 1.0);

    auto linear_term = cc->EvalMult(x, 3.0);

    auto x_squared = cc->EvalMultAndRelinearize(x, x);
    auto temp = cc->EvalMult(x, 0.2);
    auto cubic_term = cc->EvalMultAndRelinearize(temp, x_squared);

    auto result = cc->EvalAdd(const_term, linear_term);
    return cc->EvalAdd(result, cubic_term);
}

std::vector<double>
Practice3::decrypt_and_decode(const CryptoContext<DCRTPoly> &cc,
                              const Ciphertext<DCRTPoly> &ciphertext,
                              const PrivateKey<DCRTPoly> &sk) {
    Plaintext plaintext;
    cc->Decrypt(sk, ciphertext, &plaintext);
    plaintext->SetLength(8);
    return plaintext->GetRealPackedValue();
}