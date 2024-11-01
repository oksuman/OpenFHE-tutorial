#include "practice1.h"
#include <gtest/gtest.h>

class Practice1Test : public ::testing::Test {
  protected:
    void SetUp() override {
        uint32_t multDepth = 4;
        uint32_t scaleModSize = 50;
        uint32_t batchSize = 8;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetBatchSize(batchSize);
        parameters.SetSecurityLevel(HEStd_128_classic);

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
    }

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;
};

TEST_F(Practice1Test, LinearPolynomialTest) {
    std::vector<double> x_values = {1.0, 2.0, 3.0, 4.0};
    std::vector<double> y_values = {0.5, 1.5, 2.5, 3.5};

    auto x_plain = cc->MakeCKKSPackedPlaintext(x_values);
    auto y_plain = cc->MakeCKKSPackedPlaintext(y_values);

    auto x_cipher = cc->Encrypt(keyPair.publicKey, x_plain);
    auto y_cipher = cc->Encrypt(keyPair.publicKey, y_plain);

    auto result = Practice1::evaluateLinearPolynomial(cc, x_cipher, y_cipher);
    auto decrypted =
        Practice1::decrypt_and_decode(cc, result, keyPair.secretKey);

    for (size_t i = 0; i < x_values.size(); i++) {
        double expected = 2 * x_values[i] + y_values[i];
        EXPECT_NEAR(decrypted[i], expected, 0.0001);
    }
}

TEST_F(Practice1Test, TriangleAreaTest) {
    std::vector<double> base_values = {2.0, 3.0, 4.0, 5.0};
    std::vector<double> height_values = {3.0, 4.0, 5.0, 6.0};

    auto base_plain = cc->MakeCKKSPackedPlaintext(base_values);
    auto height_plain = cc->MakeCKKSPackedPlaintext(height_values);

    auto base_cipher = cc->Encrypt(keyPair.publicKey, base_plain);
    auto height_cipher = cc->Encrypt(keyPair.publicKey, height_plain);

    auto result =
        Practice1::computeTriangleArea(cc, base_cipher, height_cipher);
    auto decrypted =
        Practice1::decrypt_and_decode(cc, result, keyPair.secretKey);

    for (size_t i = 0; i < base_values.size(); i++) {
        double expected = (base_values[i] * height_values[i]) / 2.0;
        EXPECT_NEAR(decrypted[i], expected, 0.0001);
    }
}

TEST_F(Practice1Test, CubicPolynomialTest) {
    std::vector<double> x_values = {1.0, 2.0, 3.0, 4.0};

    auto x_plain = cc->MakeCKKSPackedPlaintext(x_values);
    auto x_cipher = cc->Encrypt(keyPair.publicKey, x_plain);

    auto result = Practice1::evaluateCubicPolynomial(cc, x_cipher);
    auto decrypted =
        Practice1::decrypt_and_decode(cc, result, keyPair.secretKey);

    for (size_t i = 0; i < x_values.size(); i++) {
        double x = x_values[i];
        double expected = 1 + 3 * x + 0.2 * x * x * x;
        EXPECT_NEAR(decrypted[i], expected, 0.0001);
    }
}