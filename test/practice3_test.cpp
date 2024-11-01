#include "practice3.h"
#include <gtest/gtest.h>

class Practice3Test : public ::testing::Test {
  protected:
    void SetUp() override {
        uint32_t multDepth = 2;
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
        cc->EvalRotateKeyGen(keyPair.secretKey, {-4, -2, -1, 1, 2, 4});
    }

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;
};

TEST_F(Practice3Test, CustomRotateTest) {
    std::vector<double> input = {-2.5, 1.5, 2.0, -1.0, 0.5, -3.0, 2.7, 1.2};
    int32_t rotation = 3;

    auto plain = cc->MakeCKKSPackedPlaintext(input);
    auto cipher = cc->Encrypt(keyPair.publicKey, plain);

    auto result = Practice3::customRotate(cc, cipher, rotation);
    auto decrypted =
        Practice3::decrypt_and_decode(cc, result, keyPair.secretKey);

    std::vector<double> expected = {-1.0, 0.5, -3.0, 2.7, 1.2, -2.5, 1.5, 2.0};
    ASSERT_EQ(decrypted.size(), 8);
    for (size_t i = 0; i < decrypted.size(); i++) {
        EXPECT_NEAR(decrypted[i], expected[i], 0.0001);
    }
}

TEST_F(Practice3Test, PermutationTest) {
    std::vector<double> input = {-1.5, 2.8, -0.5, 1.2, 2.5, -2.0, 0.7, 1.8};

    auto plain = cc->MakeCKKSPackedPlaintext(input);
    auto cipher = cc->Encrypt(keyPair.publicKey, plain);

    auto result = Practice3::permutateVector(cc, cipher);
    auto decrypted =
        Practice3::decrypt_and_decode(cc, result, keyPair.secretKey);

    std::vector<double> expected = {2.8, -0.5, 1.2, -1.5, -2.0, 0.7, 1.8, 2.5};
    ASSERT_EQ(decrypted.size(), 8);
    for (size_t i = 0; i < decrypted.size(); i++) {
        EXPECT_NEAR(decrypted[i], expected[i], 0.0001);
    }
}

TEST_F(Practice3Test, EfficientCubicPolynomialTest) {
    std::vector<double> input = {-2.0, 1.5, -1.0, 2.5, 0.5, -2.5, 3.0, -0.5};

    auto plain = cc->MakeCKKSPackedPlaintext(input);
    auto cipher = cc->Encrypt(keyPair.publicKey, plain);

    auto result = Practice3::efficientCubicPolynomial(cc, cipher);
    auto decrypted =
        Practice3::decrypt_and_decode(cc, result, keyPair.secretKey);

    std::vector<double> expected;
    for (const auto &x : input) {
        expected.push_back(1 + 3 * x + 0.2 * x * x * x);
    }

    ASSERT_EQ(decrypted.size(), 8);
    for (size_t i = 0; i < decrypted.size(); i++) {
        EXPECT_NEAR(decrypted[i], expected[i], 0.0001);
    }
}