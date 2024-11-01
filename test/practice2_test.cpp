#include "practice2.h"
#include <gtest/gtest.h>

class Practice2Test : public ::testing::Test {
  protected:
    void SetUp() override {
        uint32_t multDepth = 2;
        uint32_t scaleModSize = 50;
        uint32_t batchSize = 4;

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
        cc->EvalRotateKeyGen(keyPair.secretKey, {-4, -3, -2, -1, 1, 2, 3, 4});
    }

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;
};

TEST_F(Practice2Test, AverageTest) {
    std::vector<double> input = {-1.5, 0.5, 1.0, 2.0};
    double expected_avg = 0.5; // (-1.5+0.5+1.0+2.0)/4

    auto plain = cc->MakeCKKSPackedPlaintext(input);
    auto cipher = cc->Encrypt(keyPair.publicKey, plain);

    auto result = Practice2::computeAverage(cc, cipher);
    auto decrypted =
        Practice2::decrypt_and_decode(cc, result, keyPair.secretKey);

    ASSERT_EQ(decrypted.size(), 4);
    for (size_t i = 0; i < decrypted.size(); i++) {
        EXPECT_NEAR(decrypted[i], expected_avg, 0.0001);
    }
}

TEST_F(Practice2Test, DotProductTest) {
    std::vector<double> input1 = {-1.0, 0.5, 1.5, 2.0};
    std::vector<double> input2 = {1.0, -0.5, 1.0, -1.5};
    double expected_dot =
        -2.75; // (-1.0*1.0) + (0.5*-0.5) + (1.5*1.0) + (2.0*-1.5)

    auto plain1 = cc->MakeCKKSPackedPlaintext(input1);
    auto plain2 = cc->MakeCKKSPackedPlaintext(input2);

    auto cipher1 = cc->Encrypt(keyPair.publicKey, plain1);
    auto cipher2 = cc->Encrypt(keyPair.publicKey, plain2);

    auto result = Practice2::computeDotProduct(cc, cipher1, cipher2);
    auto decrypted =
        Practice2::decrypt_and_decode(cc, result, keyPair.secretKey);

    ASSERT_EQ(decrypted.size(), 4);
    for (size_t i = 0; i < decrypted.size(); i++) {
        EXPECT_NEAR(decrypted[i], expected_dot, 0.0001);
    }
}