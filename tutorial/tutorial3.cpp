/*
 * OpenFHE Library Integration
 * This example demonstrates basic CKKS operations using OpenFHE
 */
#include "openfhe.h"

using namespace lbcrypto;

int main() {

    uint32_t multDepth = 31;
    uint32_t scaleModSize = 59;
    uint32_t firstModSize = 60;
    uint32_t batchSize = 4096;

    SecurityLevel securityLevel = HEStd_128_classic;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetFirstModSize(firstModSize);

    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension "
              << cc->GetRingDimension() << std::endl
              << std::endl;

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(KEYSWITCH);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    /*
        Set up for Bootstrapping
    */
    std::vector<uint32_t> levelBudget = {4, 5};
    std::vector<uint32_t> bsgsDim = {0, 0};
    cc->EvalBootstrapSetup(levelBudget, bsgsDim, batchSize);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey,
                            batchSize); // Required for Bootstrapping

    std::vector<double> msg = {-0.9, -0.7, -0.5, -0.1, 0.1, 0.5, 0.7, 0.9};

    std::cout << "msg: " << msg << std::endl;
    std::cout << std::endl;

    Plaintext ptx =
        cc->MakeCKKSPackedPlaintext(msg, 1, multDepth - 1, nullptr, batchSize);
    auto ctx = cc->Encrypt(keyPair.publicKey, ptx);

    std::cout << "Maximum level: " << multDepth << std::endl;
    std::cout << "Level of ciphertext before bootstrapping: " << ctx->GetLevel()
              << std::endl;

    auto ctx_boot = cc->EvalBootstrap(ctx, 2, 17);

    std::cout << "Level of ciphertext after bootstrapping: "
              << ctx_boot->GetLevel() << std::endl;

    Plaintext ptx_boot;
    cc->Decrypt(keyPair.secretKey, ctx_boot, &ptx_boot);
    ptx_boot->SetLength(8);
    std::vector<double> msg_boot = ptx_boot->GetRealPackedValue();
    std::cout << "msg after bootstrapping: " << msg_boot << std::endl;
    std::cout << std::endl;

    return 0;
}