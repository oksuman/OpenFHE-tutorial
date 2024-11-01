/*
 * OpenFHE Library Integration
 * This example demonstrates basic CKKS operations using OpenFHE
 */
#include "openfhe.h"

using namespace lbcrypto;

int main() {

    uint32_t multDepth = 10;
    uint32_t scaleModSize = 50;
    SecurityLevel securityLevel = HEStd_128_classic;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(4);
    parameters.SetSecurityLevel(securityLevel);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension "
              << cc->GetRingDimension() << std::endl
              << std::endl;
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(KEYSWITCH);
    cc->Enable(ADVANCEDSHE); // Required for Chebyshev associated functions.

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1, 2, 3, -1, -2, -3});

    std::vector<double> msg1 = {2, 4, -2, -4};
    std::vector<double> msg2 = {2, 5, 10, 20};

    std::cout << "msg1: " << msg1 << std::endl;
    std::cout << "msg2: " << msg2 << std::endl;
    std::cout << std::endl;

    Plaintext ptx1 = cc->MakeCKKSPackedPlaintext(msg1);
    Plaintext ptx2 = cc->MakeCKKSPackedPlaintext(msg2);

    auto ctx1 = cc->Encrypt(keyPair.publicKey, ptx1);
    auto ctx2 = cc->Encrypt(keyPair.publicKey, ptx2);

    /*
        1) Rotation
        - Positive rotation: Performs left circular shift
        - Negative rotation: Performs right circular shift
    */
    auto ctx_rot1 = cc->EvalRotate(ctx1, 1);
    auto ctx_rot2 = cc->EvalRotate(ctx1, -2);

    Plaintext ptx_rot1, ptx_rot2;
    cc->Decrypt(keyPair.secretKey, ctx_rot1, &ptx_rot1);
    cc->Decrypt(keyPair.secretKey, ctx_rot2, &ptx_rot2);
    ptx_rot1->SetLength(4);
    ptx_rot2->SetLength(4);
    std::vector<double> msg_rot1 = ptx_rot1->GetRealPackedValue();
    std::vector<double> msg_rot2 = ptx_rot2->GetRealPackedValue();
    std::cout << "rotation of msg1 by 1: " << msg_rot1 << std::endl;
    std::cout << "rotation of msg1 by -2: " << msg_rot2 << std::endl;
    std::cout << std::endl;

    /*
        2) Evaluate non-polynomial function.
    */

    // 2-1) Evaluation of Sign function.
    auto signFunction = [](double x) -> double {
        if (x > 0)
            return 1.0;
        if (x < 0)
            return -1.0;
        return 0.0;
    };

    std::cout << "Level of ciphertext before sign evaluation: "
              << ctx1->GetLevel() << std::endl;

    auto ctx_sign = cc->EvalChebyshevFunction(signFunction, ctx1, -5, 5, 31);

    std::cout << "Level of ciphertext after sign evaluation: "
              << ctx_sign->GetLevel() << std::endl;

    Plaintext ptx_sign;
    cc->Decrypt(keyPair.secretKey, ctx_sign, &ptx_sign);
    ptx_sign->SetLength(4);
    std::vector<double> msg_sign = ptx_sign->GetRealPackedValue();
    std::cout << "sign(msg1): " << msg_sign << std::endl;
    std::cout << std::endl;

    // 2-2) Evaluation of 1/x function.
    std::cout << "Level of ciphertext before 1/x evaluation: "
              << ctx2->GetLevel() << std::endl;

    auto ctx_inverse = cc->EvalDivide(ctx2, 2, 20, 31);

    std::cout << "Level of ciphertext after 1/x evaluation: "
              << ctx_inverse->GetLevel() << std::endl;

    Plaintext ptx_inverse;
    cc->Decrypt(keyPair.secretKey, ctx_inverse, &ptx_inverse);
    ptx_inverse->SetLength(4);
    std::vector<double> msg_inverse = ptx_inverse->GetRealPackedValue();
    std::cout << "1/msg2: " << msg_inverse << std::endl;
    std::cout << std::endl;

    return 0;
}