/*
 * OpenFHE Library Integration
 * This example demonstrates basic CKKS operations using OpenFHE
 */
#include "openfhe.h"

using namespace lbcrypto;

int main() {

    /*
        1) Generate Parameters and Crypto Context

        - multDepth: Available rescaling operations for fresh ciphertexts.
        - scaleModSize: Log size of the scaling factor; ciphertext modulus ≈
       scaleModSize^multDepth.
        - Higher ciphertext modulus and ring dimension can reduce performance.
        - Security level affects ring dimension and ciphertext modulus.
        - Current code automatically sets the ring dimension based on the given
       parameters.

        - Ring dimension can be set manually.
        - Try different batch sizes!
    */
    uint32_t multDepth = 2;
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

    /*
        2) Key Generation
        - keyPair consists of a secretKey and a publicKey.
        - EvalMultKeyGen generates an evaluation key used for relinearization.
    */
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> msg1 = {1.0, 2.0, 3.0, 4.0};
    std::vector<double> msg2 = {5.0, 6.0, 7.0, 8.0};

    std::cout << "msg1: " << msg1 << std::endl;
    std::cout << "msg2: " << msg2 << std::endl;
    std::cout << std::endl;

    /*
        3) Encode the message
    */
    Plaintext ptx1 = cc->MakeCKKSPackedPlaintext(msg1);
    Plaintext ptx2 = cc->MakeCKKSPackedPlaintext(msg2);

    std::cout << "ptx1: " << std::endl;
    std::cout << ptx1 << std::endl;

    std::cout << "ptx2: " << std::endl;
    std::cout << ptx2 << std::endl;
    std::cout << std::endl;

    /*
        4) Encrypt the Plaintext

        - A ciphertext is a pair of ring elements.
        - The type of ciphertext is "Ciphertext<DCRTPoly>" (we can also use
       "auto").
    */
    auto ctx1 = cc->Encrypt(keyPair.publicKey, ptx1);
    auto ctx2 = cc->Encrypt(keyPair.publicKey, ptx2);

    // // // What if we just print ciphertext?
    // std::cout << "ctx1: " << std::endl;
    // std::cout << ctx1 << std::endl;

    // std::cout << "ctx2: " << std::endl;
    // std::cout << ctx2 << std::endl;
    // std::cout << std::endl;
    // // //

    /*
        5) Decrypt the Ciphertext

        - Let's verify that the decryption result is correct.
        - SetLength is optional.
    */
    Plaintext decrypted_ptx1, decrypted_ptx2;
    cc->Decrypt(keyPair.secretKey, ctx1, &decrypted_ptx1);
    cc->Decrypt(keyPair.secretKey, ctx2, &decrypted_ptx2);

    decrypted_ptx1->SetLength(4);
    decrypted_ptx2->SetLength(4);

    std::vector<double> decrypted_msg1 = decrypted_ptx1->GetRealPackedValue();
    std::vector<double> decrypted_msg2 = decrypted_ptx2->GetRealPackedValue();

    std::cout << "decrypted msg1: " << decrypted_msg1 << std::endl;
    std::cout << "decrypted msg2: " << decrypted_msg2 << std::endl;
    std::cout << std::endl;
    /*
        Homomorphic Evaluations
        1) Addition
        2) Scalar Multiplication
        3) Plaintext-Ciphertext Multiplication
        4) Ciphertext-Ciphertext Multiplication
    */

    // 1-1) Add Scalar to Ciphertext
    // ctx_add1 = cxt1 + 1
    auto ctx_add1 = cc->EvalAdd(ctx1, 1);

    Plaintext ptx_add1;
    cc->Decrypt(keyPair.secretKey, ctx_add1, &ptx_add1);
    ptx_add1->SetLength(4);
    std::vector<double> msg_add1 = ptx_add1->GetRealPackedValue();
    std::cout << "msg1 + 1: " << msg_add1 << std::endl;

    // 1-2) Add Packed-Plaintext to Ciphertext
    auto ctx_add2 = cc->EvalAdd(
        ctx1, cc->MakeCKKSPackedPlaintext(std::vector<double>{0, 1, 0, 1}));

    Plaintext ptx_add2;
    cc->Decrypt(keyPair.secretKey, ctx_add2, &ptx_add2);
    ptx_add2->SetLength(4);
    std::vector<double> msg_add2 = ptx_add2->GetRealPackedValue();
    std::cout << "msg1 + {0,1,0,1}: " << msg_add2 << std::endl;

    // 1-3) Ciphertext-Ciphertext Addition
    auto ctx_add3 = cc->EvalAdd(ctx1, ctx2);

    Plaintext ptx_add3;
    cc->Decrypt(keyPair.secretKey, ctx_add3, &ptx_add3);
    ptx_add3->SetLength(4);
    std::vector<double> msg_add3 = ptx_add3->GetRealPackedValue();
    std::cout << "msg1 + msg2: " << msg_add3 << std::endl;

    // 1-4) Ciphertext-Ciphertext Subtraction
    auto ctx_add4 = cc->EvalSub(ctx1, ctx2);

    Plaintext ptx_add4;
    cc->Decrypt(keyPair.secretKey, ctx_add4, &ptx_add4);
    ptx_add4->SetLength(4);
    std::vector<double> msg_add4 = ptx_add4->GetRealPackedValue();
    std::cout << "msg1 - msg2: " << msg_add4 << std::endl;
    std::cout << std::endl;

    // 2-1) Scalar Multiplication (no rescaling required, 0 depth).
    std::cout << "Level of ciphertext before multiplication: "
              << ctx1->GetLevel() << std::endl;
    auto ctx_mult1 = cc->GetScheme()->MultByInteger(ctx1, 2);
    std::cout << "Level of ciphertext after multiplication: "
              << ctx_mult1->GetLevel() << std::endl;

    Plaintext ptx_mult1;
    cc->Decrypt(keyPair.secretKey, ctx_mult1, &ptx_mult1);
    ptx_mult1->SetLength(4);
    std::vector<double> msg_mult1 = ptx_mult1->GetRealPackedValue();
    std::cout << "2*msg1: " << msg_mult1 << std::endl;
    std::cout << std::endl;

    // 2-2) Multiplying with rescaling
    std::cout << "Level of ciphertext before multiplication: "
              << ctx1->GetLevel() << std::endl;
    auto ctx_mult2 = cc->EvalMult(ctx1, 0.5);
    std::cout << "Level of ciphertext after multiplication: "
              << ctx_mult2->GetLevel() << std::endl;

    Plaintext ptx_mult2;
    cc->Decrypt(keyPair.secretKey, ctx_mult2, &ptx_mult2);
    ptx_mult2->SetLength(4);
    std::vector<double> msg_mult2 = ptx_mult2->GetRealPackedValue();
    std::cout << "0.5*msg1: " << msg_mult2 << std::endl;
    std::cout << std::endl;

    // 3) Plaintext-Ciphertext Multiplication
    std::cout << "Level of ciphertext before multiplication: "
              << ctx1->GetLevel() << std::endl;
    auto ctx_mult3 = cc->EvalMult(
        ctx1, cc->MakeCKKSPackedPlaintext(std::vector<double>{1, 0, 0, 0}));
    std::cout << "Level of ciphertext after multiplication: "
              << ctx_mult3->GetLevel() << std::endl;

    Plaintext ptx_mult3;
    cc->Decrypt(keyPair.secretKey, ctx_mult3, &ptx_mult3);
    ptx_mult3->SetLength(4);
    std::vector<double> msg_mult3 = ptx_mult3->GetRealPackedValue();
    std::cout << "msg1*{1,0,0,0}: " << msg_mult3 << std::endl;
    std::cout << std::endl;

    // 4) Ciphertext-Ciphertext Multiplication
    std::cout << "Level of ciphertext before multiplication: "
              << ctx1->GetLevel() << std::endl;
    auto ctx_mult4 = cc->EvalMultAndRelinearize(ctx1, ctx2);
    std::cout << "Level of ciphertext after multiplication: "
              << ctx_mult4->GetLevel() << std::endl;

    Plaintext ptx_mult4;
    cc->Decrypt(keyPair.secretKey, ctx_mult4, &ptx_mult4);
    ptx_mult4->SetLength(4);
    std::vector<double> msg_mult4 = ptx_mult4->GetRealPackedValue();
    std::cout << "msg1*msg2: " << msg_mult4 << std::endl;
    std::cout << std::endl;

    return 0;
}