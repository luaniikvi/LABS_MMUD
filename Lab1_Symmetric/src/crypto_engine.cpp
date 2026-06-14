// crypto_engine.cpp
#include "crypto_engine.hpp"
#include "utils.hpp"
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <set>
#include <stdint.h>
#include <algorithm>

// Function-local static avoids static-init-order crash when tests.cpp's
// NonceRegistryCleanup runs before this TU's file-scope statics are constructed.
static std::set<std::string>& GetNonceRegistry() {
    static std::set<std::string> reg;
    return reg;
}
static bool persistentRegistryLoaded = false;
static const char* NONCE_REGISTRY_FILE = ".aestool_nonce_registry.json";

static bool IsAeadMode(const std::string& mode) {
    return mode == "gcm" || mode == "ccm";
}

static bool RequiresNonceReuseProtection(const std::string& mode) {
    return mode == "ctr" || mode == "gcm" || mode == "ccm";
}

static std::string MakeKeyNonceToken(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    return ToHex(key) + "||" + ToHex(iv);
}

static void LoadPersistentNonceRegistry() {
    if (persistentRegistryLoaded) {
        return;
    }
    persistentRegistryLoaded = true;

    std::ifstream f(NONCE_REGISTRY_FILE);
    if (!f) {
        return;
    }

    try {
        nlohmann::json j;
        f >> j;
        if (!j.contains("entries") || !j["entries"].is_array()) {
            return;
        }
        for (const auto& entry : j["entries"]) {
            if (entry.contains("key") && entry.contains("nonce")) {
                GetNonceRegistry().insert(entry["key"].get<std::string>() + "||" + entry["nonce"].get<std::string>());
            }
        }
    } catch (...) {
        // Fail closed on corrupt registry: treat as empty rather than crash.
    }
}

static void AppendPersistentNonceEntry(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::string& mode) {
    nlohmann::json j;
    std::ifstream in(NONCE_REGISTRY_FILE);
    if (in) {
        try {
            in >> j;
        } catch (...) {
            j = nlohmann::json::object();
        }
    }
    if (!j.contains("entries") || !j["entries"].is_array()) {
        j["entries"] = nlohmann::json::array();
    }

    j["entries"].push_back({
        {"key", ToHex(key)},
        {"nonce", ToHex(iv)},
        {"mode", mode}
    });

    std::ofstream out(NONCE_REGISTRY_FILE);
    if (out) {
        out << j.dump(2) << "\n";
    }
}

void CheckKeyNonceReuse(const CryptoConfig& config) {
    if (!RequiresNonceReuseProtection(config.mode)) {
        return;
    }

    LoadPersistentNonceRegistry();
    const std::string token = MakeKeyNonceToken(config.key, config.iv);
    if (GetNonceRegistry().count(token)) {
        throw std::runtime_error("CRITICAL SECURITY VIOLATION: Detected reuse of (Key, Nonce) pair!");
    }
}

void RegisterKeyNonceUse(const CryptoConfig& config) {
    if (!RequiresNonceReuseProtection(config.mode)) {
        return;
    }

    const std::string token = MakeKeyNonceToken(config.key, config.iv);
    if (GetNonceRegistry().insert(token).second) {
        AppendPersistentNonceEntry(config.key, config.iv, config.mode);
    }
}

void ClearNonceRegistry() {
    GetNonceRegistry().clear();
    persistentRegistryLoaded = true;  // prevent re-loading from file
}

static void ValidateIvLength(const CryptoConfig& config) {
    if (config.mode == "ecb") {
        return;
    }

    if (config.iv.empty()) {
        throw std::runtime_error("SECURITY VIOLATION: IV/nonce is required for mode " + config.mode + "!");
    }

    if (config.mode == "cbc" || config.mode == "ctr" || config.mode == "ofb" || config.mode == "cfb" || config.mode == "xts") {
        if (config.iv.size() != 16) {
            throw std::runtime_error("SECURITY VIOLATION: IV/tweak must be exactly 16 bytes for this mode!");
        }
    } else if (config.mode == "gcm") {
        if (config.iv.size() != 12) {
            throw std::runtime_error("SECURITY VIOLATION: IV must be exactly 12 bytes for GCM mode!");
        }
    } else if (config.mode == "ccm") {
        if (config.iv.size() < 7 || config.iv.size() > 13) {
            throw std::runtime_error("SECURITY VIOLATION: IV must be between 7 and 13 bytes for CCM mode!");
        }
    }
}

std::vector<uint8_t> EncryptAES(const std::vector<uint8_t>& plaintext, CryptoConfig& config, std::vector<uint8_t>& outTag) {
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    if (config.mode == "ecb") {
        if (!config.suppressWarnings) {
            std::cerr << "[WARNING] ECB mode is insecure and should not be used for real data.\n";
        }
        if (plaintext.size() > 16384 && !config.allowEcb) {
            throw std::runtime_error("ECB encryption rejected: Plaintext size exceeds 16 KiB limit!");
        }
    }

    if (config.key.empty()) {
        config.key.resize((config.mode == "xts" ? 64 : 32));
        prng.GenerateBlock(config.key.data(), config.key.size());
    } else {
        if (config.mode == "xts") {
            if (config.key.size() != 32 && config.key.size() != 64) {
                throw std::runtime_error("SECURITY VIOLATION: XTS requires exactly a 32-byte or 64-byte key!");
            }
        } else {
            if (config.key.size() != 16 && config.key.size() != 24 && config.key.size() != 32) {
                throw std::runtime_error("SECURITY VIOLATION: AES key size must be exactly 16, 24, or 32 bytes (128, 192, or 256 bits)!");
            }
        }
    }

    if (config.iv.empty() && config.mode != "ecb") {
        config.iv.resize((config.mode == "gcm" || config.mode == "ccm" ? 12 : AES::BLOCKSIZE));
        prng.GenerateBlock(config.iv.data(), config.iv.size());
    } else if (!config.iv.empty() && config.mode != "ecb") {
        ValidateIvLength(config);
    }

    CheckKeyNonceReuse(config);

    std::vector<uint8_t> ciphertext;

    if (config.isAead && !IsAeadMode(config.mode)) {
        throw std::runtime_error("--aead is only supported for gcm and ccm modes!");
    }

    if (config.mode == "gcm") {
        if (!config.isAead) {
            throw std::runtime_error("GCM mode requires --aead for authenticated encryption!");
        }
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        ciphertext.resize(plaintext.size());
        outTag.resize(16);
        enc.EncryptAndAuthenticate(ciphertext.data(), outTag.data(), outTag.size(),
                                   config.iv.data(), config.iv.size(),
                                   (const byte*)config.aad.data(), config.aad.size(),
                                   plaintext.data(), plaintext.size());
    }
    else if (config.mode == "ccm") {
        if (!config.isAead) {
            throw std::runtime_error("CCM mode requires --aead for authenticated encryption!");
        }
        CCM<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        // Crypto++ CCM REQUIRES SetMessageLength before any encrypt call
        enc.SpecifyDataLengths(config.aad.size(), plaintext.size());
        ciphertext.resize(plaintext.size());
        outTag.resize(16);
        enc.EncryptAndAuthenticate(ciphertext.data(), outTag.data(), outTag.size(),
                                   config.iv.data(), config.iv.size(),
                                   (const byte*)config.aad.data(), config.aad.size(),
                                   plaintext.data(), plaintext.size());
    }
    else if (config.mode == "cbc") {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        auto padding = config.noPadding ? CryptoPP::StreamTransformationFilter::NO_PADDING : CryptoPP::StreamTransformationFilter::PKCS_PADDING;
        CryptoPP::VectorSource(plaintext, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ciphertext), padding));
    }
    else if (config.mode == "ctr") {
        CTR_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        CryptoPP::VectorSource(plaintext, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ciphertext), CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
    else if (config.mode == "ofb") {
        OFB_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        CryptoPP::VectorSource(plaintext, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ciphertext), CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
    else if (config.mode == "cfb") {
        CFB_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        CryptoPP::VectorSource(plaintext, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ciphertext), CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
    else if (config.mode == "xts") {
        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
        CryptoPP::VectorSource(plaintext, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ciphertext), CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
    else if (config.mode == "ecb") {
        ECB_Mode<AES>::Encryption enc;
        enc.SetKey(config.key.data(), config.key.size());
        auto padding = config.noPadding ? CryptoPP::StreamTransformationFilter::NO_PADDING : CryptoPP::StreamTransformationFilter::PKCS_PADDING;
        CryptoPP::VectorSource(plaintext, true, new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ciphertext), padding));
    }
    else throw std::invalid_argument("Unsupported mode!");

    return ciphertext;
}

std::vector<uint8_t> DecryptAES(const std::vector<uint8_t>& ciphertext, const CryptoConfig& config, const std::vector<uint8_t>& tag) {
    using namespace CryptoPP;
    std::vector<uint8_t> decrypted;

    if (config.mode == "ecb") {
        if (!config.suppressWarnings) {
            std::cerr << "[WARNING] ECB mode is insecure and should not be used for real data.\n";
        }
    }

    if (config.mode == "xts") {
        if (config.key.size() != 32 && config.key.size() != 64) {
            throw std::runtime_error("SECURITY VIOLATION: XTS requires exactly a 32-byte or 64-byte key!");
        }
    } else if (config.mode != "ecb") {
        if (config.key.size() != 16 && config.key.size() != 24 && config.key.size() != 32) {
            throw std::runtime_error("SECURITY VIOLATION: AES key size must be exactly 16, 24, or 32 bytes (128, 192, or 256 bits)!");
        }
    } else {
        if (config.key.size() != 16 && config.key.size() != 24 && config.key.size() != 32) {
            throw std::runtime_error("SECURITY VIOLATION: AES key size must be exactly 16, 24, or 32 bytes (128, 192, or 256 bits)!");
        }
    }

    if (config.mode != "ecb") {
        ValidateIvLength(config);
    }

    if (config.isAead && !IsAeadMode(config.mode)) {
        throw std::runtime_error("--aead is only supported for gcm and ccm modes!");
    }

    try {
        if (config.mode == "gcm") {
            if (!config.isAead) {
                throw std::runtime_error("GCM mode requires --aead for authenticated decryption!");
            }
            if (tag.empty()) {
                throw std::runtime_error("AEAD decryption requires a non-empty authentication tag!");
            }
            GCM<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            decrypted.resize(ciphertext.size());
            if (!dec.DecryptAndVerify(decrypted.data(), tag.data(), tag.size(),
                                     config.iv.data(), config.iv.size(),
                                     (const byte*)config.aad.data(), config.aad.size(),
                                     ciphertext.data(), ciphertext.size())) {
                decrypted.clear();
                throw std::runtime_error("AEAD authentication tag verification failed!");
            }
        }
        else if (config.mode == "ccm") {
            if (!config.isAead) {
                throw std::runtime_error("CCM mode requires --aead for authenticated decryption!");
            }
            if (tag.empty()) {
                throw std::runtime_error("AEAD decryption requires a non-empty authentication tag!");
            }
            CCM<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            // Crypto++ CCM REQUIRES SpecifyDataLengths before any decrypt call
            dec.SpecifyDataLengths(config.aad.size(), ciphertext.size());
            decrypted.resize(ciphertext.size());
            if (!dec.DecryptAndVerify(decrypted.data(), tag.data(), tag.size(),
                                     config.iv.data(), config.iv.size(),
                                     (const byte*)config.aad.data(), config.aad.size(),
                                     ciphertext.data(), ciphertext.size())) {
                decrypted.clear();
                throw std::runtime_error("AEAD authentication tag verification failed!");
            }
        }
        else if (config.mode == "cbc") {
            CBC_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            auto padding = config.noPadding ? CryptoPP::StreamTransformationFilter::NO_PADDING : CryptoPP::StreamTransformationFilter::PKCS_PADDING;
            CryptoPP::VectorSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(decrypted), padding));
        }
        else if (config.mode == "ctr") {
            CTR_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            CryptoPP::VectorSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(decrypted), CryptoPP::StreamTransformationFilter::NO_PADDING));
        }
        else if (config.mode == "ofb") {
            OFB_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            CryptoPP::VectorSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(decrypted), CryptoPP::StreamTransformationFilter::NO_PADDING));
        }
        else if (config.mode == "cfb") {
            CFB_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            CryptoPP::VectorSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(decrypted), CryptoPP::StreamTransformationFilter::NO_PADDING));
        }
        else if (config.mode == "xts") {
            XTS_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(config.key.data(), config.key.size(), config.iv.data(), config.iv.size());
            CryptoPP::VectorSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(decrypted), CryptoPP::StreamTransformationFilter::NO_PADDING));
        }
        else if (config.mode == "ecb") {
            ECB_Mode<AES>::Decryption dec;
            dec.SetKey(config.key.data(), config.key.size());
            auto padding = config.noPadding ? CryptoPP::StreamTransformationFilter::NO_PADDING : CryptoPP::StreamTransformationFilter::PKCS_PADDING;
            CryptoPP::VectorSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(decrypted), padding));
        }
        else throw std::invalid_argument("Unsupported mode!");
    }
    catch (...) {
        decrypted.clear();
        throw;
    }

    return decrypted;
}
