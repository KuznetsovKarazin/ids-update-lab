#include "ids_core.h"
#include "ids_protocol.h"
#include "model_contract.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

class OpenSslCrypto final : public ids::Crypto {
public:
    OpenSslCrypto() {
        BIO* bio = BIO_new_mem_buf(ids_generated::kPublicKeyPem, int(sizeof(ids_generated::kPublicKeyPem) - 1));
        if (!bio) throw std::runtime_error("key BIO allocation");
        key_ = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!key_ || EVP_PKEY_base_id(key_) != EVP_PKEY_RSA || EVP_PKEY_bits(key_) != 2048)
            throw std::runtime_error("RSA2048 public key required");
    }
    ~OpenSslCrypto() override { EVP_PKEY_free(key_); }
    bool verify(const uint8_t* payload, size_t length, const uint8_t* signature) override {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
        EVP_PKEY_CTX* pctx = nullptr;
        const bool result = EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, key_) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
            EVP_DigestVerify(ctx, signature, 256, payload, length) == 1;
        EVP_MD_CTX_free(ctx);
        return result;
    }
    bool sha256(const uint8_t* bytes, size_t length, uint8_t* digest) override {
        unsigned output_length = 0;
        return EVP_Digest(bytes, length, digest, &output_length, EVP_sha256(), nullptr) == 1 && output_length == 32;
    }
private:
    EVP_PKEY* key_ = nullptr;
};

class FileStorage final : public ids::Storage {
public:
    explicit FileStorage(const std::string& directory) {
        std::filesystem::create_directories(directory);
        unsigned existing = 0;
        for (const char* name : names_) if (std::filesystem::exists(directory + name)) ++existing;
        if (existing != 0 && existing != 4)
            throw std::runtime_error("incomplete store; refusing to create a missing model/journal area");
        for (unsigned slot = 0; slot < 4; ++slot) {
            paths_[slot] = directory + names_[slot];
            fds_[slot] = ::open(paths_[slot].c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
            const bool created = fds_[slot] >= 0;
            if (fds_[slot] < 0 && errno == EEXIST) fds_[slot] = ::open(paths_[slot].c_str(), O_RDWR);
            if (fds_[slot] < 0) throw std::runtime_error("store open failed");
            struct stat statbuf{};
            if (fstat(fds_[slot], &statbuf)) throw std::runtime_error("store stat failed");
            if (created) {
                if (!erase(slot)) throw std::runtime_error("store initialization failed");
            } else if (statbuf.st_size != off_t(bytes(slot))) throw std::runtime_error("invalid slot file length; refusing reset");
        }
    }
    ~FileStorage() override { for (int fd : fds_) if (fd >= 0) ::close(fd); }
    bool read(unsigned slot, size_t offset, void* target, size_t length) override {
        if (slot > 3 || offset > bytes(slot) || length > bytes(slot) - offset) return false;
        return pread(fds_[slot], target, length, off_t(offset)) == ssize_t(length);
    }
    bool write(unsigned slot, size_t offset, const void* source, size_t length) override {
        if (slot > 3 || offset > bytes(slot) || length > bytes(slot) - offset) return false;
        std::array<uint8_t, 4 + ids::kMaxEnvelope> before{};
        if (length > before.size() || !read(slot, offset, before.data(), length)) return false;
        auto* bytes = static_cast<const uint8_t*>(source);
        for (size_t i = 0; i < length; ++i) if ((before[i] & bytes[i]) != bytes[i]) return false;
        return pwrite(fds_[slot], source, length, off_t(offset)) == ssize_t(length) && fsync(fds_[slot]) == 0;
    }
    bool erase(unsigned slot) override {
        if (slot > 3) return false;
        return erase_range(slot, 0, bytes(slot));
    }
    bool erase_range(unsigned slot, size_t offset, size_t length) override {
        if (slot > 3 || length == 0 || offset % ids::kEraseSectorBytes != 0 ||
            length % ids::kEraseSectorBytes != 0 || offset > bytes(slot) || length > bytes(slot) - offset)
            return false;
        std::array<uint8_t, ids::kEraseSectorBytes> erased{};
        erased.fill(0xff);
        for (size_t relative = 0; relative < length; relative += erased.size()) {
            if (pwrite(fds_[slot], erased.data(), erased.size(), off_t(offset + relative)) != ssize_t(erased.size())) return false;
        }
        return fsync(fds_[slot]) == 0;
    }
private:
    static size_t bytes(unsigned slot) { return slot < 2 ? ids::kSlotBytes : ids::kJournalPageBytes; }
    const char* names_[4]{"/ids_a.bin", "/ids_b.bin", "/ids_meta0.bin", "/ids_meta1.bin"};
    std::string paths_[4];
    int fds_[4]{-1, -1, -1, -1};
};

class NativePlatform final : public ids::Platform {
public:
    uint64_t microseconds() override {
        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    size_t free_heap() override { return 0; } // Unknown on host; never interpret as MCU memory measurement.
    const char* chip() override { return "native_host_NOT_MCU"; }
    const char* build() override { return "native-shared-core-v1"; }
    const char* origin() override { return ids_generated::kDataOrigin; }
    void output(const std::string& json) override { std::cout << json << '\n' << std::flush; }
    void restart() override { std::exit(75); }
};

int main(int argc, char** argv) {
    std::string directory = "native-store";
    bool model_only = false;
    ids::ErasePolicy erase_policy = ids::ErasePolicy::FullSlot;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--store") == 0 && i + 1 < argc) directory = argv[++i];
        else if (std::strcmp(argv[i], "--model-only") == 0) model_only = true;
        else if (std::strcmp(argv[i], "--erase-policy") == 0 && i + 1 < argc) {
            if (!ids::parse_erase_policy(argv[++i], erase_policy)) {
                std::cerr << "erase policy must be full_slot or necessary_sectors\n"; return 2;
            }
        }
        else { std::cerr << "usage: ids_update_native [--store DIR] [--model-only] [--erase-policy full_slot|necessary_sectors]\n"; return 2; }
    }
    try {
        FileStorage storage(directory);
        OpenSslCrypto crypto;
        ids::Engine engine(storage, crypto, ids_generated::factory_envelope(), ids_generated::factory_length(),
            ids_generated::kFeatureCount, ids_generated::kFeatureContractHash, model_only, ids_generated::kRuntimeAbi, erase_policy);
        NativePlatform platform;
        ids::Protocol protocol(engine, platform, ids_generated::kFeatureContractHash, ids_generated::kFeatureCount);
        const auto result = engine.boot();
        protocol.status("boot", result.reason);
        std::array<char, ids::kMaxLine + 1> line{};
        size_t length = 0;
        bool overflow = false, invalid = false;
        for (int ch; (ch = std::getchar()) != EOF;) {
            if (ch == '\n') {
                if (overflow) protocol.line_error("line_too_long");
                else if (invalid) protocol.line_error("invalid_control_character");
                else if (length) { line[length] = 0; protocol.process(line.data()); }
                length = 0; overflow = false; invalid = false;
            } else if (ch != '\r') {
                if (ch < 32 || ch > 126) invalid = true;
                if (length < ids::kMaxLine) line[length++] = char(ch);
                else overflow = true;
            }
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
