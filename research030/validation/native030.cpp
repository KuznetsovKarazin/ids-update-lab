#include "ids_core.h"
#include "ids_mlp.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <array>
#include <vector>
#include <fstream>
#include <iterator>
#include <cstring>
#include <iostream>
#include <cstdio>

class Crypt final: public ids::Crypto {
    EVP_PKEY* key_ = nullptr;
public:
    explicit Crypt(const char* filename) {FILE* f=fopen(filename,"rb");if(f){key_=PEM_read_PUBKEY(f,nullptr,nullptr,nullptr);fclose(f);}}
    ~Crypt(){EVP_PKEY_free(key_);}
    bool verify(const uint8_t* p,size_t n,const uint8_t* sig) override {
        EVP_MD_CTX* c=EVP_MD_CTX_new();EVP_PKEY_CTX* pc=nullptr;
        bool ok=key_&&c&&EVP_DigestVerifyInit(c,&pc,EVP_sha256(),nullptr,key_)==1&&EVP_PKEY_CTX_set_rsa_padding(pc,RSA_PKCS1_PADDING)==1&&EVP_DigestVerify(c,sig,256,p,n)==1;
        EVP_MD_CTX_free(c);return ok;
    }
    bool sha256(const uint8_t* p,size_t n,uint8_t* out) override {unsigned count=0;return EVP_Digest(p,n,out,&count,EVP_sha256(),nullptr)==1&&count==32;}
};
class Mem final: public ids::Storage {
    std::array<std::vector<uint8_t>,4> data_;
public:
    Mem(){for(unsigned i=0;i<4;i++)data_[i].assign(i<2?ids::kSlotBytes:ids::kJournalPageBytes,255);}
    bool valid(unsigned s,size_t o,size_t n){return s<4&&o<=data_[s].size()&&n<=data_[s].size()-o;}
    bool read(unsigned s,size_t o,void* p,size_t n) override {if(!valid(s,o,n))return false;memcpy(p,data_[s].data()+o,n);return true;}
    bool write(unsigned s,size_t o,const void* p,size_t n) override {if(!valid(s,o,n))return false;auto b=(const uint8_t*)p;for(size_t i=0;i<n;i++)if((data_[s][o+i]&b[i])!=b[i])return false;memcpy(data_[s].data()+o,p,n);return true;}
    bool erase(unsigned s) override {return s<4&&erase_range(s,0,data_[s].size());}
    bool erase_range(unsigned s,size_t o,size_t n) override {if(!valid(s,o,n)||o%4096||n%4096)return false;memset(data_[s].data()+o,255,n);return true;}
};
uint32_t le32(const uint8_t*p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
int main(int argc,char**argv){
    if(argc==2&&std::string(argv[1])=="round"){
        int64_t v;unsigned shift;while(std::cin>>v>>shift)std::cout<<ids::mlp_round_shift_away(v,shift)<<"\n";return 0;
    }
    if(argc==2&&std::string(argv[1])=="decode-short"){
        for(size_t n=0;n<160;n++) {auto p=new uint8_t[n?n:1]{};ids::MlpData m;bool accepted=ids::decode_mlp_body(p,n,4,m);delete[]p;if(accepted)return 4;}return 0;
    }
    if(argc!=3)return 2;
    std::ifstream f(argv[1],std::ios::binary);std::vector<uint8_t> e((std::istreambuf_iterator<char>(f)),{});
    if(e.size()<96||e.size()>4096)return 2;
    Mem store;Crypt crypto(argv[2]);ids::Engine engine(store,crypto,e.data(),e.size(),8,e.data()+40,false,le32(e.data()+28),ids::ErasePolicy::NecessarySectors);
    auto r=engine.boot();if(!r.ok){std::cerr<<r.reason;return 3;}
    std::array<float,8> raw;
    while(std::cin.read(reinterpret_cast<char*>(raw.data()),sizeof(raw))) {float p=0;int label=-1;auto inf=engine.infer(raw.data(),8,p,label);if(inf.ok)std::printf("{\"ok\":true,\"p\":%.9g,\"label\":%d}\n",double(p),label);else std::printf("{\"ok\":false,\"reason\":\"%s\"}\n",inf.reason);}
    return std::cin.eof()?0:2;
}
