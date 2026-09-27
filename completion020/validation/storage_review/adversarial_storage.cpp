// Independent native storage review. No MCU or physical power loss is exercised.
// Authentication is stubbed ONLY for deterministic, syntactically valid fixtures;
// SHA-256 binding is real OpenSSL. This does not test cryptographic authentication.
#include "ids_core.h"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;
uint64_t checks = 0, cuts = 0, retries = 0;
void demand(bool v, const std::string& what) { ++checks; if (!v) throw std::runtime_error(what); }
void put32(uint8_t* p, uint32_t v) { for (unsigned i=0;i<4;++i) p[i]=uint8_t(v>>(8*i)); }
void put64(uint8_t* p, uint64_t v) { for (unsigned i=0;i<8;++i) p[i]=uint8_t(v>>(8*i)); }
void putf(uint8_t* p, float f) { uint32_t v; std::memcpy(&v,&f,4); put32(p,v); }
std::array<uint8_t,32> contract = [] { std::array<uint8_t,32> c{}; c.fill(0x13); return c; }();
Bytes model(uint32_t version) {
    Bytes b(376, 0); std::memcpy(b.data(),"SIDSPK1",7); put32(b.data()+8,104); put32(b.data()+12,256);
    uint8_t* p=b.data()+16; std::memcpy(p,"SIDSB01",7); put32(p+8,1); put32(p+12,1);
    put32(p+16,version); put32(p+20,2); std::memcpy(p+24,contract.data(),32);
    std::memcpy(p+56,"fixture",7); putf(p+72,0.5f); putf(p+76,float(version)*0.001f);
    putf(p+80,0.1f); putf(p+84,0.2f); putf(p+88,1.1f); putf(p+92,1.2f); putf(p+96,0.4f); putf(p+100,-0.3f);
    return b;
}
const Bytes factory=model(1);
struct FixtureCrypto final : ids::Crypto {
    bool verify(const uint8_t*,size_t,const uint8_t*) override { return true; }
    bool sha256(const uint8_t* b,size_t n,uint8_t* out) override { unsigned len=0; return EVP_Digest(b,n,out,&len,EVP_sha256(),nullptr)==1 && len==32; }
};
struct PowerCut {};
struct Mutation { char kind; unsigned area; size_t offset,length; };
struct Flash final : ids::Storage {
    std::array<Bytes,4> data;
    std::vector<Mutation> mutations;
    int target=-1, read_target=-1, reads=0;
    bool random_mask=false, silent=false;
    uint64_t seed=0; size_t prefix=0;
    double fraction=0.5;
    Flash() { for(unsigned a=0;a<4;++a) data[a].assign(a<2?65536:4096,0xff); }
    bool read(unsigned a,size_t off,void* out,size_t n) override {
        if (reads++==read_target) return false;
        if(a>=4 || off>data[a].size() || n>data[a].size()-off) return false;
        std::memcpy(out,data[a].data()+off,n); return true;
    }
    void mutate(unsigned a,size_t off,const uint8_t* desired,size_t n,bool erase) {
        const int index=int(mutations.size()); mutations.push_back({erase?'E':'W',a,off,n});
        const bool inject=index==target;
        std::mt19937_64 rng(seed);
        for(size_t i=0;i<n;++i) {
            const uint8_t goal=erase?0xff:desired[i];
            if(!erase && (data[a][off+i]&goal)!=goal) throw std::runtime_error("illegal NOR write");
            if(!inject) data[a][off+i]=goal;
            else {
                uint8_t mask=0;
                for(unsigned bit=0;bit<8;++bit) {
                    const bool set=random_mask ? (double(rng())/double(std::numeric_limits<uint64_t>::max())<fraction) : i*8+bit<prefix;
                    if(set) mask=uint8_t(mask|uint8_t(1u<<bit));
                }
                if(erase) data[a][off+i]=uint8_t(data[a][off+i]|mask);
                else data[a][off+i]=uint8_t(data[a][off+i] & uint8_t(goal | uint8_t(~mask)));
            }
        }
        if(inject && !silent) throw PowerCut{};
    }
    bool write(unsigned a,size_t off,const void* src,size_t n) override {
        if(a>=4 || off>data[a].size() || n>data[a].size()-off) return false;
        mutate(a,off,static_cast<const uint8_t*>(src),n,false); return true;
    }
    bool erase(unsigned a) override { if(a>=4) return false; mutate(a,0,nullptr,data[a].size(),true); return true; }
    void reset_faults() { target=read_target=-1; reads=0; mutations.clear(); silent=false; }
};
ids::Engine engine(Flash& f,FixtureCrypto& c) { return ids::Engine(f,c,factory.data(),factory.size(),2,contract.data(),false,1); }
void install(ids::Engine& e,uint32_t version) { auto b=model(version); auto r=e.update(b.data(),b.size()); demand(r.ok,std::string("install ")+std::to_string(version)+": "+r.reason); }
Flash baseline(uint32_t v) { Flash f; FixtureCrypto c; auto e=engine(f,c); demand(e.boot().ok,"provision baseline"); for(uint32_t i=2;i<=v;++i) install(e,i); f.reset_faults(); return f; }
void recovery(Flash& f,uint32_t oldv,uint32_t nextv,bool can_be_new=true,bool must_be_new=false) {
    f.reset_faults(); FixtureCrypto c; auto e=engine(f,c); auto r=e.boot();
    demand(r.ok,std::string("recovery boot: ")+r.reason);
    const auto v=e.model().version; demand(v==oldv || (can_be_new && v==nextv),"recovery neither exact old nor new");
    if(must_be_new) demand(v==nextv,"completed journal commit not activated after lost ACK");
    ids::Model expected{}; auto b=model(v); demand(e.validate(b.data(),b.size(),expected).ok,"fixture validates");
    demand(expected.digest==e.model().digest,"recovery payload digest binding");
    auto before=f.data; auto replay=e.update(b.data(),b.size());
    demand(!replay.ok && std::string(replay.reason)=="replay_or_downgrade","replay rejected after cut");
    demand(before==f.data,"replay changes no flash");
    install(e,nextv+1); ++retries;
    f.reset_faults(); auto next=engine(f,c); demand(next.boot().ok && next.model().version==nextv+1,"retry after torn record");
}
void positive_counterexample() {
    Flash f=baseline(2);
    // Old accepted A remains committed in slot 0. A partial erase leaves the
    // commit/length untouched but changes a zero of signed payload magic to 1.
    demand(f.data[0][24]==uint8_t('S'),"fixture slot payload magic location");
    f.data[0][24]=uint8_t(f.data[0][24]|0x80);
    FixtureCrypto c; auto e=engine(f,c); auto r=e.boot();
#ifdef LEGACY
    demand(!r.ok && std::string(r.reason)=="committed_slot_invalid","old-code counterexample did not reproduce");
    std::cout << "{\"legacy_counterexample_reproduced\":true,\"boot_reason\":\"" << r.reason << "\",\"checks\":" << checks << "}\n";
#else
    demand(r.ok && e.model().version==2,"journal did not retain unaffected active B");
#endif
}
#ifndef LEGACY
void cut_matrix(const Flash& base,uint32_t oldv) {
    Flash reference=base; FixtureCrypto c; auto r=engine(reference,c); demand(r.boot().ok,"matrix reference boot"); reference.reset_faults(); install(r,oldv+1);
    const auto operations=reference.mutations;
    demand(operations.size()==5 || operations.size()==6,"unexpected mutation operation count");
    for(size_t op=0;op<operations.size();++op) {
        const auto m=operations[op];
        std::vector<size_t> prefixes{0,1,7,8,15,16,31,32,63,64,127,128,255,256,511,512,1023,1024,m.length*8};
        // All bit positions for every program call; the erase prefix sweep
        // covers every byte of occupied model/record space, plus page boundaries.
        if(m.kind=='W') for(size_t p=0;p<=m.length*8;++p) prefixes.push_back(p);
        else { for(size_t p=0;p<=std::min(m.length,size_t(4096));++p) prefixes.push_back(p*8); prefixes.push_back(m.length*8-1); }
        std::sort(prefixes.begin(),prefixes.end()); prefixes.erase(std::unique(prefixes.begin(),prefixes.end()),prefixes.end());
        for(size_t prefix:prefixes) {
            if(prefix>m.length*8) continue;
            Flash f=base; auto e=engine(f,c); demand(e.boot().ok,"prefix boot"); f.reset_faults(); f.target=int(op); f.prefix=prefix;
            auto b=model(oldv+1); bool cut=false; try{(void)e.update(b.data(),b.size());}catch(const PowerCut&){cut=true;}
            demand(cut,"prefix injection not reached"); ++cuts; recovery(f,oldv,oldv+1,op+1==operations.size(),op+1==operations.size() && prefix==m.length*8);
        }
        for(unsigned random=0;random<160;++random) {
            Flash f=base; auto e=engine(f,c); demand(e.boot().ok,"random boot"); f.reset_faults(); f.target=int(op); f.random_mask=true;
            f.seed=24092026+uint64_t(oldv)*1000000+op*10000+random; f.fraction=std::array<double,4>{.01,.1,.5,.99}[random%4];
            auto b=model(oldv+1); bool cut=false; try{(void)e.update(b.data(),b.size());}catch(const PowerCut&){cut=true;}
            demand(cut,"random injection not reached"); ++cuts; recovery(f,oldv,oldv+1,op+1==operations.size());
        }
        // A driver incorrectly reporting success after a partial operation must
        // be caught by readback/validation; recovery remains coherent.
        Flash f=base; auto e=engine(f,c); demand(e.boot().ok,"silent boot"); f.reset_faults(); f.target=int(op); f.prefix=m.length*4; f.silent=true;
        auto b=model(oldv+1); const auto result=e.update(b.data(),b.size());
        (void)result; recovery(f,oldv,oldv+1); // Some half erases already finish all non-FF data.
    }
}
void read_errors(uint32_t oldv) {
    const auto base=baseline(oldv); FixtureCrypto c;
    Flash ref=base; auto e=engine(ref,c); demand(e.boot().ok,"read ref boot"); ref.reset_faults(); install(e,oldv+1); const int reads=ref.reads;
    for(int i=0;i<reads;++i) { Flash f=base; auto live=engine(f,c); demand(live.boot().ok,"read fault boot"); f.reset_faults(); f.read_target=i; auto b=model(oldv+1); auto r=live.update(b.data(),b.size()); demand(!r.ok,"read error ignored during update"); recovery(f,oldv,oldv+1); }
    ref=base; ref.reset_faults(); auto b=engine(ref,c); demand(b.boot().ok,"read boot reference"); const int boot_reads=ref.reads;
    for(int i=0;i<boot_reads;++i) { Flash f=base; f.reset_faults(); f.read_target=i; auto live=engine(f,c); auto r=live.boot(); demand(!r.ok && !live.ready(),"boot read error silently fell back"); }
}
void binding_and_exhaustion() {
    auto f=baseline(2); FixtureCrypto c;
    f.data[1][24]=uint8_t(f.data[1][24]|0x80); auto e=engine(f,c); auto r=e.boot();
    demand(!r.ok && std::string(r.reason)=="selected_slot_invalid","selected bad slot fallback");
    f=baseline(2); // Modify highest selector's digest consistently in both rails;
    f.data[2][128+48]^=1; f.data[2][128+49]^=1;
    auto changed=engine(f,c); r=changed.boot(); demand(!r.ok && std::string(r.reason)=="selected_slot_binding","journal digest binding ignored");
    f=baseline(2); // Forge only the sequence for exhaustion edge; outside fault model.
    uint8_t seq[8]; put64(seq,std::numeric_limits<uint64_t>::max());
    for(unsigned i=0;i<8;++i) { f.data[2][128+16+2*i]=seq[i]; f.data[2][128+17+2*i]=uint8_t(~seq[i]); }
    auto maxed=engine(f,c); demand(maxed.boot().ok,"max seq boot"); auto candidate=model(3); r=maxed.update(candidate.data(),candidate.size());
    demand(!r.ok && std::string(r.reason)=="journal_sequence_exhausted","sequence wrapped");
    f.reset_faults(); auto after=engine(f,c); demand(after.boot().ok && after.model().version==2,"seq exhaustion lost current");
    f=baseline(2); std::copy(f.data[2].begin()+128,f.data[2].begin()+256,f.data[3].begin());
    auto ambiguous=engine(f,c); r=ambiguous.boot(); demand(!r.ok && std::string(r.reason)=="journal_ambiguous_sequence","duplicate highest not rejected");
}
void checkpoints() {
    FixtureCrypto c;
    for(auto point:{ids::Checkpoint::AfterErase,ids::Checkpoint::AfterWrite,ids::Checkpoint::AfterVerify,ids::Checkpoint::AfterSlotCommit,ids::Checkpoint::AfterJournalBody,ids::Checkpoint::AfterCommit}) {
        auto f=baseline(2); auto e=engine(f,c); demand(e.boot().ok,"checkpoint boot"); auto b=model(3);
        auto hook=[](ids::Checkpoint actual,void* p){return actual==*static_cast<ids::Checkpoint*>(p);};
        auto r=e.update(b.data(),b.size(),hook,&point); demand(!r.ok && !e.ready(),"checkpoint returns ready");
        f.reset_faults(); auto after=engine(f,c); demand(after.boot().ok,"checkpoint reboot");
        demand(after.model().version==(point==ids::Checkpoint::AfterCommit?3u:2u),"checkpoint activation boundary");
    }
}
void provisioning_faults() {
    FixtureCrypto c; Flash ref; auto e=engine(ref,c); demand(e.boot().ok,"provision reference"); const auto ops=ref.mutations;
    for(size_t op=0;op<ops.size();++op) for(unsigned how=0;how<3;++how) {
        Flash f; f.target=int(op); f.prefix=how==0?0:how==1?ops[op].length*4:ops[op].length*8;
        auto live=engine(f,c); bool hit=false; try{(void)live.boot();}catch(const PowerCut&){hit=true;} demand(hit,"provision cut hit");
        f.reset_faults(); auto after=engine(f,c); auto result=after.boot();
        demand((result.ok && after.model().version==1) || (!result.ok && std::string(result.reason)=="unprovisioned_dirty_store"),"unexpected first provisioning recovery");
    }
}
void consecutive_failed_appends() {
    FixtureCrypto c; auto f=baseline(2);
    // Exhaust all append positions after the authoritative selector, then
    // repeatedly erase the other page while the old selector stays authoritative.
    for(unsigned attempt=0;attempt<70;++attempt) {
        f.reset_faults(); auto e=engine(f,c); demand(e.boot().ok && e.model().version==2,"repeated torn append boot");
        auto hook=[](ids::Checkpoint point,void*){return point==ids::Checkpoint::AfterJournalBody;};
        auto candidate=model(3); auto r=e.update(candidate.data(),candidate.size(),hook,nullptr);
        demand(!r.ok && std::string(r.reason)=="interrupted_after_journal_body","repeated torn append checkpoint");
    }
    f.reset_faults(); auto final=engine(f,c); demand(final.boot().ok && final.model().version==2,"latest survived consumed pages");
    install(final,3); f.reset_faults(); auto after=engine(f,c); demand(after.boot().ok && after.model().version==3,"eventual commit after consumed pages");
}
void rail_property() {
    // Exhaustive single logical byte: every valid byte and every subset of its
    // eight zero rails under erase; likewise subsets of the eight target-zero
    // rails under program from 0xffff. A valid result must be the same codeword.
    for(unsigned byte=0;byte<256;++byte) {
        const uint16_t encoded=uint16_t(byte | ((byte^255u)<<8));
        std::array<unsigned,8> zero{}; unsigned k=0;
        for(unsigned bit=0;bit<16;++bit) if((encoded&(1u<<bit))==0) zero[k++]=bit;
        for(unsigned mask=0;mask<256;++mask) {
            uint16_t erased=encoded, programmed=0xffff;
            for(unsigned i=0;i<8;++i) if(mask&(1u<<i)) {erased=uint16_t(erased|(1u<<zero[i]));programmed=uint16_t(programmed&~(1u<<zero[i]));}
            // Explicit parentheses avoid equality/XOR precedence ambiguity.
            const bool ev=(uint8_t(erased)^uint8_t(erased>>8))==255;
            const bool pv=(uint8_t(programmed)^uint8_t(programmed>>8))==255;
            demand(!ev || erased==encoded,"erase creates different valid rail codeword");
            demand(!pv || programmed==encoded,"partial program creates different valid rail codeword");
        }
    }
}
#endif
}
int main() { try {
    positive_counterexample();
#ifndef LEGACY
    rail_property(); checkpoints(); binding_and_exhaustion(); provisioning_faults(); read_errors(2); read_errors(64); consecutive_failed_appends();
    cut_matrix(baseline(2),2); cut_matrix(baseline(64),64);
    std::cout << "{\"status\":\"pass\",\"measurement_origin\":\"native_fault_model_not_MCU\",\"checks\":"<<checks<<",\"power_cut_simulations\":"<<cuts<<",\"successful_followup_updates\":"<<retries<<",\"authentication_stubbed\":true,\"partial_bit_directions\":\"program_1_to_0_erase_0_to_1\"}\n";
#endif
    return 0;
} catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<"\n"; return 1; } }
