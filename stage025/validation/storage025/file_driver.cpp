// Direct validation of the production native FileStorage adapter, not an MCU.
#define main production_native_entrypoint
#include "../../firmware/native/main.cpp"
#undef main
#include <limits>
int main(int argc,char** argv) {
    try {
        if(argc!=2) throw std::runtime_error("expected fresh store path");
        FileStorage storage(argv[1]);size_t checks=0;
        auto expect=[&](bool ok,const char* why){++checks;if(!ok)throw std::runtime_error(why);};
        std::array<uint8_t,4096> zero{};std::array<uint8_t,ids::kSlotBytes> read{};
        for(unsigned a=0;a<4;++a) {
            const size_t size=a<2?ids::kSlotBytes:ids::kJournalPageBytes;
            for(size_t off=0;off<size;off+=4096) expect(storage.write(a,off,zero.data(),zero.size()),"seed zero write");
        }
        for(auto args:{std::array<size_t,3>{4,0,4096},{0,0,0},{0,1,4096},{0,0,4095},{0,65536,4096},{0,61440,8192},{2,4096,4096},{0,std::numeric_limits<size_t>::max(),4096}})
            expect(!storage.erase_range(unsigned(args[0]),args[1],args[2]),"invalid range accepted");
        for(unsigned a=0;a<4;++a) {
            const size_t size=a<2?ids::kSlotBytes:ids::kJournalPageBytes;
            expect(storage.read(a,0,read.data(),size),"range read");
            for(size_t i=0;i<size;++i) expect(read[i]==0,"invalid erase changed bytes");
        }
        expect(storage.erase_range(0,4096,8192),"interior model erase rejected");
        expect(storage.read(0,0,read.data(),read.size()),"model read");
        for(size_t i=0;i<read.size();++i) expect(read[i]==(i>=4096&&i<12288?255:0),"model range inaccurate");
        expect(storage.erase_range(2,0,4096),"journal range erase rejected");
        expect(storage.read(2,0,read.data(),4096),"journal read");
        for(size_t i=0;i<4096;++i) expect(read[i]==255,"journal range inaccurate");
        expect(storage.erase(1),"legacy full erase rejected");
        expect(storage.read(1,0,read.data(),read.size()),"full erase read");
        for(auto b:read)expect(b==255,"legacy erase incomplete");
        std::cout<<"{\"status\":\"pass\",\"checks\":"<<checks<<",\"measurement_origin\":\"native_file_storage_not_MCU\"}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
