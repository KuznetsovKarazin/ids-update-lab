#include "ids_mlp.h"
#include <cmath>
#include <cstring>
#include <limits>

namespace ids {
namespace {
constexpr unsigned dimensions[] = {8,16,8,1};
uint32_t u32(const uint8_t* p) { return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24; }
int32_t i32(const uint8_t* p) { uint32_t u=u32(p); int32_t i; std::memcpy(&i,&u,4); return i; }
float f32(const uint8_t* p) { uint32_t u=u32(p); float f; std::memcpy(&f,&u,4); return f; }
float sigmoid(float z) { if(z>=0) return 1.0f/(1.0f+std::exp(-z)); float e=std::exp(z); return e/(1.0f+e); }
int32_t clampq(int32_t x) { return x < -127 ? -127 : (x > 127 ? 127 : x); }
}
int32_t mlp_round_shift_away(int64_t value, uint32_t shift) {
    // Valid callers bound product by INT32_MAX squared; adding <=2^61
    // therefore cannot overflow signed int64. No signed right shift is used.
    if (shift < 1 || shift > 62) return 0;
    const uint64_t a = value < 0 ? uint64_t(-value) : uint64_t(value);
    const uint64_t rounded = (a + (uint64_t(1) << (shift-1))) >> shift;
    // Requantization output immediately saturates; limit before narrowing.
    const int32_t limited = rounded > 127 ? 127 : int32_t(rounded);
    return value < 0 ? -limited : limited;
}
bool decode_mlp_body(const uint8_t* p, size_t length, uint32_t abi, MlpData& m) {
    if(!p || length < 160 || (abi!=4 && abi!=5) || u32(p+20)!=8 || u32(p+76)!=3) return false;
    for(unsigned j=0;j<4;++j) if(u32(p+144+4*j)!=dimensions[j]) return false;
    const size_t expected = abi==4 ? 160+4*(kMlpWeights+kMlpBiases) : 168+36+kMlpWeights+4*kMlpBiases;
    if(length!=expected) return false;
    MlpData candidate{}; size_t pos=160, wi=0, bi=0;
    if(abi==5) {
        candidate.input_scale=f32(p+pos); pos+=4; candidate.qthreshold=i32(p+pos);pos+=4;
        if(!std::isfinite(candidate.input_scale) || candidate.input_scale<=0 || candidate.qthreshold < -127 || candidate.qthreshold>128) return false;
    }
    for(unsigned l=0;l<3;++l) {
        unsigned ni=dimensions[l], no=dimensions[l+1];
        if(abi==5) {
            candidate.multipliers[l]=u32(p+pos); candidate.shifts[l]=u32(p+pos+4); candidate.output_scales[l]=f32(p+pos+8);pos+=12;
            if(candidate.multipliers[l]==0 || candidate.multipliers[l]>0x7fffffff || candidate.shifts[l]<1 || candidate.shifts[l]>62 || !std::isfinite(candidate.output_scales[l]) || candidate.output_scales[l]<=0) return false;
        }
        for(unsigned j=0;j<ni*no;++j) {
            if(abi==4) { candidate.weights[wi]=f32(p+pos);pos+=4; if(!std::isfinite(candidate.weights[wi])) return false; }
            else { int q=int(p[pos++]);if(q>127)q-=256; if(q==-128)return false;candidate.qweights[wi]=int8_t(q); }
            ++wi;
        }
        for(unsigned j=0;j<no;++j) {
            if(abi==4) { candidate.biases[bi]=f32(p+pos);pos+=4;if(!std::isfinite(candidate.biases[bi]))return false; }
            else { candidate.qbiases[bi]=i32(p+pos);pos+=4;int64_t b=candidate.qbiases[bi];if(b<0)b=-b;if(b+int64_t(ni)*127*127>0x7fffffff)return false; }
            ++bi;
        }
    }
    m=candidate;return pos==length;
}
bool infer_mlp(const MlpData& m,uint32_t abi,const float* x,float& probability,int& quantized_label) {
    if(!x || (abi!=4&&abi!=5))return false;
    std::array<float,16> a{}, b{};std::array<int32_t,16> qa{},qb{};
    for(unsigned j=0;j<8;++j) {
        if(!std::isfinite(x[j]))return false;
        a[j]=x[j];
        if(abi==5) {float q=x[j]/m.input_scale;if(!std::isfinite(q))return false;
            qa[j]=q>=127?127:(q<=-127?-127:(q>=0?int32_t(std::floor(double(q)+0.5)):-int32_t(std::floor(-double(q)+0.5))));}
    }
    size_t wi=0,bi=0;
    for(unsigned l=0;l<3;++l) {
        unsigned ni=dimensions[l],no=dimensions[l+1];
        for(unsigned j=0;j<no;++j) {
            if(abi==4) {float sum=m.biases[bi+j];for(unsigned k=0;k<ni;++k) {float term=a[k]*m.weights[wi+k*no+j];sum=sum+term;if(!std::isfinite(sum))return false;}b[j]=(l<2&&sum<0)?0:sum;}
            else {int32_t sum=m.qbiases[bi+j];for(unsigned k=0;k<ni;++k)sum+=qa[k]*int32_t(m.qweights[wi+k*no+j]);
                int32_t q=mlp_round_shift_away(int64_t(sum)*int64_t(m.multipliers[l]),m.shifts[l]);qb[j]=(l<2&&q<0)?0:clampq(q);}
        }
        a=b;qa=qb;wi+=ni*no;bi+=no;
    }
    if(abi==4){probability=sigmoid(a[0]);quantized_label=-1;}
    else{float z=float(qa[0])*m.output_scales[2];if(!std::isfinite(z))return false;probability=sigmoid(z);quantized_label=qa[0]>=m.qthreshold?1:0;}
    return std::isfinite(probability);
}
}
