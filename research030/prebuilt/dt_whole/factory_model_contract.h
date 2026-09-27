// PUBLIC TEST KEY ONLY. Factory bytes are patched and re-signed by the host.
#pragma once
#include <cstdint>
#include <cstddef>
namespace ids_generated {
inline constexpr unsigned kFeatureCount=8;
inline constexpr unsigned kRuntimeAbi=3;
inline constexpr unsigned kFactoryVersion = 1;
inline constexpr unsigned char kFeatureContractHash[32]={143,58,186,126,107,206,9,255,216,252,31,173,156,5,64,129,98,144,118,41,159,36,162,9,226,90,68,60,45,91,114,37};
inline constexpr unsigned char kPublicKeyPem[]=R"PEM(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA37IWDQwXomCzK6zmKaXO
cBTUL+TimD/N3V2EclnZTYlLDYh0kVTe4ixl6Oft9KxfFCFw5MnTFbQUCT8eHbqB
QJ0WuYJw9F1EY8SYjwmt3YuJqj6vUTvahKgrcfMHSZLsOpwCTFgLi/nr+aqEx8Ic
sIP0CtSWBBpaSJ8qXOxnEhr8EkoqZ2GUxVzGWg82KVCPUrVgmB6mOH4+g0r+zFAO
EF4B/+UO49+VaR4WuNWEhaqteW2kms2tvZnua3U8aZ1BSTr1LVDFWrI22SxN7apZ
1+dDKn9vHyHLDBm+46GEdBAVWyyOTkiX5yJLMtqmS57Y48/RvpGivKyhAvQtGGhS
yQIDAQAB
-----END PUBLIC KEY-----
)PEM";
inline constexpr const char* kDataOrigin="TON_IoT_temporal_030";
struct FactoryRegion { unsigned char magic[16]; uint32_t length; unsigned char bytes[4096]; };
__attribute__((used)) inline const FactoryRegion kFactoryRegion={{73,68,83,48,51,48,70,65,67,84,79,82,89,82,69,71},368,{83,73,68,83,80,75,49,0,96,0,0,0,0,1,0,0,83,73,68,83,84,48,49,0,1,0,0,0,3,0,0,0,1,0,0,0,8,0,0,0,143,58,186,126,107,206,9,255,216,252,31,173,156,5,64,129,98,144,118,41,159,36,162,9,226,90,68,60,45,91,114,37,98,111,111,116,115,116,114,97,112,48,51,48,0,0,0,0,0,0,0,63,1,0,0,0,255,255,255,255,255,255,0,0,0,0,0,0,0,0,0,0,44,107,191,193,14,26,65,14,170,158,251,54,117,18,75,165,27,169,202,239,213,141,222,184,61,41,182,172,236,113,86,54,26,194,195,196,164,90,112,137,144,153,84,168,244,63,141,187,132,98,221,9,119,133,164,32,89,171,125,149,232,218,129,66,90,16,32,62,114,7,60,12,162,211,90,122,186,7,194,65,31,33,82,107,162,201,137,100,210,255,84,110,69,92,191,236,140,66,41,59,171,78,82,188,148,35,59,104,176,78,157,163,21,146,178,210,245,53,75,17,81,187,144,137,197,9,73,90,109,134,28,231,38,245,208,177,176,148,24,183,28,40,172,141,183,119,55,243,221,107,208,51,26,90,154,160,120,13,15,88,153,98,56,134,11,99,225,29,28,88,16,126,160,112,200,70,252,17,191,7,253,56,96,38,22,224,8,91,244,213,176,223,3,239,138,230,220,226,128,164,248,155,135,31,155,244,164,68,132,81,63,3,124,166,64,46,33,35,245,134,57,142,238,208,173,247,138,78,87,123,71,47,47,167,41,180,37,98,108,48,203,189,83,40,6,131,91,1,231,53,215,143,229,75,6,102}};
inline const unsigned char* factory_envelope(){return kFactoryRegion.bytes;}
inline size_t factory_length(){return reinterpret_cast<const volatile FactoryRegion*>(&kFactoryRegion)->length;}
inline uint32_t factory_version(){const volatile unsigned char* p=kFactoryRegion.bytes+32;return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
}
