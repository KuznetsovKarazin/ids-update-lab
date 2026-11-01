// PUBLIC TEST KEY ONLY. Factory bytes are patched and re-signed by the host.
#pragma once
#include <cstdint>
#include <cstddef>
namespace ids_generated {
inline constexpr unsigned kFeatureCount=8;
inline constexpr unsigned kRuntimeAbi=2;
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
__attribute__((used)) inline const FactoryRegion kFactoryRegion={{73,68,83,48,51,48,70,65,67,84,79,82,89,82,69,71},448,{83,73,68,83,80,75,49,0,176,0,0,0,0,1,0,0,83,73,68,83,66,48,49,0,1,0,0,0,2,0,0,0,1,0,0,0,8,0,0,0,143,58,186,126,107,206,9,255,216,252,31,173,156,5,64,129,98,144,118,41,159,36,162,9,226,90,68,60,45,91,114,37,98,111,111,116,115,116,114,97,112,48,51,48,0,0,0,0,0,0,0,63,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,63,0,0,128,63,0,0,128,63,0,0,128,63,0,0,128,63,0,0,128,63,0,0,128,63,0,0,128,63,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,165,35,103,211,67,183,241,79,194,234,120,36,173,174,65,133,183,183,226,137,94,162,27,163,47,143,118,196,157,21,88,161,183,212,205,43,165,163,151,128,225,149,213,38,113,149,196,14,131,37,27,12,168,72,107,25,19,246,194,95,237,200,163,139,248,147,208,161,167,194,185,247,20,94,5,130,218,86,75,87,202,180,30,231,107,194,69,85,131,246,56,133,187,77,239,107,196,222,205,9,13,1,80,25,221,30,164,188,40,204,22,234,162,150,137,170,241,85,37,126,125,116,51,240,129,133,208,63,33,105,27,52,219,19,46,244,36,234,218,222,255,111,5,161,81,25,49,0,59,104,183,143,161,105,21,213,182,32,183,179,64,227,235,49,135,43,143,64,105,125,248,205,209,239,59,42,168,47,174,179,220,59,123,221,224,244,116,195,161,143,6,134,91,24,136,31,155,182,178,39,187,79,13,13,203,126,100,179,186,55,239,227,195,50,147,6,171,125,104,175,80,222,34,71,111,193,138,123,81,157,220,152,50,23,232,136,140,111,23,180,39,188,127,13,152,58,107,206,49,94,42,162,44,67,39,59}};
inline const unsigned char* factory_envelope(){return kFactoryRegion.bytes;}
inline size_t factory_length(){return reinterpret_cast<const volatile FactoryRegion*>(&kFactoryRegion)->length;}
inline uint32_t factory_version(){const volatile unsigned char* p=kFactoryRegion.bytes+32;return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
}
