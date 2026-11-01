#!/usr/bin/env python3
"""Author: Oleksandr Kuznetsov. Native tests of the exact MCU streaming decoder."""
import ctypes
import json
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "stream_inflate.h"
#include <vector>
#include <cstring>
struct State { std::vector<unsigned char> bytes; bool reject; };
static unsigned rom_calls = 0;
// A strong linker assignment models ESP-IDF's ROM symbol binding. The project
// must never call this incompatible inflater, even when that symbol exists.
extern "C" int ids039_test_rom_inflater(void*, const void*, size_t*, void*, void*, size_t*, unsigned) {
  ++rom_calls; return -1;
}
extern "C" unsigned ids039_test_rom_calls() { return rom_calls; }
static bool sink(void* context, const uint8_t* bytes, size_t n) {
  auto& state = *static_cast<State*>(context);
  if (state.reject) return false;
  state.bytes.insert(state.bytes.end(), bytes, bytes+n); return true;
}
extern "C" int decode(const uint8_t* data, size_t length, size_t expected,
                      size_t chunk, uint8_t* output, int reject) {
  StreamInflate inflater; inflater.reset(expected); State state{{},bool(reject)};
  for(size_t offset=0;offset<length;offset+=chunk) {
    const size_t n = length-offset < chunk ? length-offset : chunk;
    if(!inflater.feed(data+offset,n,offset+n==length,sink,&state)) return -1;
  }
  if(!inflater.complete() || state.bytes.size()!=expected) return -2;
  std::memcpy(output,state.bytes.data(),expected); return 0;
}
'''

class StreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        target = Path(cls.tmp.name)
        (target/'wrapper.cpp').write_text(SOURCE)
        vendor = ROOT/'firmware/components/miniz_tinfl'
        subprocess.run(['cc','-fPIC','-O2','-DMINIZ_NO_STDIO','-DMINIZ_NO_TIME',
                        '-I'+str(vendor),'-c',str(vendor/'miniz_tinfl.c'),'-o',str(target/'miniz.o')],check=True)
        subprocess.run(['c++','-std=c++17','-fPIC','-shared','-O2','-I'+str(vendor),
                        '-I'+str(ROOT/'firmware/main'),str(target/'wrapper.cpp'),str(target/'miniz.o'),
                        '-Wl,--defsym,tinfl_decompress=ids039_test_rom_inflater',
                        '-o',str(target/'decoder.so')],check=True)
        cls.lib=ctypes.CDLL(str(target/'decoder.so'))
        cls.lib.decode.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_int]
        cls.lib.decode.restype=ctypes.c_int
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def decode(self, data, expected, chunk=1024, reject=False):
        output=ctypes.create_string_buffer(max(1,expected))
        result=self.lib.decode(data,len(data),expected,chunk,output,reject)
        return result,output.raw[:expected]
    def test_stream_and_ring_boundaries(self):
        rng=random.Random(390)
        samples=[b'x',b'\0'*339504,bytes(range(256))*2000,rng.randbytes(340001)]
        for raw in samples:
            for level in (0,1,6,9):
                for chunk in (1,7,257,1024,32768):
                    with self.subTest(size=len(raw),level=level,chunk=chunk):
                        self.assertEqual(self.decode(zlib.compress(raw,level),len(raw),chunk),(0,raw))
    def test_project_inflater_is_not_replaced_by_rom_symbol(self):
        raw=bytes(range(251))*1400
        status,decoded=self.decode(zlib.compress(raw,6),len(raw))
        self.assertEqual(status,0)
        self.assertEqual(decoded,raw)
        self.assertEqual(self.lib.ids039_test_rom_calls(),0)
    def test_corrupt_truncated_extra_and_wrong_length(self):
        raw=bytes(range(251))*1800; data=zlib.compress(raw)
        cases=[data[:-1],data[:-8],data+b'trailer',data+data,bytes([data[0]^1])+data[1:],data[:-1]+bytes([data[-1]^1])]
        for encoded in cases:
            self.assertNotEqual(self.decode(encoded,len(raw))[0],0)
        for length in (len(raw)-1,len(raw)+1):
            self.assertNotEqual(self.decode(data,length)[0],0)
        self.assertNotEqual(self.decode(data,len(raw),reject=True)[0],0)
    def test_frozen_full_images(self):
        images=list((ROOT.parent/'research030/prebuilt').glob('*_whole/ids_update_lab.bin'))
        images+=list((ROOT/'build/prebuilt').glob('*/*_whole/ids_update_lab.bin'))
        for image in images:
            raw=image.read_bytes()
            self.assertEqual(self.decode(zlib.compress(raw,6),len(raw)),(0,raw))
if __name__=='__main__': unittest.main()
