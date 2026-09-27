#include "ids_core.h"
#include "ids_line_reader.h"
#include "ids_protocol.h"
extern "C" const unsigned ids_size_probe[] = {sizeof(ids::Model), sizeof(ids::Engine), sizeof(ids::LineReader), ids::kMaxLine, ids::kMaxEnvelope, sizeof(ids::TreeData)};
