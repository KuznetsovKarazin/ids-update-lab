idf_component_register(SRCS "ids_core.cpp" "ids_tree.cpp" "ids_protocol.cpp" INCLUDE_DIRS "include")
target_compile_options(${COMPONENT_LIB} PRIVATE -ffp-contract=off)
