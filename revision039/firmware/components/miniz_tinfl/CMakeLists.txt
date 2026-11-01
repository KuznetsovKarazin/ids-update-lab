# Author: Oleksandr Kuznetsov
idf_component_register(SRCS "miniz_tinfl.c" INCLUDE_DIRS ".")
target_compile_definitions(${COMPONENT_LIB} PUBLIC MINIZ_NO_STDIO MINIZ_NO_TIME)
