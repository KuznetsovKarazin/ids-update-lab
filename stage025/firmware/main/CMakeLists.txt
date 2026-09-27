idf_component_register(SRCS "main.cpp" "firmware_ota.cpp"
  INCLUDE_DIRS "." "generated"
  REQUIRES ids_core mbedtls esp_partition esp_timer esp_system app_update driver)
target_compile_options(${COMPONENT_LIB} PRIVATE -ffp-contract=off)
