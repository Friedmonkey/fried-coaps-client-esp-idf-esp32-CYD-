idf_component_register(
    SRCS "src/fried_coaps_client.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_event nvs_flash coap protocol_examples_common
)
