#pragma once

/*
 * WARNING
 * libcoap is not multi-thread safe, so only this thread must make any coap_*()
 * calls.  Any external (to this thread) data transmitted in/out via libcoap
 * therefore has to be passed in/out by xQueue*() via this thread.
 */

#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/param.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "nvs_flash.h"

#include "protocol_examples_common.h"

#include "coap3/coap.h"

#ifndef CONFIG_COAP_CLIENT_SUPPORT
#error COAP_CLIENT_SUPPORT needs to be enabled
#endif /* COAP_CLIENT_SUPPORT */

#define COAP_DEFAULT_TIME_SEC 60

//log level value between 0 and 7
#define EXAMPLE_COAP_LOG_DEFAULT_LEVEL 7


//when doing a send the message_handler will put the data inside coap_response_buffer
//once resp_wait is done waiting its safe that message_handler is done
//and you can then read from the coap_response_buffer and use it's data
extern char coap_response_buffer[1024]; // adjust size as needed
extern int resp_wait;
extern coap_optlist_t* optlist;

const static char* TAG = "CoAPs_client";

void coaps_init();
coap_response_t message_handler(coap_session_t* session, const coap_pdu_t* sent, const coap_pdu_t* received, const coap_mid_t mid);
void coap_log_handler(coap_log_t level, const char* message);
coap_address_t* coap_get_address(coap_uri_t* uri);
int coap_build_optlist(coap_uri_t* uri);
coap_session_t* coap_start_psk_session(coap_context_t* ctx, coap_address_t* dst_addr, coap_uri_t* uri, const char* coap_psk_identity, const char* coap_psk_key);
char* CoAPsSend(coap_pdu_code_t method, bool wait, const char* fullurl, const char* identity, const char* key, const char* data, size_t data_len);
char* CoAPsGet(const char* fullurl, const char* identity, const char* key);
char* CoAPsPost(const char* fullurl, const char* identity, const char* key, const char* data, size_t data_len);
char* CoAPsPut(bool wait, const char* fullurl, const char* identity, const char* key, const char* data, size_t data_len);
