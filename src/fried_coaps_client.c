#include "fried_coaps_client.h"

char coap_response_buffer[1024]; // used by the client functions
int resp_wait = 1;
coap_optlist_t* optlist = NULL;

void coaps_init()
{
    // Initialize NVS (required by Wi-Fi/ETH)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize network stack
    ESP_ERROR_CHECK(esp_netif_init());

    // Create default event loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Start Wi-Fi or Ethernet using example helper (optional, but easiest)
    ESP_ERROR_CHECK(example_connect());

    ESP_LOGI("CoAPs_init", "Network stack initialized, ready for CoAP!");
}

coap_response_t
message_handler(coap_session_t* session,
    const coap_pdu_t* sent,
    const coap_pdu_t* received,
    const coap_mid_t mid)
{
    const unsigned char* data = NULL;
    size_t data_len;
    size_t offset;
    size_t total;

    coap_pdu_code_t rcvd_code = coap_pdu_get_code(received);

    if (COAP_RESPONSE_CLASS(rcvd_code) == 2) {
        if (coap_get_data_large(received, &data_len, &data, &offset, &total)) {
            // Copy only what fits into the buffer safely
            size_t copy_len = total < sizeof(coap_response_buffer) - 1 ? total : sizeof(coap_response_buffer) - 1;
            memcpy(coap_response_buffer, data, copy_len);
            coap_response_buffer[copy_len] = '\0'; // null terminate
        }

        resp_wait = 0; // signal the waiting loop
        return COAP_RESPONSE_OK;
    }

    // Non-2.xx responses – something went wrong
    printf("CoAP error response: %d.%02d", (rcvd_code >> 5), rcvd_code & 0x1F);

    if (coap_get_data_large(received, &data_len, &data, &offset, &total)) {
        printf(": ");
        for (size_t i = 0; i < data_len; i++) {
            printf("%c", isprint(data[i]) ? data[i] : '.');
        }
    }
    printf("\n");

    resp_wait = 0; // stop waiting even on error
    return COAP_RESPONSE_OK;
}

void coap_log_handler(coap_log_t level, const char* message)
{
    uint32_t esp_level = ESP_LOG_INFO;
    char* cp = strchr(message, '\n');

    if (cp)
        ESP_LOG_LEVEL(esp_level, TAG, "%.*s", (int)(cp - message), message);
    else
        ESP_LOG_LEVEL(esp_level, TAG, "%s", message);
}

coap_address_t* coap_get_address(coap_uri_t* uri) {
    static coap_address_t dst_addr;
    char phostname[64]; // enough for IPv6 string

    if (uri->host.length >= sizeof(phostname)) {
        ESP_LOGE(TAG, "Host string too long");
        return NULL;
    }

    // copy host string and null-terminate
    memcpy(phostname, uri->host.s, uri->host.length);
    phostname[uri->host.length] = '\0';

    coap_address_init(&dst_addr);

    // try IPv4 first
    if (inet_pton(AF_INET, phostname, &dst_addr.addr.sin.sin_addr) == 1) {
        dst_addr.size = sizeof(dst_addr.addr.sin);
        dst_addr.addr.sin.sin_family = AF_INET;
        dst_addr.addr.sin.sin_port = htons(uri->port);
        ESP_LOGI(TAG, "Parsed IPv4 address: %s", phostname);
        return &dst_addr;
    }

    // try IPv6 next
    if (inet_pton(AF_INET6, phostname, &dst_addr.addr.sin6.sin6_addr) == 1) {
        dst_addr.size = sizeof(dst_addr.addr.sin6);
        dst_addr.addr.sin6.sin6_family = AF_INET6;
        dst_addr.addr.sin6.sin6_port = htons(uri->port);
        ESP_LOGI(TAG, "Parsed IPv6 address: %s", phostname);
        return &dst_addr;
    }

    ESP_LOGE(TAG, "Invalid IP address: %s", phostname);
    return NULL;
}

int coap_build_optlist(coap_uri_t* uri)
{
#define BUFSIZE 40
    unsigned char _buf[BUFSIZE];
    unsigned char* buf;
    size_t buflen;
    int res;

    optlist = NULL;

    if (uri->scheme == COAP_URI_SCHEME_COAPS && !coap_dtls_is_supported()) {
        ESP_LOGE(TAG, "MbedTLS DTLS Client Mode not configured");
        return 0;
    }
    if (uri->scheme == COAP_URI_SCHEME_COAPS_TCP && !coap_tls_is_supported()) {
        ESP_LOGE(TAG, "MbedTLS TLS Client Mode not configured");
        return 0;
    }
    if (uri->scheme == COAP_URI_SCHEME_COAP_TCP && !coap_tcp_is_supported()) {
        ESP_LOGE(TAG, "TCP Client Mode not configured");
        return 0;
    }

    if (uri->path.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(&optlist,
                coap_new_optlist(COAP_OPTION_URI_PATH,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }

    if (uri->query.length) {
        buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

        while (res--) {
            coap_insert_optlist(&optlist,
                coap_new_optlist(COAP_OPTION_URI_QUERY,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

            buf += coap_opt_size(buf);
        }
    }
    return 1;
}

coap_session_t*
coap_start_psk_session(coap_context_t* ctx, coap_address_t* dst_addr, coap_uri_t* uri, const char* coap_psk_identity, const char* coap_psk_key)
{
    static coap_dtls_cpsk_t dtls_psk;
    static char client_sni[256];

    memset(client_sni, 0, sizeof(client_sni));
    memset(&dtls_psk, 0, sizeof(dtls_psk));
    dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
    dtls_psk.validate_ih_call_back = NULL;
    dtls_psk.ih_call_back_arg = NULL;
    if (uri->host.length)
        memcpy(client_sni, uri->host.s, MIN(uri->host.length, sizeof(client_sni) - 1));
    else
        memcpy(client_sni, "localhost", 9);
    dtls_psk.client_sni = client_sni;
    dtls_psk.psk_info.identity.s = (const uint8_t*)coap_psk_identity;
    dtls_psk.psk_info.identity.length = strlen(coap_psk_identity);
    dtls_psk.psk_info.key.s = (const uint8_t*)coap_psk_key;
    dtls_psk.psk_info.key.length = strlen(coap_psk_key);
    return coap_new_client_session_psk2(ctx, NULL, dst_addr,
        uri->scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
        &dtls_psk);
}



char* CoAPsSend(coap_pdu_code_t method, bool wait, const char* fullurl, const char* identity, const char* key,
    const char* data, size_t data_len)
{
    coap_address_t* dst_addr;
    static coap_uri_t uri;

    coap_context_t* ctx = NULL;
    coap_session_t* session = NULL;
    coap_pdu_t* request = NULL;
    unsigned char token[8];
    size_t tokenlength;

    /* Set up the CoAP logging */
    coap_set_log_handler(coap_log_handler);
    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);

    /* Set up the CoAP context */
    ctx = coap_new_context(NULL);
    if (!ctx) {
        ESP_LOGE(TAG, "coap_new_context() failed");
        goto clean_up;
    }

    coap_context_set_block_mode(ctx,
        COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

    coap_register_response_handler(ctx, message_handler);

    if (coap_split_uri((const uint8_t*)fullurl, strlen(fullurl), &uri) == -1) {
        ESP_LOGE(TAG, "CoAP server URI error");
        goto clean_up;
    }

    if (!coap_build_optlist(&uri))
        goto clean_up;

    dst_addr = coap_get_address(&uri);
    if (!dst_addr) {
        ESP_LOGE(TAG, "Failed to get destination address");
        goto clean_up;
    }

    /* Select session type */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
        session = coap_start_psk_session(ctx, dst_addr, &uri, identity, key);
    }
    else {
        session = coap_new_client_session(ctx, NULL, dst_addr,
            uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP : COAP_PROTO_UDP);
    }

    if (!session) {
        ESP_LOGE(TAG, "coap_new_client_session() failed");
        goto clean_up;
    }

    /* Create GET request */
    request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
        method, session);
    if (!request) {
        ESP_LOGE(TAG, "coap_new_pdu() failed");
        goto clean_up;
    }

    /* Add unique token */
    coap_session_new_token(session, &tokenlength, token);
    coap_add_token(request, tokenlength, token);

    /* Add URI options */
    coap_add_optlist_pdu(request, &optlist);

    //add data if we have any
    if (data && data_len > 0) {
        unsigned char buf[4];
        coap_insert_optlist(&optlist,
            coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
                coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_APPLICATION_JSON),
                buf));

        /* Add POST data */
        coap_add_data_large_request(session, request, data_len, (const uint8_t*)data, NULL, NULL);
    }

    /* Signal that we're waiting for response */
    resp_wait = 1;
    coap_send(session, request);

    /* Wait for response or timeout */
    int wait_ms = COAP_DEFAULT_TIME_SEC * 1000;
    while (resp_wait) {
        int result = coap_io_process(ctx, wait_ms > 1000 ? 1000 : wait_ms);
        if (result >= 0) {
            if (result >= wait_ms) {
                ESP_LOGE(TAG, "No response from server");
                break;
            }
            else {
                wait_ms -= result;
            }
        }
    }

clean_up:
    if (optlist) {
        coap_delete_optlist(optlist);
        optlist = NULL;
    }
    if (session) {
        coap_session_release(session);
    }
    if (ctx) {
        coap_free_context(ctx);
    }
    coap_cleanup();

    /* Return the buffer set by message_handler */
    return coap_response_buffer;
}



//char* CoAPsSend(coap_pdu_code_t method, bool wait, const char* fullurl, const char* identity, const char* key,
//    const char* data, size_t data_len)
//{
//    coap_address_t* dst_addr;
//    static coap_uri_t uri;
//    coap_context_t* ctx = NULL;
//    coap_session_t* session = NULL;
//    coap_pdu_t* request = NULL;
//    unsigned char token[8];
//    size_t tokenlength;
//    int resp_wait = 0;
//
//    /* Set up the CoAP logging */
//    coap_set_log_handler(coap_log_handler);
//    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);
//
//    /* Set up the CoAP context */
//    ctx = coap_new_context(NULL);
//    if (!ctx) {
//        ESP_LOGE(TAG, "coap_new_context() failed");
//        goto clean_up;
//    }
//
//    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
//    coap_register_response_handler(ctx, message_handler);
//
//    if (coap_split_uri((const uint8_t*)fullurl, strlen(fullurl), &uri) == -1) {
//        ESP_LOGE(TAG, "CoAP server URI error");
//        goto clean_up;
//    }
//
//    if (!coap_build_optlist(&uri))
//        goto clean_up;
//
//    dst_addr = coap_get_address(&uri);
//    if (!dst_addr) {
//        ESP_LOGE(TAG, "Failed to get destination address");
//        goto clean_up;
//    }
//
//    /* Select session type */
//    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
//        session = coap_start_psk_session(ctx, dst_addr, &uri, identity, key);
//    }
//    else {
//        session = coap_new_client_session(ctx, NULL, dst_addr,
//            uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP : COAP_PROTO_UDP);
//    }
//
//    if (!session) {
//        ESP_LOGE(TAG, "coap_new_client_session() failed");
//        goto clean_up;
//    }
//
//    /* Create POST request */
//    request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
//        method, session);
//    if (!request) {
//        ESP_LOGE(TAG, "coap_new_pdu() failed");
//        goto clean_up;
//    }
//
//    /* Add unique token */
//    coap_session_new_token(session, &tokenlength, token);
//    coap_add_token(request, tokenlength, token);
//
//    /* Add URI options */
//    coap_add_optlist_pdu(request, &optlist);
//
//    /* Add Content-Format Option for JSON */
//    if (data && data_len > 0) {
//        unsigned char buf[4];
//        coap_insert_optlist(&optlist,
//            coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
//                coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_APPLICATION_JSON),
//                buf));
//
//        /* Add POST data */
//        coap_add_data_large_request(session, request, data_len, (const uint8_t*)data, NULL, NULL);
//    }
//
//    /* Signal that we're waiting for response */
//    resp_wait = 1;
//    coap_send(session, request);
//
//    //if (wait)
//    {
//        /* Wait for response or timeout */
//        int wait_ms = 4000;//COAP_DEFAULT_TIME_SEC * 1000;
//        while (resp_wait) {
//            int result = coap_io_process(ctx, wait_ms > 1000 ? 1000 : wait_ms);
//            if (result >= 0) {
//                if (result >= wait_ms) {
//                    ESP_LOGE(TAG, "No response from server");
//                    break;
//                }
//                else {
//                    wait_ms -= result;
//                }
//            }
//        }
//    }
//    //else
//    {
//        //coap_io_process(ctx, 1000);
//    }
//
//clean_up:
//    if (optlist) {
//        coap_delete_optlist(optlist);
//        optlist = NULL;
//    }
//    if (session) {
//        coap_session_release(session);
//    }
//    if (ctx) {
//        coap_free_context(ctx);
//    }
//    coap_cleanup();
//
//    /* Return the buffer set by message_handler */
//    return coap_response_buffer;
//}



char* CoAPsGet(const char* fullurl, const char* identity, const char* key) 
{
    return CoAPsSend(COAP_REQUEST_CODE_GET, true, fullurl, identity, key, NULL, 0);
}
char* CoAPsPost(const char* fullurl, const char* identity, const char* key, const char* data, size_t data_len)
{
    return CoAPsSend(COAP_REQUEST_CODE_POST, true, fullurl, identity, key, data, data_len);
}
char* CoAPsPut(bool wait, const char* fullurl, const char* identity, const char* key, const char* data, size_t data_len)
{
    return CoAPsSend(COAP_REQUEST_CODE_PUT, wait, fullurl, identity, key, data, data_len);
}

//char* CoAPsPost(const char* fullurl, const char* identity, const char* key,
//    const char* data, size_t data_len) {
//    coap_address_t* dst_addr;
//    static coap_uri_t uri;
//    coap_context_t* ctx = NULL;
//    coap_session_t* session = NULL;
//    coap_pdu_t* request = NULL;
//    unsigned char token[8];
//    size_t tokenlength;
//    int resp_wait = 0;
//
//    /* Set up the CoAP logging */
//    coap_set_log_handler(coap_log_handler);
//    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);
//
//    /* Set up the CoAP context */
//    ctx = coap_new_context(NULL);
//    if (!ctx) {
//        ESP_LOGE(TAG, "coap_new_context() failed");
//        goto clean_up;
//    }
//
//    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
//    coap_register_response_handler(ctx, message_handler);
//
//    if (coap_split_uri((const uint8_t*)fullurl, strlen(fullurl), &uri) == -1) {
//        ESP_LOGE(TAG, "CoAP server URI error");
//        goto clean_up;
//    }
//
//    if (!coap_build_optlist(&uri))
//        goto clean_up;
//
//    dst_addr = coap_get_address(&uri);
//    if (!dst_addr) {
//        ESP_LOGE(TAG, "Failed to get destination address");
//        goto clean_up;
//    }
//
//    /* Select session type */
//    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
//        session = coap_start_psk_session(ctx, dst_addr, &uri, identity, key);
//    }
//    else {
//        session = coap_new_client_session(ctx, NULL, dst_addr,
//            uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP : COAP_PROTO_UDP);
//    }
//
//    if (!session) {
//        ESP_LOGE(TAG, "coap_new_client_session() failed");
//        goto clean_up;
//    }
//
//    /* Create POST request */
//    request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
//        COAP_REQUEST_CODE_POST, session);
//    if (!request) {
//        ESP_LOGE(TAG, "coap_new_pdu() failed");
//        goto clean_up;
//    }
//
//    /* Add unique token */
//    coap_session_new_token(session, &tokenlength, token);
//    coap_add_token(request, tokenlength, token);
//
//    /* Add URI options */
//    coap_add_optlist_pdu(request, &optlist);
//
//    /* Add Content-Format Option for JSON */
//    if (data && data_len > 0) {
//        unsigned char buf[4];
//        coap_insert_optlist(&optlist,
//            coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
//                coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_APPLICATION_JSON),
//                buf));
//
//        /* Add POST data */
//        coap_add_data_large_request(session, request, data_len, (const uint8_t*)data, NULL, NULL);
//    }
//
//    /* Signal that we're waiting for response */
//    resp_wait = 1;
//    coap_send(session, request);
//
//    /* Wait for response or timeout */
//    int wait_ms = COAP_DEFAULT_TIME_SEC * 1000;
//    while (resp_wait) {
//        int result = coap_io_process(ctx, wait_ms > 1000 ? 1000 : wait_ms);
//        if (result >= 0) {
//            if (result >= wait_ms) {
//                ESP_LOGE(TAG, "No response from server");
//                break;
//            }
//            else {
//                wait_ms -= result;
//            }
//        }
//    }
//
//clean_up:
//    if (optlist) {
//        coap_delete_optlist(optlist);
//        optlist = NULL;
//    }
//    if (session) {
//        coap_session_release(session);
//    }
//    if (ctx) {
//        coap_free_context(ctx);
//    }
//    coap_cleanup();
//
//    /* Return the buffer set by message_handler */
//    return coap_response_buffer;
//}
//
//char* CoAPsPut(const char* fullurl, const char* identity, const char* key,
//    const char* data, size_t data_len) {
//    coap_address_t* dst_addr;
//    static coap_uri_t uri;
//    coap_context_t* ctx = NULL;
//    coap_session_t* session = NULL;
//    coap_pdu_t* request = NULL;
//    unsigned char token[8];
//    size_t tokenlength;
//    int resp_wait = 0;
//
//    /* Set up the CoAP logging */
//    coap_set_log_handler(coap_log_handler);
//    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);
//
//    /* Set up the CoAP context */
//    ctx = coap_new_context(NULL);
//    if (!ctx) {
//        ESP_LOGE(TAG, "coap_new_context() failed");
//        goto clean_up;
//    }
//
//    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
//    coap_register_response_handler(ctx, message_handler);
//
//    if (coap_split_uri((const uint8_t*)fullurl, strlen(fullurl), &uri) == -1) {
//        ESP_LOGE(TAG, "CoAP server URI error");
//        goto clean_up;
//    }
//
//    if (!coap_build_optlist(&uri))
//        goto clean_up;
//
//    dst_addr = coap_get_address(&uri);
//    if (!dst_addr) {
//        ESP_LOGE(TAG, "Failed to get destination address");
//        goto clean_up;
//    }
//
//    /* Select session type */
//    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
//        session = coap_start_psk_session(ctx, dst_addr, &uri, identity, key);
//    }
//    else {
//        session = coap_new_client_session(ctx, NULL, dst_addr,
//            uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP : COAP_PROTO_UDP);
//    }
//
//    if (!session) {
//        ESP_LOGE(TAG, "coap_new_client_session() failed");
//        goto clean_up;
//    }
//
//    /* Create POST request */
//    request = coap_new_pdu(coap_is_mcast(dst_addr) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
//        COAP_REQUEST_CODE_PUT, session);
//    if (!request) {
//        ESP_LOGE(TAG, "coap_new_pdu() failed");
//        goto clean_up;
//    }
//
//    /* Add unique token */
//    coap_session_new_token(session, &tokenlength, token);
//    coap_add_token(request, tokenlength, token);
//
//    /* Add URI options */
//    coap_add_optlist_pdu(request, &optlist);
//
//    /* Add Content-Format Option for JSON */
//    if (data && data_len > 0) {
//        unsigned char buf[4];
//        coap_insert_optlist(&optlist,
//            coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
//                coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_APPLICATION_JSON),
//                buf));
//
//        /* Add POST data */
//        coap_add_data_large_request(session, request, data_len, (const uint8_t*)data, NULL, NULL);
//    }
//
//    /* Signal that we're waiting for response */
//    resp_wait = 1;
//    coap_send(session, request);
//
//    /* Wait for response or timeout */
//    int wait_ms = 4000;//COAP_DEFAULT_TIME_SEC * 1000;
//    while (resp_wait) {
//        int result = coap_io_process(ctx, wait_ms > 1000 ? 1000 : wait_ms);
//        if (result >= 0) {
//            if (result >= wait_ms) {
//                ESP_LOGE(TAG, "No response from server");
//                break;
//            }
//            else {
//                wait_ms -= result;
//            }
//        }
//    }
//
//clean_up:
//    if (optlist) {
//        coap_delete_optlist(optlist);
//        optlist = NULL;
//    }
//    if (session) {
//        coap_session_release(session);
//    }
//    if (ctx) {
//        coap_free_context(ctx);
//    }
//    coap_cleanup();
//
//    /* Return the buffer set by message_handler */
//    return coap_response_buffer;
//}