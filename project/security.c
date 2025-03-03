#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int TYPE = 0;
char* HOST = NULL;
int HANDSHAKE_STAGE = 0;
tlv* CH = NULL;
tlv* SH = NULL;

void init_sec(int type, char* host) {
    init_io();  

    TYPE = type;
    HOST = host;
    load_certificate("server_cert.bin");

    if(type == SERVER){
        load_private_key("server_key.bin");
    }
    else{
        generate_private_key();
    }
    load_ca_public_key("ca_public_key.bin");
    derive_public_key();
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if(TYPE == CLIENT && HANDSHAKE_STAGE < 3){
        if(HANDSHAKE_STAGE == 0){
            tlv* ch = create_tlv(CLIENT_HELLO);
            tlv *nn = create_tlv(NONCE);
            tlv *pub_key = create_tlv(PUBLIC_KEY);

            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            add_val(nn, nonce, NONCE_SIZE);

            add_val(pub_key, public_key, pub_key_size);
            add_tlv(ch, nn);
            add_tlv(ch, pub_key);
            uint16_t len = serialize_tlv(buf, ch);
            CH = ch;
            HANDSHAKE_STAGE = 1;
            return len;
        }
        else if (HANDSHAKE_STAGE == 2){
            tlv* finished = create_tlv(FINISHED);
            tlv* transcript = create_tlv(TRANSCRIPT);

            uint8_t *ptr = buf;
            ptr += serialize_tlv(ptr, CH);
            ptr += serialize_tlv(ptr, SH);
            derive_keys(buf, ptr - buf);
            uint8_t hmac_digest[MAC_SIZE];
            hmac(hmac_digest, buf, ptr - buf);
            add_val(transcript, hmac_digest, MAC_SIZE);

            add_tlv(finished, transcript);
            uint16_t len = serialize_tlv(buf, finished);
            HANDSHAKE_STAGE = 3;
            return len;
        }
    }
    if(TYPE == SERVER && HANDSHAKE_STAGE < 3){
        if(HANDSHAKE_STAGE == 1){      
            tlv *cert = deserialize_tlv(certificate, cert_size);
            tlv *sh = create_tlv(SERVER_HELLO);
            tlv *nn = create_tlv(NONCE);
            tlv *pub_key = create_tlv(PUBLIC_KEY);

            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            add_val(nn, nonce, NONCE_SIZE);
            add_val(pub_key, public_key, pub_key_size);
            add_tlv(sh, nn);
            add_tlv(sh, cert);
            add_tlv(sh, pub_key);

            tlv* hs_sig = create_tlv(HANDSHAKE_SIGNATURE);
            uint8_t *signature = malloc(72);

            uint8_t *ptr = buf; 
            ptr += serialize_tlv(ptr, CH);
            ptr += serialize_tlv(ptr, nn);
            ptr += serialize_tlv(ptr, cert);
            ptr += serialize_tlv(ptr, pub_key);

            int sig_len = sign(signature, buf, ptr - buf);
            add_val(hs_sig, signature, sig_len);
            add_tlv(sh, hs_sig);

            ptr = buf;
            ptr += serialize_tlv(ptr, CH);
            ptr += serialize_tlv(ptr, sh);
            derive_keys(buf, ptr - buf);

            uint16_t len = serialize_tlv(buf, sh);

            SH = sh;
            HANDSHAKE_STAGE = 2;
            return len;
        }
    }
    uint8_t input_buf[MAX_PLAINTEXT];
    int input_size = input_io(input_buf, MAX_PLAINTEXT);
    if(input_size > 0){
        tlv* data = create_tlv(DATA);
        tlv* init_vector = create_tlv(IV);
        tlv* cipher_text = create_tlv(CIPHERTEXT);
        tlv* mac = create_tlv(MAC);

        uint8_t init_vector_buffer[IV_SIZE];
        uint8_t cipher_buffer[1000];
        generate_nonce(init_vector_buffer, IV_SIZE);
        int encrypted_len = encrypt_data(init_vector_buffer, cipher_buffer, input_buf, input_size);

        add_val(init_vector, init_vector_buffer, IV_SIZE);
        add_val(cipher_text, cipher_buffer, encrypted_len);

        uint8_t mac_buffer[1000];
        uint8_t mac_digest[MAC_SIZE];
        uint8_t* ptr = mac_buffer;
        ptr += serialize_tlv(ptr, init_vector);
        ptr += serialize_tlv(ptr, cipher_text);
        hmac(mac_digest, mac_buffer, ptr - mac_buffer);

        add_val(mac, mac_digest, MAC_SIZE);
        
        add_tlv(data, init_vector);
        add_tlv(data, cipher_text);
        add_tlv(data, mac);

        uint16_t len = serialize_tlv(buf, data);
        free_tlv(data);
        return len;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    tlv *incoming = deserialize_tlv(buf, length);
    if(incoming == NULL){
        return;
    }
    if(TYPE == SERVER && HANDSHAKE_STAGE < 3){
        if(incoming->type == CLIENT_HELLO){
            if(HANDSHAKE_STAGE != 0){
                exit(6);
            }
            tlv* client_pub_key = get_tlv(incoming, PUBLIC_KEY);
            load_peer_public_key(client_pub_key->val, client_pub_key->length);
            derive_secret();
            CH = incoming;
            HANDSHAKE_STAGE = 1;
            return;
        }
        else if(incoming->type == FINISHED){
            if(HANDSHAKE_STAGE != 2){
                exit(6);
            }
            verify_finished(incoming);
            HANDSHAKE_STAGE = 3;
            return;
        }
    }
    if(TYPE == CLIENT && HANDSHAKE_STAGE < 3){
        if(HANDSHAKE_STAGE == 1 && incoming->type == SERVER_HELLO){
            tlv *server_pub_key = get_tlv(incoming, PUBLIC_KEY);
            verify_server_hello(incoming);
            load_peer_public_key(server_pub_key->val, server_pub_key->length);

            derive_secret();
            SH = incoming;
            HANDSHAKE_STAGE = 2;
            return;
        }
    }
    if(HANDSHAKE_STAGE == 3){
        verify_data(incoming);
        tlv* cipher_text = get_tlv(incoming, CIPHERTEXT);
        tlv* init_vector = get_tlv(incoming, IV);
        uint8_t output_buffer[MAX_PLAINTEXT];
        int output_len = decrypt_cipher(output_buffer, cipher_text->val, cipher_text->length, init_vector->val);
        output_io(output_buffer, output_len);
    }
}

void verify_server_hello(tlv* sh){
    uint8_t buf[1024];

    tlv* cert = get_tlv(sh, CERTIFICATE);
    tlv* cert_sig = get_tlv(cert, SIGNATURE);
    tlv* dns_name = get_tlv(cert, DNS_NAME);
    tlv* cert_pub_key = get_tlv(cert, PUBLIC_KEY);
    load_peer_public_key(cert_pub_key->val, cert_pub_key->length);

    uint8_t *ptr = buf;
    ptr += serialize_tlv(ptr, dns_name);
    ptr += serialize_tlv(ptr, cert_pub_key);

    if(verify(cert_sig->val, cert_sig->length, buf, ptr - buf, ec_ca_public_key) != 1){
        exit(1);
    }
    if(strcmp(dns_name->val, HOST) != 0){
        exit(2);
    }

    tlv* nn = get_tlv(sh, NONCE);
    tlv* pub_key = get_tlv(sh, PUBLIC_KEY);
    tlv* hs_sig = get_tlv(sh, HANDSHAKE_SIGNATURE);
    ptr = buf;
    ptr += serialize_tlv(ptr, CH);
    ptr += serialize_tlv(ptr, nn);
    ptr += serialize_tlv(ptr, cert);
    ptr += serialize_tlv(ptr, pub_key);
    if(verify(hs_sig->val, hs_sig->length, buf, ptr - buf, ec_peer_public_key) != 1){
        exit(3);
    }
}

void verify_finished(tlv* finished){
    tlv* transcript = get_tlv(finished, TRANSCRIPT);

    uint8_t buf[1024];
    uint8_t *ptr = buf;
    ptr += serialize_tlv(ptr, CH);
    ptr += serialize_tlv(ptr, SH);
    
    uint8_t hmac_digest[MAC_SIZE];
    hmac(hmac_digest, buf, ptr - buf);
    if (memcmp(hmac_digest, transcript->val, MAC_SIZE) != 0){
        exit(4);
    }
}

void verify_data(tlv* data){
    if(data->type == CLIENT_HELLO || data->type == SERVER_HELLO || data->type == FINISHED){
        exit(6);
    }
    tlv *init_vector = get_tlv(data, IV);
    tlv *cipher_text = get_tlv(data, CIPHERTEXT);   

    tlv *mac = get_tlv(data, MAC);

    uint8_t buf[1024];
    uint8_t *ptr = buf;
    ptr += serialize_tlv(ptr, init_vector);
    ptr += serialize_tlv(ptr, cipher_text);
    uint8_t hmac_digest[MAC_SIZE];

    hmac(hmac_digest, buf, ptr - buf);
    if (memcmp(hmac_digest, mac->val, MAC_SIZE) != 0)
    {
        exit(5);
    }
}
