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
    if(TYPE == CLIENT){
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
    }
    else{
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

            free_tlv(sh);
            free(signature);
            HANDSHAKE_STAGE = 2;
            return len;
        }
    }
}

void output_sec(uint8_t* buf, size_t length) {
    tlv *incoming = deserialize_tlv(buf, length);
    if(incoming == NULL){
        return;
    }
    if(TYPE == SERVER){
        if(incoming->type == CLIENT_HELLO){
            if(HANDSHAKE_STAGE != 0){
                exit(6);
            }
            tlv* client_pub_key = get_tlv(incoming, PUBLIC_KEY);
            load_peer_public_key(client_pub_key->val, client_pub_key->length);
            derive_secret();
            CH = incoming;
            HANDSHAKE_STAGE = 1;
        }
        else{
            
        }
    }
    else {
        if(HANDSHAKE_STAGE == 1 && incoming->type == SERVER_HELLO){


            load_peer_public_key(server_pub_key->val, server_pub_key->length);
            derive_secret();

        }
    }
}
