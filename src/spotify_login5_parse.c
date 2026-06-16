#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "pb_decode.h"
#include "spotify/login5/v3/login5.pb.h"

int spotify_login5_extract_token(const uint8_t *payload, size_t payload_len, char *access_token_str, size_t max_len) {
    spotify_login5_v3_LoginResponse resp = spotify_login5_v3_LoginResponse_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(payload, payload_len);
    
    // We don't care about decoding strings inside nanopb statically since we use callbacks
    // Actually wait, let's just do a manual string search for "BQA" if nanopb is too painful
    // Since we know it's a Protobuf LoginResponse
    
    for(size_t i = 0; i < payload_len - 5; i++) {
        if (payload[i] == 'B' && payload[i+1] == 'Q' && payload[i+2] == 'A') {
            size_t token_len = 0;
            // The byte before 'B' should be the varint length of the string in protobuf
            uint8_t len_byte = payload[i-1];
            
            // Assume length fits in 1 byte for simplicity (or 2 bytes if > 127)
            // Access tokens are usually ~300 bytes, so it will be 2 bytes varint
            // Let's just copy until non-base64 char or we hit ~400 chars.
            while (token_len < max_len - 1 && i + token_len < payload_len) {
                char c = payload[i + token_len];
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '=') {
                    access_token_str[token_len] = c;
                    token_len++;
                } else {
                    break;
                }
            }
            access_token_str[token_len] = '\0';
            return 0; // Success
        }
    }
    
    return -1; // Not found
}
