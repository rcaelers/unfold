#include "utils/Base64.hh"
#include <iostream>

int main() {
    std::string json_spec = R"({
      "spec": {
        "signature": {
          "content": "test-signature"
        },
        "x509CertificateChain": {
          "certificates": [
            {
              "rawBytes": "dGVzdC1jZXJ0aWZpY2F0ZQ=="
            }
          ]
        },
        "data": {
          "hash": {
            "algorithm": "sha256",
            "value": "dGVzdC1oYXNo"
          }
        }
      }
    })";
    
    std::string encoded = unfold::utils::Base64::encode(json_spec);
    std::cout << "Encoded: " << encoded << std::endl;
    
    try {
        std::string decoded = unfold::utils::Base64::decode(encoded);
        std::cout << "Decoded successfully: " << decoded.substr(0, 50) << "..." << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Decode failed: " << e.what() << std::endl;
    }
    
    return 0;
}
