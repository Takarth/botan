/*
* PSSR
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PSSR_H_
#define BOTAN_PSSR_H_

#include <botan/internal/emsa.h>
#include <botan/hash.h>

namespace Botan {

/**
* PSSR (called EMSA4 in IEEE 1363 and in old versions of the library)
*/
class PSSR final : public EMSA
   {
   public:

      /**
      * @param hash the hash function to use
      */
      explicit PSSR(std::unique_ptr<HashFunction> hash);

      /**
      * @param hash the hash function to use
      * @param salt_size the size of the salt to use in bytes
      */
      PSSR(std::unique_ptr<HashFunction> hash, size_t salt_size);

      std::unique_ptr<EMSA> new_object() override;

      std::string name() const override;

      AlgorithmIdentifier config_for_x509(const std::string& algo_name,
                                          const std::string& cert_hash_name) const override;

      bool requires_message_recovery() const override { return true; }
   private:
      void update(const uint8_t input[], size_t length) override;

      secure_vector<uint8_t> raw_data() override;

      secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t>& msg,
                                      size_t output_bits,
                                      RandomNumberGenerator& rng) override;

      bool verify(const secure_vector<uint8_t>& coded,
                  const secure_vector<uint8_t>& raw,
                  size_t key_bits) override;

      std::unique_ptr<HashFunction> m_hash;
      size_t m_salt_size;
      bool m_required_salt_len;
   };

/**
* PSSR_Raw
* This accepts a pre-hashed buffer
*/
class PSSR_Raw final : public EMSA
   {
   public:

      /**
      * @param hash the hash function to use
      */
      explicit PSSR_Raw(std::unique_ptr<HashFunction> hash);

      /**
      * @param hash the hash function to use
      * @param salt_size the size of the salt to use in bytes
      */
      PSSR_Raw(std::unique_ptr<HashFunction> hash, size_t salt_size);

      std::unique_ptr<EMSA> new_object() override;

      std::string name() const override;

      bool requires_message_recovery() const override { return true; }
   private:
      void update(const uint8_t input[], size_t length) override;

      secure_vector<uint8_t> raw_data() override;

      secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t>& msg,
                                         size_t output_bits,
                                         RandomNumberGenerator& rng) override;

      bool verify(const secure_vector<uint8_t>& coded,
                  const secure_vector<uint8_t>& raw,
                  size_t key_bits) override;

      std::unique_ptr<HashFunction> m_hash;
      secure_vector<uint8_t> m_msg;
      size_t m_salt_size;
      bool m_required_salt_len;
   };

}

#endif
