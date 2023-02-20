/*
* (C) 2016,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stateful_rng.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

namespace Botan {

void Stateful_RNG::clear()
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);
   m_reseed_counter = 0;
   m_last_pid = 0;
   clear_state();
   }

void Stateful_RNG::force_reseed()
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);
   m_reseed_counter = 0;
   }

bool Stateful_RNG::is_seeded() const
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);
   return m_reseed_counter > 0;
   }

void Stateful_RNG::initialize_with(std::span<const uint8_t> input)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   clear();
   add_entropy(input);
   }

void Stateful_RNG::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   if(output.empty())
      {
      // We won't produce any output but we must give the derived stateful
      // RNG a chance to use the provided input for seeding. Therefore, no
      // reseed_check() is performed before calling generate_output().
      this->generate_output({}, input);

      if(8*input.size() >= security_level())
         {
         reset_reseed_counter();
         }

      return;
      }

   const size_t max_per_request = max_number_of_bytes_per_request();

   if(max_per_request == 0) // no limit
      {
      reseed_check();
      this->generate_output(output, input);
      }
   else
      {
      size_t output_length = output.size();
      size_t output_offset = 0;
      while(output_length > 0)
         {
         const size_t this_req = std::min(max_per_request, output_length);

         /*
         * We split the request into several requests to the underlying DRBG but
         * pass the input to each invocation. It might be more sensible to only
         * provide it for the first invocation, however between 2.0 and 2.15
         * HMAC_DRBG always provided it for all requests so retain that here.
         */

         reseed_check();
         this->generate_output(output.subspan(output_offset, this_req), input);

         output_offset += this_req;
         output_length -= this_req;
         }
      }
   }

size_t Stateful_RNG::reseed(Entropy_Sources& srcs,
                            size_t poll_bits,
                            std::chrono::milliseconds poll_timeout)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   const size_t bits_collected = RandomNumberGenerator::reseed(srcs, poll_bits, poll_timeout);

   if(bits_collected >= security_level())
      {
      reset_reseed_counter();
      }

   return bits_collected;
   }

void Stateful_RNG::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   lock_guard_type<recursive_mutex_type> lock(m_mutex);

   RandomNumberGenerator::reseed_from_rng(rng, poll_bits);

   if(poll_bits >= security_level())
      {
      reset_reseed_counter();
      }
   }

void Stateful_RNG::reset_reseed_counter()
   {
   // Lock is held whenever this function is called
   m_reseed_counter = 1;
   }

void Stateful_RNG::reseed_check()
   {
   // Lock is held whenever this function is called

   const uint32_t cur_pid = OS::get_process_id();

   const bool fork_detected = (m_last_pid > 0) && (cur_pid != m_last_pid);

   if(is_seeded() == false ||
      fork_detected ||
      (m_reseed_interval > 0 && m_reseed_counter >= m_reseed_interval))
      {
      m_reseed_counter = 0;
      m_last_pid = cur_pid;

      if(m_underlying_rng)
         {
         reseed_from_rng(*m_underlying_rng, security_level());
         }

      if(m_entropy_sources)
         {
         reseed(*m_entropy_sources, security_level());
         }

      if(!is_seeded())
         {
         if(fork_detected)
            throw Invalid_State("Detected use of fork but cannot reseed DRBG");
         else
            throw PRNG_Unseeded(name());
         }
      }
   else
      {
      BOTAN_ASSERT(m_reseed_counter != 0, "RNG is seeded");
      m_reseed_counter += 1;
      }
   }

}
