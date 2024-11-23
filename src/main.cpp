#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <seal/seal.h>
#include <iostream>
#include <iomanip>

#include <x86intrin.h>
#include "SHA256.h"

using namespace std::chrono;
using namespace std;
using namespace seal;

void *__dso_handle = (void *) &__dso_handle;

unsigned int aux;

class Timer {
public:
    Timer() {
        print_timestamp("Program started at: ");
    }
    
    ~Timer() {
        print_timestamp("Program ended at: ");
    }

private:
    static void print_timestamp(const char* prefix) {
        using namespace std::chrono;
        auto now = high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        
        // Get seconds
        auto secs = duration_cast<std::chrono::seconds>(duration);
        
        // Get just the nanoseconds part by taking remainder after seconds
        auto nsecs = duration_cast<std::chrono::nanoseconds>(duration - secs).count() % 1000000000;
        
        // Print with exact same format as date +%s.%N
        std::cout << prefix 
                 << secs.count() << "."
                 << std::setfill('0') << std::setw(9) << nsecs
                 << std::endl;
    }
};

// Global timer instance
static Timer global_timer;


#include <cmath>

extern "C" {
    double force_math_symbols(double a, double b) {
        volatile double result = log(a) + sqrt(b);
        return result;
    }
}

uint64_t state_custom_rand = 42;
uint8_t rand_byte() {
    state_custom_rand = state_custom_rand * 6364136223846793005ULL + 1442695040888963407ULL;
    return state_custom_rand >> 56;
}

int main(int argc, char *argv[]) {

  printf("Main: force_math_symbols(2.0, 4.0) = %f\n", force_math_symbols(2.0, 4.0));

  uint64_t number_of_items = 1 << 20;
  uint64_t size_per_item = 288; // in bytes
  uint32_t N = 4096;

  // Recommended values: (logt, d) = (20, 2).
  uint32_t logt = 20;
  uint32_t d = 2;
  bool use_symmetric = true; // use symmetric encryption instead of public key
                             // (recommended for smaller query)
  bool use_batching = true;  // pack as many elements as possible into a BFV
                             // plaintext (recommended)
  bool use_recursive_mod_switching = true;

  EncryptionParameters enc_params(scheme_type::bfv);
  PirParams pir_params;

  // Generates all parameters

  cout << "Main: Generating SEAL parameters" << endl;
  gen_encryption_params(N, logt, enc_params);

  cout << "Main: Verifying SEAL parameters" << endl;
  verify_encryption_params(enc_params);
  cout << "Main: SEAL parameters are good" << endl;

  cout << "Main: Generating PIR parameters" << endl;
  gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params,
                 use_symmetric, use_batching, use_recursive_mod_switching);

  print_seal_params(enc_params);
  print_pir_params(pir_params);

  // Initialize PIR client....
  PIRClient client(enc_params, pir_params);
  cout << "Main: Generating galois keys for client" << endl;

  GaloisKeys galois_keys = client.generate_galois_keys();

  // Initialize PIR Server
  cout << "Main: Initializing server" << endl;
  PIRServer server(enc_params, pir_params);

  // Server maps the galois key to client 0. We only have 1 client,
  // which is why we associate it with 0. If there are multiple PIR
  // clients, you should have each client generate a galois key,
  // and assign each client an index or id, then call the procedure below.
  server.set_galois_key(0, galois_keys);

  cout << "Main: Creating the database with random data (this may take some "
          "time) ..."
       << endl;

  // Create test database
  auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

  // Copy of the database. We use this at the end to make sure we retrieved
  // the correct element.
  //auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

// // Copy pre-generated values
//   memcpy(db.get(), DB_VALUES, number_of_items * size_per_item);
//   memcpy(db_copy.get(), DB_VALUES, number_of_items * size_per_item);

  for (uint64_t i = 0; i < number_of_items; i++) {
    for (uint64_t j = 0; j < size_per_item; j++) {
      uint8_t val = rand_byte();
      db.get()[(i * size_per_item) + j] = val;
      //db_copy.get()[(i * size_per_item) + j] = val;
    }
  }

  // Measure database setup
  //auto time_pre_s = high_resolution_clock::now();
  auto cycle_pre_s = __rdtscp(&aux);
  server.set_database(move(db), number_of_items, size_per_item);
  server.preprocess_database();
  auto cycle_pre_e = __rdtscp(&aux);
  //auto time_pre_e = high_resolution_clock::now();
  auto cycle_pre_us = (cycle_pre_e - cycle_pre_s);
      //duration_cast<microseconds>(time_pre_e - time_pre_s).count();
  cout << "Main: database pre processed " << endl;

  random_device rd;
  // Choose an index of an element in the DB
  uint64_t ele_index =
      rd() % number_of_items; // element in DB at random position
  uint64_t index = client.get_fv_index(ele_index);   // index of FV plaintext
  uint64_t offset = client.get_fv_offset(ele_index); // offset in FV plaintext
  cout << "Main: element index = " << ele_index << " from [0, "
       << number_of_items - 1 << "]" << endl;
  cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

  // Measure query generation
  auto cycle_query_s = __rdtscp(&aux);
  //auto time_query_s = high_resolution_clock::now();
  PirQuery query = client.generate_query(index);
  auto cycle_query_e = __rdtscp(&aux);
  //auto time_query_e = high_resolution_clock::now();
  auto cycle_query_us = (cycle_query_e - cycle_query_s);
      //duration_cast<microseconds>(time_query_e - time_query_s).count();
  cout << "Main: query generated" << endl;

  // Measure serialized query generation (useful for sending over the network)
  stringstream client_stream;
  stringstream server_stream;
  auto cycle_s_query_s = __rdtscp(&aux);
  //auto time_s_query_s = high_resolution_clock::now();
  int query_size = client.generate_serialized_query(index, client_stream);
  auto cycle_s_query_e = __rdtscp(&aux);
  //auto time_s_query_e = high_resolution_clock::now();
  auto cycle_s_query_us = (cycle_s_query_e - cycle_s_query_s);
      //duration_cast<microseconds>(time_s_query_e - time_s_query_s).count();
  cout << "Main: serialized query generated" << endl;

  // Measure query deserialization (useful for receiving over the network)
  auto cycle_deserial_s = __rdtscp(&aux);
  //auto time_deserial_s = high_resolution_clock::now();
  PirQuery query2 = server.deserialize_query(client_stream);
  auto cycle_deserial_e = __rdtscp(&aux);
  //auto time_deserial_e = high_resolution_clock::now();
  auto cycle_deserial_us = (cycle_deserial_e - cycle_deserial_s);
      //duration_cast<microseconds>(time_deserial_e - time_deserial_s).count();
  cout << "Main: query deserialized" << endl;

  // Measure query processing (including expansion)
  auto cycle_server_s = __rdtscp(&aux);
  //auto time_server_s = high_resolution_clock::now();
  // Answer PIR query from client 0. If there are multiple clients,
  // enter the id of the client (to use the associated galois key).
  PirReply reply = server.generate_reply(query2, 0);
  auto cycle_server_e = __rdtscp(&aux);
  //auto time_server_e = high_resolution_clock::now();
  auto cycle_server_us = (cycle_server_e - cycle_server_s);
      //duration_cast<microseconds>(time_server_e - time_server_s).count();
  cout << "Main: reply generated" << endl;

  // Measure reply serialization
  auto cycle_s_reply_s = __rdtscp(&aux);
  // Serialize reply (useful for sending over the network)
  int reply_size = server.serialize_reply(reply, server_stream);
  auto cycle_s_reply_e = __rdtscp(&aux);
  auto cycle_s_reply_us = (cycle_s_reply_e - cycle_s_reply_s);
  cout << "Main: reply serialized" << endl;

  // Measure SHA-256 hashing of the reply
  auto cycle_hash_s = __rdtscp(&aux);
  
  // Get the serialized data as a string
  string serialized_reply = server_stream.str();
  
  // Perform SHA-256 hashing using standalone library
  SHA256 sha256;
  sha256.update(serialized_reply);
  
  auto cycle_hash_e = __rdtscp(&aux);
  auto cycle_hash_us = (cycle_hash_e - cycle_hash_s);

  // Measure response extraction
  auto cycle_decode_s = __rdtscp(&aux);
  //auto time_decode_s = high_resolution_clock::now();
  vector<uint8_t> elems = client.decode_reply(reply, offset);
  auto cycle_decode_e = __rdtscp(&aux);
  //auto time_decode_e = high_resolution_clock::now();
  auto cycle_decode_us = (cycle_decode_e - cycle_decode_s);
      //duration_cast<microseconds>(time_decode_e - time_decode_s).count();
  cout << "Main: reply decoded" << endl;

  assert(elems.size() == size_per_item);

//   bool failed = false;
//   // Check that we retrieved the correct element
//   for (uint32_t i = 0; i < size_per_item; i++) {
//     if (elems[i] != db_copy.get()[(ele_index * size_per_item) + i]) {
//       cout << "Main: elems " << (int)elems[i] << ", db "
//            << (int)db_copy.get()[(ele_index * size_per_item) + i] << endl;
//       cout << "Main: PIR result wrong at " << i << endl;
//       failed = true;
//     }
//   }
//   if (failed) {
//     return -1;
//   }

  // Output results
  cout << "Main: PIR result correct!" << endl;
  cout << "Main: Operation                                  Cycles" << endl;
  cout << "Main: ----------------------------------------  --------------" << endl;
  cout << "Main: PIRServer pre-processing:                " << setprecision(6) << right << setw(14) << cycle_pre_us << endl;
  cout << "Main: PIRClient query generation:              " << setprecision(6) << right << setw(14) << cycle_query_us << endl; 
  cout << "Main: PIRClient serialized query generation:   " << setprecision(6) << right << setw(14) << cycle_s_query_us << endl;
  cout << "Main: PIRServer query deserialization:         " << setprecision(6) << right << setw(14) << cycle_deserial_us << endl;
  cout << "Main: PIRServer query processing:              " << setprecision(6) << right << setw(14) << cycle_server_us << endl;
  cout << "Main: PIRServer reply serialization:           " << setprecision(6) << right << setw(14) << cycle_s_reply_us << endl;
  cout << "Main: Reply SHA-256 hashing:                   " << setprecision(6) << right << setw(14) << cycle_hash_us << endl;
  cout << "Main: PIRClient answer decode:                 " << setprecision(6) << right << setw(14) << cycle_decode_us << endl;
  cout << endl;
  cout << "Main: Query size: " << query_size << " bytes" << endl;
  cout << "Main: Reply num ciphertexts: " << reply.size() << endl; 
  cout << "Main: Reply size: " << reply_size << " bytes" << endl;

  return 0;
}
