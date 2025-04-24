#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <iostream>
#include <fstream>

using namespace std;
using namespace seal;

inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}
template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*                                                                                                                                                                                                                                                        
    We're not going to print every column of the matrix. Instead                                                                                                                                                                            
    we print a few slots from beginning.                                                                                                                                                                                               
    */
    std::size_t print_size = 10;
    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    std::cout << " ]\n";
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    std::cout <<  " ]\n";
    std::cout << std::endl;
}


std::string get_last_word(const std::string& s) {
  auto index = s.find_last_of(' ');
  return s.substr(++index);
}


void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    for (std::size_t i = 0; i < coeff_modulus_size; i++)
      {
	std::cout << coeff_modulus[i].value() << " * ";
      }

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}


int main(void)
{
    
    cout << "FHE Basic operations demonstration" << endl;
    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 8192;
    // We just chose the modulus degree, this is degree of the polynomial has to be a power of 2
    
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(1024);
parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    auto &context_data = *context.key_context_data();
    cout << *(context_data.total_coeff_modulus()) << endl;
    cout << endl;
    cout << "Scheme: BFV" << endl;
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    /*
    When parameters are used to create SEALContext, Microsoft SEAL will first
    validate those parameters. The parameters chosen here are valid.
    */
    cout << "Parameter validation (success): " << context.parameter_error_message() << endl;
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    /* "STEP 1: Key Generation - Black Box" */

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
BatchEncoder batch_encoder(context);
 
    size_t slot_count = batch_encoder.slot_count();
      vector<uint64_t> pod_matrix(slot_count, 0ULL);
      pod_matrix[0] = 1032183ULL;
      vector<uint64_t> pod_matrix2(slot_count, 0ULL);
      pod_matrix2[0] = 15ULL;
      Plaintext p1;
      batch_encoder.encode(pod_matrix,p1);
      Plaintext p2;
      batch_encoder.encode(pod_matrix2,p2);
      Ciphertext c1; 
     encryptor.encrypt(p2, c1);

    Ciphertext c2;
    evaluator.add_plain(c1,p1,c2);
    Plaintext c2_decrypted;
    cout << "Plaintext = " << pod_matrix[0] << endl;
    cout << "Ciphertext = " << pod_matrix2[0] << endl;
    cout << "decryption of Plaintext + Ciphertext = ";
    vector<uint64_t> pod_result;
    decryptor.decrypt(c2, c2_decrypted);
    batch_encoder.decode(c2_decrypted, pod_result);
    cout << pod_result[0] << endl;

}

