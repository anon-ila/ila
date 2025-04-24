// This example demonstrates functinoality of mod switching.
// We take a random plaintext, encrypt it and then compute 8th power of this encrypted ciphertext
// witout modulus switching first and with modulus switching after.
// Without modulus switching the muplicative depth exhausts after comuting 6th power
// With modulus switching we can see that we can compute 8th power.
// Note: Only 2 modulus switching operations are necessary third one is added inorder to gain more noise
// so the this program type checks in ila.

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

inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}

int main(void)
{
    
    cout << "FHE Basic operations demonstration" << endl;
    EncryptionParameters parms(scheme_type::bgv);

    size_t poly_modulus_degree = 32768;
    // We just chose the modulus degree, this is degree of the polynomial has to be a power of 2
    
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // parms.set_plain_modulus(1024);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 50, 50, 55, 60,60 }));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    /*
    When parameters are used to create SEALContext, Microsoft SEAL will first
    validate those parameters. The parameters chosen here are valid.
    */
    cout << "Parameter validation (success): " << context.parameter_error_message() << endl;
    cout << endl;
    auto context_data = context.key_context_data();
    cout << "----> Level (chain index): " << context_data->chain_index();
    cout << " ...... key_context_data()" << endl;
    cout << "      parms_id: " << context_data->parms_id() << endl;
    cout << "      coeff_modulus primes: ";
    cout << hex;
    for (const auto &prime : context_data->parms().coeff_modulus())
    {
        cout << prime.value() << " ";
    }
    cout << dec << endl;
    cout << "\\" << endl;
    cout << " \\-->";
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
    Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4");
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    Ciphertext encry_le;
    encry_le = encrypted;
    
    cout << "    + plain:       " << plain.parms_id()  << endl;
    cout << "    + encrypted:   " << encrypted.parms_id() << endl << endl;
         print_line(__LINE__);
    cout << "Perform modulus switching on encrypted and print." << endl;
    context_data = context.first_context_data();
    cout << "---->";
    while (context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index() << endl;
        cout << "      parms_id of encrypted: " << encrypted.parms_id() << endl;
        cout << "      Noise budget at this level: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
        cout << "\\" << endl;
        cout << " \\-->";
        evaluator.mod_switch_to_next_inplace(encrypted);
        context_data = context_data->next_context_data();
    }

    cout << " Level (chain index): " << context_data->chain_index() << endl;
    cout << "      parms_id of encrypted: " << encrypted.parms_id() << endl;
    cout << "      Noise budget at this level: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "\\" << endl;
    cout << " \\-->";
    cout << " End of chain reached" << endl << endl;
    
    print_line(__LINE__);
    cout << "With modulus switching." << endl;
    
    cout << "Computation is more efficient with modulus switching." << endl;
    print_line(__LINE__);
    cout << "Compute the 10th power." << endl;
    encryptor.encrypt(plain, encrypted);
    cout << "    + Noise budget fresh:                   " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 2nd power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "    + Noise budget after modulus switching::         " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 4th power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;

    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "    + Noise budget after modulus switching:  " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 8th power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "    + Noise budget after modulus switching:  " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 10th power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "    + Noise budget after modulus switching:  " << decryptor.invariant_noise_budget(encrypted) << " bits"
         << endl;
    
}

