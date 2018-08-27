#include <stdexcept>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "cubic_gadget.cpp"

template<typename ppT>
bool cubic_gadget_test_iteration(libff::bit_vector x_bits) {
    typedef libff::Fr<ppT> FieldT;
    libsnark::protoboard<FieldT> pb;

    // We get the field element corresponding to the bits x_bits
    // And we assign this value to the sol_x protoboard variable
    // which contains the secret value x that is supposed to satisfy x**3 + x + 5 == 35
    libsnark::pb_variable<FieldT> sol_x;
    FieldT sol_x_value = field_element_from_bits(pb, x_bits);
    sol_x.allocate(pb);
    pb.val(sol_x) = sol_x_value;

    // Setup the tested gadget
    cubic_gadget<FieldT> tested_gadget(pb, sol_x);
    tested_gadget.generate_r1cs_constraints();
    tested_gadget.generate_r1cs_witness();

    // No public input: This circuit we built is only working for the statement x**3 + x + 5 == 35
    // Thus all inputs are private, as they represent the witness 
    // (input value and intermediate value of the wires)
    pb.set_input_sizes(0);

    bool is_valid_witness = pb.is_satisfied();
    if(is_valid_witness == false) {
        return false;
    }

    // Generate keypair
    auto keypair = libsnark::r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());

    auto primary_input = pb.primary_input(); // Should be empty, as we do not have public input here
    auto auxiliary_input = pb.auxiliary_input();

    std::cout << "[DEBUG] Primary input: " << primary_input << std::endl;
    std::cout << "[DEBUG] Auxiliary input: " << auxiliary_input << std::endl;

    // Generate the proof
    auto proof = libsnark::r1cs_ppzksnark_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    // Verify the proof
    const bool proof_result = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, primary_input, proof);
    if(proof_result == false){
        return false;
    }

    return true;
}


int run_cubic_gadget_tests() {
    typedef libff::alt_bn128_pp ppT;    
    ppT::init_public_params();
    bool res_test = false;

    std::cout << "[Test: cubic_gadget] Start tests" << std::endl;

    // Bad private input variable: wrong_sol_x_bits does not satisfy the constraints
    // In fact: 4**3 + 4 + 5 = 64 + 4 + 5 = 73 =/= 35 !!
    // SHOULD NOT PASS
    libff::bit_vector wrong_sol_x_bits = {0, 0, 1}; // 4 in binary (little endianness)
    res_test = cubic_gadget_test_iteration<ppT>(wrong_sol_x_bits);
    if (res_test == true) {
        throw std::invalid_argument("The argument is not a valid solution to the equation BUT the test pass");
    }

    // Valid private input variable: good_sol_x_bits satisfies the constraints
    // In fact: 3**3 + 3 + 5 = 27 + 3 + 5 = 35
    // SHOULD PASS
    libff::bit_vector good_sol_x_bits = {1, 1}; // 3 in binary (little endianness)
    res_test = cubic_gadget_test_iteration<ppT>(good_sol_x_bits);
    if (res_test == false) {
        throw std::invalid_argument("The argument is a valid solution to the equation BUT the test does not pass");
    }

    std::cout << "[Test: cubic_gadget] End of tests" << std::endl;

    return 0;
}
