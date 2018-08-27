#include <stdexcept>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "generic_cubic_gadget.cpp"

template<typename ppT>
bool generic_cubic_gadget_test_iteration(
        libff::bit_vector coeff_A,
        libff::bit_vector coeff_B,
        libff::bit_vector coeff_C,
        libff::bit_vector coeff_D,
        libff::bit_vector coeff_E,
        libff::bit_vector x_bits
){
    typedef libff::Fr<ppT> FieldT;
    libsnark::protoboard<FieldT> pb;

    // First of all we need to allocate the primary input (public)
    // on the protoboard, because, the protoboard stores variables like:
    // |P_I_1|P_I_2|P_I_3||A_I_1|A_I_2|
    //                    ^
    //                    |_ where this position (separation between primary and auxiliary input)
    //                       is given by N in the function pb.set_input_sizes(N);
    const std::vector<FieldT> field_coefficients = {
        field_element_from_bits(pb, coeff_A), 
        field_element_from_bits(pb, coeff_B),
        field_element_from_bits(pb, coeff_C), 
        field_element_from_bits(pb, coeff_D),
        field_element_from_bits(pb, coeff_E)
    };
    libsnark::pb_variable_array<FieldT> coefficients;    
    coefficients.allocate(pb, field_coefficients.size());
    coefficients.fill_with_field_elements(pb, field_coefficients);

    // Now we can allocate the auxiliary input to the protoboard
    libsnark::pb_variable<FieldT> sol_x;
    FieldT sol_x_value = field_element_from_bits(pb, x_bits);
    sol_x.allocate(pb);
    pb.val(sol_x) = sol_x_value;

    // Now we specify the primary and auxiliary inputs
    // Primary input: field_coefficients
    // Auxiliary input: sol_x
    pb.set_input_sizes(field_coefficients.size());

    // Setup the tested gadget
    generic_cubic_gadget<FieldT> tested_gadget(pb, coefficients, sol_x);
    tested_gadget.generate_r1cs_constraints();
    tested_gadget.generate_r1cs_witness();

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

int run_generic_cubic_gadget_tests() {
    typedef libff::alt_bn128_pp ppT;    
    ppT::init_public_params();
    bool res_test = false;

    std::cout << "[Test: generic_cubic_gadget] Start tests" << std::endl;

    // We encode the statement: x**3 + x + 5 = 35
    // with sol_x = 3
    // This test SHOULD PASS
    libff::bit_vector coeff_A_bits = {1};
    libff::bit_vector coeff_B_bits = {0};
    libff::bit_vector coeff_C_bits = {1};
    libff::bit_vector coeff_D_bits = {1, 0, 1};
    libff::bit_vector coeff_E_bits = {1, 1, 0, 0, 0, 1};
    libff::bit_vector sol_x_bits = {1, 1};
    res_test = generic_cubic_gadget_test_iteration<ppT>(
        coeff_A_bits,
        coeff_B_bits,
        coeff_C_bits,
        coeff_D_bits,
        coeff_E_bits,
        sol_x_bits
    );
    if (res_test == false) {
        throw std::invalid_argument("The argument a valid solution to the equation BUT the test does not pass");
    }

    // We encode the statement: 4*x**3 + 2*x + 7 = 2071
    // with sol_x = 8
    // This test SHOULD PASS
    coeff_A_bits = {0, 0, 1};
    coeff_B_bits = {0};
    coeff_C_bits = {0, 1};
    coeff_D_bits = {1, 1, 1};
    coeff_E_bits = {1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1};
    sol_x_bits = {0, 0, 0, 1};
    res_test = generic_cubic_gadget_test_iteration<ppT>(
        coeff_A_bits,
        coeff_B_bits,
        coeff_C_bits,
        coeff_D_bits,
        coeff_E_bits,
        sol_x_bits
    );
    if (res_test == false) {
        throw std::invalid_argument("The argument a valid solution to the equation BUT the test does not pass");
    }

    // We encode the statement: 4*x**3 + 2*x + 7 = 2071
    // with sol_x = 16
    // This test SHOULD NOT PASS
    coeff_A_bits = {0, 0, 1};
    coeff_B_bits = {0};
    coeff_C_bits = {0, 1};
    coeff_D_bits = {1, 1, 1};
    coeff_E_bits = {1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1};
    sol_x_bits = {0, 0, 0, 0, 1};
    res_test = generic_cubic_gadget_test_iteration<ppT>(
        coeff_A_bits,
        coeff_B_bits,
        coeff_C_bits,
        coeff_D_bits,
        coeff_E_bits,
        sol_x_bits
    );
    if (res_test == true) {
        throw std::invalid_argument("The argument is not a valid solution to the equation BUT the test pass");
    }

    std::cout << "[Test: generic_cubic_gadget] End of tests" << std::endl;
    std::cout << "[Test: generic_cubic_gadget] All tests PASSED" << std::endl;

    return 0;
}
