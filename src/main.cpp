
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "cubic_gadget.cpp"

template<typename ppT>
bool cubic_gadget_test(libff::bit_vector x_bits) {
    std::cout << "[DEBUG] 1" << std::endl;
    typedef libff::Fr<ppT> FieldT;
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable_array<FieldT> sol_bits;
    sol_bits.allocate(pb, x_bits.size(), "sol_bits");
    sol_bits.fill_with_bits(pb, x_bits);
    auto sol_x_value = sol_bits.get_field_element_from_bits(pb);
    std::cout << "[DEBUG] sol_x_value: " << sol_x_value << std::endl;
    libsnark::pb_variable<FieldT> sol_x;
    sol_x.allocate(pb);
    pb.val(sol_x) = sol_x_value;

    // Setup the tested gadget
    std::cout << "[DEBUG] 2" << std::endl;
    cubic_gadget<FieldT> tested_gadget(pb, sol_x);
    tested_gadget.generate_r1cs_constraints();
    tested_gadget.generate_r1cs_witness();
    pb.set_input_sizes(0); // Only no public input (this circuit is built for this specific equation)

    std::cout << "[DEBUG] 3" << std::endl;
    bool is_valid_witness = pb.is_satisfied();
    if(is_valid_witness == false) {
        return false;
    }

    //auto keypair = r1cs_ppzksnark_generator<ppT>(constraints)
    // Generate keypair
    std::cout << "[DEBUG] 4" << std::endl;
    auto keypair = libsnark::r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());

    auto primary_input = pb.primary_input(); // Should be empty
    auto auxiliary_input = pb.auxiliary_input();
    std::cout << "[DEBUG] Primary input: " << primary_input << std::endl;
    std::cout << "[DEBUG] Auxiliary input: " << auxiliary_input << std::endl;

    // Generate the proof
    std::cout << "[DEBUG] 5" << std::endl;
    auto proof = libsnark::r1cs_ppzksnark_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    // Verify the proof
    std::cout << "[DEBUG] 6" << std::endl;
    const bool proof_result = libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, primary_input, proof);
    if(proof_result == false){
        return false;
    }

    std::cout << "[DEBUG] 7" << std::endl;

    return true;
}


int main() {
    typedef libff::alt_bn128_pp ppT;    
    ppT::init_public_params();
    bool res_test = false;

    std::cout << "Start tests...\n";

    // Bad Private input variable
    libff::bit_vector wrong_sol_x_bits = {0, 0, 1}; // 4
    res_test = cubic_gadget_test<ppT>(wrong_sol_x_bits);
    assert(res_test == false);
    std::cout << "Value of res_test: " << res_test << std::endl;

    // Valid Private input variable
    libff::bit_vector good_sol_x_bits = {1, 1}; // 3
    res_test = cubic_gadget_test<ppT>(good_sol_x_bits);
    assert(res_test == true);
    std::cout << "Value of res_test: " << res_test << std::endl;

    std::cout << "End of tests\n";

    return 0;
}