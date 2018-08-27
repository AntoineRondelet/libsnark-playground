#include <stdexcept>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "cubic_gadget/test.cpp"
#include "generic_cubic_gadget/test.cpp"

int main() {
    run_cubic_gadget_tests();
    run_generic_cubic_gadget_tests();

    return 0;
}