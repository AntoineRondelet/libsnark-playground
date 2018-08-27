#ifndef __UTILS_HPP__
#define __UTILS_HPP__

#include <libsnark/gadgetlib1/gadget.hpp>

template<typename FieldT>
FieldT field_element_from_bits(libsnark::protoboard<FieldT> &pb, libff::bit_vector field_element_bits);

#include "utils.tcc"
#endif