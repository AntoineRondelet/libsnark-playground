template<typename FieldT>
FieldT field_element_from_bits(libsnark::protoboard<FieldT> &pb, libff::bit_vector field_element_bits) {
    libsnark::pb_variable_array<FieldT> array_bits;
    array_bits.allocate(pb, field_element_bits.size(), "field_element_bits");
    array_bits.fill_with_bits(pb, field_element_bits);
    auto field_value = array_bits.get_field_element_from_bits(pb);
    return field_value;
}
