/*
 * This gadget aims to prove the knowledge of the root of a polynomial (the polynomial is public)
 * without revealing which root is known.
 * 
 * This gadget can be useful to prove membership of a set.
 * In fact, this gadget can be seen as an extension of the binary constraint implemented in
 * the "basic_gadget" file of libsnark.
 * In this "basic_gadget.tcc", we can see:
 * 
 *  template<typename FieldT>
 *  void generate_boolean_r1cs_constraint(protoboard<FieldT> &pb, const pb_linear_combination<FieldT> &lc, const std::string &annotation_prefix)
 *  // forces lc to take value 0 or 1 by adding constraint lc * (1-lc) = 0
 *  {
 *  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(lc, 1-lc, 0),
 *                        FMT(annotation_prefix, " boolean_r1cs_constraint"));
 *  }
 *
 * In brief, to make sure that an input (i) is a boolean (ie: i ∈ S, with S = {0, 1}) we define the constraint:
 * x * (1 - x) = 0
 * This makes perfect sense, since only 0 or 1 would satisfy this constraint.
 * 
 * This is because 0, and 1 are the only roots of the polynomial defined by:
 * x * (1 - x) = x - x**2
 * 
 * We can carry out the same reasoning to extend the set S to any set, in order to prove that
 * we know an element e, such that e ∈ {root_1, root_2, root_3, ..., root_n}, where root_i define a root
 * of the polynomial we use.
 * 
 * Note: The size of the set S is equal to the degree of the polynomial we use.
 * 
 * Thus, by having the roots has the public input, a user can prove to th verifier that the value V
 * he used to compute the proof, is in the set S of roots of the public polynomial, WITHOUT revealing
 * to which root V actually corresponds.
 * 
 * For a set of public inputs (roots) R1, R2, R3, we have the following statement we want to prove:
 * (R1 - x) * (R2 - x) * (R3 - x) = 0
 * which results in the corresponding set of constraints:
 * x1 = R1 - x0
 * x2 = R2 - x0
 * x3 = R3 - x0
 * x4 = x1 * x2
 * x5 = x4 * x3
 * x6 = 0
 **/