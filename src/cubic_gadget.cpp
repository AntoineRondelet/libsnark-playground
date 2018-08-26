// Prove that we know the solution to the equation x**3 + x + 5 == 35 (answer is 3)

// The complete R1CS

/*
From Vitalik's medium post
- Problem: we want to prove that we know the solution of the cubic equation: x**3+x+5 == 35

We state the problem in the form of a program, that we then flatten and transform into an arithmetic circuit and R1CS
We obtain a variable vector X = {x_0, x_1, x_2, x_3, x_4}, where x_0 = "dummy variable one", and x_4 = "dummy variable out"

We have a circuit with 4 gates, thus we have 4 constraints to satisfy. The R1CS contains 4 constraints in the form:
s.a * s.b - s.c = 0 that need to be satisfied.

sym_1 = x * x    ==> x1 = x0 * x0
y = sym_1 * x    ==> x2 = x1 * x0
sym_2 = y + x    ==> x3 = x2 + x0
~out = sym_2 + 5 ==> x4 = x3 + 5

 * A R1CS constraint is a formal expression of the form
 *
 *                < A , X > * < B , X > = < C , X > ,
 *
 * where X = (x_0,x_1,...,x_m) is a vector of formal variables and A,B,C each
 * consist of 1+m elements in <FieldT>.
 *
 * A R1CS constraint is used to construct a R1CS constraint system.


A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}"
Thus a linear combination is something like: c_1 * x_1 + c_2 * x_2 + ... + c_n * x_n

A r1cs_constraint takes 3 linear combinations a, b, and c:
```
    r1cs_constraint(const linear_combination<FieldT> &a, // A linear combination is the result of a dot product
                    const linear_combination<FieldT> &b,
                    const linear_combination<FieldT> &c
    );
```
Thus, we can see that each args of the r1cs_constraint is encoding one of the dot product:
    - The &a represents the dot product < A , X >
    - The &b represents the dot product < B , X >
    - The &c represents the dot product < C , X >

We obtain the following R1C for the gate1 (x2 = x1 * x1)
X: (x0, x1, x2, x3, x4) --> size 5 because ONE is not included
A: [0, 1, 0, 0, 0, 0]   --> size 6 because the first term refers to the ONE variable
B: [0, 1, 0, 0, 0, 0]   --> size 6 because the first term refers to the ONE variable
C: [0, 0, 1, 0, 0, 0]   --> size 6 because the first term refers to the ONE variable

Verification of the equality for the R1C:
< A , X > * < B , X > = dot_product([0, 1, 0, 0, 0, 0], [ONE, X]) = x0 * x0
< C , X > = x1

Thus < A , X > * < B , X > = < C , X > ==> x0 * x0 = x1 which corresponds to the first flattened gate
Thus, the first constraint of the libsnark::protoboard will be:

r1cs_constraint<FieldT> firstGate = r1cs_constraint<FieldT>(
                    < A , X >,
                    < B , X >,
                    < C , X >)

which gives:

r1cs_constraint<FieldT> firstGate = r1cs_constraint<FieldT>(
                    x0,
                    x0,
                    x1)

This first constraint is then added to the libsnark::protoboard (to the R1CS basically)

pb.add_r1cs_constraint(firstGate);

We follow the same approach for the other gates, and we add the corresponding constraints to the R1C system (libsnark::protoboard).
This results in the generate_r1cs_constraints() function.

A call to the function pb.num_constraints() should return 4 in our case (because the circuit has 4 gates)
(see the number of calls to pb.add_r1cs_constraint() in the implementation of the generate_r1cs_constraints() function)

**NOTE:** If we were to create a gadget X that uses the cubic_gadget, we'd do cubic_gadget->generate_r1cs_constraints()
in the generate_r1cs_constraints() function of the gadget X, and then define the constraints proper to X.
In fact, the generate_r1cs_constraints() function is basically the encoding of the circuit for a given problem.
Thus, we can use it as a "black box" in future uses. If the given problem does not change, then the circuit 
remains the same, and we can just use it as it is.

The witness for this R1CS is: [1, 3, 35, 9, 27, 30]
It is the assignment to all the variables, including input, output and internal variables.

- Gadget constructor: Basically in the gadget constructor, we allocate the variables on the libsnark::protoboard
- In the generate_r1cs_constraints() function, we generate the constraints using the variables allocated on the libsnark::protoboard
- In the generate_witness() we generate a witness given an input (this witness has to respect the constraints defined in the generate_r1cs_constraints() function)

Partial assignment of the variable vector:
[1, S_0, S_1, S_2, S_3, 35], where the S means that the value is secret
The full assignment of the variable vector is:
[1, 3, 9, 27, 30, 35]. This is the witness (the S_i are basically revealed and satisfy the circuit)


Circuits/R1CS: Each gate is a mathematical constraint and each wire is a variable
*/

#include <libsnark/gadgetlib1/gadget.hpp>

template<typename FieldT>
class cubic_gadget : public libsnark::gadget<FieldT> {
public:
    //static std::vector<FieldT> polynomial_coefficients; 
    // For now we do a gadget that works only for the polynomial x**3 + x + 5 == 35
    // After that we can imagine expanding the code to make it work for all types of equations:
    // k.x**3 + l.x**2 + m.x + n = p, where k,m,l,n and p are field elements/binary coefficients
    // And the gadget can be used to prove that we know a solution to the equation
    //static FieldT polynomial_degree; // Degree of the polynomial (3 here)
    //static FieldT right_term; // 35 here, the term on the right of the equation we build the snark for
    //const libsnark::pb_variable<FieldT> &sol_x; // Secret solution (x = 3) to the equation: x**3 + x + 5 == 35
    libsnark::protoboard<FieldT> &pb;
    const std::string annotation_prefix="";
    libsnark::pb_variable_array<FieldT> vars; // All variables that are allocated on the libsnark::protoboard (this is the vector X = [x0, x1, x2, x3, x4])
    libsnark::pb_variable<FieldT> final_coeff;
    libsnark::pb_variable<FieldT> result;
    const libsnark::pb_variable<FieldT> &sol_x; // Input variable
    cubic_gadget(
        libsnark::protoboard<FieldT> &in_pb,
        const libsnark::pb_variable<FieldT> &in_sol_x, // in_sol_x represents the only input variable (x_0)
        const std::string &in_annotation_prefix=""
    ):
        libsnark::gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " cubic_equation")),
        pb(in_pb),
        sol_x(in_sol_x),
        vars(),
        annotation_prefix(in_annotation_prefix)
    {
        // Define constructor here:
        // Aims to allocate the variables on the libsnark::protoboard
        vars.allocate(pb, 5, FMT(this->annotation_prefix, " vars")); // 5 because size(X) = 5 (5 variables)

        // Value of 5 (coeff C)
        libsnark::pb_variable_array<FieldT> final_coeff_bits;
        libff::bit_vector coeff_bits = {1, 0, 1}; // 5: BE CAREFUL with the endianness !!!
        final_coeff_bits.allocate(pb, coeff_bits.size(), "final_coeff_bits");
        final_coeff_bits.fill_with_bits(pb, coeff_bits);
        auto coeff_value = final_coeff_bits.get_field_element_from_bits(pb);
        final_coeff.allocate(pb);
        pb.val(final_coeff) = coeff_value;

        // Value of 35 (result)
        libsnark::pb_variable_array<FieldT> result_bits;
        libff::bit_vector res_bits = {1, 1, 0, 0, 0, 1}; // 35: BE CAREFUL with the endianness !!!
        result_bits.allocate(pb, res_bits.size(), "result_bits");
        result_bits.fill_with_bits(pb, res_bits);
        auto res_value = result_bits.get_field_element_from_bits(pb);
        result.allocate(pb);
        pb.val(result) = res_value;
    }

    // Creates all constraints on the libsnark::protoboard
    void generate_r1cs_constraints() {
        //x0 * x0 = x1
        libsnark::r1cs_constraint<FieldT> constraint1 = libsnark::r1cs_constraint<FieldT>(
            vars[0],
            vars[0],
            vars[1]
        );

        //x1 * x0 = x2
        libsnark::r1cs_constraint<FieldT> constraint2 = libsnark::r1cs_constraint<FieldT>(
            vars[1],
            vars[0],
            vars[2]
        );

        //x3 * 1 = x2 + x0
        libsnark::r1cs_constraint<FieldT> constraint3 = libsnark::r1cs_constraint<FieldT>(
            vars[3],
            FieldT::one(),
            vars[2] + vars[0]
        );

        //x4 * 1 = x3 + 5
        libsnark::r1cs_constraint<FieldT> constraint4 = libsnark::r1cs_constraint<FieldT>(
            vars[4],
            FieldT::one(),
            vars[3] + pb.val(final_coeff)
        );

        //x4 * 1 = 35 (constraint on the value of the output)
        libsnark::r1cs_constraint<FieldT> constraint5 = libsnark::r1cs_constraint<FieldT>(
            vars[4],
            FieldT::one(),
            pb.val(result)
        );

        pb.add_r1cs_constraint(constraint1);
        pb.add_r1cs_constraint(constraint2);
        pb.add_r1cs_constraint(constraint3);
        pb.add_r1cs_constraint(constraint4);
        pb.add_r1cs_constraint(constraint5);
    }

    void generate_r1cs_witness() {
        pb.val(vars[0]) = pb.val(sol_x); // Input variable

        // Generate an assignment for all non-input variables (internal wires)
        pb.val(vars[1]) = pb.val(vars[0]) * pb.val(vars[0]);
        pb.val(vars[2]) = pb.val(vars[1]) * pb.val(vars[0]);
        pb.val(vars[3]) = pb.val(vars[2]) + pb.val(vars[0]);
        pb.val(vars[4]) = pb.val(vars[3]) + pb.val(final_coeff);
    }
};