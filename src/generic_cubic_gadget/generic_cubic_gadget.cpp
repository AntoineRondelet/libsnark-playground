/*
 * While the "cubic_gadget" aims to provide a circuit for the statement:
 * (E) x**3 + x + 5 = 35
 * This gadget ("generic_cubic_gagdet") is more generic, and provides a circuit for the statement:
 * (E') A*x**3 + B*x**2 + C*x + D = E
 * where, A, B, C, D, and E are fields elements of the field we are working on (FieldT)
 * 
 * As a consequence, to use this gadget, one has to provide the coefficients:
 * A, B, C, D, and E as public input (primary input)
 * The sol_x being the secret solution that is used to generate a valid witness 
 * will still remain as a private input (auxiliary input).
 * 
 * The set of constraints encoding (E') becomes:
 * x1 = A * x0
 * x2 = x1 * x0
 * x3 = x2 * x0
 * x4 = B * x0
 * x5 = x4 * x0
 * x6 = C * x0
 * x7 = x6 + D
 * x8 = x5 + x3
 * x9 = x8 + x7
 * x9 = E
 * 
 **/ 

#include <libsnark/gadgetlib1/gadget.hpp>
#include "utils.hpp"

/*
 * This gadget is made to prove the knowledge of x such that: 
 * A*x**3 + B*x**2 + C*x + D = E, where A, B, C, D, and E are given as primary input
 **/
template<typename FieldT>
class generic_cubic_gadget : public libsnark::gadget<FieldT> {
public:
    libsnark::protoboard<FieldT> &pb;
    const std::string annotation_prefix="";

    // Solution x that satisfies: (E') A*x**3 + B*x**2 + C*x + D = E (auxiliary input)
    const libsnark::pb_variable<FieldT> &sol_x;

    // Array that contains the values of the coefficients of the polynomial (along with E)
    const libsnark::pb_variable_array<FieldT> &coefficients;

    // X = [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9] variables allocated on the protoboard
    libsnark::pb_variable_array<FieldT> vars;
    generic_cubic_gadget(
        libsnark::protoboard<FieldT> &in_pb,
        const libsnark::pb_variable_array<FieldT> &in_coefficients,
        const libsnark::pb_variable<FieldT> &in_sol_x,
        const std::string &in_annotation_prefix=""
    ):
        libsnark::gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " generic_cubic_equation")),
        pb(in_pb),
        sol_x(in_sol_x),
        coefficients(in_coefficients),
        vars(),
        annotation_prefix(in_annotation_prefix)
    {
        vars.allocate(pb, 10, FMT(this->annotation_prefix, " vars")); // size(X) = 10 (10 variables)
    }

    // Creates all constraints on the libsnark::protoboard
    void generate_r1cs_constraints() {
        // A * x0 = x1
        libsnark::r1cs_constraint<FieldT> constraint1 = libsnark::r1cs_constraint<FieldT>(
            coefficients[0],
            vars[0],
            vars[1]
        );

        // x1 * x0 = x2
        libsnark::r1cs_constraint<FieldT> constraint2 = libsnark::r1cs_constraint<FieldT>(
            vars[1],
            vars[0],
            vars[2]
        );

        // x2 * x0 = x3
        libsnark::r1cs_constraint<FieldT> constraint3 = libsnark::r1cs_constraint<FieldT>(
            vars[2],
            vars[0],
            vars[3]
        );

        // B * x0 = x4
        libsnark::r1cs_constraint<FieldT> constraint4 = libsnark::r1cs_constraint<FieldT>(
            coefficients[1],
            vars[0],
            vars[4]
        );
        
        // x4 * x0 = x5
        libsnark::r1cs_constraint<FieldT> constraint5 = libsnark::r1cs_constraint<FieldT>(
            vars[4],
            vars[0],
            vars[5]
        );

        // C * x0 = x6
        libsnark::r1cs_constraint<FieldT> constraint6 = libsnark::r1cs_constraint<FieldT>(
            coefficients[2],
            vars[0],
            vars[6]
        );

        // x6 + D = x7
        libsnark::r1cs_constraint<FieldT> constraint7 = libsnark::r1cs_constraint<FieldT>(
            vars[6] + coefficients[3],
            FieldT::one(),
            vars[7]
        );

        // x5 + x3 = x8
        libsnark::r1cs_constraint<FieldT> constraint8 = libsnark::r1cs_constraint<FieldT>(
            vars[5] + vars[3],
            FieldT::one(),
            vars[8]
        );

        // x8 + x7 = x9
        libsnark::r1cs_constraint<FieldT> constraint9 = libsnark::r1cs_constraint<FieldT>(
            vars[8] + vars[7],
            FieldT::one(),
            vars[9]
        );

        // E = x9 (constraint on the value of the output)
        libsnark::r1cs_constraint<FieldT> constraint10 = libsnark::r1cs_constraint<FieldT>(
            vars[9],
            FieldT::one(),
            coefficients[4]
        );

        pb.add_r1cs_constraint(constraint1);
        pb.add_r1cs_constraint(constraint2);
        pb.add_r1cs_constraint(constraint3);
        pb.add_r1cs_constraint(constraint4);
        pb.add_r1cs_constraint(constraint5);
        pb.add_r1cs_constraint(constraint6);
        pb.add_r1cs_constraint(constraint7);
        pb.add_r1cs_constraint(constraint8);
        pb.add_r1cs_constraint(constraint9);
        pb.add_r1cs_constraint(constraint10);
    }

    void generate_r1cs_witness() {
        pb.val(vars[0]) = pb.val(sol_x); // Input variable

        // Generate an assignment for all non-input variables 
        // (internal wires of the circuit)
        pb.val(vars[1]) = pb.val(coefficients[0]) * pb.val(vars[0]);
        pb.val(vars[2]) = pb.val(vars[1]) * pb.val(vars[0]);
        pb.val(vars[3]) = pb.val(vars[2]) * pb.val(vars[0]);
        pb.val(vars[4]) = pb.val(coefficients[1]) * pb.val(vars[0]);
        pb.val(vars[5]) = pb.val(vars[4]) * pb.val(vars[0]);
        pb.val(vars[6]) = pb.val(coefficients[2]) * pb.val(vars[0]);
        pb.val(vars[7]) = pb.val(vars[6]) + pb.val(coefficients[3]);
        pb.val(vars[8]) = pb.val(vars[5]) + pb.val(vars[3]);
        pb.val(vars[9]) = pb.val(vars[8]) + pb.val(vars[7]);
    }
};