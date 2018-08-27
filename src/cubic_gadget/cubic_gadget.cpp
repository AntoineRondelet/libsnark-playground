/*
 * This gadget proves that one knows the solution to the equation: (E) x**3 + x + 5 == 35 (answer is 3)
 * without revealing the answer. 
 * This gadget aims to follow the serie of articles written by V. Buterin about zk-SNARKS
 * See: https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649
 * 
 * Below, I'll go again through the different steps needed to write the gadget to prove the solution of (E).
 * 
 * Problem: we want to prove that we know the solution of the cubic equation: (E) x**3+x+5 == 35 
 * without revealing the solution to the network.
 * 
 * This problem can be formulated into a program, and is then flattened:
 * Flattening converts a program into a sequence of statements that are of one of the forms:
 * - x = y 
 * - x = y (op) z
 * Where y can be a variable or a number and (op) is an operator (Note: Arithmetic operations are done
 * over a field, thus, we can "do everything we want", we have an addition, multiplication, subtraction, and division)
 * 
 * The flattened version of the program is used to build a circuit, which has gates and wires.
 * Basically gates are operators, and wires are variables
 * 
 * The flattened version of the program to verify (E) is given by:
 * - x1 = x0 * x0 -> Gives: x1 = x0**2
 * - x2 = x1 * x0 -> Gives: x2 = x0**3 (we have the first term of the left side of (E))
 * - x3 = x2 + x0 -> Gives: x0**3 + x0 (we have thre first + second term of the left side of (E))
 * - x4 = x3 + 5  -> Gives: x0**3 + x0 + 5 (which is the left side of ==)
 * Note, a last statement can be added in order to respect the condition "== 35"
 * - x4 = 35
 * 
 * At this point, we have the vector of variables: X = {x_0, x_1, x_2, x_3, x_4}
 * 
 * From the following flattened code, we can see that each line can be seen as wires entering a gate (right side of the equality)
 * which results in an output wire (left side).
 * 
 * The next step consists in "encoding" this circuit into a set of constraints. In order to do so,
 * each statement of the flattened code (which is basically a gate in the corresponding circuit)
 * will be written as a R1CS constraint (Rank 1 Constraint System), which is in the form:
 * < A , X > * < B , X > = < C , X >, where < Y , Z > represents the dot product of the vectors Z, and Y.
 * Here we have seen that X = {x_0, x_1, x_2, x_3, x_4} (see above) is the vector of variables,
 * and A, B, and C, are vectors of elements in the field we work in.
 * 
 * From this, we can see that each constraint is composed of 3 linear combinations. In fact, if we note:
 * - linear combnation a = < A , X > 
 * - linear combnation b = < B , X > 
 * - linear combnation c = < C , X > 
 * Then each constraint of the R1CS becomes: a * b = c
 * 
 * We can see this by looking at the r1cs_constraint class which contains 3 linear combinations 
 * attributes: a, b, and c:
 * ```
 * r1cs_constraint(const linear_combination<FieldT> &a,
 *                 const linear_combination<FieldT> &b,
 *                 const linear_combination<FieldT> &c
 * );
 * ```
 * 
 * With this in mind, we can begin to build our R1CS from the flattened code above, by 
 * building each constraint after the other.
 * 
 * Here is the R1C for the first gate g1: x1 = x0 * x0
 * 
 * For the first gate, we have:
 * X = [ONE]  A = [0]  B = [0]  C = [0]
 *     [x0]       [1]      [1]      [0]
 *     [x1]       [0]      [0]      [1]
 *     [x2]       [0]      [0]      [0]
 *     [x3]       [0]      [0]      [0]
 *     [x4]       [0]      [0]      [0]
 * 
 * Which results in:
 * - linear_combination a = < A , X > = x0
 * - linear_combination b = < B , X > = x0
 * - linear_combination c = < C , X > = x1
 * 
 * Thus, in the "language of Libsnark", the first constraint is written:
 * r1cs_constraint<FieldT> firstGate = r1cs_constraint<FieldT>(
 *      x0, // a
 *      x0, // b
 *      x1  // c
 * );
 * 
 * Then, this constraint (R1C: Rank 1 constraint) is added to the protoboard in order to be part of the
 * Rank 1 Constraint system. To do so, we do:
 * pb.add_r1cs_constraint(firstGate);
 * Where, pb, is the protoboard of the gadget.
 * 
 * We follow the same approach for the other gates, and we add the corresponding constraints 
 * to the protoboard to form the R1CS.
 * Adding all of these constraints, in often done in the: generate_r1cs_constraints() function of the gadget.
 * 
 * 
 * Note: We have seen that a gadget could be seen as a circuit. In order to build complex circuits, it is 
 * common to use gadgets inside gadgets. If this is the case, then, we can use the "embedded" gadget as 
 * a black box, and just call: embedded_gagdet->generate_r1cs_constraints(); inside the function generate_r1cs_constraints()
 * of the gagdet we define.
 * 
 * In sum, we have just seen how to "transform" our flattened code into a R1CS, in a gadget, that we can now use as a black 
 * box for further use.
 * 
 * Having a generate_r1cs_constraints() function is, however, not enough to be useful. Other functions need to be implemented:
 * - Gadget constructor: Basically in the gadget constructor, we allocate the variables on the protoboard.
 * - generate_r1cs_constraints(): We generate the set of constraints using the variables allocated on the protoboard
 * - generate_witness(): We generate a witness given an input. The witness is a valid assignment to all the variables, including input, output and internal variables (ie: wires in the circuit).
 * It has to respect the constraints defined in the generate_r1cs_constraints() function.
 **/ 

#include <libsnark/gadgetlib1/gadget.hpp>

template<typename FieldT>
FieldT field_element_from_bits(libsnark::protoboard<FieldT> &pb, libff::bit_vector field_element_bits) {
    libsnark::pb_variable_array<FieldT> array_bits;
    array_bits.allocate(pb, field_element_bits.size(), "final_coeff_bits");
    array_bits.fill_with_bits(pb, field_element_bits);
    auto field_value = array_bits.get_field_element_from_bits(pb);
    return field_value;
}

/*
 * This gadget is made ONLY to prove the knowledge of x such that: x**3 + x + 5 = 35
 **/
template<typename FieldT>
class cubic_gadget : public libsnark::gadget<FieldT> {
public:
    libsnark::protoboard<FieldT> &pb;
    const std::string annotation_prefix="";

    // Input variable: solution x to (E), such that F(x) = 35
    // Where F(x) is defined as F(x) = A*x**3 + B*x**2 + C*x + D = Right_part
    // where A = 1, B = 0, C = 1, D = 5, and Right_part = 35
    // Note:
    // The coefficients of the polynomial, along with the Right_part are HARDCODED into this gadget)
    // Further gadgets will illustrate how to do to build a circuit for dynamic values for the coeffs of the polynomial
    const libsnark::pb_variable<FieldT> &sol_x;

    // vector X = [x0, x1, x2, x3, x4] of variables allocated on the protoboard
    libsnark::pb_variable_array<FieldT> vars;
    
    libsnark::pb_variable<FieldT> coeff_D;
    libsnark::pb_variable<FieldT> right_part;
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
        vars.allocate(pb, 5, FMT(this->annotation_prefix, " vars")); // size(X) = 5 (5 variables)

        // Value of 5 (coeff C)
        FieldT coeff_D_value = field_element_from_bits(pb, {1, 0, 1});
        coeff_D.allocate(pb);
        pb.val(coeff_D) = coeff_D_value;

        // Value of 35 (result)
        FieldT right_part_value = field_element_from_bits(pb, {1, 1, 0, 0, 0, 1});
        right_part.allocate(pb);
        pb.val(right_part) = right_part_value;
    }

    // Creates all constraints on the libsnark::protoboard
    void generate_r1cs_constraints() {
        // x0 * x0 = x1
        libsnark::r1cs_constraint<FieldT> constraint1 = libsnark::r1cs_constraint<FieldT>(
            vars[0],
            vars[0],
            vars[1]
        );

        // x1 * x0 = x2
        libsnark::r1cs_constraint<FieldT> constraint2 = libsnark::r1cs_constraint<FieldT>(
            vars[1],
            vars[0],
            vars[2]
        );

        // x3 * 1 = x2 + x0
        libsnark::r1cs_constraint<FieldT> constraint3 = libsnark::r1cs_constraint<FieldT>(
            vars[3],
            FieldT::one(),
            vars[2] + vars[0]
        );

        // x4 * 1 = x3 + 5
        libsnark::r1cs_constraint<FieldT> constraint4 = libsnark::r1cs_constraint<FieldT>(
            vars[4],
            FieldT::one(),
            vars[3] + pb.val(coeff_D)
        );

        // x4 * 1 = 35 (constraint on the value of the output)
        libsnark::r1cs_constraint<FieldT> constraint5 = libsnark::r1cs_constraint<FieldT>(
            vars[4],
            FieldT::one(),
            pb.val(right_part)
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
        pb.val(vars[4]) = pb.val(vars[3]) + pb.val(coeff_D);
    }
};