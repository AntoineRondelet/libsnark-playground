# Using Libsnark: Building a gadget

## Reminder about zkSNARKs

A very high-level recap' on the different steps to follow when we want to build a zkSNARK for a program.

1. Initially we have a computer program (we do some "random computation")
2. Convert the program into a sequence of statements (flattening):
    - x = y
    - x = y (op) z
3. We obtain an arithmetic circuit which is an intermediate representation. Contains:
    - Wires (or "arcs"): Take values in the field F)
    - Gates (or "nodes"): Add or Multiply wires
4. We compile the arithmetic circuit into a Rank-1 Constraint System (R1CS):
    - We convert each logic gate into a Rank-1 Constraint (R1C) (for each gate, we have the corresponding R1C), which is a a group of 3 vectors (a,b,c) such that the solution to the R1CS is a vector s, such that s must satisfy the equation: `s.a * s.b - s.c = 0`
    - The size of each vector is the total number of variables in the system.
        - The variables are: the "dummy variable" (`~one`), input variables, intermediate variables, and the "output variable" (`~out`)
    - The R1CS we obtain is made of 3 matrices: A, B, and C of size `n*m`, where `n` (the number of lines) is equal to the number of gates in the arithmetic circuit, and `m` (the number of columns) is equal to the number of variables in the system. Basically, these matrices, encode all the constraints that need to be satisfied for the assignement to be valid. A valid witness (assignment to all variables in the `s` vector, or equivalently, an assignment of all the wires in the arithmetic circuit (Note: All variables of the witness should be elements of the field F)) is valid if all the constraints are satisfied.
5. We convert the set of R1CS into a Quadratic Arithmetic Program (QAP) (see: `libsnark/reductions/r1cs_to_qap`):
    - We use Lagrange Interpolation, that gives us the polynomial that passes through all the given points
    - In this step, we go from vectors to a group of polynomials.
    - Using QAP instead of R1CS enables to check all the constraints at the same time by doing the dot product check on the polynomials: `A(x) * B(x) - C(x) = H * Z(x)`, instead of checking all the constraints individually in the R1CS.

Corresponding files:
- R1CS: `libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp`
- QAP: `libsnark/relations/arithmetic_programs/qap/qap.hpp`
- R1CS to QAP reduction: `libsnark/reductions/r1cs_to_qap`

## Use of libsnark

1. Express the statements to be proved as an R1CS (or any of the other languages supported by libsnark, such as arithmetic circuits, Boolean circuits, or TinyRAM).
2. Use libsnark's generator algorithm to create the public parameters for this statement (once and for all).
3. Use libsnark's prover algorithm to create proofs of true statements about the satisfiability of the R1CS.
4. Use libsnark's verifier algorithm to check proofs for alleged statements.

Note: Libsnark provides libraries for conveniently constructing R1CS instances out of reusable "gadgets". Thus, gadget, are "just" reusable R1CS. When we know that a R1CS, is "the translation" of an arithmetic circuit into a set of constraints on vectors, we see that the use of gadgets, enables to "build more complex circuits from other circuits".
Using gadgets, enables to easily build complex instances of R1CS.

## Notes about the code

### Variable

The class from: `libsnark/relations/variable.hpp`:

```
template<typename FieldT>
class variable {
public:

    var_index_t index;

    variable(const var_index_t index = 0) : index(index) {};

    linear_term<FieldT> operator*(const integer_coeff_t int_coeff) const;
    linear_term<FieldT> operator*(const FieldT &field_coeff) const;

    linear_combination<FieldT> operator+(const linear_combination<FieldT> &other) const;
    linear_combination<FieldT> operator-(const linear_combination<FieldT> &other) const;

    linear_term<FieldT> operator-() const;

    bool operator==(const variable<FieldT> &other) const;
};
```

This piece of code reminds us that a variable represents an expression of the form `x_{index}`. In fact, we know, that after the "flattening" process, we created a lot of variables from the reduction of the program, and as soon as we deal with arithmetic circuits or R1CS, the witness is a vector of variables. Thus, if we have, `X` being the assignment to all variables, we have `X = vec<1, x_1, x_2, ..., X_n>`, with `n` the size of the vector/numnber of variables.

Moreover, we see that if we use the `*` operation of the variable class, we obtain a `linear_term`, in the form `field_element * x_{index}`. If we use the `+` operator, however, we obtain a `linear_combination`.

### Pb variable

The class from: `libsnark/gadgetlib1/pb_variable.hpp`

```
template<typename FieldT>
class pb_variable : public variable<FieldT> {
public:
    pb_variable(const var_index_t index = 0) : variable<FieldT>(index) {};

    void allocate(protoboard<FieldT> &pb, const std::string &annotation="");
};
```

The code of the class, tells us that a `pb_variable`, is basically a wrapper around the `variable` class above, that we can allocate on a `protoboard`. We can allocate `pb_variables` on a protoboard, this will add a new variable at the next available index in the protoboard.

### Protoboard

A protoboard basically contains a R1CS, and an assignment to this R1CS:

- Looking at the code from the file `libsnark/gadgetlib1/protoboard.hpp`, we see that, the protoboard contains:
    - An assignment for the R1CS: `r1cs_variable_assignment<FieldT> values;` (where `r1cs_variable_assignment` is defined as a vector of elements in the field F, see: `using r1cs_variable_assignment = std::vector<FieldT>;`in file `libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp`)
    - A R1CS object: `r1cs_constraint_system<FieldT> constraint_system;`

Note: The code gives us details on how primary and auxiliary input are stored on the protoboard

```
template<typename FieldT>
r1cs_variable_assignment<FieldT> protoboard<FieldT>::full_variable_assignment() const
{
    return values;
}

template<typename FieldT>
r1cs_primary_input<FieldT> protoboard<FieldT>::primary_input() const
{
    return r1cs_primary_input<FieldT>(values.begin(), values.begin() + num_inputs());
}

template<typename FieldT>
r1cs_auxiliary_input<FieldT> protoboard<FieldT>::auxiliary_input() const
{
    return r1cs_primary_input<FieldT>(values.begin() + num_inputs(), values.end());
}
```

Where `values` is a private member:
```
r1cs_variable_assignment<FieldT> values; /* values[0] will hold the value of the first allocated variable of the protoboard, *NOT* constant 1 */
```

The input size set in the protoboard, via:
```
void set_input_sizes(const size_t primary_input_size);
```
which sets the value: `primary_input_size` of the `constraint_system` contained in the protoboard `constraint_system.primary_input_size = primary_input_size;`

This value is returned, when calling `r1cs_constraint_system.num_inputs()`:
```
template<typename FieldT>
size_t r1cs_constraint_system<FieldT>::num_inputs() const
{
    return primary_input_size;
}
```
Which is the function called by `protoboard.num_inputs()`.

Thus, the value set by: `set_input_sizes(const size_t primary_input_size);` defines the shift that enables to differentiate between primary and auxiliary input.

### Gadget

The class from: `libsnark/gadgetlib1/gadget.hpp`

```
template<typename FieldT>
class gadget {
protected:
    protoboard<FieldT> &pb;
    const std::string annotation_prefix;
public:
    gadget(protoboard<FieldT> &pb, const std::string &annotation_prefix="");
};
```

tells us that a gadget, is nothing else other than a protoboard, with an annotation.

### Conclusion

All in all, we saw that a gadget is just a protoboard with "a name". A protoboard is simply a Rank-1 Constraints System.

Note: A gadget can even be built directly from a R1CS. This logic is implemented in: `libsnark/gadgetlib1/gadget_from_r1cs.tcc`

## Additional notes about some basic gadgets

### Packing gadget

This gadget enables to "pack" several bits into a field element.

## Generic Group Model (GG)

The generic group model was proposed by Shoup to give exact bounds on the difficulty of the discrete logarithm problem and the Diffie-Hellman problem in the situation where the attacker has no information about the specific representation of the group being used.

In other words the attacker is trying to solve a discrete logarithm (or Diffie-Hellman) problem in a group isomorphic to `C_p` but does not know whether this group is realised as, say, a multiplicative group or as an elliptic curve group.

The generic group model suffers from some of the same problems as the random oracle model. In particular, it has been shown using a similar argument that there exist cryptographic schemes which are provably secure in the generic group model but which are trivially insecure once the random group encoding is replaced with an efficiently computable instantiation of the encoding function.

## Glossary

- BACS: Bilinear Arithmetic Circuit Satisfiability
- USCS: Unitary-Square Constraint Systems
- TBCS: Two-input Boolean Circuit Satisfiability

### Notes

- zkSNARK for database membership:
Using Merkle trees, she could instead put a Merkle root commitment in the instance; a Merkle verification path in the witness; and a Merkle path check in the condition. That way Bob does not need to have access to the entire database to be able to carry out the verification. He can just verify by checking the merkle verification path and the merkle root.

- When we have binary values, the constraint on these values is that we want to make sure they belong to {0, 1}
- Same applies for all fields elements regardless of the field we operate on. We need to verify that the elements are in the field.

## Compile the project and run the tests for the gagdet

1. In order to compile the project, run:
```
mkdir build
cd build
cmake .. && make
cd ../zksnark_element && ../build/src/main
```
**MacOS compilation:**
```
brew install pkg-config

mkdir build && cd build

LD_LIBRARY_PATH=/usr/local/opt/openssl/lib:"${LD_LIBRARY_PATH}"
CPATH=/usr/local/opt/openssl/include:"${CPATH}"
PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:"${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH

CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig cmake -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF ..

make
```
2. Run the project:
```
./build/src/main
```
