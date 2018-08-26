# Using Libsnark: Building a gadget step by step

The purpose of this repo is to play around with libsnark, in order for me to get familiar with this library.

In: [/src/cubic_gadget](https://github.com/AntoineRondelet/libsnark-playground/tree/master/src) I propose an implementation of a gagdet that follows [V. Buterin's article about Quadratic Arithmetic Programs](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649).

## Disclaimer

**[WARNING] DO NOT use any of these gadgets into production**.

I'm always happy to have feedback or contributions if you spot mistakes, or dummy things hat could be improved.

## References

- https://github.com/scipr-lab/libsnark
- https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649

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

1. Express the statements to be proved as an R1CS (a set of constraints)
2. Use the **generator algorithm** to create the public parameters for this statement ("trusted setup" done once and for all)
3. Use the **prover algorithm** to create proofs of true statements about the satisfiability of the R1CS
4. Use the **verifier algorithm** to check proofs for alleged statements

**Note:** Libsnark provides libraries for constructing R1CS instances via reusable "gadgets". 
Gadgets, are "just" reusable R1CS. When we know that a R1CS, is "the translation" of an arithmetic circuit into a set of constraints on vectors, we see that the use of gadgets, enables to "build more complex circuits from other circuits".
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

This piece of code reminds us that a variable represents an expression of the form `x_{index}`. 
In fact, we know, that after the "flattening" process, we created a lot of variables from the reduction of the program, and as soon as we deal with arithmetic circuits or R1CS, the witness is a vector of variables. 
Thus, if we have, `X` being the assignment to all variables, we have `X = vec<1, x_1, x_2, ..., X_n>`, with `n` the size of the vector/numnber of variables.

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

The code of the class, tells us that a `pb_variable`, is basically a wrapper around the `variable` class above, that we can allocate on a `protoboard`. 
We can allocate `pb_variables` on a protoboard, this will add a new variable at the next available index in the protoboard.

### Protoboard

A protoboard basically contains a R1CS, and an assignment to this R1CS:

- Looking at the code from the file `libsnark/gadgetlib1/protoboard.hpp`, we see that, the protoboard contains:
    - An assignment for the R1CS: `r1cs_variable_assignment<FieldT> values;` (where `r1cs_variable_assignment` is defined as a vector of elements in the field F, see: `using r1cs_variable_assignment = std::vector<FieldT>;`in file `libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp`)
    - A R1CS object: `r1cs_constraint_system<FieldT> constraint_system;`

**Note:** The implementation of the protoboard class gives us details on how primary and auxiliary input are stored on the protoboard. In fact, we can see that:
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
r1cs_variable_assignment<FieldT> values;
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

-----------------------------------------

Thus, the value set by: `set_input_sizes(const size_t primary_input_size);` defines the shift that enables to differentiate between primary and auxiliary input.

-----------------------------------------

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

tells us that a gadget, basically is a protoboard, with an annotation.

### Conclusion

All in all, we saw that a gadget is a protoboard with "a name". 
A protoboard is "simply" a Rank-1 Constraints System.

**Note:** A gadget can even be built directly from a R1CS. This logic is implemented in: `libsnark/gadgetlib1/gadget_from_r1cs.tcc`

## Compile the project and run the tests for the gagdet

Additional explanations on how to build the gadget are given directly in the code source.

## Compile the project

In order to compile the project, run:
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

## Run the project:

In order to run the test of the `cubic_gadget`, run:

```
./build/src/main
```

## License notices:

### libsnark

The libsnark library is developed by SCIPR Lab (http://scipr-lab.org)
and contributors.

Copyright (c) 2012-2014 SCIPR Lab and contributors (see AUTHORS file).

All files, with the exceptions below, are released under the MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
