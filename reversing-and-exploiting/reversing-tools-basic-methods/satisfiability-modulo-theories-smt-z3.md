<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


Kimsingi, zana hii itatusaidia kupata thamani za pembejeo ambazo zinahitaji kutimiza masharti fulani na kuzihesabu kwa mkono itakuwa kuchosha sana. Kwa hivyo, unaweza kuonyesha kwa Z3 masharti ambayo pembejeo zinahitaji kutimiza na itapata thamani fulani (ikiwa inawezekana).

**Baadhi ya maandishi na mifano imetolewa kutoka [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

# Operesheni za Msingi

## Booleans/And/Or/Not
```python
#pip3 install z3-solver
from z3 import *
s = Solver() #The solver will be given the conditions

x = Bool("x") #Declare the symbos x, y and z
y = Bool("y")
z = Bool("z")

# (x or y or !z) and y
s.add(And(Or(x,y,Not(z)),y))
s.check() #If response is "sat" then the model is satifable, if "unsat" something is wrong
print(s.model()) #Print valid values to satisfy the model
```
## Ints/Simplify/Reals

## Ints/Simplify/Reals

### Introduction

### Utangulizi

In this section, we will explore the basic functionalities of the Z3 SMT solver related to integer, real, and simplification theories.

Katika sehemu hii, tutachunguza utendaji wa msingi wa suluhisho la Z3 SMT linalohusiana na nadharia za nambari za asili, halisi, na upunguzaji.

### Integers

### Nambari za Asili

The Z3 SMT solver provides support for solving problems involving integer arithmetic. It can handle operations such as addition, subtraction, multiplication, division, and modulo.

Suluhisho la Z3 SMT linatoa msaada katika kutatua matatizo yanayohusisha hisabati ya nambari za asili. Linaweza kushughulikia operesheni kama vile kuongeza, kutoa, kuzidisha, kugawanya, na modulo.

To declare an integer variable in Z3, we use the `Int` sort. For example, `x = Int('x')` creates an integer variable named `x`.

Kuweka wazi kivinjari cha nambari za asili katika Z3, tunatumia aina ya `Int`. Kwa mfano, `x = Int('x')` inaunda kivinjari cha nambari za asili kinachoitwa `x`.

### Reals

### Nambari Halisi

The Z3 SMT solver also supports solving problems involving real numbers. It can handle operations such as addition, subtraction, multiplication, division, and exponentiation.

Suluhisho la Z3 SMT pia linasaidia kutatua matatizo yanayohusisha nambari halisi. Linaweza kushughulikia operesheni kama vile kuongeza, kutoa, kuzidisha, kugawanya, na kuzidisha kwa nafasi.

To declare a real variable in Z3, we use the `Real` sort. For example, `x = Real('x')` creates a real variable named `x`.

Kuweka wazi kivinjari cha nambari halisi katika Z3, tunatumia aina ya `Real`. Kwa mfano, `x = Real('x')` inaunda kivinjari cha nambari halisi kinachoitwa `x`.

### Simplification

### Upunguzaji

The Z3 SMT solver can simplify expressions involving integers and reals. It can simplify arithmetic expressions, logical expressions, and combinations of both.

Suluhisho la Z3 SMT linaweza kupunguza mielekeo inayohusisha nambari za asili na halisi. Linaweza kupunguza mielekeo ya hisabati, mielekeo ya mantiki, na mchanganyiko wa zote mbili.

To simplify an expression in Z3, we use the `simplify` function. For example, `simplify(x + 2 * y)` simplifies the expression `x + 2 * y`.

Kupunguza mielekeo katika Z3, tunatumia kazi ya `simplify`. Kwa mfano, `simplify(x + 2 * y)` inapunguza mielekeo ya `x + 2 * y`.

### Conclusion

### Hitimisho

In this section, we have learned about the basic functionalities of the Z3 SMT solver related to integer, real, and simplification theories. We have seen how to declare integer and real variables, as well as how to simplify expressions using the `simplify` function.

Katika sehemu hii, tumefahamu kuhusu utendaji wa msingi wa suluhisho la Z3 SMT linalohusiana na nadharia za nambari za asili, halisi, na upunguzaji. Tumeona jinsi ya kuweka wazi kivinjari cha nambari za asili na halisi, pamoja na jinsi ya kupunguza mielekeo kwa kutumia kazi ya `simplify`.
```python
from z3 import *

x = Int('x')
y = Int('y')
#Simplify a "complex" ecuation
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
#And(x >= 2, 2*x**2 + y**2 >= 3)

#Note that Z3 is capable to treat irrational numbers (An irrational algebraic number is a root of a polynomial with integer coefficients. Internally, Z3 represents all these numbers precisely.)
#so you can get the decimals you need from the solution
r1 = Real('r1')
r2 = Real('r2')
#Solve the ecuation
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
#Solve the ecuation with 30 decimals
set_option(precision=30)
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
```
## Kuchapisha Mfano

To print the model of a satisfiability modulo theories (SMT) problem using the Z3 solver, you can use the `model` method. This method returns a string representation of the model.

```python
s = Solver()
# ... add constraints to the solver ...
if s.check() == sat:
    m = s.model()
    print(m)
```

The `model` method returns a model object that represents the satisfying assignment for the variables in the problem. You can access the values of the variables using the `eval` method of the model object.

```python
# Accessing variable values
x_value = m.eval(x)
y_value = m.eval(y)
```

By default, the `model` method returns a string representation of the model in a human-readable format. However, you can also customize the output format by specifying different options.

For example, you can use the `set_option` method to set the `model_format` option to `2` in order to get the model in SMT-LIB format.

```python
# Setting the model format option
set_option("model_format", 2)
```

This will change the output format of the model to SMT-LIB format, which is a standard format used in SMT solvers.

By printing the model, you can easily analyze and understand the satisfying assignment for the variables in your SMT problem. This can be helpful in debugging and verifying the correctness of your SMT encoding.
```python
from z3 import *

x, y, z = Reals('x y z')
s = Solver()
s.add(x > 1, y > 1, x + y > 3, z - x < 10)
s.check()

m = s.model()
print ("x = %s" % m[x])
for d in m.decls():
print("%s = %s" % (d.name(), m[d]))
```
# Hesabu ya Mashine

Kompyuta za kisasa na lugha za programu zinatumia hesabu juu ya **biti-vikundi vya ukubwa uliowekwa**. Hesabu ya mashine inapatikana katika Z3Py kama **Bit-Vectors**.
```python
from z3 import *

x = BitVec('x', 16) #Bit vector variable "x" of length 16 bit
y = BitVec('y', 16)

e = BitVecVal(10, 16) #Bit vector with value 10 of length 16bits
a = BitVecVal(-1, 16)
b = BitVecVal(65535, 16)
print(simplify(a == b)) #This is True!
a = BitVecVal(-1, 32)
b = BitVecVal(65535, 32)
print(simplify(a == b)) #This is False
```
## Nambari Zilizosainiwa/Zisizosainiwa

Z3 inatoa toleo maalum la operesheni za arithmetical ambapo inafanya tofauti ikiwa **bit-vector inachukuliwa kama iliyosainiwa au isiyosainiwa**. Katika Z3Py, waendeshaji **<, <=, >, >=, /, % na >>** yanalingana na toleo **lililosainiwa**. Waendeshaji **isiyosainiwa** yanalingana na **ULT, ULE, UGT, UGE, UDiv, URem na LShR.**
```python
from z3 import *

# Create to bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x + y == 2, x > 0, y > 0)

# Bit-wise operators
# & bit-wise and
# | bit-wise or
# ~ bit-wise not
solve(x & y == ~y)
solve(x < 0)

# using unsigned version of <
solve(ULT(x, 0))
```
## Kazi

**Kazi zilizotafsiriwa** kama hisabati ambapo **kazi +** ina **tafsiri ya kawaida iliyowekwa** (inahesabu namba mbili). **Kazi zisizotafsiriwa** na vipengele vya kudumu ni **mwenye nguvu sana**; zinaruhusu **tafsiri yoyote** ambayo ni **sambamba** na **vizuizi** juu ya kazi au kipengele.

Mfano: f ikitekelezwa mara mbili kwa x inatoa x tena, lakini f ikitekelezwa mara moja kwa x ni tofauti na x.
```python
from z3 import *

x = Int('x')
y = Int('y')
f = Function('f', IntSort(), IntSort())
s = Solver()
s.add(f(f(x)) == x, f(x) == y, x != y)
s.check()
m = s.model()
print("f(f(x)) =", m.evaluate(f(f(x))))
print("f(x)    =", m.evaluate(f(x)))

print(m.evaluate(f(2)))
s.add(f(x) == 4) #Find the value that generates 4 as response
s.check()
print(m.model())
```
# Mifano

## Mtekelezaji wa Sudoku

```python
from z3 import *

def solve_sudoku(grid):
    # Create a 9x9 grid of integer variables
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # Add constraints for each cell
    for i in range(9):
        for j in range(9):
            # Each cell must be between 1 and 9
            cell = cells[i][j]
            cell_constraint = And(cell >= 1, cell <= 9)

            # Each row must contain unique values
            row_constraint = Distinct(cells[i])

            # Each column must contain unique values
            column_constraint = Distinct([cells[k][j] for k in range(9)])

            # Each 3x3 subgrid must contain unique values
            subgrid_constraint = Distinct([cells[m][n] for m in range(i//3*3, i//3*3+3) for n in range(j//3*3, j//3*3+3)])

            # Combine all constraints for the cell
            cell_constraints = [cell_constraint, row_constraint, column_constraint, subgrid_constraint]

            # Add the constraints to the solver
            solver.add(cell_constraints)

    # Add the initial values to the solver
    for i in range(9):
        for j in range(9):
            if grid[i][j] != 0:
                solver.add(cells[i][j] == grid[i][j])

    # Check if there is a solution
    if solver.check() == sat:
        # Get the solution
        model = solver.model()

        # Print the solution
        for i in range(9):
            for j in range(9):
                print(model[cells[i][j]], end=" ")
            print()
    else:
        print("No solution")

# Example Sudoku grid
grid = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9]
]

# Solve the Sudoku
solve_sudoku(grid)
```

## Mtekelezaji wa Sudoku

```python
from z3 import *

def solve_sudoku(grid):
    # Unda gridi ya 9x9 ya pembejeo za nambari
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # Ongeza vikwazo kwa kila pembejeo
    for i in range(9):
        for j in range(9):
            # Kila pembejeo lazima iwe kati ya 1 na 9
            cell = cells[i][j]
            cell_constraint = And(cell >= 1, cell <= 9)

            # Kila safu lazima iwe na pembejeo tofauti
            row_constraint = Distinct(cells[i])

            # Kila nguzo lazima iwe na pembejeo tofauti
            column_constraint = Distinct([cells[k][j] for k in range(9)])

            # Kila gridi ya 3x3 lazima iwe na pembejeo tofauti
            subgrid_constraint = Distinct([cells[m][n] for m in range(i//3*3, i//3*3+3) for n in range(j//3*3, j//3*3+3)])

            # Unganisha vikwazo vyote kwa pembejeo
            cell_constraints = [cell_constraint, row_constraint, column_constraint, subgrid_constraint]

            # Ongeza vikwazo kwa mtekelezaji
            solver.add(cell_constraints)

    # Ongeza pembejeo za awali kwa mtekelezaji
    for i in range(9):
        for j in range(9):
            if grid[i][j] != 0:
                solver.add(cells[i][j] == grid[i][j])

    # Angalia kama kuna suluhisho
    if solver.check() == sat:
        # Pata suluhisho
        model = solver.model()

        # Chapisha suluhisho
        for i in range(9):
            for j in range(9):
                print(model[cells[i][j]], end=" ")
            print()
    else:
        print("Hakuna suluhisho")

# Gridi ya Sudoku ya mfano
grid = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9]
]

# Pata suluhisho la Sudoku
solve_sudoku(grid)
```
```python
# 9x9 matrix of integer variables
X = [ [ Int("x_%s_%s" % (i+1, j+1)) for j in range(9) ]
for i in range(9) ]

# each cell contains a value in {1, ..., 9}
cells_c  = [ And(1 <= X[i][j], X[i][j] <= 9)
for i in range(9) for j in range(9) ]

# each row contains a digit at most once
rows_c   = [ Distinct(X[i]) for i in range(9) ]

# each column contains a digit at most once
cols_c   = [ Distinct([ X[i][j] for i in range(9) ])
for j in range(9) ]

# each 3x3 square contains a digit at most once
sq_c     = [ Distinct([ X[3*i0 + i][3*j0 + j]
for i in range(3) for j in range(3) ])
for i0 in range(3) for j0 in range(3) ]

sudoku_c = cells_c + rows_c + cols_c + sq_c

# sudoku instance, we use '0' for empty cells
instance = ((0,0,0,0,9,4,0,3,0),
(0,0,0,5,1,0,0,0,7),
(0,8,9,0,0,0,0,4,0),
(0,0,0,0,0,0,2,0,8),
(0,6,0,2,0,1,0,5,0),
(1,0,2,0,0,0,0,0,0),
(0,7,0,0,0,0,5,2,0),
(9,0,0,0,6,5,0,0,0),
(0,4,0,9,7,0,0,0,0))

instance_c = [ If(instance[i][j] == 0,
True,
X[i][j] == instance[i][j])
for i in range(9) for j in range(9) ]

s = Solver()
s.add(sudoku_c + instance_c)
if s.check() == sat:
m = s.model()
r = [ [ m.evaluate(X[i][j]) for j in range(9) ]
for i in range(9) ]
print_matrix(r)
else:
print "failed to solve"
```
## Marejeo

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
