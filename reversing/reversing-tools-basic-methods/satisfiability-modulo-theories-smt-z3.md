<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


In modo molto semplice, questo strumento ci aiuterà a trovare valori per le variabili che devono soddisfare alcune condizioni e calcolarli a mano sarebbe molto fastidioso. Pertanto, è possibile indicare a Z3 le condizioni che le variabili devono soddisfare e troverà alcuni valori (se possibile).

**Alcuni testi ed esempi sono tratti da [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

# Operazioni di base

## Booleani/And/Or/Not
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
## Int/Semplifica/Reali

SMT solvers like Z3 can handle not only boolean formulas but also formulas involving integers and real numbers. In this section, we will explore some basic methods for working with integer and real arithmetic in Z3.

### Integers

Z3 provides support for integer arithmetic operations such as addition, subtraction, multiplication, and division. These operations can be used to build complex formulas involving integers.

#### Constants

To represent integer constants in Z3, you can use the `IntVal` function. For example, `IntVal(42)` represents the integer constant 42.

#### Variables

To represent integer variables in Z3, you can use the `Int` function. For example, `Int('x')` represents an integer variable named 'x'.

#### Arithmetic Operations

Z3 provides functions for performing arithmetic operations on integers. Some of the commonly used functions are:

- `Add`: performs addition of two integers.
- `Sub`: performs subtraction of two integers.
- `Mul`: performs multiplication of two integers.
- `Div`: performs integer division of two integers.
- `Mod`: computes the remainder of integer division.

#### Constraints

To add constraints involving integers, you can use the `And` function to combine multiple constraints. For example, `And(x > 0, y < 10)` represents the constraint that variable 'x' is greater than 0 and variable 'y' is less than 10.

### Reals

Z3 also provides support for real numbers. You can use the `RealVal` function to represent real constants and the `Real` function to represent real variables.

#### Constants

To represent real constants in Z3, you can use the `RealVal` function. For example, `RealVal(3.14)` represents the real constant 3.14.

#### Variables

To represent real variables in Z3, you can use the `Real` function. For example, `Real('x')` represents a real variable named 'x'.

#### Arithmetic Operations

Z3 provides functions for performing arithmetic operations on real numbers. Some of the commonly used functions are:

- `Add`: performs addition of two real numbers.
- `Sub`: performs subtraction of two real numbers.
- `Mul`: performs multiplication of two real numbers.
- `Div`: performs division of two real numbers.

#### Constraints

To add constraints involving real numbers, you can use the `And` function to combine multiple constraints. For example, `And(x > 0.0, y < 1.0)` represents the constraint that variable 'x' is greater than 0.0 and variable 'y' is less than 1.0.
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
## Stampa del Modello

To print the model, you can use the `model` object obtained from the solver. The `model` object contains the assignments for each variable in the formula. 

Per stampare il modello, puoi utilizzare l'oggetto `model` ottenuto dal risolutore. L'oggetto `model` contiene le assegnazioni per ogni variabile nella formula. 

```python
print(model)
```

```python
print(model)
```

This will print the assignments for each variable in the model. 

Questo stamperà le assegnazioni per ogni variabile nel modello.
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
# Aritmetica delle macchine

Le CPU moderne e i linguaggi di programmazione di uso comune utilizzano l'aritmetica su **vettori di bit di dimensione fissa**. L'aritmetica delle macchine è disponibile in Z3Py come **Bit-Vectors**.
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
## Numeri con segno/senza segno

Z3 fornisce versioni speciali con segno delle operazioni aritmetiche in cui fa differenza se il **bit-vector viene trattato come con segno o senza segno**. In Z3Py, gli operatori **<, <=, >, >=, /, % e >>** corrispondono alle versioni **con segno**. Gli operatori corrispondenti **senza segno** sono **ULT, ULE, UGT, UGE, UDiv, URem e LShR.**
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
## Funzioni

Le **funzioni interpretate** come l'aritmetica, in cui la **funzione +** ha una **interpretazione standard fissa** (aggiunge due numeri). Le **funzioni non interpretate** e le costanti sono **massimamente flessibili**; consentono **qualsiasi interpretazione** che sia **coerente** con i **vincoli** sulla funzione o costante.

Esempio: l'applicazione di f due volte a x produce di nuovo x, ma l'applicazione di f una volta a x è diversa da x.
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
# Esempi

## Risolutore di Sudoku

```python
from z3 import *

def solve_sudoku(grid):
    # Creazione del solver
    solver = Solver()

    # Creazione delle variabili
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # Vincoli per i numeri nelle celle
    for i in range(9):
        for j in range(9):
            # Vincolo per i numeri da 1 a 9
            solver.add(And(cells[i][j] >= 1, cells[i][j] <= 9))

            # Vincolo per i numeri unici nella riga
            solver.add(Distinct(cells[i]))

            # Vincolo per i numeri unici nella colonna
            solver.add(Distinct([cells[k][j] for k in range(9)]))

    # Vincolo per i numeri unici nel blocco 3x3
    for i in range(0, 9, 3):
        for j in range(0, 9, 3):
            solver.add(Distinct([cells[i + di][j + dj] for di in range(3) for dj in range(3)]))

    # Vincoli per i numeri dati nel Sudoku iniziale
    for i in range(9):
        for j in range(9):
            if grid[i][j] != 0:
                solver.add(cells[i][j] == grid[i][j])

    # Risoluzione del Sudoku
    if solver.check() == sat:
        model = solver.model()
        solution = [[model.evaluate(cells[i][j]).as_long() for j in range(9)] for i in range(9)]
        return solution
    else:
        return None

# Esempio di Sudoku da risolvere
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

# Risoluzione del Sudoku
solution = solve_sudoku(grid)

# Stampa della soluzione
if solution is not None:
    for row in solution:
        print(row)
else:
    print("Il Sudoku non ha soluzione.")
```

Questo esempio mostra come utilizzare Z3 per risolvere un Sudoku. Il Sudoku viene rappresentato come una griglia 9x9 di numeri interi, dove i numeri dati sono rappresentati come numeri diversi da zero e le celle vuote sono rappresentate come zeri. Il risolutore Z3 viene utilizzato per trovare una soluzione valida per il Sudoku. Se una soluzione viene trovata, viene stampata; altrimenti, viene stampato un messaggio che indica che il Sudoku non ha soluzione.
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
## Riferimenti

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
