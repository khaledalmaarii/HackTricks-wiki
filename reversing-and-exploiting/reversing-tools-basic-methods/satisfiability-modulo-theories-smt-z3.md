<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>


Grundlegend hilft uns dieses Tool, Werte für Variablen zu finden, die bestimmte Bedingungen erfüllen müssen, und das manuelle Berechnen dieser Werte wäre sehr lästig. Daher können Sie Z3 die Bedingungen angeben, die die Variablen erfüllen müssen, und es wird einige Werte finden (falls möglich).

**Einige Texte und Beispiele stammen von [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

# Grundlegende Operationen

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
## Ganzzahlen/Vereinfachen/Reelle Zahlen

SMT-Lösungssysteme wie Z3 können nicht nur mit booleschen Ausdrücken umgehen, sondern auch mit ganzen Zahlen (Integers) und reellen Zahlen (Reals). Dies ermöglicht es uns, komplexe mathematische Probleme zu modellieren und zu lösen.

### Ganzzahlen (Integers)

Z3 bietet eine Vielzahl von Funktionen und Operatoren, um mit ganzen Zahlen zu arbeiten. Wir können Ganzzahlen deklarieren, arithmetische Operationen durchführen und Bedingungen überprüfen. Hier sind einige Beispiele:

- Deklaration einer ganzen Zahl: `(declare-const x Int)`
- Addition: `(assert (= x (+ 2 3)))`
- Subtraktion: `(assert (= x (- 5 2)))`
- Multiplikation: `(assert (= x (* 2 3)))`
- Division: `(assert (= x (/ 10 2)))`
- Modulo: `(assert (= x (mod 10 3)))`

### Vereinfachen (Simplify)

Z3 bietet auch eine Vereinfachungsfunktion, mit der wir komplexe Ausdrücke vereinfachen können. Dies kann nützlich sein, um redundante Teile zu entfernen und den Ausdruck übersichtlicher zu gestalten. Hier ist ein Beispiel:

- Vereinfachen eines Ausdrucks: `(simplify (+ 2 (* 3 4)))`

### Reelle Zahlen (Reals)

Z3 unterstützt auch reelle Zahlen und ermöglicht es uns, mit ihnen zu rechnen. Wir können reelle Zahlen deklarieren, arithmetische Operationen durchführen und Bedingungen überprüfen. Hier sind einige Beispiele:

- Deklaration einer reellen Zahl: `(declare-const y Real)`
- Addition: `(assert (= y (+ 2.5 3.7)))`
- Subtraktion: `(assert (= y (- 5.2 2.1)))`
- Multiplikation: `(assert (= y (* 2.5 3.7)))`
- Division: `(assert (= y (/ 10.5 2.5)))`

Mit diesen Funktionen und Operatoren können wir komplexe mathematische Probleme modellieren und lösen, die sowohl Ganzzahlen als auch reelle Zahlen beinhalten.
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
## Modell ausgeben

To print the model, you can use the `model` method provided by the Z3 library. This method returns a string representation of the model, which can then be printed or used for further analysis.

```python
print(s.model())
```

Um das Modell auszugeben, können Sie die `model`-Methode der Z3-Bibliothek verwenden. Diese Methode gibt eine Zeichenfolgenrepräsentation des Modells zurück, die dann gedruckt oder für weitere Analysen verwendet werden kann.

```python
print(s.model())
```
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
# Maschinenarithmetik

Moderne CPUs und gängige Programmiersprachen verwenden Arithmetik über **Bit-Vektoren mit fester Größe**. Maschinenarithmetik ist in Z3Py als **Bit-Vektoren** verfügbar.
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
## Vorzeichenbehaftete/unvorzeichenbehaftete Zahlen

Z3 bietet spezielle vorzeichenbehaftete Versionen von arithmetischen Operationen an, bei denen es einen Unterschied macht, ob der **Bit-Vektor als vorzeichenbehaftet oder unvorzeichenbehaftet behandelt wird**. In Z3Py entsprechen die Operatoren **<, <=, >, >=, /, % und >>** den **vorzeichenbehafteten** Versionen. Die entsprechenden **unvorzeichenbehafteten** Operatoren sind **ULT, ULE, UGT, UGE, UDiv, URem und LShR.**
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
## Funktionen

**Interpretierte Funktionen** wie Arithmetik, bei denen die Funktion **+** eine **feste Standardinterpretation** hat (sie addiert zwei Zahlen). **Uninterpretierte Funktionen** und Konstanten sind **maximal flexibel**; sie erlauben **jede Interpretation**, die mit den **Einschränkungen** über die Funktion oder Konstante **konsistent** ist.

Beispiel: Wenn f zweimal auf x angewendet wird, ergibt dies wieder x, aber wenn f einmal auf x angewendet wird, ist es unterschiedlich von x.
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
# Beispiele

## Sudoku-Löser

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

            # Each row must contain distinct values
            row_constraint = Distinct(cells[i])

            # Each column must contain distinct values
            column_constraint = Distinct([cells[k][j] for k in range(9)])

            # Each 3x3 subgrid must contain distinct values
            subgrid_constraint = Distinct([cells[m][n] for m in range(i - i % 3, i - i % 3 + 3) for n in range(j - j % 3, j - j % 3 + 3)])

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
        print("No solution found")

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

# Create a solver
solver = Solver()

# Solve the Sudoku
solve_sudoku(grid)
```

Dieser Code löst ein Sudoku-Rätsel mithilfe des Z3 SMT-Solvers. Der Code erstellt ein 9x9-Raster von Integer-Variablen und fügt für jede Zelle Einschränkungen hinzu. Jede Zelle muss einen Wert zwischen 1 und 9 haben. Jede Zeile, jede Spalte und jedes 3x3-Unterraster muss unterschiedliche Werte enthalten. Der Code fügt auch die anfänglichen Werte des Rätsels hinzu und überprüft, ob eine Lösung existiert. Wenn eine Lösung gefunden wird, wird sie ausgegeben. Andernfalls wird "Keine Lösung gefunden" angezeigt.

Beispiel-Sudoku-Raster:

```
5 3 0 0 7 0 0 0 0
6 0 0 1 9 5 0 0 0
0 9 8 0 0 0 0 6 0
8 0 0 0 6 0 0 0 3
4 0 0 8 0 3 0 0 1
7 0 0 0 2 0 0 0 6
0 6 0 0 0 0 2 8 0
0 0 0 4 1 9 0 0 5
0 0 0 0 8 0 0 7 9
```

Die Lösung für dieses Sudoku-Rätsel lautet:

```
5 3 4 6 7 8 9 1 2
6 7 2 1 9 5 3 4 8
1 9 8 3 4 2 5 6 7
8 5 9 7 6 1 4 2 3
4 2 6 8 5 3 7 9 1
7 1 3 9 2 4 8 5 6
9 6 1 5 3 7 2 8 4
2 8 7 4 1 9 6 3 5
3 4 5 2 8 6 1 7 9
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
## Referenzen

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
