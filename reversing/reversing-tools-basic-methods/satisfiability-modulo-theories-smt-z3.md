<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


Βασικά, αυτό το εργαλείο θα μας βοηθήσει να βρούμε τιμές για μεταβλητές που πρέπει να ικανοποιούν κάποιες συνθήκες και η χειροκίνητη υπολογιστική τους θα είναι ενοχλητική. Επομένως, μπορείτε να υποδείξετε στο Z3 τις συνθήκες που πρέπει να ικανοποιούν οι μεταβλητές και αυτό θα βρει κάποιες τιμές (εάν είναι δυνατόν).

**Ορισμένα κείμενα και παραδείγματα εξάγονται από το [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

# Βασικές Λειτουργίες

## Λογικές Τιμές/Και/Ή/Όχι
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
## Ακέραιοι/Απλοποίηση/Πραγματικοί

Η βιβλιοθήκη Z3 παρέχει μια πληθώρα εργαλείων για την επίλυση προβλημάτων ικανοποίησης modulo θεωριών (SMT). Μερικά από αυτά τα εργαλεία περιλαμβάνουν τη δυνατότητα επίλυσης προβλημάτων με ακέραιους αριθμούς, απλοποίησης εκφράσεων και επίλυσης προβλημάτων με πραγματικούς αριθμούς.

Για την επίλυση προβλημάτων με ακέραιους αριθμούς, μπορούμε να χρησιμοποιήσουμε τη συνάρτηση `Int` της Z3. Αυτή η συνάρτηση μας επιτρέπει να δημιουργήσουμε μεταβλητές ακεραίους και να εκφράσουμε περιορισμούς μεταξύ αυτών των μεταβλητών. Έπειτα, μπορούμε να χρησιμοποιήσουμε τη συνάρτηση `solve` για να επιλύσουμε το πρόβλημα και να βρούμε μια λύση.

Για την απλοποίηση εκφράσεων, μπορούμε να χρησιμοποιήσουμε τη συνάρτηση `Simplify` της Z3. Αυτή η συνάρτηση μας επιτρέπει να μετατρέψουμε μια πολύπλοκη έκφραση σε μια απλούστερη μορφή, χωρίς να αλλάζει η σημασία της έκφρασης.

Για την επίλυση προβλημάτων με πραγματικούς αριθμούς, μπορούμε να χρησιμοποιήσουμε τη συνάρτηση `Real` της Z3. Αυτή η συνάρτηση μας επιτρέπει να δημιουργήσουμε μεταβλητές πραγματικούς αριθμούς και να εκφράσουμε περιορισμούς μεταξύ αυτών των μεταβλητών. Με τη χρήση της συνάρτησης `solve`, μπορούμε να επιλύσουμε το πρόβλημα και να βρούμε μια λύση.
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
## Εκτύπωση Μοντέλου

To print the model, you can use the `model` object obtained from the solver. The `model` object represents the satisfying assignment for the given constraints.

```python
print(model)
```

Για να εκτυπώσετε το μοντέλο, μπορείτε να χρησιμοποιήσετε το αντικείμενο `model` που έχετε λάβει από τον επιλύτη. Το αντικείμενο `model` αναπαριστά την ικανοποιητική ανάθεση για τους δεδομένους περιορισμούς.

```python
print(model)
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
# Μηχανική Αριθμητική

Οι σύγχρονοι επεξεργαστές και οι κύριες γλώσσες προγραμματισμού χρησιμοποιούν αριθμητικές πράξεις πάνω σε **δυαδικούς αριθμούς με σταθερό μέγεθος**. Η μηχανική αριθμητική είναι διαθέσιμη στο Z3Py ως **Bit-Vectors**.
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
## Υπογεγραμμένοι/Ανυπογράμμιστοι Αριθμοί

Το Z3 παρέχει ειδικές υπογεγραμμένες εκδόσεις των αριθμητικών λειτουργιών όπου κάνει διαφορά εάν το **bit-vector** θεωρείται ως υπογεγραμμένο ή ανυπογεγραμμένο. Στην Z3Py, οι τελεστές **<, <=, >, >=, /, % και >>** αντιστοιχούν στις **υπογεγραμμένες** εκδόσεις. Οι αντίστοιχοι **ανυπογεγραμμένοι** τελεστές είναι **ULT, ULE, UGT, UGE, UDiv, URem και LShR.**
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
## Συναρτήσεις

Οι **ερμηνευμένες συναρτήσεις** όπως η αριθμητική, όπου η **συνάρτηση +** έχει μια **σταθερή τυπική ερμηνεία** (προσθέτει δύο αριθμούς). Οι **μη ερμηνευμένες συναρτήσεις** και σταθερές είναι **μέγιστα ευέλικτες**· επιτρέπουν **οποιαδήποτε ερμηνεία** που είναι **συνεπής** με τους περιορισμούς πάνω στη συνάρτηση ή σταθερά.

Παράδειγμα: η εφαρμογή της f δύο φορές στο x έχει ως αποτέλεσμα το x ξανά, αλλά η εφαρμογή της f μία φορά στο x είναι διαφορετική από το x.
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
# Παραδείγματα

## Λύτης Sudoku

```python
from z3 import *

def solve_sudoku(grid):
    # Δημιουργία μοντέλου Z3
    s = Solver()

    # Δημιουργία μεταβλητών για τις τιμές των κελιών
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # Περιορισμοί για τις τιμές των κελιών
    for i in range(9):
        for j in range(9):
            # Οι τιμές των κελιών είναι από 1 έως 9
            s.add(And(cells[i][j] >= 1, cells[i][j] <= 9))

    # Περιορισμοί για τις τιμές των γραμμών
    for i in range(9):
        s.add(Distinct(cells[i]))

    # Περιορισμοί για τις τιμές των στηλών
    for j in range(9):
        s.add(Distinct([cells[i][j] for i in range(9)]))

    # Περιορισμοί για τις τιμές των τετραγώνων 3x3
    for i in range(0, 9, 3):
        for j in range(0, 9, 3):
            s.add(Distinct([cells[x][y] for x in range(i, i+3) for y in range(j, j+3)]))

    # Περιορισμός για τις αρχικές τιμές του πίνακα Sudoku
    for i in range(9):
        for j in range(9):
            if grid[i][j] != 0:
                s.add(cells[i][j] == grid[i][j])

    # Επίλυση του προβλήματος
    if s.check() == sat:
        m = s.model()
        solution = [[m.evaluate(cells[i][j]).as_long() for j in range(9)] for i in range(9)]
        return solution
    else:
        return None

# Αρχικός πίνακας Sudoku
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

# Επίλυση του Sudoku
solution = solve_sudoku(grid)

# Εκτύπωση της λύσης
if solution:
    for row in solution:
        print(row)
else:
    print("No solution found.")
```

Αυτός ο κώδικας χρησιμοποιεί τη βιβλιοθήκη Z3 για να επιλύσει ένα πρόβλημα Sudoku. Ο κώδικας δημιουργεί ένα μοντέλο Z3 και ορίζει τις μεταβλητές για τις τιμές των κελιών του Sudoku. Στη συνέχεια, ο κώδικας προσθέτει περιορισμούς για τις τιμές των κελιών, των γραμμών, των στηλών και των τετραγώνων 3x3. Επίσης, ο κώδικας προσθέτει περιορισμούς για τις αρχικές τιμές του πίνακα Sudoku. Τέλος, ο κώδικας επιλύει το πρόβλημα και εκτυπώνει τη λύση, αν υπάρχει.
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
## Αναφορές

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
