<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स साझा करें, [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में PR जमा करके।**

</details>


बहुत सरल रूप में, यह उपकरण हमें ऐसे मानों की मान्यता करने के लिए मदद करेगा जो कुछ शर्तों को पूरा करने की आवश्यकता होती है और उन्हें हाथ से गणना करना बहुत उक्तिगत होगा। इसलिए, आप Z3 को इंद्रियों की शर्तों की घोषणा कर सकते हैं और यह कुछ मान (यदि संभव हो) खोजेगा।

# मूलभूत कार्य

## बूलियन/और/या/नहीं
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
## पूर्णांक/सरल/वास्तविक संख्याएँ
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
## मॉडल प्रिंट करना

To print the model in Z3, you can use the `model` object and the `eval` method. The `eval` method takes a Z3 expression as input and returns the value assigned to that expression in the model.

Z3 में मॉडल प्रिंट करने के लिए, आप `model` ऑब्जेक्ट और `eval` मेथड का उपयोग कर सकते हैं। `eval` मेथड को Z3 व्यक्ति के रूप में इनपुट दिया जाता है और मॉडल में उस व्यक्ति को निर्धारित मान लौटाता है।

Here is an example of how to print the model:

यहां एक उदाहरण है कि मॉडल को कैसे प्रिंट करें:

```python
m = Solver()
m.add(x > 5)
m.add(y == x + 2)

if m.check() == sat:
    print(m.model())
```

This will print the model in the following format:

यह निम्नलिखित प्रारूप में मॉडल प्रिंट करेगा:

```
[y = 7, x = 6]
```

In this example, the model assigns the value 7 to the variable `y` and the value 6 to the variable `x`.

इस उदाहरण में, मॉडल वेरिएबल `y` को मान 7 और वेरिएबल `x` को मान 6 निर्धारित करता है।
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
# मशीन अंकगणित

आधुनिक सीपीयू और मुख्य-प्रवाह प्रोग्रामिंग भाषाएं **निश्चित-आकार बिट-वेक्टर्स** पर अंकगणित का उपयोग करती हैं। मशीन अंकगणित Z3Py में **बिट-वेक्टर्स** के रूप में उपलब्ध हैं।
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
## साइन्ड/अनसाइन्ड नंबर

Z3 में, अंकों को साइन्ड या अनसाइन्ड के रूप में कैसे ट्रीट किया जाता है, इसमें अंतर होता है। Z3Py में, ऑपरेटर **<, <=, >, >=, /, % और >>** साइन्ड संस्करण को दर्शाते हैं। संबंधित **अनसाइन्ड** ऑपरेटर हैं **ULT, ULE, UGT, UGE, UDiv, URem और LShR।**
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
## फ़ंक्शन्स

**इंटरप्रिटेड फ़ंक्शन्स** जैसे कि गणितीय जहां **फ़ंक्शन +** का **निश्चित मान्यांकन** होता है (यह दो नंबर जोड़ता है)। **अव्याख्यात फ़ंक्शन्स** और स्थिर मान हैं **अधिकतम लचीले** होते हैं; वे **किसी भी मान्यांकन** को अनुमति देते हैं जो फ़ंक्शन या स्थिर मान के **बाधाओं** के साथ **संगत** होता है।

उदाहरण: x पर दो बार लागू किए गए f का परिणाम फिर से x होता है, लेकिन x पर एक बार लागू किए गए f का परिणाम x से अलग होता है।
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
# उदाहरण

## सुडोकू समाधानकर्ता

```python
from z3 import *

def solve_sudoku(grid):
    # Create a 9x9 grid of integer variables
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # Each cell must contain a value between 1 and 9
    cell_constraints = [And(1 <= cells[i][j], cells[i][j] <= 9) for i in range(9) for j in range(9)]

    # Each row must contain distinct values
    row_constraints = [Distinct(cells[i]) for i in range(9)]

    # Each column must contain distinct values
    column_constraints = [Distinct([cells[i][j] for i in range(9)]) for j in range(9)]

    # Each 3x3 subgrid must contain distinct values
    subgrid_constraints = [Distinct([cells[i + k][j + l] for k in range(3) for l in range(3)]) for i in range(0, 9, 3) for j in range(0, 9, 3)]

    # Combine all constraints
    constraints = cell_constraints + row_constraints + column_constraints + subgrid_constraints

    # Create a solver and add the constraints
    solver = Solver()
    solver.add(constraints)

    # Add the initial values from the grid
    for i in range(9):
        for j in range(9):
            if grid[i][j] != 0:
                solver.add(cells[i][j] == grid[i][j])

    # Check if there is a solution
    if solver.check() == sat:
        # Get the solution
        model = solver.model()

        # Extract the values from the model
        solution = [[model.evaluate(cells[i][j]).as_long() for j in range(9)] for i in range(9)]

        return solution

    return None

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
solution = solve_sudoku(grid)

# Print the solution
if solution:
    for row in solution:
        print(row)
else:
    print("No solution found.")
```

यहां एक सुडोकू समाधानकर्ता दिया गया है जो एक 9x9 ग्रिड को समाधान करने के लिए इंटीजर चर के चरणों का उपयोग करता है। यह ग्रिड एक सुडोकू पहेली को प्रदर्शित करता है, जहां 0 रिक्त स्थानों को भरने के लिए एक समाधान ढूंढने का प्रयास किया जाता है। यदि एक समाधान पाया जाता है, तो उसे प्रिंट किया जाता है, अन्यथा "कोई समाधान नहीं मिला" प्रिंट किया जाता है।
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
# संदर्भ

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड** करने की उपलब्धता चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** का** **अनुसरण** करें।**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>
