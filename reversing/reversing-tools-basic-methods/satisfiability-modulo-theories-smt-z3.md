<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법들:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


매우 기본적으로, 이 도구는 변수가 일부 조건을 만족해야 하는 값을 찾는 데 도움을 줍니다. 이러한 값을 수동으로 계산하는 것은 매우 귀찮을 수 있습니다. 따라서, Z3에 변수가 만족해야 하는 조건을 지정하면 (가능한 경우) 일부 값을 찾아줍니다.

**일부 텍스트와 예제는 [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)에서 가져온 것입니다.**

# 기본 작업

## 부울/And/Or/Not
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
## 정수/단순화/실수

SMT(Satisfiability Modulo Theories) 문제를 해결하기 위해 Z3는 정수, 단순화 및 실수와 관련된 다양한 기능을 제공합니다.

### 정수(Integers)

Z3는 정수 연산을 지원하며, 다음과 같은 연산자를 사용할 수 있습니다.

- `+`: 덧셈
- `-`: 뺄셈
- `*`: 곱셈
- `/`: 나눗셈
- `%`: 나머지
- `div`: 몫
- `mod`: 나머지
- `abs`: 절댓값
- `^`: 거듭제곱

또한, 비교 연산자도 사용할 수 있습니다.

- `=`: 같음
- `!=`: 같지 않음
- `<`: 작음
- `>`: 큼
- `<=`: 작거나 같음
- `>=`: 크거나 같음

### 단순화(Simplification)

Z3는 식을 단순화하는 기능을 제공합니다. 이를 통해 복잡한 식을 간단하게 표현할 수 있습니다. 단순화는 `simplify()` 함수를 사용하여 수행할 수 있습니다.

### 실수(Reals)

Z3는 실수 연산을 지원하며, 다음과 같은 연산자를 사용할 수 있습니다.

- `+`: 덧셈
- `-`: 뺄셈
- `*`: 곱셈
- `/`: 나눗셈
- `^`: 거듭제곱

또한, 비교 연산자도 사용할 수 있습니다.

- `=`: 같음
- `!=`: 같지 않음
- `<`: 작음
- `>`: 큼
- `<=`: 작거나 같음
- `>=`: 크거나 같음

Z3는 실수 연산에 대한 정확한 결과를 제공하지 않을 수 있으므로, 주의가 필요합니다.
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
## 모델 출력

To print the model, you can use the `model` object returned by the solver. The `model` object contains the assignments for each variable in the formula. 

To print the assignments, you can iterate over the variables and use the `eval` method to get the assigned value. 

Here is an example:

```python
for variable in model:
    value = model.eval(variable)
    print(f"{variable} = {value}")
```

This will print each variable along with its assigned value.
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
# 기계 산술

현대의 CPU와 주류 프로그래밍 언어는 **고정 크기 비트 벡터**를 사용하여 산술 연산을 수행합니다. 기계 산술은 Z3Py에서 **비트 벡터**로 사용할 수 있습니다.
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
## 부호 있는/부호 없는 숫자

Z3는 비트 벡터가 부호 있는지 없는지에 따라 다른 방식으로 처리되는 특수한 부호 있는 버전의 산술 연산을 제공합니다. Z3Py에서 **<, <=, >, >=, /, % 및 >>** 연산자는 **부호 있는** 버전에 해당합니다. 이에 대응하는 **부호 없는** 연산자는 **ULT, ULE, UGT, UGE, UDiv, URem 및 LShR**입니다.
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
## 함수

**해석 함수**는 **함수 +**가 **고정된 표준 해석**을 가지는 산술과 같은 함수입니다. **해석되지 않은 함수**와 상수는 **최대한 유연**합니다. 이들은 함수나 상수에 대한 **제약 조건**과 **일관성이 있는** **어떤 해석**이든 허용합니다.

예시: x에 대해 f를 두 번 적용하면 다시 x가 되지만, x에 대해 f를 한 번 적용하면 x와 다릅니다.
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
# 예제

## 스도쿠 퍼즐 풀이기

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
    col_constraints = [Distinct([cells[i][j] for i in range(9)]) for j in range(9)]

    # Each 3x3 subgrid must contain distinct values
    subgrid_constraints = [Distinct([cells[i + 3 * (k // 3)][j + 3 * (k % 3)] for i in range(3) for j in range(3)]) for k in range(9)]

    # Combine all constraints
    constraints = cell_constraints + row_constraints + col_constraints + subgrid_constraints

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

# Solve the Sudoku puzzle
solution = solve_sudoku(grid)

# Print the solution
if solution:
    for row in solution:
        print(row)
else:
    print("No solution found.")
```

```python
from z3 import *

def solve_sudoku(grid):
    # 9x9 그리드의 정수 변수 생성
    cells = [[Int(f"cell_{i}_{j}") for j in range(9)] for i in range(9)]

    # 각 셀은 1부터 9까지의 값을 가져야 함
    cell_constraints = [And(1 <= cells[i][j], cells[i][j] <= 9) for i in range(9) for j in range(9)]

    # 각 행은 서로 다른 값을 가져야 함
    row_constraints = [Distinct(cells[i]) for i in range(9)]

    # 각 열은 서로 다른 값을 가져야 함
    col_constraints = [Distinct([cells[i][j] for i in range(9)]) for j in range(9)]

    # 각 3x3 서브그리드는 서로 다른 값을 가져야 함
    subgrid_constraints = [Distinct([cells[i + 3 * (k // 3)][j + 3 * (k % 3)] for i in range(3) for j in range(3)]) for k in range(9)]

    # 모든 제약 조건을 결합
    constraints = cell_constraints + row_constraints + col_constraints + subgrid_constraints

    # Solver 생성 및 제약 조건 추가
    solver = Solver()
    solver.add(constraints)

    # 그리드에서 초기 값 추가
    for i in range(9):
        for j in range(9):
            if grid[i][j] != 0:
                solver.add(cells[i][j] == grid[i][j])

    # 해결책이 있는지 확인
    if solver.check() == sat:
        # 해결책 가져오기
        model = solver.model()

        # 모델에서 값 추출
        solution = [[model.evaluate(cells[i][j]).as_long() for j in range(9)] for i in range(9)]

        return solution

    return None

# 예제 스도쿠 그리드
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

# 스도쿠 퍼즐 풀기
solution = solve_sudoku(grid)

# 해결책 출력
if solution:
    for row in solution:
        print(row)
else:
    print("해결책을 찾을 수 없습니다.")
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
## 참고 자료

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
