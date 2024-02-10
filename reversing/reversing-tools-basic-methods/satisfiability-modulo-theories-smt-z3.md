<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


Çok temel olarak, bu araç, bazı koşulları sağlaması gereken değişkenler için değerler bulmamıza yardımcı olacak ve bunları el ile hesaplamak çok sıkıcı olacaktır. Bu nedenle, Z3'e değişkenlerin sağlaması gereken koşulları belirtebilirsiniz ve mümkünse bazı değerler bulacaktır.

**Bazı metinler ve örnekler [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm) adresinden alınmıştır**

# Temel İşlemler

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
## Tamsayılar/Sadeleştirme/Gerçek Sayılar

SMT çözücüsü Z3, tamsayılar, sadeleştirme ve gerçek sayılarla çalışmak için kullanılabilir. Bu bölümde, Z3'ün bu tür ifadeleri nasıl işlediğini ve çözdüğünü öğreneceksiniz.

### Tamsayılar

Z3, tamsayılarla çalışmak için `Int` veri türünü sağlar. Tamsayı ifadeleri, aritmetik operatörlerle birleştirilerek oluşturulabilir. Örneğin, `x + y` veya `2 * z` gibi ifadeler geçerlidir. Z3, bu ifadeleri sadeleştirir ve sonucu en basit hale getirir.

### Sadeleştirme

Z3, ifadeleri sadeleştirirken, matematiksel eşitlikleri kullanır ve ifadeleri mümkün olduğunca basit hale getirir. Örneğin, `x + 0` ifadesi `x` olarak sadeleştirilir ve `x * 1` ifadesi de `x` olarak sadeleştirilir. Bu sadeleştirme işlemi, ifadelerin daha anlaşılır ve daha kolay çözülebilir hale gelmesini sağlar.

### Gerçek Sayılar

Z3, gerçek sayılarla çalışmak için `Real` veri türünü sağlar. Gerçek sayı ifadeleri, tamsayı ifadeleriyle aynı şekilde oluşturulabilir ve aritmetik operatörlerle birleştirilebilir. Z3, gerçek sayı ifadelerini de sadeleştirir ve sonucu en basit hale getirir.

Bu bölümde, Z3'ün tamsayılar, sadeleştirme ve gerçek sayılarla nasıl çalıştığını öğrendiniz. Bu bilgileri kullanarak, Z3'ü daha etkili bir şekilde kullanabilir ve tamsayı ve gerçek sayı ifadelerini çözebilirsiniz.
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
## Modeli Yazdırma

To print the model, you can use the `model` object obtained from the `check()` method. The `model` object represents the satisfying assignment for the given formula.

To print the model in Z3, you can use the `sexpr()` method of the `model` object. This method returns a string representation of the model in S-expression format.

Here is an example of how to print the model in Z3:

```python
s = Solver()
# ... add constraints and assertions ...
result = s.check()
if result == sat:
    m = s.model()
    print(m.sexpr())
```

This will print the model in S-expression format, which represents the values assigned to the variables in the model.

Keep in mind that the `sexpr()` method returns a string, so you can also save the model to a file or process it further as needed.
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
# Makine Aritmetiği

Modern CPU'lar ve yaygın kullanılan programlama dilleri, **sabit boyutlu bit vektörleri** üzerinde aritmetik işlemler yapar. Makine aritmetiği, Z3Py'de **Bit-Vektörleri** olarak mevcuttur.
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
## İmzalı/İmzasız Sayılar

Z3, **bit vektörünün imzalı veya imzasız olarak** işleme tabi tutulmasının farkını ortaya koyan özel imzalı versiyonlarını sağlar. Z3Py'de **<, <=, >, >=, /, % ve >>** operatörleri **imzalı** versiyonlara karşılık gelir. Buna karşılık **imzasız** operatörler ise **ULT, ULE, UGT, UGE, UDiv, URem ve LShR**'dir.
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
## Fonksiyonlar

**Yorumlanan fonksiyonlar**, **fonksiyon +**'ın **sabit bir standart yorumlaması** olan aritmetik gibi fonksiyonlardır (iki sayıyı toplar). **Yorumlanmayan fonksiyonlar** ve sabitler **maksimum esneklik** sağlar; fonksiyon veya sabit üzerindeki **kısıtlamalarla tutarlı olan herhangi bir yorumlamaya** izin verir.

Örnek: x'e iki kez uygulanan f, tekrar x'e döner, ancak x'e bir kez uygulanan f, x'ten farklıdır.
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
# Örnekler

## Sudoku çözücü
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
## Referanslar

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
