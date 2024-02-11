# Basiese Python

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Python Basiese Beginsels

### Nuttige inligting

list(xrange()) == range() --> In python3 is range die xrange van python2 (dit is nie 'n lys nie, maar 'n generator)\
Die verskil tussen 'n Tuple en 'n Lys is dat die posisie van 'n waarde in 'n tuple betekenis daaraan gee, maar die lyse is net geordende waardes. Tuples het strukture, maar lyse het 'n volgorde.

### Hoofhandelinge

Om 'n getal te verhoog, gebruik jy: 3\*\*2 (nie 3^2 nie)\
As jy 2/3 doen, gee dit 1 terug omdat jy twee ints (heeltalle) deel. As jy desimale wil hê, moet jy floats deel (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a en b\
a of b\
nie a\
float(a)\
int(a)\
str(d)\
ord("A") = 65\
chr(65) = 'A'\
hex(100) = '0x64'\
hex(100)\[2:] = '64'\
isinstance(1, int) = True\
"a b".split(" ") = \['a', 'b']\
" ".join(\['a', 'b']) = "a b"\
"abcdef".startswith("ab") = True\
"abcdef".contains("abc") = True\
"abc\n".strip() = "abc"\
"apbc".replace("p","") = "abc"\
dir(str) = Lys van al die beskikbare metodes\
help(str) = Definisie van die klas str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Voeg karakters bymekaar**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Dele van 'n lys**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ vanaf \[1] tot \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Kommentaar**\
\# Eenreëelkommentaar\
"""\
Verskeie reëls kommentaar\
Nog een\
"""

**Lusse**
```
if a:
#somethig
elif b:
#something
else:
#something

while(a):
#comething

for i in range(0,100):
#something from 0 to 99

for letter in "hola":
#something with a letter in "hola"
```
### Tuples

t1 = (1,'2,'three')\
t2 = (5,6)\
t3 = t1 + t2 = (1, '2', 'three', 5, 6)\
(4,) = Singelton\
d = () leë tuple\
d += (4,) --> Voeg by 'n tuple\
KAN NIE! --> t1\[1] == 'Nuwe waarde'\
list(t2) = \[5,6] --> Van tuple na lys

### Lys (array)

d = \[] leë\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> Van lys na tuple

### Woordeskat

d = {} leë\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #Onafhanklike kopie\
monthNumbers.get('key',0) #Kyk of sleutel bestaan, Gee waarde van monthNumbers\["key"] of 0 as dit nie bestaan nie

### Stel

In stelle is daar geen herhalings nie\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Geen herhalings\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #As teenwoordig, verwyder dit, as nie, niks\
myset.remove(10) #As teenwoordig, verwyder dit, as nie, gooi 'n uitsondering\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Waardes in myset OF myset2\
myset.intersection(myset2) #Waardes in myset EN myset2\
myset.difference(myset2) #Waardes in myset maar nie in myset2\
myset.symmetric\_difference(myset2) #Waardes wat nie in myset EN myset2 is (nie in beide nie)\
myset.pop() #Kry die eerste element van die stel en verwyder dit\
myset.intersection\_update(myset2) #myset = Elemente in beide myset en myset2\
myset.difference\_update(myset2) #myset = Elemente in myset maar nie in myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elemente wat nie in beide is nie

### Klasse

Die metode in \_\_It\_\_ sal gebruik word deur sort om te vergelyk of 'n objek van hierdie klas groter is as 'n ander
```python
class Person(name):
def __init__(self,name):
self.name= name
self.lastName = name.split(‘ ‘)[-1]
self.birthday = None
def __It__(self, other):
if self.lastName == other.lastName:
return self.name < other.name
return self.lastName < other.lastName #Return True if the lastname is smaller

def setBirthday(self, month, day. year):
self.birthday = date tame.date(year,month,day)
def getAge(self):
return (date time.date.today() - self.birthday).days


class MITPerson(Person):
nextIdNum = 0	# Attribute of the Class
def __init__(self, name):
Person.__init__(self,name)
self.idNum = MITPerson.nextIdNum  —> Accedemos al atributo de la clase
MITPerson.nextIdNum += 1 #Attribute of the class +1

def __it__(self, other):
return self.idNum < other.idNum
```
### map, zip, filter, lambda, sorted en eenregelige oplossingen

**Map** is soos: \[f(x) vir x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** stop wanneer die kortste van foo of bar stop:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word
```
def make_adder(n):
return lambda x: x+n
plus3 = make_adder(3)
plus3(4) = 7 # 3 + 4 = 7

class Car:
crash = lambda self: print('Boom!')
my_car = Car(); my_car.crash() = 'Boom!'
```
mult1 = \[x vir x in \[1, 2, 3, 4, 5, 6, 7, 8, 9] as x%3 == 0 ]

### Uitsonderings
```
def divide(x,y):
try:
result = x/y
except ZeroDivisionError, e:
print “division by zero!” + str(e)
except TypeError:
divide(int(x),int(y))
else:
print “result i”, result
finally
print “executing finally clause in any case”
```
### Assert()

As die voorwaarde vals is, sal die string op die skerm gedruk word.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Opwekkers, opbrengs

'n Opwekker, in plaas van om iets terug te gee, "lewer" iets op. Wanneer jy dit toegang gee, sal dit die eerste gegenereerde waarde "teruggee", dan kan jy dit weer toegang gee en dit sal die volgende gegenereerde waarde teruggee. So, al die waardes word nie op dieselfde tyd gegenereer nie en baie geheue kan bespaar word deur dit te gebruik in plaas van 'n lys met al die waardes.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Fout

### Reëlmatige Uitdrukkings

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Spesiale betekenisse:**\
. --> Alles\
\w --> \[a-zA-Z0-9\_]\
\d --> Nommer\
\s --> Spasie karakter\[ \n\r\t\f]\
\S --> Nie-spasie karakter\
^ --> Begin met\
$ --> Eindig met\
\+ --> Een of meer\
\* --> 0 of meer\
? --> 0 of 1 voorkomste

**Opsies:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Laat punt om nuwe lyn te pas\
MULTILINE --> Laat ^ en $ om in verskillende lyne te pas

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Genereer kombinasies tussen 1 of meer lysse, dalk herhalende waardes, kartesiese produk (verdelings eienskap)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Genereer kombinasies van alle karakters op elke posisie\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Elke moontlike kombinasie\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Elke moontlike kombinasie van lengte 2

**combinations**\
from itertools import **combinations** --> Genereer alle moontlike kombinasies sonder om karakters te herhaal (as "ab" bestaan, genereer dit nie "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Genereer alle moontlike kombinasies vanaf die karakter voort (byvoorbeeld, die 3de is gemeng vanaf die 3de voort maar nie met die 2de of eerste nie)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Versierders

Versierder wat die tyd meet wat 'n funksie neem om uitgevoer te word (vanaf [hier](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
```python
from functools import wraps
import time
def timeme(func):
@wraps(func)
def wrapper(*args, **kwargs):
print("Let's call our decorated function")
start = time.time()
result = func(*args, **kwargs)
print('Execution time: {} seconds'.format(time.time() - start))
return result
return wrapper

@timeme
def decorated_func():
print("Decorated func!")
```
As jy dit uitvoer, sal jy iets soos die volgende sien:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
