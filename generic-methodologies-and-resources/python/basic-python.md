# Basiese Python

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Python Basiese Beginsels

### Nuttige inligting

list(xrange()) == range() --> In python3 is die reeks die xrange van python2 (dit is nie 'n lys nie, maar 'n generator)\
Die verskil tussen 'n Tuple en 'n Lys is dat die posisie van 'n waarde in 'n tuple dit betekenis gee, maar die lyste is net geordende waardes. Tuples het strukture maar lyste het 'n volgorde.

### Hoof-operasies

Om 'n nommer te verhoog gebruik jy: 3\*\*2 (nie 3^2 nie)\
As jy 2/3 doen, gee dit 1 terug omdat jy twee ints (heeltalle) verdeel. As jy desimale wil hê, moet jy drijfgetalle verdeel (2.0/3.0).\
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
isinstance(1, int) = Waar\
"a b".split(" ") = \['a', 'b']\
" ".join(\['a', 'b']) = "a b"\
"abcdef".startswith("ab") = Waar\
"abcdef".contains("abc") = Waar\
"abc\n".strip() = "abc"\
"apbc".replace("p","") = "abc"\
dir(str) = Lys van al die beskikbare metodes\
help(str) = Definisie van die klas str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Voeg karakters saam**\
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
\# Een reël kommentaar\
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

t1 = (1, '2', 'drie')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'drie', 5, 6)\
(4,) = Singelton\
d = () leë tuple\
d += (4,) --> Byvoeging in 'n tuple\
KAN NIE! --> t1\[1] == 'Nuwe waarde'\
list(t2) = \[5, 6] --> Van tuple na lys

### List (array)

d = \[] leeg\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> Van lys na tuple

### Dictionary

d = {} leeg\
monthNumbers={1:'Jan', 2: 'feb','feb':2}—> monthNumbers ->{1:'Jan', 2: 'feb','feb':2}\
monthNumbers\[1] = 'Jan'\
monthNumbers\['feb'] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Jan', 'feb', 2]\
keys = \[k vir k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:'Jan', 2: 'feb','feb':2}\
mN = monthNumbers.copy() #Onafhanklike kopie\
monthNumbers.get('sleutel',0) #Kyk of sleutel bestaan, Gee waarde van monthNumbers\["sleutel"] of 0 indien dit nie bestaan nie

### Set

In stelle is daar geen herhalings nie\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Geen herhalings\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Indien teenwoordig, verwyder dit, indien nie, niks\
myset.remove(10) #Indien teenwoordig, verwyder dit, indien nie, gooi 'n uitsondering\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Waardes in myset OF myset2\
myset.intersection(myset2) #Waardes in myset EN myset2\
myset.difference(myset2) #Waardes in myset maar nie in myset2\
myset.symmetric\_difference(myset2) #Waardes wat nie in myset EN myset2 is nie (nie in beide nie)\
myset.pop() #Kry die eerste element van die stel en verwyder dit\
myset.intersection\_update(myset2) #myset = Elemente in beide myset en myset2\
myset.difference\_update(myset2) #myset = Elemente in myset maar nie in myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elemente wat nie in beide is

### Classes

Die metode in \_\_It\_\_ sal die een wees wat deur sort gebruik word om te vergelyk of 'n objek van hierdie klas groter is as 'n ander
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
### map, zip, filter, lambda, sorted en een-regelige programme

**Map** is soos: \[f(x) vir x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** stop wanneer die kortste van foo of bar stop:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** word gebruik om 'n funksie te definieer\
(lambda x,y: x+y)(5,3) = 8 --> Gebruik lambda as 'n eenvoudige **funksie**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Gebruik lambda om 'n lys te sorteer\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Gebruik lambda om te filter\
**reduce** (lambda x,y: x\*y, \[1,2,3,4]) = 24
```
def make_adder(n):
return lambda x: x+n
plus3 = make_adder(3)
plus3(4) = 7 # 3 + 4 = 7

class Car:
crash = lambda self: print('Boom!')
my_car = Car(); my_car.crash() = 'Boom!'
```
```html
mult1 = \[x vir x in \[1, 2, 3, 4, 5, 6, 7, 8, 9] as x%3 == 0 ]

### Uitsonderings
```
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

Indien die voorwaarde vals is, sal die string op die skerm gedruk word.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Opwekkers, opbrengs

'n Opwekker, in plaas van om iets terug te gee, "opbreng" dit iets. Wanneer jy dit toegang gee, sal dit die eerste waarde wat opgewek is "teruggee", dan kan jy dit weer toegang gee en dit sal die volgende waarde wat opgewek is teruggee. Dus, word nie al die waardes op dieselfde tyd opgewek nie en baie geheue kan bewaar word deur dit te gebruik in plaas van 'n lys met al die waardes.
```
def myGen(n):
yield n
yield n + 1
```
```afrikaans
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Fout

### Gereelde Uitdrukkings

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Spesiale betekenisse:**\
. --> Alles\
\w --> \[a-zA-Z0-9\_]\
\d --> Nommer\
\s --> WitSpasie karakter\[ \n\r\t\f]\
\S --> Nie-witSpasie karakter\
^ --> Begin met\
$ --> Eindig met\
\+ --> Een of meer\
\* --> 0 of meer\
? --> 0 of 1 voorkomste

**Opsies:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Laat die punt toe om 'n nuwe lyn te pas\
MULTILINE --> Laat ^ en $ toe om in verskillende lyne te pas

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Genereer kombinasies tussen 1 of meer lysse, dalk herhalende waardes, kartesiese produk (distributiewe eienskap)\
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

Versierder wat die tyd meet wat 'n funksie benodig om uitgevoer te word (van [hier](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
```
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
As jy dit hardloop, sal jy iets soos die volgende sien:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{% hint style="success" %}
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
