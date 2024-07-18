# Grundlagen von Python

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Python-Grundlagen

### Nützliche Informationen

list(xrange()) == range() --> In Python 3 ist range das xrange von Python 2 (es ist kein Liste, sondern ein Generator)\
Der Unterschied zwischen einem Tupel und einer Liste besteht darin, dass die Position eines Werts in einem Tupel eine Bedeutung hat, während Listen nur geordnete Werte sind. Tupel haben Strukturen, Listen haben eine Reihenfolge.

### Hauptoperationen

Um eine Zahl zu potenzieren, verwenden Sie: 3\*\*2 (nicht 3^2)\
Wenn Sie 2/3 eingeben, gibt es 1 zurück, weil Sie zwei Ganzzahlen (integers) dividieren. Wenn Sie Dezimalzahlen möchten, sollten Sie Floats dividieren (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a and b\
a or b\
not a\
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
dir(str) = Liste aller verfügbaren Methoden\
help(str) = Definition der Klasse str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Zeichen verbinden**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Teile einer Liste**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ von \[1] bis \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Kommentare**\
\# Einzeiliger Kommentar\
"""\
Mehrere Zeilen Kommentar\
Ein weiterer\
"""

**Schleifen**
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
### Tupel

t1 = (1, '2', 'drei')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'drei', 5, 6)\
(4,) = Singelton\
d = () leeres Tupel\
d += (4,) --> Hinzufügen zu einem Tupel\
KANN NICHT! --> t1\[1] == 'Neuer Wert'\
list(t2) = \[5, 6] --> Vom Tupel zur Liste

### Liste (Array)

d = \[] leer\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> Von Liste zu Tupel

### Wörterbuch

d = {} leer\
monthNumbers={1:'Jan', 2: 'feb','feb':2}--> monthNumbers ->{1:'Jan', 2: 'feb','feb':2}\
monthNumbers\[1] = 'Jan'\
monthNumbers\['feb'] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Jan', 'feb', 2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:'Jan', 2: 'feb','feb':2}\
mN = monthNumbers.copy() #Unabhängige Kopie\
monthNumbers.get('key',0) #Überprüfen, ob der Schlüssel existiert, Rückgabe des Werts von monthNumbers\["key"] oder 0, wenn er nicht existiert

### Menge

In Mengen gibt es keine Wiederholungen\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Keine Wiederholungen\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Wenn vorhanden, entfernen, wenn nicht, nichts\
myset.remove(10) #Wenn vorhanden, entfernen, wenn nicht, Ausnahme auslösen\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Werte in myset ODER myset2\
myset.intersection(myset2) #Werte in myset UND myset2\
myset.difference(myset2) #Werte in myset, aber nicht in myset2\
myset.symmetric\_difference(myset2) #Werte, die weder in myset NOCH in myset2 sind (nicht in beiden)\
myset.pop() #Das erste Element der Menge erhalten und entfernen\
myset.intersection\_update(myset2) #myset = Elemente sowohl in myset als auch in myset2\
myset.difference\_update(myset2) #myset = Elemente in myset, aber nicht in myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elemente, die in keinem der beiden sind

### Klassen

Die Methode in \_\_It\_\_ wird von sort verwendet, um zu überprüfen, ob ein Objekt dieser Klasse größer ist als ein anderes
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
### map, zip, filter, lambda, sorted und Einzeiler

**Map** funktioniert wie: \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** stoppt, wenn der kürzere von foo oder bar stoppt:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** wird verwendet, um eine Funktion zu definieren\
(lambda x,y: x+y)(5,3) = 8 --> Verwenden Sie lambda als einfache **Funktion**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Verwenden Sie lambda zum Sortieren einer Liste\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Verwenden Sie lambda zum Filtern\
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
mult1 = \[x für x in \[1, 2, 3, 4, 5, 6, 7, 8, 9\] wenn x%3 == 0 ]

### Ausnahmen
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

Wenn die Bedingung falsch ist, wird der String auf dem Bildschirm ausgegeben.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generatoren, yield

Ein Generator gibt nicht etwas zurück, sondern er "yieldet" etwas. Wenn du darauf zugreifst, wird er den ersten generierten Wert "zurückgeben", dann kannst du erneut darauf zugreifen und er wird den nächsten generierten Wert zurückgeben. Daher werden nicht alle Werte gleichzeitig generiert und es könnte viel Speicher gespart werden, wenn man dies anstelle einer Liste mit allen Werten verwendet.
```
def myGen(n):
yield n
yield n + 1
```
```markdown
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Fehler

### Reguläre Ausdrücke

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Besondere Bedeutungen:**\
. --> Alles\
\w --> \[a-zA-Z0-9\_]\
\d --> Zahl\
\s --> Leerzeichenzeichen\[ \n\r\t\f]\
\S --> Nicht-Leerzeichen-Zeichen\
^ --> Beginnt mit\
$ --> Endet mit\
\+ --> Ein oder mehr\
\* --> 0 oder mehr\
? --> 0 oder 1 Vorkommen

**Optionen:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Erlaubt Punkt, um Zeilenumbruch anzupassen\
MULTILINE --> Erlaubt ^ und $ in verschiedenen Zeilen anzupassen

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Generiert Kombinationen zwischen 1 oder mehr Listen, möglicherweise wiederholende Werte, kartesisches Produkt (Verteilungseigenschaft)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Generiert Kombinationen aller Zeichen an jeder Position\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Jede mögliche Kombination\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Jede mögliche Kombination der Länge 2

**combinations**\
from itertools import **combinations** --> Generiert alle möglichen Kombinationen ohne wiederholende Zeichen (wenn "ab" vorhanden ist, wird nicht "ba" generiert)\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Generiert alle möglichen Kombinationen ab dem Zeichen (zum Beispiel wird das 3. ab dem 3. gemischt, aber nicht mit dem 2. oder 1.)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Dekorateure

Dekorateur, der die Zeit misst, die eine Funktion benötigt, um ausgeführt zu werden (von [hier](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Wenn Sie es ausführen, sehen Sie etwas Ähnliches wie das Folgende:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{% hint style="success" %}
Lernen Sie AWS-Hacking und üben Sie:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking und üben Sie: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}
