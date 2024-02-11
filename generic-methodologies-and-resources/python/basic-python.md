# Podstawy Pythona

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawy Pythona

### Przydatne informacje

list(xrange()) == range() --> W pythonie 3 zakres (range) jest odpowiednikiem zakresu (xrange) w pythonie 2 (nie jest to lista, ale generator)\
Różnica między Tuple a Listą polega na tym, że pozycja wartości w krotce ma znaczenie, podczas gdy listy są po prostu uporządkowanymi wartościami. Krotki mają strukturę, ale listy mają porządek.

### Główne operacje

Aby podnieść liczbę do potęgi, używamy: 3\*\*2 (nie 3^2)\
Jeśli wykonasz 2/3, zwróci 1, ponieważ dzielisz dwie liczby całkowite (integers). Jeśli chcesz uzyskać liczby dziesiętne, powinieneś podzielić liczby zmiennoprzecinkowe (2.0/3.0).\
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
dir(str) = Lista wszystkich dostępnych metod\
help(str) = Definicja klasy str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Łączenie znaków**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Części listy**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ od \[1] do \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Komentarze**\
\# Komentarz jednolinijkowy\
"""\
Komentarz wieloliniowy\
Kolejny\
"""

**Pętle**
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
### Krotki

t1 = (1,'2,'trzy')\
t2 = (5,6)\
t3 = t1 + t2 = (1, '2', 'trzy', 5, 6)\
(4,) = Singelton\
d = () pusta krotka\
d += (4,) --> Dodawanie do krotki\
NIE MOŻNA! --> t1\[1] == 'Nowa wartość'\
list(t2) = \[5,6] --> Z krotki do listy

### Lista (tablica)

d = \[] pusta\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> Z listy do krotki

### Słownik

d = {} pusty\
monthNumbers={1:’Sty’, 2: ‘lut’,’lut’:2}—> monthNumbers ->{1:’Sty’, 2: ‘lut’,’lut’:2}\
monthNumbers\[1] = ‘Sty’\
monthNumbers\[‘lut’] = 2\
list(monthNumbers) = \[1,2,’lut’]\
monthNumbers.values() = \[‘Sty’,’lut’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Sty’, 2: ‘lut’,’lut’:2}\
mN = monthNumbers.copy() #Niezależna kopia\
monthNumbers.get('klucz',0) #Sprawdź, czy klucz istnieje, Zwróć wartość monthNumbers\["klucz"] lub 0, jeśli nie istnieje

### Zbiór

W zbiorach nie ma powtórzeń\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Brak powtórzeń\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Jeśli jest obecny, usuń go, jeśli nie, nic\
myset.remove(10) #Jeśli jest obecny, usuń go, jeśli nie, zgłoś wyjątek\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Wartości w myset LUB myset2\
myset.intersection(myset2) #Wartości w myset I myset2\
myset.difference(myset2) #Wartości w myset, ale nie w myset2\
myset.symmetric\_difference(myset2) #Wartości, które nie są w myset I myset2 (nie w obu)\
myset.pop() #Pobierz pierwszy element zbioru i usuń go\
myset.intersection\_update(myset2) #myset = Elementy zarówno w myset, jak i myset2\
myset.difference\_update(myset2) #myset = Elementy w myset, ale nie w myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elementy, które nie są w obu

### Klasy

Metoda \_\_lt\_\_ będzie używana przez sortowanie do porównywania, czy obiekt tej klasy jest większy od innego
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
### map, zip, filter, lambda, sorted i jednolinijkowce

**Map** działa tak: \[f(x) dla x w iterowalnym] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**Zip** kończy działanie, gdy skończy się krótszy z foo lub bar:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** służy do definiowania funkcji\
(lambda x,y: x+y)(5,3) = 8 --> Użyj lambdy jako prostej **funkcji**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Użyj lambdy do sortowania listy\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Użyj lambdy do filtrowania\
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
mult1 = \[x dla x in \[1, 2, 3, 4, 5, 6, 7, 8, 9] jeśli x%3 == 0 ]

### Wyjątki
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

Jeśli warunek jest fałszywy, ciąg znaków zostanie wyświetlony na ekranie.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generatory, yield

Generator zamiast zwracać coś, "yielduje" coś. Gdy do niego się odwołasz, "zwróci" pierwszą wygenerowaną wartość, a następnie będziesz mógł się do niego odwołać ponownie i zwróci kolejną wygenerowaną wartość. W ten sposób wszystkie wartości nie są generowane jednocześnie, co pozwala zaoszczędzić dużo pamięci w porównaniu do listy zawierającej wszystkie wartości.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Błąd

### Wyrażenia regularne

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Specjalne znaczenia:**\
. --> Wszystko\
\w --> \[a-zA-Z0-9\_]\
\d --> Liczba\
\s --> Biały znak \[ \n\r\t\f]\
\S --> Znak nie będący białym znakiem\
^ --> Zaczyna się od\
$ --> Kończy się na\
\+ --> Jeden lub więcej\
\* --> Zero lub więcej\
? --> 0 lub 1 wystąpienia

**Opcje:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Pozwala na dopasowanie kropki do nowej linii\
MULTILINE --> Pozwala na dopasowanie ^ i $ w różnych liniach

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Generuje kombinacje między 1 lub więcej listami, możliwe powtórzenie wartości, iloczyn kartezjański (własność rozdzielności)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Generuje kombinacje wszystkich znaków na każdej pozycji\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Wszystkie możliwe kombinacje\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Wszystkie możliwe kombinacje o długości 2

**combinations**\
from itertools import **combinations** --> Generuje wszystkie możliwe kombinacje bez powtarzających się znaków (jeśli istnieje "ab", nie generuje "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Generuje wszystkie możliwe kombinacje od znaku w przód (na przykład 3. jest mieszane od 3. w przód, ale nie z 2. lub 1.)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Dekoratory

Dekorator, który mierzy czas potrzebny do wykonania funkcji (z [tutaj](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Jeśli uruchomisz to, zobaczysz coś takiego jak poniżej:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
