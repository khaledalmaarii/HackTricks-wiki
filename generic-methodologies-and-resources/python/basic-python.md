# Msingi wa Python

{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Msingi wa Python

### Taarifa muhimu

list(xrange()) == range() --> Katika python3 range ni xrange ya python2 (siyo orodha bali jenereta)\
Tofauti kati ya Tuple na Orodha ni kwamba nafasi ya thamani katika tuple inampa maana lakini orodha ni thamani zilizopangwa tu. Tuples zina miundo lakini orodha zina utaratibu.

### Operesheni Kuu

Kuongeza nambari unatumia: 3\*\*2 (siyo 3^2)\
Ikiwa unafanya 2/3 inarudisha 1 kwa sababu unagawanya ints (namba kamili). Ikiwa unataka desimali unapaswa kugawanya floats (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a na b\
a au b\
si a\
float(a)\
int(a)\
str(d)\
ord("A") = 65\
chr(65) = 'A'\
hex(100) = '0x64'\
hex(100)\[2:] = '64'\
isinstance(1, int) = Kweli\
"a b".split(" ") = \['a', 'b']\
" ".join(\['a', 'b']) = "a b"\
"abcdef".startswith("ab") = Kweli\
"abcdef".contains("abc") = Kweli\
"abc\n".strip() = "abc"\
"apbc".replace("p","") = "abc"\
dir(str) = Orodha ya njia zote zilizopo\
help(str) = Maelezo ya darasa la str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Jumuisha herufi**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Sehemu za orodha**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ kutoka \[1] hadi \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Maoni**\
\# Maoni ya mstari mmoja\
"""\
Maoni ya mistari kadhaa\
Nyingine\
"""

**Mizunguko**
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
d = () tupu tuple\
d += (4,) --> Kuongeza kwenye tuple\
CANT! --> t1\[1] == 'Thamani mpya'\
list(t2) = \[5,6] --> Kutoka kwenye tuple kwenda kwenye orodha

### List (array)

d = \[] tupu\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> Kutoka kwenye orodha kwenda kwenye tuple

### Dictionary

d = {} tupu\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #Nakala huru\
monthNumbers.get('key',0) #Angalia ikiwa funguo ipo, Rudi thamani ya monthNumbers\["funguo"] au 0 ikiwa haipo

### Set

Kwenye seti hakuna kurudia\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Hakuna kurudia\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Ikiwepo, iondoe, ikiwa la, usifanye kitu\
myset.remove(10) #Ikiwepo iondoe, ikiwa la, italeta kosa\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Thamani za myset AU myset2\
myset.intersection(myset2) #Thamani zilizo kwenye myset NA myset2\
myset.difference(myset2) #Thamani zilizo kwenye myset lakini sio kwenye myset2\
myset.symmetric\_difference(myset2) #Thamani ambazo sio kwenye myset NA myset2 (sio kwenye zote mbili)\
myset.pop() #Pata kipengele cha kwanza cha seti na iondoe\
myset.intersection\_update(myset2) #myset = Elementi zilizo kwenye myset na myset2\
myset.difference\_update(myset2) #myset = Elementi zilizo kwenye myset lakini sio kwenye myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elementi ambazo sio kwenye zote mbili

### Classes

Mbinu katika \_\_It\_\_ itatumika na sort kulinganisha ikiwa kitu cha darasa hili ni kikubwa kuliko kingine
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
### ramani, zip, chuja, lambda, iliyopangwa na mistari moja

**Ramani** ni kama: \[f(x) kwa x katika iterable] --> ramani(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** inakoma wakati mfupi kati ya foo au bar inapokoma:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** hutumika kufafanua kazi\
(lambda x,y: x+y)(5,3) = 8 --> Tumia lambda kama kazi rahisi\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Tumia lambda kupanga orodha\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Tumia lambda kuchuja\
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
mult1 = \[x kwa x katika \[1, 2, 3, 4, 5, 6, 7, 8, 9] kama x%3 == 0 ]

### Mafunzo ya Kipekee
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

Ikiwa hali ni ya uwongo, kamba itachapishwa kwenye skrini
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generators, yield

Mjenzi, badala ya kurudisha kitu, inatoa kitu. Unapopata, ita "rudisha" thamani ya kwanza iliyozalishwa, kisha, unaweza kuipata tena na itarudisha thamani inayofuata iliyozalishwa. Kwa hivyo, thamani zote hazizalishwi wakati mmoja na kiasi kikubwa cha kumbukumbu kinaweza kuokolewa kwa kutumia hii badala ya orodha na thamani zote.
```
def myGen(n):
yield n
yield n + 1
```
```markdown
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Kosa

### Mifumo ya Kawaida

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Maana Maalum:**\
. --> Kila kitu\
\w --> \[a-zA-Z0-9\_]\
\d --> Nambari\
\s --> Tabia ya nafasi nyeupe\[ \n\r\t\f]\
\S --> Tabia isiyo ya nafasi nyeupe\
^ --> Anza na\
$ --> Maliza na\
\+ --> Moja au zaidi\
\* --> 0 au zaidi\
? --> 0 au 1 mara

**Chaguo:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Ruhusu mshale kufanana na mstari mpya\
MULTILINE --> Ruhusu ^ na $ kufanana kwenye mistari tofauti

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Inazalisha mchanganyiko kati ya orodha 1 au zaidi, labda kurudia thamani, matokeo ya mchanganyiko wa Cartesian (mali ya kugawa)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Inazalisha mchanganyiko wa wahusika wote katika kila nafasi\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Kila mchanganyiko unaowezekana\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Kila mchanganyiko unaowezekana wa urefu wa 2

**combinations**\
from itertools import **combinations** --> Inazalisha mchanganyiko wote unaowezekana bila kurudia wahusika (ikiwa "ab" ipo, haitoi "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Inazalisha mchanganyiko wote unaowezekana kutoka kwa wahusika kuelekea mbele (kwa mfano, ya tatu inachanganywa kutoka ya tatu na kuendelea lakini sio na ya pili au ya kwanza)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Wapambaaji

Wapambaaji ambao hupima muda ambao kazi inahitaji kutekelezwa (kutoka [hapa](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Ukiikimbia, utaona kitu kama hiki:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
