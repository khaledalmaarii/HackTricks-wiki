# Python Base

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Basi di Python

### Informazioni utili

list(xrange()) == range() --> In python3 range è l'equivalente di xrange di python2 (non è una lista ma un generatore)\
La differenza tra una Tuple e una Lista è che la posizione di un valore in una tuple gli dà un significato, mentre le liste sono solo valori ordinati. Le tuple hanno una struttura, ma le liste hanno un ordine.

### Operazioni principali

Per elevare un numero si usa: 3\*\*2 (non 3^2)\
Se fai 2/3 restituisce 1 perché stai dividendo due interi (integers). Se vuoi decimali dovresti dividere float (2.0/3.0).\
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
dir(str) = Lista di tutti i metodi disponibili\
help(str) = Definizione della classe str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Unisci caratteri**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Parti di una lista**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ da \[1] a \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Commenti**\
\# Commento su una sola riga\
"""\
Commento su più righe\
Un altro\
"""

**Cicli**
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
### Tuple

t1 = (1, '2', 'tre')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'tre', 5, 6)\
(4,) = Singelton\
d = () tupla vuota\
d += (4,) --> Aggiunta in una tupla\
NON POSSIBILE! --> t1\[1] == 'Nuovo valore'\
list(t2) = \[5, 6] --> Da tupla a lista

### Lista (array)

d = \[] vuota\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> Da lista a tupla

### Dizionario

d = {} vuoto\
monthNumbers = {1: 'Gen', 2: 'feb', 'feb': 2} --> monthNumbers -> {1: 'Gen', 2: 'feb', 'feb': 2}\
monthNumbers\[1] = 'Gen'\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Gen', 'feb', 2]\
keys = \[k for k in monthNumbers]\
a = {'9': 9}\
monthNumbers.update(a) = {'9': 9, 1: 'Gen', 2: 'feb', 'feb': 2}\
mN = monthNumbers.copy() #Copia indipendente\
monthNumbers.get('key', 0) #Verifica se la chiave esiste, restituisce il valore di monthNumbers\["key"] o 0 se non esiste

### Insieme

Negli insiemi non ci sono ripetizioni\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Nessuna ripetizione\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Se presente, rimuovilo, altrimenti niente\
myset.remove(10) #Se presente, rimuovilo, altrimenti solleva un'eccezione\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Valori in myset O myset2\
myset.intersection(myset2) #Valori in myset E myset2\
myset.difference(myset2) #Valori in myset ma non in myset2\
myset.symmetric\_difference(myset2) #Valori che non sono in myset E myset2 (non in entrambi)\
myset.pop() #Ottieni il primo elemento dell'insieme e rimuovilo\
myset.intersection\_update(myset2) #myset = Elementi presenti sia in myset che in myset2\
myset.difference\_update(myset2) #myset = Elementi presenti in myset ma non in myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elementi che non sono presenti in entrambi

### Classi

Il metodo in \_\_It\_\_ sarà quello utilizzato da sort per confrontare se un oggetto di questa classe è più grande di un altro
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
### map, zip, filter, lambda, sorted e one-liners

**Map** è come: \[f(x) per x in iterabile] --> map(tupla,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** si interrompe quando il più corto tra foo e bar si interrompe:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** viene utilizzato per definire una funzione\
(lambda x,y: x+y)(5,3) = 8 --> Usa lambda come una semplice **funzione**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Usa lambda per ordinare una lista\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Usa lambda per filtrare\
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
mult1 = \[x per x in \[1, 2, 3, 4, 5, 6, 7, 8, 9] se x%3 == 0 ]

### Eccezioni
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

Se la condizione è falsa, la stringa verrà stampata a schermo.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generatori, yield

Un generatore, invece di restituire qualcosa, "yielda" qualcosa. Quando lo si accede, restituirà il primo valore generato, quindi è possibile accedervi nuovamente e restituirà il prossimo valore generato. Quindi, tutti i valori non vengono generati contemporaneamente e si può risparmiare molta memoria utilizzando questo invece di una lista con tutti i valori.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Errore

### Espressioni regolari

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Significati speciali:**\
. --> Tutto\
\w --> \[a-zA-Z0-9\_]\
\d --> Numero\
\s --> Carattere spazio bianco\[ \n\r\t\f]\
\S --> Carattere non spazio bianco\
^ --> Inizia con\
$ --> Finisce con\
\+ --> Uno o più\
\* --> 0 o più\
? --> 0 o 1 occorrenze

**Opzioni:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Consenti al punto di corrispondere a una nuova riga\
MULTILINE --> Consenti a ^ e $ di corrispondere in righe diverse

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Genera combinazioni tra 1 o più liste, forse ripetendo valori, prodotto cartesiano (proprietà distributiva)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Genera combinazioni di tutti i caratteri in ogni posizione\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Ogni possibile combinazione\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Ogni possibile combinazione di lunghezza 2

**combinations**\
from itertools import **combinations** --> Genera tutte le possibili combinazioni senza ripetere i caratteri (se "ab" esiste, non genera "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Genera tutte le possibili combinazioni dal carattere in poi (ad esempio, il terzo è mescolato dal terzo in poi ma non con il secondo o il primo)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Decoratori

Decoratore che misura il tempo necessario per eseguire una funzione (da [qui](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Se lo esegui, vedrai qualcosa di simile al seguente:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
