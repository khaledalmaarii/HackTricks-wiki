# Βασική Python

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικά της Python

### Χρήσιμες πληροφορίες

list(xrange()) == range() --> Στην Python 3, η range είναι η xrange της Python 2 (δεν είναι μια λίστα αλλά ένας γεννήτορας)\
Η διαφορά μεταξύ ενός Tuple και μιας Λίστας είναι ότι η θέση μιας τιμής σε ένα Tuple της δίνει νόημα, ενώ οι λίστες είναι απλά ταξινομημένες τιμές. Τα Tuple έχουν δομές, αλλά οι λίστες έχουν μια σειρά.

### Κύριες λειτουργίες

Για να αυξήσετε έναν αριθμό χρησιμοποιείτε: 3\*\*2 (όχι 3^2)\
Εάν κάνετε 2/3 επιστρέφει 1 επειδή διαιρείτε δύο ακέραιους αριθμούς (integers). Εάν θέλετε δεκαδικά ψηφία θα πρέπει να διαιρέσετε δεκαδικούς αριθμούς (2.0/3.0).\
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
dir(str) = Λίστα με όλες τις διαθέσιμες μεθόδους\
help(str) = Ορισμός της κλάσης str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Ένωση χαρακτήρων**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Μέρη μιας λίστας**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ από \[1] έως \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Σχόλια**\
\# Σχόλιο μιας γραμμής\
"""\
Πολλαπλά σχόλια γραμμών\
Άλλο ένα\
"""

**Βρόχοι**
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
### Πλειάδες (Tuples)

t1 = (1, '2', 'τρία')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'τρία', 5, 6)\
(4,) = Μοναδικός\
d = () κενή πλειάδα\
d += (4,) --> Προσθήκη σε πλειάδα\
ΔΕΝ ΓΙΝΕΤΑΙ! --> t1\[1] == 'Νέα τιμή'\
list(t2) = \[5, 6] --> Από πλειάδα σε λίστα

### Λίστες (Πίνακες)

d = \[] κενή\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> Από λίστα σε πλειάδα

### Λεξικά (Dictionaries)

d = {} κενό\
monthNumbers = {1: 'Ιαν', 2: 'φεβ', 'φεβ': 2} --> monthNumbers -> {1: 'Ιαν', 2: 'φεβ', 'φεβ': 2}\
monthNumbers\[1] = 'Ιαν'\
monthNumbers\[‘φεβ’] = 2\
list(monthNumbers) = \[1, 2, 'φεβ']\
monthNumbers.values() = \['Ιαν', 'φεβ', 2]\
keys = \[k for k in monthNumbers]\
a = {'9': 9}\
monthNumbers.update(a) = {'9': 9, 1: 'Ιαν', 2: 'φεβ', 'φεβ': 2}\
mN = monthNumbers.copy() #Ανεξάρτητο αντίγραφο\
monthNumbers.get('key', 0) #Έλεγχος αν υπάρχει το κλειδί, Επιστροφή της τιμής του monthNumbers\["key"] ή 0 αν δεν υπάρχει

### Σύνολα (Sets)

Στα σύνολα δεν υπάρχουν επαναλήψεις\
myset = set(\['α', 'β']) = {'α', 'β'}\
myset.add('γ') = {'α', 'β', 'γ'}\
myset.add('α') = {'α', 'β', 'γ'} #Χωρίς επανάληψη\
myset.update(\[1, 2, 3]) = set(\['α', 1, 2, 'β', 'γ', 3])\
myset.discard(10) #Αν υπάρχει, αφαίρεσέ το, αλλιώς τίποτα\
myset.remove(10) #Αν υπάρχει, αφαίρεσέ το, αλλιώς αναίρεση\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Τιμές που υπάρχουν στο myset Ή myset2\
myset.intersection(myset2) #Τιμές που υπάρχουν και στο myset ΚΑΙ myset2\
myset.difference(myset2) #Τιμές που υπάρχουν στο myset αλλά όχι στο myset2\
myset.symmetric\_difference(myset2) #Τιμές που δεν υπάρχουν ούτε στο myset ΟΥΤΕ myset2 (δεν υπάρχουν και στα δύο)\
myset.pop() #Πάρε το πρώτο στοιχείο του συνόλου και αφαίρεσέ το\
myset.intersection\_update(myset2) #myset = Στοιχεία που υπάρχουν και στο myset και στο myset2\
myset.difference\_update(myset2) #myset = Στοιχεία που υπάρχουν στο myset αλλά όχι στο myset2\
myset.symmetric\_difference\_update(myset2) #myset = Στοιχεία που δεν υπάρχουν ούτε στο myset ΟΥΤΕ myset2

### Κλάσεις (Classes)

Η μέθοδος στο \_\_It\_\_ θα χρησιμοποιηθεί από την sort για να συγκρίνει αν ένα αντικείμενο αυτής της κλάσης είναι μεγαλύτερο από ένα άλλο
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
### map, zip, filter, lambda, sorted και μία γραμμή

Το **Map** είναι σαν: \[f(x) για x σε iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**Zip** σταματάει όταν το μικρότερο από τα foo ή bar σταματήσει:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** χρησιμοποιείται για να ορίσει μια συνάρτηση\
(lambda x,y: x+y)(5,3) = 8 --> Χρησιμοποιήστε το lambda ως απλή **συνάρτηση**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Χρησιμοποιήστε το lambda για να ταξινομήσετε μια λίστα\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Χρησιμοποιήστε το lambda για να φιλτράρετε\
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
mult1 = \[x για x σε \[1, 2, 3, 4, 5, 6, 7, 8, 9] αν x%3 == 0 ]

### Εξαιρέσεις
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

Εάν η συνθήκη είναι ψευδής, η συμβολοσειρά θα εκτυπωθεί στην οθόνη.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Γεννήτριες, yield

Μια γεννήτρια, αντί να επιστρέφει κάτι, "παράγει" κάτι. Όταν την αποκτάτε πρόσβαση, θα "επιστρέψει" την πρώτη τιμή που παράχθηκε, και στη συνέχεια μπορείτε να την αποκτήσετε ξανά και θα επιστρέψει την επόμενη τιμή που παράχθηκε. Έτσι, όλες οι τιμές δεν παράγονται ταυτόχρονα και μπορεί να εξοικονομηθεί πολύ μνήμη χρησιμοποιώντας αυτό αντί για μια λίστα με όλες τις τιμές.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Σφάλμα

### Κανονικές εκφράσεις

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Ειδικές σημασίες:**\
. --> Όλα\
\w --> \[a-zA-Z0-9\_]\
\d --> Αριθμός\
\s --> Χαρακτήρας κενού διαστήματος\[ \n\r\t\f]\
\S --> Χαρακτήρας μη κενού διαστήματος\
^ --> Αρχίζει με\
$ --> Τελειώνει με\
\+ --> Ένας ή περισσότεροι\
\* --> 0 ή περισσότεροι\
? --> 0 ή 1 εμφανίσεις

**Επιλογές:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Επιτρέπει την αντιστοίχιση του τελείας με νέα γραμμή\
MULTILINE --> Επιτρέπει την αντιστοίχιση του ^ και του $ σε διαφορετικές γραμμές

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Δημιουργεί συνδυασμούς μεταξύ 1 ή περισσότερων λιστών, ίσως επαναλαμβανόμενες τιμές, καρτεσιανό γινόμενο (ιδιότητα διανομής)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Δημιουργεί συνδυασμούς όλων των χαρακτήρων σε κάθε θέση\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Κάθε δυνατός συνδυασμός\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Κάθε δυνατός συνδυασμός μήκους 2

**combinations**\
from itertools import **combinations** --> Δημιουργεί όλους τους δυνατούς συνδυασμούς χωρίς επανάληψη χαρακτήρων (αν υπάρχει "ab", δεν δημιουργεί "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Δημιουργεί όλους τους δυνατούς συνδυασμούς από τον χαρακτήρα και μετά (για παράδειγμα, το 3ο ανακατεύεται από το 3ο και μετά, αλλά όχι με το 2ο ή το 1ο)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Διακοσμητές

Διακοσμητής που μετρά τον χρόνο που χρειάζεται μια συνάρτηση για να εκτελεστεί (από [εδώ](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Εάν το εκτελέσετε, θα δείτε κάτι παρόμοιο με το παρακάτω:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
