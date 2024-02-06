# Python Básico

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Conceitos Básicos de Python

### Informações Úteis

list(xrange()) == range() --> No python3, range é o xrange do python2 (não é uma lista, mas um gerador)\
A diferença entre uma Tupla e uma Lista é que a posição de um valor em uma tupla lhe dá significado, mas as listas são apenas valores ordenados. As tuplas têm estruturas, mas as listas têm uma ordem.

### Principais operações

Para elevar um número você usa: 3\*\*2 (não 3^2)\
Se você fizer 2/3, ele retorna 1 porque está dividindo dois inteiros (int). Se você deseja decimais, deve dividir floats (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a and b\
a or b\
not a\
float(a)\
int(a)\
str(d)\
ord("A") = 65\
chr(65) = 'A'\
hex(100) = '0x64'\
hex(100)\[2:] = '64'\
isinstance(1, int) = True\
"a b".split(" ") = \['a', 'b']\
" ".join(\['a', 'b']) = "a b"\
"abcdef".startswith("ab") = True\
"abcdef".contains("abc") = True\
"abc\n".strip() = "abc"\
"apbc".replace("p","") = "abc"\
dir(str) = Lista de todos os métodos disponíveis\
help(str) = Definição da classe str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Juntar caracteres**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Partes de uma lista**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ de \[1] a \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Comentários**\
\# Comentário de uma linha\
"""\
Comentário de várias linhas\
Outro\
"""

**Loops**
```
if a:
#somethig
elif b:
#something
else:
#something

while(a):
#comething

for i in range(0,100):
#something from 0 to 99

for letter in "hola":
#something with a letter in "hola"
```
### Tuplas

t1 = (1, '2', 'três')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'três', 5, 6)\
(4,) = Singleton\
d = () tupla vazia\
d += (4,) --> Adicionando em uma tupla\
NÃO PODE! --> t1\[1] == 'Novo valor'\
list(t2) = \[5, 6] --> De tupla para lista

### Lista (array)

d = \[] vazio\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> De lista para tupla

### Dicionário

d = {} vazio\
monthNumbers={1:'Jan', 2: 'fev','fev':2}--> monthNumbers ->{1:'Jan', 2: 'fev','fev':2}\
monthNumbers\[1] = 'Jan'\
monthNumbers\['fev'] = 2\
list(monthNumbers) = \[1, 2, 'fev']\
monthNumbers.values() = \['Jan', 'fev', 2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:'Jan', 2: 'fev','fev':2}\
mN = monthNumbers.copy() #Cópia independente\
monthNumbers.get('chave',0) #Verifica se a chave existe, Retorna o valor de monthNumbers\["chave"] ou 0 se não existir

### Conjunto

Nos conjuntos não há repetições\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Sem repetições\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Se presente, remove, se não, nada\
myset.remove(10) #Se presente, remove, se não, gera exceção\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Valores em myset OU myset2\
myset.intersection(myset2) #Valores em myset E myset2\
myset.difference(myset2) #Valores em myset mas não em myset2\
myset.symmetric\_difference(myset2) #Valores que não estão em myset E myset2 (não em ambos)\
myset.pop() #Obtém o primeiro elemento do conjunto e remove\
myset.intersection\_update(myset2) #myset = Elementos em ambos myset e myset2\
myset.difference\_update(myset2) #myset = Elementos em myset mas não em myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elementos que não estão em ambos

### Classes

O método em \_\_It\_\_ será o utilizado pelo sort para comparar se um objeto desta classe é maior que outro
```python
class Person(name):
def __init__(self,name):
self.name= name
self.lastName = name.split(‘ ‘)[-1]
self.birthday = None
def __It__(self, other):
if self.lastName == other.lastName:
return self.name < other.name
return self.lastName < other.lastName #Return True if the lastname is smaller

def setBirthday(self, month, day. year):
self.birthday = date tame.date(year,month,day)
def getAge(self):
return (date time.date.today() - self.birthday).days


class MITPerson(Person):
nextIdNum = 0	# Attribute of the Class
def __init__(self, name):
Person.__init__(self,name)
self.idNum = MITPerson.nextIdNum  —> Accedemos al atributo de la clase
MITPerson.nextIdNum += 1 #Attribute of the class +1

def __it__(self, other):
return self.idNum < other.idNum
```
### map, zip, filter, lambda, sorted e one-liners

**Map** é como: \[f(x) para x em iterável] --> map(tupla, \[a, b]) = \[(1, 2, 3), (4, 5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** para quando o mais curto entre foo ou bar para:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** é usado para definir uma função\
(lambda x,y: x+y)(5,3) = 8 --> Use lambda como uma **função** simples\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Use lambda para ordenar uma lista\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Use lambda para filtrar\
**reduce** (lambda x,y: x\*y, \[1,2,3,4]) = 24
```
def make_adder(n):
return lambda x: x+n
plus3 = make_adder(3)
plus3(4) = 7 # 3 + 4 = 7

class Car:
crash = lambda self: print('Boom!')
my_car = Car(); my_car.crash() = 'Boom!'
```
```python
mult1 = [x for x in [1, 2, 3, 4, 5, 6, 7, 8, 9] if x%3 == 0 ]
```

### Exceções
```
def divide(x,y):
try:
result = x/y
except ZeroDivisionError, e:
print “division by zero!” + str(e)
except TypeError:
divide(int(x),int(y))
else:
print “result i”, result
finally
print “executing finally clause in any case”
```
### Assert()

Se a condição for falsa, a string será impressa na tela
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Geradores, yield

Um gerador, ao invés de retornar algo, "cede" algo. Quando você o acessa, ele irá "retornar" o primeiro valor gerado e, em seguida, você pode acessá-lo novamente e ele irá retornar o próximo valor gerado. Portanto, todos os valores não são gerados ao mesmo tempo e muita memória pode ser economizada usando isso em vez de uma lista com todos os valores.
```
def myGen(n):
yield n
yield n + 1
```
```markdown
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Erro

### Expressões Regulares

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Significados Especiais:**\
. --> Tudo\
\w --> \[a-zA-Z0-9\_]\
\d --> Número\
\s --> Caractere de espaço em branco\[ \n\r\t\f]\
\S --> Caractere que não é espaço em branco\
^ --> Começa com\
$ --> Termina com\
\+ --> Um ou mais\
\* --> 0 ou mais\
? --> 0 ou 1 ocorrência

**Opções:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Permite que o ponto corresponda à quebra de linha\
MULTILINE --> Permite que ^ e $ correspondam em linhas diferentes

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Gera combinações entre 1 ou mais listas, talvez repetindo valores, produto cartesiano (propriedade distributiva)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Gera combinações de todos os caracteres em cada posição\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Todas as combinações possíveis\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Todas as combinações possíveis de comprimento 2

**combinations**\
from itertools import **combinations** --> Gera todas as combinações possíveis sem repetir caracteres (se "ab" existir, não gera "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Gera todas as combinações possíveis a partir do caractere em diante (por exemplo, o 3º é misturado a partir do 3º em diante, mas não com o 2º ou o primeiro)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Decoradores

Decorador que mede o tempo que uma função precisa para ser executada (de [aqui](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
```
```python
from functools import wraps
import time
def timeme(func):
@wraps(func)
def wrapper(*args, **kwargs):
print("Let's call our decorated function")
start = time.time()
result = func(*args, **kwargs)
print('Execution time: {} seconds'.format(time.time() - start))
return result
return wrapper

@timeme
def decorated_func():
print("Decorated func!")
```
Se você executar, verá algo como o seguinte:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
