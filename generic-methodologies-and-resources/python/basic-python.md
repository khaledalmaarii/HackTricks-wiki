# 기본 Python

{% hint style="success" %}
AWS 해킹 배우고 실습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 실습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 가입하거나 [**텔레그램 그룹**](https://t.me/peass) 참여 또는 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 팔로우하기**.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 요령 공유하기.

</details>
{% endhint %}

## Python 기초

### 유용한 정보

list(xrange()) == range() --> Python3에서 range는 Python2의 xrange와 같음 (리스트가 아닌 제너레이터)\
튜플과 리스트의 차이점은 튜플에서 값의 위치가 의미를 갖지만 리스트는 순서가 있는 값들뿐임. 튜플은 구조를 가지지만 리스트는 순서를 가짐.

### 주요 작업

숫자를 제곱하려면: 3\*\*2 (3^2가 아님)\
2/3을 하면 1이 반환됨, 왜냐하면 두 정수(integers)를 나누기 때문. 소수점을 원한다면 부동소수점(floats)으로 나눠야 함 (2.0/3.0).\
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
dir(str) = 사용 가능한 모든 메서드 목록\
help(str) = 클래스 str의 정의\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**문자 결합**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**리스트의 일부**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ [1]부터 [2]까지\
"qwertyuiop"\[:-1] = 'qwertyuio'

**주석**\
\# 한 줄 주석\
"""\
여러 줄 주석\
또 다른 줄\
"""

**반복문**
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
### 튜플

t1 = (1, '2', 'three')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'three', 5, 6)\
(4,) = 싱글톤\
d = () 빈 튜플\
d += (4,) --> 튜플에 추가\
CANT! --> t1\[1] == 'New value'\
list(t2) = \[5, 6] --> 튜플에서 리스트로

### 리스트 (배열)

d = \[] 빈\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> 리스트에서 튜플로

### 사전

d = {} 빈\
monthNumbers={1:'Jan', 2: 'feb','feb':2}--> monthNumbers ->{1:'Jan', 2: 'feb','feb':2}\
monthNumbers\[1] = 'Jan'\
monthNumbers\['feb'] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Jan', 'feb', 2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:'Jan', 2: 'feb','feb':2}\
mN = monthNumbers.copy() #독립적 복사\
monthNumbers.get('key',0) #키가 있는지 확인, monthNumbers\["key"]의 값 또는 존재하지 않으면 0 반환

### 집합

집합에는 중복이 없음\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #중복 없음\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #존재하면 제거, 없으면 아무것도 안 함\
myset.remove(10) #존재하면 제거, 없으면 예외 발생\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #myset 또는 myset2의 값\
myset.intersection(myset2) #myset과 myset2의 값\
myset.difference(myset2) #myset에는 있지만 myset2에는 없는 값\
myset.symmetric\_difference(myset2) #myset과 myset2에 모두 없는 값\
myset.pop() #집합의 첫 번째 요소 가져오고 제거\
myset.intersection\_update(myset2) #myset = myset과 myset2의 요소\
myset.difference\_update(myset2) #myset = myset에는 있지만 myset2에는 없는 요소\
myset.symmetric\_difference\_update(myset2) #myset = 두 집합에 모두 없는 요소

### 클래스

\_\_It\_\_ 메소드는 이 클래스의 객체가 다른 것보다 큰지 비교하는 데 사용될 것입니다.
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
### 맵, 집, 필터, 람다, 정렬 및 원라이너

**맵**은 다음과 같습니다: \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**집**은 foo 또는 bar 중 짧은 것이 멈출 때 멈춥니다:
```
for f, b in zip(foo, bar):
print(f, b)
```
**람다**는 함수를 정의하는 데 사용됩니다.\
(lambda x,y: x+y)(5,3) = 8 --> 람다를 간단한 **함수**로 사용\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> 람다를 사용하여 리스트 정렬\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> 람다를 사용하여 필터링\
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
mult1 = \[x for x in \[1, 2, 3, 4, 5, 6, 7, 8, 9] if x%3 == 0 ]

### 예외 처리
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

만약 조건이 거짓이면 문자열이 화면에 출력됩니다.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### 제너레이터, yield

제너레이터는 무언가를 반환하는 대신에 무언가를 "생성"합니다. 제너레이터에 액세스하면 생성된 첫 번째 값을 "반환"하고, 다시 액세스하면 생성된 다음 값을 반환합니다. 따라서 모든 값이 동시에 생성되지 않으며 모든 값을 포함하는 목록 대신에 이를 사용하여 많은 메모리를 절약할 수 있습니다.
```
def myGen(n):
yield n
yield n + 1
```
```markdown
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Error

### 정규 표현식

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**특수 의미:**\
. --> 모든 것\
\w --> \[a-zA-Z0-9\_]\
\d --> 숫자\
\s --> 공백 문자\[ \n\r\t\f]\
\S --> 공백이 아닌 문자\
^ --> 시작\
$ --> 끝\
\+ --> 하나 이상\
\* --> 0개 이상\
? --> 0 또는 1회 발생

**옵션:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> 점이 새 줄과 일치하도록 허용\
MULTILINE --> ^ 및 $가 다른 줄에서 일치하도록 허용

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> 1개 이상의 목록 간의 조합을 생성하며 값 반복, 카테시안 곱(분배 법칙)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> 각 위치의 모든 문자의 조합을 생성함\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... 모든 가능한 조합\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] 길이 2의 모든 가능한 조합

**combinations**\
from itertools import **combinations** --> 문자를 반복하지 않고 모든 가능한 조합을 생성함 ("ab"가 있는 경우 "ba"를 생성하지 않음)\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> 문자 이후의 모든 가능한 조합을 생성함(예: 3번째는 3번째부터 혼합되지만 2번째나 첫 번째와는 혼합되지 않음)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3)']

### 데코레이터

함수가 실행되는 데 필요한 시간을 측정하는 데코레이터([여기](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74) 참조):
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
만약 실행하면 다음과 같은 내용을 볼 수 있습니다:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 팁을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
{% endhint %}
