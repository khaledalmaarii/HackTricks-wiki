# 基本的Python

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## Python基础知识

### 有用的信息

list(xrange()) == range() --> 在Python3中，range是Python2中xrange的等价物（它不是一个列表，而是一个生成器）\
元组和列表的区别在于元组中的值的位置具有意义，而列表只是有序的值。元组具有结构，而列表具有顺序。

### 主要操作

要求一个数的幂，可以使用：3\*\*2（而不是3^2）\
如果你执行2/3，它会返回1，因为你在除以两个整数（integers）。如果你想要小数，你应该除以浮点数（2.0/3.0）。\
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
dir(str) = 所有可用方法的列表\
help(str) = 类str的定义\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**连接字符**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**列表的部分**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ 从\[1]到\[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**注释**\
\# 单行注释\
"""\
多行注释\
另一个\
"""

**循环**
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
### 元组

t1 = (1, '2', 'three')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'three', 5, 6)\
(4,) = 单元素元组\
d = () 空元组\
d += (4,) --> 添加到元组中\
无法！ --> t1\[1] == 'New value'\
list(t2) = \[5, 6] --> 从元组转换为列表

### 列表（数组）

d = \[] 空\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> 从列表转换为元组

### 字典

d = {} 空\
monthNumbers = {1: 'Jan', 2: 'feb', 'feb': 2} --> monthNumbers -> {1: 'Jan', 2: 'feb', 'feb': 2}\
monthNumbers\[1] = 'Jan'\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Jan', 'feb', 2]\
keys = \[k for k in monthNumbers]\
a = {'9': 9}\
monthNumbers.update(a) = {'9': 9, 1: 'Jan', 2: 'feb', 'feb': 2}\
mN = monthNumbers.copy() #独立副本\
monthNumbers.get('key', 0) #检查键是否存在，返回monthNumbers\["key"]的值，如果不存在则返回0

### 集合

集合中没有重复项\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #没有重复项\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #如果存在，则删除，如果不存在，则不执行任何操作\
myset.remove(10) #如果存在，则删除，如果不存在，则引发异常\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #myset和myset2中的值\
myset.intersection(myset2) #myset和myset2中的共同值\
myset.difference(myset2) #myset中存在但myset2中不存在的值\
myset.symmetric\_difference(myset2) #myset和myset2中都不存在的值\
myset.pop() #获取集合的第一个元素并将其删除\
myset.intersection\_update(myset2) #myset = myset和myset2中的共同元素\
myset.difference\_update(myset2) #myset = myset中存在但myset2中不存在的元素\
myset.symmetric\_difference\_update(myset2) #myset = myset和myset2中都不存在的元素

### 类

\_\_It\_\_中的方法将被sort用于比较该类的对象是否大于其他对象
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
### map、zip、filter、lambda、sorted和一行代码

**map**的用法类似于：\[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip**会在foo或bar中较短的那个停止：
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** 用于定义一个函数\
(lambda x,y: x+y)(5,3) = 8 --> 使用 lambda 作为简单的 **函数**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> 使用 lambda 对列表进行排序\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> 使用 lambda 进行过滤\
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

### 异常处理
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
### Assert（断言）

如果条件为假，则字符串将在屏幕上打印出来。
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### 生成器, yield

一个生成器不是返回某个值，而是"产出"某个值。当你访问它时，它会"返回"第一个生成的值，然后你可以再次访问它，它会返回下一个生成的值。因此，所有的值不是同时生成的，使用生成器而不是包含所有值的列表可以节省大量内存。
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Error

### 正则表达式

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**特殊含义：**\
. --> 任意字符\
\w --> \[a-zA-Z0-9\_]\
\d --> 数字\
\s --> 空白字符\[ \n\r\t\f]\
\S --> 非空白字符\
^ --> 开头\
$ --> 结尾\
\+ --> 一个或多个\
\* --> 0个或多个\
? --> 0个或1个

**选项：**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> 允许点匹配换行符\
MULTILINE --> 允许^和$在不同行匹配

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> 生成1个或多个列表之间的组合，可能重复值，笛卡尔积（分配性质）\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> 生成每个位置上所有字符的组合\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... 每个可能的组合\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] 长度为2的每个可能组合

**combinations**\
from itertools import **combinations** --> 生成所有可能的组合，不重复字符（如果存在"ab"，不生成"ba"）\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> 从字符开始生成所有可能的组合（例如，第3个从第3个开始混合，但不与第2个或第1个混合）\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### 装饰器

装饰器，用于测量函数执行所需的时间（来自[这里](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)）：
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
如果你运行它，你会看到类似下面的内容：
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
