# 基础 Python

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或**关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## Python 基础

### 有用信息

list(xrange()) == range() --> 在 Python3 中，range 是 Python2 的 xrange（它不是列表而是生成器）\
元组和列表的区别在于元组中值的位置赋予其含义，而列表只是有序值。元组具有结构，而列表具有顺序。

### 主要操作

要求一个数的幂，使用：3\*\*2（不是 3^2）\
如果执行 2/3，会返回 1，因为您在将两个整数（integers）相除。如果要小数，应该除以浮点数（2.0/3.0）。\
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
help(str) = 类 str 的定义\
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
'abc’\[1:3] = ‘bc’ 从 \[1] 到 \[2]\
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
d += (4,) --> 添加到元组\
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
monthNumbers={1:'Jan', 2: 'feb','feb':2}—> monthNumbers ->{1:'Jan', 2: 'feb','feb':2}\
monthNumbers\[1] = 'Jan'\
monthNumbers\['feb'] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Jan', 'feb', 2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:'Jan', 2: 'feb','feb':2}\
mN = monthNumbers.copy() #独立复制\
monthNumbers.get('key',0) #检查键是否存在，如果存在则返回monthNumbers\["key"]的值，否则返回0

### 集合

集合中没有重复项\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #无重复项\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #如果存在，则移除，否则不做任何操作\
myset.remove(10) #如果存在则移除，否则引发异常\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #myset和myset2的值\
myset.intersection(myset2) #myset和myset2中的值\
myset.difference(myset2) #myset中但不在myset2中的值\
myset.symmetric\_difference(myset2) #不在myset和myset2中的值（两者都不在）\
myset.pop() #获取集合的第一个元素并将其移除\
myset.intersection\_update(myset2) #myset = myset和myset2中的元素\
myset.difference\_update(myset2) #myset = myset中但不在myset2中的元素\
myset.symmetric\_difference\_update(myset2) #myset = 两者都不在的元素

### 类

\_\_It\_\_中的方法将用于排序，以比较此类的对象是否大于其他对象
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
### map, zip, filter, lambda, sorted and one-liners

**Map** 的用法类似于：\[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** 在 foo 或 bar 较短时停止：
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
```python
mult1 = [x for x in [1, 2, 3, 4, 5, 6, 7, 8, 9] if x%3 == 0 ]
```

### 异常
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

如果条件为假，则会在屏幕上打印字符串
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### 生成器，yield

生成器不是返回某个东西，而是"产出"某个东西。当你访问它时，它会"返回"生成的第一个值，然后，你可以再次访问它，它将返回生成的下一个值。因此，所有的值不是同时生成的，使用这种方法而不是包含所有值的列表可以节省大量内存。
```
def myGen(n):
yield n
yield n + 1
```
```markdown
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Error

### 正则表达式

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**特殊含义:**\
. --> Everything\
\w --> \[a-zA-Z0-9\_]\
\d --> Number\
\s --> WhiteSpace char\[ \n\r\t\f]\
\S --> Non-whitespace char\
^ --> Starts with\
$ --> Ends with\
\+ --> One or more\
\* --> 0 or more\
? --> 0 or 1 occurrences

**选项:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Allow dot to match newline\
MULTILINE --> Allow ^ and $ to match in different lines

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Generates combinations between 1 or more lists, perhaps repeating values, cartesian product (distributive property)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Generates combinations of all characters in every position\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Every posible combination\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Every possible combination of length 2

**combinations**\
from itertools import **combinations** --> Generates all possible combinations without repeating characters (if "ab" existing, doesn't generate "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Generates all possible combinations from the char onwards(for example, the 3rd is mixed from the 3rd onwards but not with the 2nd o first)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### 装饰器

Decorator that size the time that a function needs to be executed (from [here](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
如果你运行它，你会看到类似以下内容：
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
