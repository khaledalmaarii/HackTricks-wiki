# Temel Python

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramanla öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Python Temelleri

### Faydalı bilgiler

list(xrange()) == range() --> Python3'te range, python2'nin xrange'ıdır (bir liste değil, bir üreteçtir)\
Bir Tuple ve Bir Liste arasındaki fark, bir tuple'daki bir değerin konumunun ona anlam vermesidir, ancak listeler sadece sıralı değerlerdir. Tuples yapıya sahiptir, ancak listeler bir sıraya sahiptir.

### Temel işlemler

Bir sayıyı yükseltmek için: 3\*\*2 (3^2 değil)\
2/3 yaparsanız, iki tamsayıyı (integers) böldüğünüz için 1 döner. Ondalık sayılar istiyorsanız float'ları bölmelisiniz (2.0/3.0).\
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
dir(str) = Tüm mevcut yöntemlerin listesi\
help(str) = str sınıfının tanımı\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Karakterleri birleştirme**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Liste parçaları**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ \[1]'den \[2]'ye\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Yorumlar**\
\# Tek satırlık yorum\
"""\
Birkaç satırlık yorum\
Bir diğeri\
"""

**Döngüler**
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
### Tuplelar

t1 = (1, '2', 'üç')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'üç', 5, 6)\
(4,) = Tek elemanlı\
d = () boş tuple\
d += (4,) --> Tuple'a ekleme yapma\
YAPAMAZSIN! --> t1\[1] == 'Yeni değer'\
list(t2) = \[5, 6] --> Tuple'dan liste yapma

### Liste (dizi)

d = \[] boş\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> Listeden tuple yapma

### Sözlük

d = {} boş\
ayNumaraları = {1: 'Oca', 2: 'şub', 'şub': 2} --> ayNumaraları -> {1: 'Oca', 2: 'şub', 'şub': 2}\
ayNumaraları\[1] = 'Oca'\
ayNumaraları\[‘şub’] = 2\
list(ayNumaraları) = \[1, 2, 'şub']\
ayNumaraları.values() = \['Oca', 'şub', 2]\
keys = \[k for k in ayNumaraları]\
a = {'9': 9}\
ayNumaraları.update(a) = {'9': 9, 1: 'Oca', 2: 'şub', 'şub': 2}\
mN = ayNumaraları.copy() #Bağımsız kopya\
ayNumaraları.get('anahtar', 0) #Anahtar var mı diye kontrol et, ayNumaraları\["anahtar"]'ın değerini döndür veya yoksa 0 döndür

### Küme

Kümelerde tekrarlamalar yoktur\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Tekrarlamalar yok\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Eğer varsa kaldır, yoksa bir şey yapma\
myset.remove(10) #Eğer varsa kaldır, yoksa hata ver\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #myset VEYA myset2'deki değerler\
myset.intersection(myset2) #myset VE myset2'deki değerler\
myset.difference(myset2) #myset'teki ama myset2'de olmayan değerler\
myset.symmetric\_difference(myset2) #myset VE myset2'de olmayan değerler (her ikisinde de olmayan)\
myset.pop() #Kümenin ilk elemanını al ve kaldır\
myset.intersection\_update(myset2) #myset = myset VE myset2'deki elemanlar\
myset.difference\_update(myset2) #myset = myset'teki ama myset2'de olmayan elemanlar\
myset.symmetric\_difference\_update(myset2) #myset = myset VE myset2'de olmayan elemanlar

### Sınıflar

\_\_It\_\_ içindeki yöntem, bu sınıfın bir nesnesinin diğerinden daha büyük olup olmadığını karşılaştırmak için sort tarafından kullanılacak yöntem olacaktır.
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
### map, zip, filter, lambda, sorted ve tek satırlar

**Map** şu şekilde çalışır: \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** foo veya bar'ın daha kısa olanı durduğunda durur:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda**, bir fonksiyon tanımlamak için kullanılır\
(lambda x,y: x+y)(5,3) = 8 --> Basit bir **fonksiyon** olarak lambda kullanın\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Bir listeyi sıralamak için lambda kullanın\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Filtrelemek için lambda kullanın\
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

### İstisnalar
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

Eğer koşul yanlış ise, dize ekran üzerinde yazdırılacaktır.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Üreteçler, yield

Bir üreteç, bir şey döndürmek yerine bir şey "yield" eder. Ona eriştiğinizde, ilk üretilen değeri "döndürür" ve sonra tekrar erişebilirsiniz ve bir sonraki üretilen değeri döndürür. Bu nedenle, tüm değerler aynı anda üretilmez ve tüm değerleri içeren bir liste yerine bunu kullanarak çok fazla bellek tasarrufu sağlanabilir.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Hata

### Düzenli İfadeler

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Özel anlamlar:**\
. --> Her şeyi\
\w --> \[a-zA-Z0-9\_]\
\d --> Sayı\
\s --> Boşluk karakteri\[ \n\r\t\f]\
\S --> Boşluk olmayan karakter\
^ --> İle başlar\
$ --> İle biter\
\+ --> Bir veya daha fazla\
\* --> 0 veya daha fazla\
? --> 0 veya 1 kez

**Seçenekler:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Noktanın yeni satırı eşleştirmesine izin verir\
MULTILINE --> ^ ve $'ın farklı satırlarda eşleşmesine izin verir

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> 1 veya daha fazla liste arasında kombinasyonlar oluşturur, değerleri tekrarlayabilir, kartez ürünü (dağıtma özelliği)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Her pozisyonda tüm karakterlerin kombinasyonlarını oluşturur\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Tüm olası kombinasyonlar\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Uzunluğu 2 olan tüm olası kombinasyonlar

**combinations**\
from itertools import **combinations** --> Tekrar eden karakterleri olmadan tüm olası kombinasyonları oluşturur ("ab" varsa "ba" oluşturmaz)\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Karakterden sonraki tüm olası kombinasyonları oluşturur (örneğin, 3. karakter 3. karakterden itibaren karıştırılır, ancak 2. veya 1. ile karıştırılmaz)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Dekoratörler

Bir fonksiyonun çalışması için gereken süreyi ölçen bir dekoratör (buradan alındı: [buradan](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Eğer çalıştırırsanız, aşağıdakine benzer bir şey göreceksiniz:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin.**
* **Hacking hilelerinizi paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>
