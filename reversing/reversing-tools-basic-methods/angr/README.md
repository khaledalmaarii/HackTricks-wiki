<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

Bu hile sayfasının bir kısmı [angr belgelerine](https://docs.angr.io/_/downloads/en/stable/pdf/) dayanmaktadır.

# Kurulum
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Temel İşlemler

This section covers the basic actions that can be performed using angr. These actions include loading a binary, analyzing its control flow, exploring different paths, and solving constraints.

Bu bölüm, angr kullanılarak gerçekleştirilebilecek temel işlemleri kapsar. Bu işlemler arasında bir ikili dosyanın yüklenmesi, kontrol akışının analiz edilmesi, farklı yolların keşfedilmesi ve kısıtlamaların çözülmesi bulunur.

## Loading a Binary

## Bir İkili Dosyanın Yüklenmesi

To start analyzing a binary with angr, you need to load it into an angr project. This can be done using the `angr.Project()` function, which takes the path to the binary as an argument.

Bir ikili dosyayı angr ile analiz etmeye başlamak için, onu bir angr projesine yüklemeniz gerekmektedir. Bu, `angr.Project()` fonksiyonunu kullanarak yapılabilir ve bu fonksiyonun argüman olarak ikili dosyanın yolunu alır.

```python
import angr

# Load the binary
project = angr.Project("/path/to/binary")
```

```python
import angr

# İkili dosyayı yükle
proje = angr.Project("/ikili/dosyanın/yolu")
```

## Analyzing Control Flow

## Kontrol Akışının Analiz Edilmesi

Once the binary is loaded, you can analyze its control flow using angr's CFG (Control Flow Graph) analysis. The CFG represents the possible paths and basic blocks in the binary.

İkili dosya yüklendikten sonra, angr'nin CFG (Kontrol Akış Grafiği) analizi kullanılarak kontrol akışını analiz edebilirsiniz. CFG, ikili dosyadaki olası yolları ve temel blokları temsil eder.

```python
# Analyze the control flow
cfg = project.analyses.CFG()
```

```python
# Kontrol akışını analiz et
cfg = proje.analyses.CFG()
```

## Exploring Paths

## Yolların Keşfedilmesi

After analyzing the control flow, you can explore different paths in the binary using angr's PathGroup. The PathGroup keeps track of the different paths and allows you to explore them.

Kontrol akışını analiz ettikten sonra, angr'nin PathGroup'u kullanarak ikili dosyadaki farklı yolları keşfedebilirsiniz. PathGroup, farklı yolları takip eder ve bunları keşfetmenize olanak sağlar.

```python
# Explore the paths
path_group = project.factory.path_group()
```

```python
# Yolları keşfet
path_group = proje.factory.path_group()
```

## Solving Constraints

## Kısıtlamaların Çözülmesi

During the exploration of paths, you may encounter constraints that need to be solved. Angr provides a solver engine that can be used to solve these constraints.

Yolların keşfi sırasında, çözülmesi gereken kısıtlamalarla karşılaşabilirsiniz. Angr, bu kısıtlamaları çözmek için kullanılabilecek bir çözücü motor sağlar.

```python
# Solve constraints
solver = project.solver
```

```python
# Kısıtlamaları çöz
solver = proje.solver
```
```python
import angr
import monkeyhex # this will format numerical results in hexadecimal
#Load binary
proj = angr.Project('/bin/true')

#BASIC BINARY DATA
proj.arch #Get arch "<Arch AMD64 (LE)>"
proj.arch.name #'AMD64'
proj.arch.memory_endness #'Iend_LE'
proj.entry #Get entrypoint "0x4023c0"
proj.filename #Get filename "/bin/true"

#There are specific options to load binaries
#Usually you won't need to use them but you could
angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```
# Yüklenen Veri

Yüklenen veri, programın çalışması için belleğe yüklenen tüm verileri içerir. Bu veriler, programın çalışması sırasında kullanılan değişkenler, fonksiyonlar ve diğer önemli bilgileri içerir.

## Main Object Information

Ana nesne bilgisi, programın ana nesnesi hakkında bilgi sağlar. Ana nesne, programın çalıştırılabilir dosyasının başlangıcını temsil eder ve programın yürütme akışının buradan başladığı yerdir. Ana nesne bilgisi, programın başlangıç adresini, boyutunu ve diğer ilgili bilgileri içerir. Bu bilgiler, programın analizi ve tersine mühendislik çalışmaları için önemlidir.
```python
#LOADED DATA
proj.loader #<Loaded true, maps [0x400000:0x5004000]>
proj.loader.min_addr #0x400000
proj.loader.max_addr #0x5004000
proj.loader.all_objects #All loaded
proj.loader.shared_objects #Loaded binaries
"""
OrderedDict([('true', <ELF Object true, maps [0x400000:0x40a377]>),
('libc.so.6',
<ELF Object libc-2.31.so, maps [0x500000:0x6c4507]>),
('ld-linux-x86-64.so.2',
<ELF Object ld-2.31.so, maps [0x700000:0x72c177]>),
('extern-address space',
<ExternObject Object cle##externs, maps [0x800000:0x87ffff]>),
('cle##tls',
<ELFTLSObjectV2 Object cle##tls, maps [0x900000:0x91500f]>)])
"""
proj.loader.all_elf_objects #Get all ELF objects loaded (Linux)
proj.loader.all_pe_objects #Get all binaries loaded (Windows)
proj.loader.find_object_containing(0x400000)#Get object loaded in an address "<ELF Object fauxware, maps [0x400000:0x60105f]>"
```
## Ana Hedef

The main objective of the angr framework is to provide a powerful and flexible platform for analyzing and reverse engineering binary programs. It aims to automate the process of program analysis, making it easier for researchers and analysts to understand the behavior and vulnerabilities of software.

angr framework'in ana hedefi, ikili programları analiz etmek ve tersine mühendislik yapmak için güçlü ve esnek bir platform sağlamaktır. Program analizi sürecini otomatikleştirmeyi hedefleyerek, araştırmacıların ve analistlerin yazılımın davranışını ve güvenlik açıklarını anlamalarını kolaylaştırmayı amaçlar.
```python
#Main Object (main binary loaded)
obj = proj.loader.main_object #<ELF Object true, maps [0x400000:0x60721f]>
obj.execstack #"False" Check for executable stack
obj.pic #"True" Check PIC
obj.imports #Get imports
obj.segments #<Regions: [<ELFSegment flags=0x5, relro=0x0, vaddr=0x400000, memsize=0xa74, filesize=0xa74, offset=0x0>, <ELFSegment flags=0x4, relro=0x1, vaddr=0x600e28, memsize=0x1d8, filesize=0x1d8, offset=0xe28>, <ELFSegment flags=0x6, relro=0x0, vaddr=0x601000, memsize=0x60, filesize=0x50, offset=0x1000>]>
obj.find_segment_containing(obj.entry) #Get segment by address
obj.sections #<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>, <.interp | offset 0x238, vaddr 0x400238, size 0x1c>, <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>, <.note.gnu.build-id ...
obj.find_section_containing(obj.entry) #Get section by address
obj.plt['strcmp'] #Get plt address of a funcion (0x400550)
obj.reverse_plt[0x400550] #Get function from plt address ('strcmp')
```
## Semboller ve Yer Değiştirmeler

Semboller ve yer değiştirmeler, tersine mühendislik sürecinde önemli bir rol oynar. Semboller, bir programın bellekteki farklı bölümlerini temsil eden işaretlerdir. Bu semboller, işlevler, değişkenler ve diğer veri yapılarını temsil edebilir. Yer değiştirmeler ise, sembollerin fiziksel bellekteki konumlarını ifade eder.

Tersine mühendislik yaparken, semboller ve yer değiştirmeleri anlamak önemlidir çünkü bu bilgiler, programın çalışma mantığını ve bellek yapısını anlamamıza yardımcı olur. Ayrıca, semboller ve yer değiştirmeler, hedef programın davranışını değiştirmek veya istenmeyen işlevleri etkinleştirmek için kullanılabilir.

Semboller ve yer değiştirmeler, çoğunlukla derleyici ve linker tarafından oluşturulan özel veri yapılarıdır. Bu veri yapıları, programın çalışma zamanında sembollerin ve yer değiştirmelerin nasıl kullanılacağını belirler. Tersine mühendislik yaparken, bu veri yapılarını analiz etmek ve anlamak önemlidir.

Tersine mühendislik sürecinde semboller ve yer değiştirmeleri anlamak için çeşitli araçlar ve teknikler bulunmaktadır. Bu araçlar ve teknikler, sembollerin ve yer değiştirmelerin nasıl kullanıldığını ve nasıl manipüle edilebileceğini gösterir. Bu bilgiler, tersine mühendislik yaparken programın iç yapısını daha iyi anlamamıza yardımcı olur ve istenilen sonuçları elde etmemizi sağlar.
```python
strcmp = proj.loader.find_symbol('strcmp') #<Symbol "strcmp" in libc.so.6 at 0x1089cd0>

strcmp.name #'strcmp'
strcmp.owne #<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>
strcmp.rebased_addr #0x1089cd0
strcmp.linked_addr #0x89cd0
strcmp.relative_addr #0x89cd0
strcmp.is_export #True, as 'strcmp' is a function exported by libc

#Get strcmp from the main object
main_strcmp = proj.loader.main_object.get_symbol('strcmp')
main_strcmp.is_export #False
main_strcmp.is_import #True
main_strcmp.resolvedby #<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```
## Bloklar

Blocks (bloklar), programın çalışma sürecindeki temel yapı taşlarıdır. Bir programın çalışması sırasında, her bir blok belirli bir işlevi yerine getirir ve ardışık olarak çalışır. Bloklar, programın akışını kontrol etmek, verileri işlemek ve sonuçları üretmek için kullanılır.

Bir blok, bir veya daha fazla komut veya ifade içerebilir. Bu komutlar ve ifadeler, belirli bir görevi yerine getirmek için bir araya getirilir. Örneğin, bir blok, bir döngüyü veya bir koşul ifadesini içerebilir.

Bir blok, genellikle süslü parantezler {} ile tanımlanır ve içindeki komutlar veya ifadeler bu süslü parantezler arasına yazılır. Bloklar, programın akışını kontrol etmek için kullanılan kontrol yapılarıyla birlikte kullanılır.

Bir blok, programın çalışma sürecinde belirli bir noktada başlar ve sona erer. Bloklar, programın akışını kontrol etmek için kullanılan kontrol yapılarıyla birlikte kullanılır. Örneğin, bir döngü bloğu, belirli bir koşul sağlandığı sürece tekrarlanan bir dizi komut veya ifade içerebilir.

Bir blok içindeki komutlar veya ifadeler, belirli bir sırayla çalışır. Bu sıra, programın akışını kontrol eden kontrol yapıları tarafından belirlenir. Örneğin, bir döngü bloğu, içindeki komutları veya ifadeleri belirli bir sayıda veya belirli bir koşul sağlandığı sürece tekrarlar.

Bir blok içindeki komutlar veya ifadeler, programın akışını kontrol etmek için kullanılan kontrol yapıları tarafından yönlendirilir. Bu kontrol yapıları, programın akışını belirli bir şekilde değiştirmek için kullanılır. Örneğin, bir koşul ifadesi, belirli bir koşulun sağlanıp sağlanmadığını kontrol eder ve buna göre programın akışını değiştirir.

Bir blok içindeki komutlar veya ifadeler, programın akışını kontrol etmek için kullanılan kontrol yapıları tarafından yönlendirilir. Bu kontrol yapıları, programın akışını belirli bir şekilde değiştirmek için kullanılır. Örneğin, bir koşul ifadesi, belirli bir koşulun sağlanıp sağlanmadığını kontrol eder ve buna göre programın akışını değiştirir.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Dinamik Analiz

## Simülasyon Yöneticisi, Durumlar
```python
#Live States
#This is useful to modify content in a live analysis
state = proj.factory.entry_state()
state.regs.rip #Get the RIP
state.mem[proj.entry].int.resolved #Resolve as a C int (BV)
state.mem[proj.entry].int.concreteved #Resolve as python int
state.regs.rsi = state.solver.BVV(3, 64) #Modify RIP
state.mem[0x1000].long = 4 #Modify mem

#Other States
project.factory.entry_state()
project.factory.blank_state() #Most of its data left uninitialized
project.factory.full_init_statetate() #Execute through any initializers that need to be run before the main binary's entry point
project.factory.call_state() #Ready to execute a given function.

#Simulation manager
#The simulation manager stores all the states across the execution of the binary
simgr = proj.factory.simulation_manager(state) #Start
simgr.step() #Execute one step
simgr.active[0].regs.rip #Get RIP from the last state
```
## Fonksiyonları Çağırma

* `args` üzerinden bir argüman listesi ve `env` üzerinden bir çevre değişkenleri sözlüğü `entry_state` ve `full_init_state` içine geçirebilirsiniz. Bu yapıların içindeki değerler dize veya bit vektörleri olabilir ve durumda simüle edilen yürütme için argümanlar ve çevre olarak seri hale getirilecektir. Varsayılan `args` boş bir listedir, bu yüzden analiz ettiğiniz programın en az bir `argv[0]` bulmasını bekliyorsanız, her zaman bunu sağlamalısınız!
* Eğer `argc`'nin sembolik olmasını isterseniz, sembolik bir bit vektörünü `entry_state` ve `full_init_state` yapıcılarına `argc` olarak geçirebilirsiniz. Ancak dikkatli olun: bunu yaparsanız, `args`'a geçirdiğiniz argüman sayısından daha büyük olamayacağına dair bir kısıtlama da sonuç durumuna eklemelisiniz.
* Çağrı durumunu kullanmak için, `.call_state(addr, arg1, arg2, ...)` şeklinde çağırmanız gerekmektedir, burada `addr` çağırmak istediğiniz fonksiyonun adresi ve `argN` ise o fonksiyona geçirilecek N'inci argümandır, ya bir python tamsayısı, dize veya dizi olarak veya bir bit vektörü olarak. Bellekte ayrılmış bir hafıza kullanmak ve gerçekten bir nesnenin bir işaretçisini geçirmek isterseniz, bunu bir PointerWrapper içine almalısınız, yani `angr.PointerWrapper("beni göster!")`. Bu API'nin sonuçları biraz tahmin edilemez olabilir, ancak üzerinde çalışıyoruz.

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Sembolik Bit Vektörler ve Kısıtlamalar

Sembolik bit vektörleri, angr çerçevesinde kullanılan önemli bir kavramdır. Sembolik bit vektörleri, programın çalışması sırasında değişkenlerin sembolik değerlerini temsil etmek için kullanılır. Bu, programın farklı girişlerle nasıl davrandığını analiz etmek için kullanışlıdır.

Kısıtlamalar, sembolik bit vektörlerinin üzerinde uygulanan koşullardır. Bu kısıtlamalar, sembolik ifadelerin belirli bir değeri alması gerektiğini veya belirli bir ilişkiyi sağlaması gerektiğini belirtir. Kısıtlamalar, sembolik ifadelerin gerçek değerlerini belirlemek için kullanılır.

angr, sembolik bit vektörleri ve kısıtlamaları kullanarak programların analizini gerçekleştirir. Bu sayede, programın farklı girişlerle nasıl davrandığını anlamak ve potansiyel güvenlik açıklarını tespit etmek mümkün hale gelir.
```python
x = state.solver.BVS("x", 64) #Symbolic variable BV of length 64
y = state.solver.BVS("y", 64)

#Symbolic oprations
tree = (x + 1) / (y + 2)
tree #<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
tree.op #'__floordiv__' Access last operation
tree.args #(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
tree.args[0].op #'__add__' Access of dirst arg
tree.args[0].args #(<BV64 x_9_64>, <BV64 0x1>)
tree.args[0].args[1].op #'BVV'
tree.args[0].args[1].args #(1, 64)

#Symbolic constraints solver
state = proj.factory.entry_state() #Get a fresh state without constraints
input = state.solver.BVS('input', 64)
operation = (((input + 4) * 3) >> 1) + input
output = 200
state.solver.add(operation == output)
state.solver.eval(input) #0x3333333333333381
state.solver.add(input < 2**32)
state.satisfiable() #False

#Solver solutions
solver.eval(expression) #one possible solution
solver.eval_one(expression) #solution to the given expression, or throw an error if more than one solution is possible.
solver.eval_upto(expression, n) #n solutions to the given expression, returning fewer than n if fewer than n are possible.
solver.eval_atleast(expression, n) #n solutions to the given expression, throwing an error if fewer than n are possible.
solver.eval_exact(expression, n) #n solutions to the given expression, throwing an error if fewer or more than are possible.
solver.min(expression) #minimum possible solution to the given expression.
solver.max(expression) #maximum possible solution to the given expression.
```
## Hooking

Hooking, Türkçe'de "kanca" anlamına gelir ve yazılımın çalışma sürecine müdahale etmek için kullanılan bir tekniktir. Hooking, bir işlevin normal işleyişini değiştirmek veya izlemek için kullanılır. Bu teknik, hedef uygulamanın davranışını değiştirmek veya izlemek için kullanılabilir.

### Hooking Türleri

1. **API Hooking**: API hooking, bir uygulamanın API çağrılarını değiştirmek veya izlemek için kullanılır. Bu yöntem, hedef uygulamanın işlevselliğini değiştirmek veya izlemek için kullanılabilir.

2. **Function Hooking**: Function hooking, bir işlevin normal işleyişini değiştirmek veya izlemek için kullanılır. Bu yöntem, hedef uygulamanın belirli bir işlevini değiştirmek veya izlemek için kullanılabilir.

3. **Inline Hooking**: Inline hooking, bir işlevin başlangıcına veya sonuna eklenen özel bir kod parçasıyla işlevin normal işleyişini değiştirmek için kullanılır. Bu yöntem, hedef uygulamanın işlevini değiştirmek veya izlemek için kullanılabilir.

### Hooking Kullanım Alanları

1. **Debugging**: Hooking, bir uygulamanın hatalarını tespit etmek ve gidermek için kullanılabilir. Hedef uygulamanın işlevlerini izleyerek, hatalı veya beklenmeyen davranışları tespit etmek mümkündür.

2. **Malware Analizi**: Hooking, zararlı yazılımların davranışını izlemek ve analiz etmek için kullanılabilir. Zararlı yazılımların API çağrılarını izleyerek, zararlı faaliyetleri tespit etmek mümkündür.

3. **Güvenlik Araştırmaları**: Hooking, güvenlik araştırmalarında kullanılan bir tekniktir. Hedef uygulamanın işlevlerini izleyerek, güvenlik açıklarını tespit etmek ve gidermek mümkündür.

### Hooking İşlemi

Hooking işlemi genellikle aşağıdaki adımları içerir:

1. **Hook Noktasının Belirlenmesi**: Hooking yapılacak işlevin veya API çağrısının belirlenmesi gerekmektedir.

2. **Hook Fonksiyonunun Oluşturulması**: Hooking işlemi için özel bir fonksiyon oluşturulmalıdır. Bu fonksiyon, hedef işlevin normal işleyişini değiştirecek veya izleyecek kodu içermelidir.

3. **Hook Fonksiyonunun Bağlanması**: Oluşturulan hook fonksiyonu, hedef işleve bağlanmalıdır. Bu sayede, hedef işlevin normal işleyişi değiştirilebilir veya izlenebilir hale gelir.

### Hooking Araçları

Birçok farklı araç, hooking işlemini gerçekleştirmek için kullanılabilir. İşletim sistemi seviyesinde hooking yapmak için araçlar mevcuttur. Ayrıca, bazı reverse engineering araçları da hooking işlemini desteklemektedir.

Örnek olarak, Angr, IDA Pro, OllyDbg ve Frida gibi araçlar hooking işlemini gerçekleştirmek için kullanılabilir. Bu araçlar, farklı hooking yöntemlerini destekleyerek, hedef uygulamanın işlevselliğini değiştirmek veya izlemek için kullanılabilir.
```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```
Ayrıca, sembolün bulunduğu adresi kancalamak için ilk argüman olarak sembolün adını sağlayarak `proj.hook_symbol(name, hook)` kullanabilirsiniz.

# Örnekler

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
