# Angr - Örnekler

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

{% hint style="info" %}
Eğer program, `scanf` kullanarak **stdin'den bir seferde birden fazla değer alıyorsa**, `scanf`'den sonra başlayan bir durum oluşturmanız gerekmektedir.
{% endhint %}

Kodlar [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf) adresinden alınmıştır.

### Adrese ulaşmak için giriş (adresi belirterek)
```python
import angr
import sys

def main(argv):
path_to_binary = argv[1]  # :string
project = angr.Project(path_to_binary)

# Start in main()
initial_state = project.factory.entry_state()
# Start simulation
simulation = project.factory.simgr(initial_state)

# Find the way yo reach the good address
good_address = 0x804867d

# Avoiding this address
avoid_address = 0x080485A8
simulation.explore(find=good_address , avoid=avoid_address ))

# If found a way to reach the address
if simulation.found:
solution_state = simulation.found[0]

# Print the string that Angr wrote to stdin to follow solution_state
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Adrese ulaşmak için giriş (yazdırmaları gösteren)
```python
# If you don't know the address you want to recah, but you know it's printing something
# You can also indicate that info

import angr
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

def is_successful(state):
#Successful print
stdout_output = state.posix.dumps(sys.stdout.fileno())
return b'Good Job.' in stdout_output

def should_abort(state):
#Avoid this print
stdout_output = state.posix.dumps(sys.stdout.fileno())
return b'Try again.' in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Kayıt Defteri Değerleri

Registry values, Windows işletim sistemindeki kayıt defterinde depolanan verilerdir. Kayıt defteri, sistem yapılandırmasını, kullanıcı ayarlarını ve diğer önemli bilgileri saklar. Kayıt defteri değerleri, anahtarlar altında saklanır ve her bir değer, bir anahtarın altında bir ad ve bir veri türü ile tanımlanır.

Kayıt defteri değerlerine erişmek ve bunları değiştirmek için çeşitli yöntemler vardır. Bu değerleri okumak, yazmak veya silmek için kayıt defteri düzenleyicisi kullanılabilir. Ayrıca, kayıt defteri değerlerini programatik olarak erişmek için birçok programlama dilinde kayıt defteri API'leri bulunmaktadır.

Kayıt defteri değerlerini anlamak ve analiz etmek için bazı araçlar ve teknikler mevcuttur. Bu araçlar, kayıt defteri değerlerini otomatik olarak analiz edebilir ve anlamlandırabilir. Örneğin, kayıt defteri değerlerini incelemek ve analiz etmek için "regedit" veya "reg" komutunu kullanabilirsiniz.

Kayıt defteri değerlerini anlamak, sistem yapılandırmasını anlamak ve sorunları gidermek için önemlidir. Ayrıca, kötü amaçlı yazılımların veya zararlı programların tespit edilmesi ve analiz edilmesi için de kullanılabilir.
```python
# Angr doesn't currently support reading multiple things with scanf (Ex:
# scanf("%u %u).) You will have to tell the simulation engine to begin the
# program after scanf is called and manually inject the symbols into registers.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Address were you want to indicate the relation BitVector - registries
start_address = 0x80488d1
initial_state = project.factory.blank_state(addr=start_address)


# Create Bit Vectors
password0_size_in_bits = 32  # :integer
password0 = claripy.BVS('password0', password0_size_in_bits)

password1_size_in_bits = 32  # :integer
password1 = claripy.BVS('password1', password1_size_in_bits)

password2_size_in_bits = 32  # :integer
password2 = claripy.BVS('password2', password2_size_in_bits)

# Relate it Vectors with the registriy values you are interested in to reach an address
initial_state.regs.eax = password0
initial_state.regs.ebx = password1
initial_state.regs.edx = password2

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0)
solution1 = solution_state.solver.eval(password1)
solution2 = solution_state.solver.eval(password2)

# Aggregate and format the solutions you computed above, and then print
# the full string. Pay attention to the order of the integers, and the
# expected base (decimal, octal, hexadecimal, etc).
solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2 ]))  # :string
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Yığın Değerleri

The stack is a data structure used by programs to store local variables and function call information. When a function is called, its local variables and return address are pushed onto the stack. The stack grows downwards, meaning that new values are added at the top of the stack.

In reverse engineering, understanding the values stored on the stack can be crucial for analyzing the behavior of a program. By examining the stack values at different points in the program's execution, you can gain insights into how the program manipulates data and makes decisions.

To view the stack values during program execution, you can use a debugger or a dynamic analysis tool like angr. These tools allow you to set breakpoints at specific locations in the program and inspect the stack at those points.

By examining the stack values, you can identify important variables and function arguments, which can help you understand the program's logic and potentially find vulnerabilities or weaknesses.

Overall, understanding the stack values is an essential skill in reverse engineering, as it allows you to gain insights into a program's inner workings and make informed decisions during the analysis process.
```python
# Put bit vectors in th stack to find out the vallue that stack position need to
# have to reach a rogram flow

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Go to some address after the scanf where values have already being set in the stack
start_address = 0x8048697
initial_state = project.factory.blank_state(addr=start_address)

# Since we are starting after scanf, we are skipping this stack construction
# step. To make up for this, we need to construct the stack ourselves. Let us
# start by initializing ebp in the exact same way the program does.
initial_state.regs.ebp = initial_state.regs.esp

# In this case scanf("%u %u") is used, so 2 BVS are going to be needed
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)

# Now, in the address were you have stopped, check were are the scanf values saved
# Then, substrack form the esp registry the needing padding to get to the
# part of the stack were the scanf values are being saved and push the BVS
# (see the image below to understan this -8)
padding_length_in_bytes = 8  # :integer
initial_state.regs.esp -= padding_length_in_bytes

initial_state.stack_push(password0)
initial_state.stack_push(password1)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0)
solution1 = solution_state.solver.eval(password1)

solution = ' '.join(map(str, [ solution0, solution1 ]))
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
Bu senaryoda, giriş `scanf("%u %u")` ile alındı ve değer olarak `"1 1"` verildi, bu yüzden yığının **kullanıcı girişinden** gelen **`0x00000001`** değerlerini görebilirsiniz. Bu değerlerin `$ebp - 8`'de başladığını görebilirsiniz. Bu nedenle, kodda **`$esp`'den 8 bayt çıkardık (o anda `$ebp` ve `$esp` aynı değere sahipti)** ve ardından BVS'yi iteledik.

![](<../../../.gitbook/assets/image (614).png>)

### Statik Bellek Değerleri (Global değişkenler)
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

#Get an address after the scanf. Once the input has already being saved in the memory positions
start_address = 0x8048606
initial_state = project.factory.blank_state(addr=start_address)

# The binary is calling scanf("%8s %8s %8s %8s").
# So we need 4 BVS of size 8*8
password0 = claripy.BVS('password0', 8*8)
password1 = claripy.BVS('password1', 8*8)
password2 = claripy.BVS('password2', 8*8)
password3 = claripy.BVS('password3', 8*8)

# Write the symbolic BVS in the memory positions
password0_address = 0xa29faa0
initial_state.memory.store(password0_address, password0)
password1_address = 0xa29faa8
initial_state.memory.store(password1_address, password1)
password2_address = 0xa29fab0
initial_state.memory.store(password2_address, password2)
password3_address = 0xa29fab8
initial_state.memory.store(password3_address, password3)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

# Get the values the memory addresses should store
solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()
solution2 = solution_state.solver.eval(password2,cast_to=bytes).decode()
solution3 = solution_state.solver.eval(password3,cast_to=bytes).decode()

solution = ' '.join([ solution0, solution1, solution2, solution3 ])

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Dinamik Bellek Değerleri (Malloc)

Malloc, C programlama dilinde dinamik bellek tahsisi yapmak için kullanılan bir işlevdir. Dinamik bellek tahsisi, programın çalışma zamanında değişken miktarda bellek tahsis etmesine olanak tanır. Malloc işlevi, programın çalışması sırasında bellek blokları oluşturur ve bu bloklara erişim sağlar.

Malloc işlevi, bir bellek bloğu oluştururken, bloğun boyutunu belirtmek için kullanılan bir parametre alır. Bu boyut, programın ihtiyaçlarına göre değişebilir. Malloc işlevi, bellek bloğunu oluşturduktan sonra, bloğun başlangıç adresini döndürür. Bu adres, oluşturulan bellek bloğuna erişmek için kullanılır.

Malloc işlevi, dinamik bellek tahsisinin yanı sıra, bellek sızıntılarını da önlemek için kullanılabilir. Bellek sızıntıları, programın bellek bloklarını serbest bırakmadan önce bellek tahsis ettiği durumlarda ortaya çıkar. Malloc işlevi, bellek bloklarını serbest bırakmadan önce bu blokları izlemek ve gerektiğinde belleği serbest bırakmak için kullanılabilir.

Malloc işlevi, C programlama dilinde yaygın olarak kullanılan bir araçtır ve dinamik bellek tahsisinin etkin bir şekilde yapılmasını sağlar. Bu nedenle, Malloc işlevinin kullanımı ve dinamik bellek değerlerinin yönetimi, bir programcı için önemli bir beceridir.
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Get address after scanf
start_address = 0x804869e
initial_state = project.factory.blank_state(addr=start_address)

# The binary is calling scanf("%8s %8s") so 2 BVS are needed.
password0 = claripy.BVS('password0', 8*8)
password1 = claripy.BVS('password0', 8*8)

# Find a coupble of addresses that aren't used by the binary (like 0x4444444 & 0x4444454)
# The address generated by mallosc is going to be saved in some address
# Then, make that address point to the fake heap addresses were the BVS are going to be saved
fake_heap_address0 = 0x4444444
pointer_to_malloc_memory_address0 = 0xa79a118
initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
fake_heap_address1 = 0x4444454
pointer_to_malloc_memory_address1 = 0xa79a120
initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

# Save the VBS in the new fake heap addresses created
initial_state.memory.store(fake_heap_address0, password0)
initial_state.memory.store(fake_heap_address1, password1)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()

solution = ' '.join([ solution0, solution1 ])

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Dosya Simülasyonu

Angr, dosya sistemi üzerinde çalışan programları simüle etmek için de kullanılabilir. Bu, programın dosya işlemlerini taklit etmek ve belirli bir dosya durumunda nasıl davrandığını görmek için kullanışlı olabilir.

Angr, dosya sistemi simülasyonu için `simuvex.SimFile` sınıfını kullanır. Bu sınıf, dosya işlemlerini taklit etmek için gerekli olan işlevleri sağlar.

Aşağıda, bir dosya simülasyonu örneği verilmiştir:

```python
import angr
import simuvex

# Dosya simülasyonu için gerekli olan dosya nesnesini oluşturun
file = simuvex.SimFile('/path/to/file', 'r')

# Dosya nesnesini kullanarak bir dosya simülasyonu oluşturun
state = angr.Project('/path/to/binary').factory.entry_state(fs={'/path/to/file': file})

# Dosya simülasyonunu çalıştırın
simgr = angr.Project(state)
simgr.run()

# Dosya simülasyonu sonucunda elde edilen durumu kontrol edin
if simgr.deadended:
    print("Dosya simülasyonu başarıyla tamamlandı.")
else:
    print("Dosya simülasyonu tamamlanamadı.")
```

Bu örnekte, `simuvex.SimFile` sınıfı kullanılarak bir dosya nesnesi oluşturulur. Ardından, `angr.Project` sınıfı kullanılarak bir dosya simülasyonu oluşturulur. Son olarak, `simgr.run()` yöntemiyle dosya simülasyonu çalıştırılır ve `simgr.deadended` özelliği kontrol edilerek simülasyonun başarıyla tamamlanıp tamamlanmadığı belirlenir.

Dosya simülasyonu, programın belirli bir dosya durumunda nasıl davrandığını anlamak için kullanışlı bir araçtır. Bu, programın dosya işlemlerini taklit ederek, dosya işlemlerinin sonuçlarını analiz etmenizi sağlar.
```python
#In this challenge a password is read from a file and we want to simulate its content

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Get an address just before opening the file with th simbolic content
# Or at least when the file is not going to suffer more changes before being read
start_address = 0x80488db
initial_state = project.factory.blank_state(addr=start_address)

# Specify the filena that is going to open
# Note that in theory, the filename could be symbolic.
filename = 'WCEXPXBW.txt'
symbolic_file_size_bytes = 64

# Create a BV which is going to be the content of the simbolic file
password = claripy.BVS('password', symbolic_file_size_bytes * 8)

# Create the file simulation with the simbolic content
password_file = angr.storage.SimFile(filename, content=password)

# Add the symbolic file we created to the symbolic filesystem.
initial_state.fs.insert(filename, password_file)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution = solution_state.solver.eval(password,cast_to=bytes).decode()

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
{% hint style="info" %}
Sembolik dosya, sembolik verilerle birleştirilmiş sabit verileri de içerebilir:
```python
# Hello world, my name is John.
# ^                       ^
# ^ address 0             ^ address 24 (count the number of characters)
# In order to represent this in memory, we would want to write the string to
# the beginning of the file:
#
# hello_txt_contents = claripy.BVV('Hello world, my name is John.', 30*8)
#
# Perhaps, then, we would want to replace John with a
# symbolic variable. We would call:
#
# name_bitvector = claripy.BVS('symbolic_name', 4*8)
#
# Then, after the program calls fopen('hello.txt', 'r') and then
# fread(buffer, sizeof(char), 30, hello_txt_file), the buffer would contain
# the string from the file, except four symbolic bytes where the name would be
# stored.
# (!)
```
{% endhint %}

### Kısıtlamaları Uygulama

{% hint style="info" %}
Bazen 16 karakter uzunluğundaki 2 kelimeyi **karakter karakter** karşılaştırmak gibi basit insan işlemleri, **angr** için maliyetli olabilir çünkü üreteceği dalları **üstel olarak** üretmesi gerekmektedir çünkü her if için 1 dal üretir: `2^16`\
Bu nedenle, **angr'ye daha önceki bir noktaya gitmesini** (gerçek zor kısmın zaten yapıldığı nokta) ve bu kısıtlamaları manuel olarak **ayarlamasını istemek daha kolaydır**.
{% endhint %}
```python
# After perform some complex poperations to the input the program checks
# char by char the password against another password saved, like in the snippet:
#
# #define REFERENCE_PASSWORD = "AABBCCDDEEFFGGHH";
# int check_equals_AABBCCDDEEFFGGHH(char* to_check, size_t length) {
#   uint32_t num_correct = 0;
#   for (int i=0; i<length; ++i) {
#     if (to_check[i] == REFERENCE_PASSWORD[i]) {
#       num_correct += 1;
#     }
#   }
#   return num_correct == length;
# }
#
# ...
#
# char* input = user_input();
# char* encrypted_input = complex_function(input);
# if (check_equals_AABBCCDDEEFFGGHH(encrypted_input, 16)) {
#   puts("Good Job.");
# } else {
#   puts("Try again.");
# }
#
# The function checks if *to_check == "AABBCCDDEEFFGGHH". This is very RAM consumming
# as the computer needs to branch every time the if statement in the loop was called (16
# times), resulting in 2^16 = 65,536 branches, which will take too long of a
# time to evaluate for our needs.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)

# Get an address to check after the complex function and before the "easy compare" operation
address_to_check_constraint = 0x8048671
simulation.explore(find=address_to_check_constraint)


if simulation.found:
solution_state = simulation.found[0]

# Find were the input that is going to be compared is saved in memory
constrained_parameter_address = 0x804a050
constrained_parameter_size_bytes = 16
# Set the bitvector
constrained_parameter_bitvector = solution_state.memory.load(
constrained_parameter_address,
constrained_parameter_size_bytes
)

# Indicate angr that this BV at this point needs to be equal to the password
constrained_parameter_desired_value = 'BWYRUBQCMVSBRGFU'.encode()
solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)

print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
{% hint style="danger" %}
Bazı senaryolarda, gereksiz dalları kaydetmek ve çözümü bulmak için benzer durumları birleştiren **veritesting** etkinleştirebilirsiniz: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
Bu senaryolarda yapabileceğiniz başka bir şey de, angr'a daha kolay anlaşılabilir bir şey vermek için fonksiyonu **hook** etmektir.
{% endhint %}

### Simülasyon Yöneticileri

Bazı simülasyon yöneticileri diğerlerinden daha kullanışlı olabilir. Önceki örnekte bir sorun vardı çünkü birçok kullanışlı dal oluşturuldu. Burada, **veritesting** tekniği bu dalları birleştirecek ve bir çözüm bulacaktır.\
Bu simülasyon yöneticisi ayrıca şu şekilde etkinleştirilebilir: `simulation = project.factory.simgr(initial_state, veritesting=True)`
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)
# Set simulation technique
simulation.use_technique(angr.exploration_techniques.Veritesting())


def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())

return 'Good Job.'.encode() in stdout_output  # :boolean

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')


if __name__ == '__main__':
main(sys.argv)
```
### Bir işlevin bir çağrısını kancalamak/geçmek

In this example, we will use angr to hook/bypass a specific call to a function in a binary. 

Bu örnekte, bir ikili dosyadaki belirli bir işlevin çağrısını kancalamak/geçmek için angr kullanacağız.

First, we need to create an angr project and load the binary:

İlk olarak, bir angr projesi oluşturmalı ve ikili dosyayı yüklemeliyiz:

```python
import angr

project = angr.Project("/path/to/binary")
```

Next, we need to find the address of the call instruction we want to hook/bypass. We can use the `project.factory.block()` method to get a basic block at a specific address:

Ardından, kancalamak/geçmek istediğimiz çağrı talimatının adresini bulmamız gerekiyor. Belirli bir adreste temel bir blok elde etmek için `project.factory.block()` yöntemini kullanabiliriz:

```python
call_address = 0x12345678
block = project.factory.block(call_address)
```

Now, we can use the `block.vex` attribute to get the VEX representation of the basic block. We can then iterate over the instructions in the block to find the specific call instruction:

Şimdi, `block.vex` özniteliğini kullanarak temel bloğun VEX temsilini alabiliriz. Ardından, bloktaki talimatları döngüyle gezerek belirli çağrı talimatını bulabiliriz:

```python
for stmt in block.vex.statements:
    if stmt.tag == 'Ist_IMark' and stmt.addr == call_address:
        call_stmt = stmt
        break
```

Once we have the call instruction, we can modify it to hook/bypass the function call. For example, we can replace the call instruction with a jump to a different address:

Çağrı talimatını elde ettikten sonra, işlev çağrısını kancalamak/geçmek için değiştirebiliriz. Örneğin, çağrı talimatını farklı bir adrese yönlendiren bir atlama talimatıyla değiştirebiliriz:

```python
jump_target = 0x87654321
call_stmt.stmt = call_stmt.stmt.replace('call', 'jmp')
call_stmt.stmt = call_stmt.stmt.replace(hex(call_address), hex(jump_target))
```

Finally, we can use the `block.bytes` attribute to get the modified bytes of the basic block. We can then patch the binary with the modified bytes:

Son olarak, `block.bytes` özniteliğini kullanarak temel bloğun değiştirilmiş baytlarını alabiliriz. Ardından, ikili dosyayı değiştirilmiş baytlarla yamalayabiliriz:

```python
patched_bytes = block.bytes
project.loader.memory.write_bytes(call_address, patched_bytes)
```

Now, when the binary is executed, the modified call instruction will be executed as a jump to the specified address, effectively hooking/bypassing the original function call.

Artık ikili dosya çalıştırıldığında, değiştirilmiş çağrı talimatı belirtilen adrese atlama olarak çalıştırılacak ve böylece orijinal işlev çağrısı kancalanacak/geçilecektir.
```python
# This level performs the following computations:
#
# 1. Get 16 bytes of user input and encrypt it.
# 2. Save the result of check_equals_AABBCCDDEEFFGGHH (or similar)
# 3. Get another 16 bytes from the user and encrypt it.
# 4. Check that it's equal to a predefined password.
#
# The ONLY part of this program that we have to worry about is #2. We will be
# replacing the call to check_equals_ with our own version, using a hook, since
# check_equals_ will run too slowly otherwise.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

# Hook the address of the call to hook indicating th length of the instruction (of the call)
check_equals_called_address = 0x80486b8
instruction_to_skip_length = 5
@project.hook(check_equals_called_address, length=instruction_to_skip_length)
def skip_check_equals_(state):
#Load the input of the function reading direcly the memory
user_input_buffer_address = 0x804a054
user_input_buffer_length = 16
user_input_string = state.memory.load(
user_input_buffer_address,
user_input_buffer_length
)

# Create a simbolic IF that if the loaded string frommemory is the expected
# return True (1) if not returns False (0) in eax
check_against_string = 'XKSPZSJKJYQCQXZV'.encode() # :string

state.regs.eax = claripy.If(
user_input_string == check_against_string,
claripy.BVV(1, 32),
claripy.BVV(0, 32)
)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Bir fonksiyonu kancalamak / Simprosedür

In some cases, you may want to modify the behavior of a specific function during the execution of a binary. This can be useful for various purposes, such as bypassing certain checks or altering the flow of the program. One way to achieve this is by hooking the function using a technique called simprocedure.

Bir ikili dosyanın yürütülmesi sırasında belirli bir fonksiyonun davranışını değiştirmek isteyebilirsiniz. Bu, belirli kontrolleri atlamak veya programın akışını değiştirmek gibi çeşitli amaçlar için faydalı olabilir. Bunun için kullanılan bir teknik olan simprosedürü kullanarak fonksiyonu kancalamak mümkündür.

Simprocedures are essentially replacement functions that can be used to override the original behavior of a function. When a hooked function is called, the simprocedure is executed instead, allowing you to control the flow of the program and modify its behavior as desired.

Simprosedürler, bir fonksiyonun orijinal davranışını geçersiz kılmak için kullanılan yerine geçen fonksiyonlardır. Kancalanan bir fonksiyon çağrıldığında, istenen şekilde programın akışını kontrol etmenizi ve davranışını değiştirmenizi sağlayan simprosedür çalıştırılır.

The angr framework provides a convenient way to hook functions using simprocedures. You can define a custom simprocedure that will be executed when a specific function is called. This allows you to modify the behavior of the function without modifying the original binary.

angr çatısı, simprosedürleri kullanarak fonksiyonları kancalamak için pratik bir yol sağlar. Belirli bir fonksiyon çağrıldığında çalıştırılacak özel bir simprosedür tanımlayabilirsiniz. Bu, orijinal ikili dosyayı değiştirmeden fonksiyonun davranışını değiştirmenizi sağlar.

To hook a function using angr, you can use the `sim_procedure` decorator provided by the framework. This decorator allows you to define a custom simprocedure for a specific function. Here's an example:

Bir fonksiyonu angr kullanarak kancalamak için, çatı tarafından sağlanan `sim_procedure` dekoratörünü kullanabilirsiniz. Bu dekoratör, belirli bir fonksiyon için özel bir simprosedür tanımlamanıza olanak sağlar. İşte bir örnek:

```python
import angr

# Define a custom simprocedure
class CustomSimProcedure(angr.SimProcedure):
    def run(self, arg1, arg2):
        # Modify the behavior of the function
        # ...

# Hook the function using the custom simprocedure
proj.hook(0x123456, CustomSimProcedure())
```

In this example, we define a custom simprocedure called `CustomSimProcedure` that overrides the behavior of a specific function. We then use the `hook` method provided by angr to hook the function at address `0x123456` with our custom simprocedure.

Bu örnekte, belirli bir fonksiyonun davranışını geçersiz kılan `CustomSimProcedure` adında özel bir simprosedür tanımlıyoruz. Ardından, angr tarafından sağlanan `hook` yöntemini kullanarak belirli bir adresteki (`0x123456`) fonksiyonu özel simprosedürümüzle kancalıyoruz.
```python
# Hook to the function called check_equals_WQNDNKKWAWOLXBAC

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

# Define a class and a tun method to hook completelly a function
class ReplacementCheckEquals(angr.SimProcedure):
# This C code:
#
# int add_if_positive(int a, int b) {
#   if (a >= 0 && b >= 0) return a + b;
#   else return 0;
# }
#
# could be simulated with python:
#
# class ReplacementAddIfPositive(angr.SimProcedure):
#   def run(self, a, b):
#     if a >= 0 and b >=0:
#       return a + b
#     else:
#       return 0
#
# run(...) receives the params of the hooked function
def run(self, to_check, length):
user_input_buffer_address = to_check
user_input_buffer_length = length

# Read the data from the memory address given to the function
user_input_string = self.state.memory.load(
user_input_buffer_address,
user_input_buffer_length
)

check_against_string = 'WQNDNKKWAWOLXBAC'.encode()

# Return 1 if equals to the string, 0 otherways
return claripy.If(
user_input_string == check_against_string,
claripy.BVV(1, 32),
claripy.BVV(0, 32)
)


# Hook the check_equals symbol. Angr automatically looks up the address
# associated with the symbol. Alternatively, you can use 'hook' instead
# of 'hook_symbol' and specify the address of the function. To find the
# correct symbol, disassemble the binary.
# (!)
check_equals_symbol = 'check_equals_WQNDNKKWAWOLXBAC' # :string
project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Birden fazla parametre ile scanf'i simüle etmek

Bazı durumlarda, birden fazla parametre ile scanf işlevini simüle etmek gerekebilir. Bu, angr kütüphanesini kullanarak yapılabilir. İşte bir örnek:

```python
import angr

# Hedef programın dosya yolunu belirtin
binary_path = "/path/to/program"

# angr projesini oluşturun
proj = angr.Project(binary_path, auto_load_libs=False)

# scanf işlevinin adresini bulun
scanf_addr = 0x12345678

# scanf işlevinin sembolik çağrısını oluşturun
scanf_call = proj.factory.call_state(scanf_addr)

# scanf'in ilk parametresini belirleyin
param1 = angr.claripy.BVS("param1", 32)  # 32 bit sembolik değişken oluşturun
scanf_call.regs.eax = param1  # eax kaydını sembolik değişkenle güncelleyin

# scanf'in ikinci parametresini belirleyin
param2 = angr.claripy.BVS("param2", 32)  # 32 bit sembolik değişken oluşturun
scanf_call.regs.ebx = param2  # ebx kaydını sembolik değişkenle güncelleyin

# scanf işlevini çağırın
proj.factory.simulation_manager().step(state=scanf_call)

# Sonuçları alın
result_state = proj.factory.simulation_manager().active[0]

# Sembolik değişkenlerin değerlerini elde edin
param1_value = result_state.solver.eval(param1)
param2_value = result_state.solver.eval(param2)

# Elde edilen değerleri yazdırın
print("Parametre 1 değeri:", param1_value)
print("Parametre 2 değeri:", param2_value)
```

Bu örnekte, scanf işlevinin sembolik bir çağrısını oluşturuyoruz. İlk parametre için 32 bit sembolik bir değişken ve ikinci parametre için başka bir 32 bit sembolik değişken oluşturuyoruz. Ardından, scanf işlevini çağırıyoruz ve sonuçları elde ediyoruz.
```python
# This time, the solution involves simply replacing scanf with our own version,
# since Angr does not support requesting multiple parameters with scanf.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

class ReplacementScanf(angr.SimProcedure):
# The code uses: 'scanf("%u %u", ...)'
def run(self, format_string, param0, param1):
scanf0 = claripy.BVS('scanf0', 32)
scanf1 = claripy.BVS('scanf1', 32)

# Get the addresses from the params and store the BVS in memory
scanf0_address = param0
self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
scanf1_address = param1
self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

# Now, we want to 'set aside' references to our symbolic values in the
# globals plugin included by default with a state. You will need to
# store multiple bitvectors. You can either use a list, tuple, or multiple
# keys to reference the different bitvectors.
self.state.globals['solutions'] = (scanf0, scanf1)

scanf_symbol = '__isoc99_scanf'
project.hook_symbol(scanf_symbol, ReplacementScanf())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

# Grab whatever you set aside in the globals dict.
stored_solutions = solution_state.globals['solutions']
solution = ' '.join(map(str, map(solution_state.solver.eval, stored_solutions)))

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Statik İkili Dosyalar

Statik ikili dosyalar, tüm bağımlılıklarını içeren ve çalıştırılabilir bir dosya olarak derlenen ikili dosyalardır. Bu dosyalar, çalıştırıldıkları sistemde herhangi bir dış bağımlılığa ihtiyaç duymazlar. Bu nedenle, statik ikili dosyalar, farklı sistemlerde çalıştırılmak üzere taşınabilir ve dağıtılabilir.

Statik ikili dosyaların avantajları şunlardır:

- Bağımlılıkların yönetimi kolaydır.
- Sistemdeki güncellemelerden etkilenmezler.
- Taşınabilir ve dağıtılabilirler.

Ancak, statik ikili dosyaların dezavantajları da vardır:

- Dosya boyutu genellikle daha büyüktür.
- Güncellemeler için yeniden derleme gerektirirler.
- Bellek kullanımı daha yüksek olabilir.

Statik ikili dosyalar, çeşitli programlama dilleri ve derleyiciler kullanılarak oluşturulabilir. Bu dosyalar, hedef sistemde çalıştırılmak üzere derlenirken, tüm bağımlılıkları dahil edecek şekilde yapılandırılmalıdır.
```python
# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc

import angr
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

#Find the addresses were the lib functions are loaded in the binary
#For example you could find: call   0x804ed80 <__isoc99_scanf>
project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output  # :boolean

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

* Bir **cybersecurity şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu keşfedin.
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter**'da beni takip edin 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
