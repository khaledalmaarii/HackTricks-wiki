# Angr - Mifano

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

{% hint style="info" %}
Ikiwa programu inatumia `scanf` kupata **thamani kadhaa kwa wakati mmoja kutoka kwa stdin** unahitaji kuzalisha hali ambayo inaanza baada ya **`scanf`**.
{% endhint %}

Mambo yaliyochukuliwa kutoka [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Ingiza ili kufikia anwani (ikiashiria anwani)
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
### Kuingiza ili kufikia anwani (inayoonyesha prints)
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
### Thamani za Usajili

Registry ni sehemu muhimu ya mfumo wa Windows ambapo habari na mipangilio ya programu zinahifadhiwa. Thamani za Usajili ni vipengele muhimu katika Registry ambavyo hushikilia data kama vile mipangilio ya programu, mipangilio ya mfumo, na maelezo mengine muhimu.

Kuna aina tofauti za thamani za Usajili ambazo zinaweza kuhifadhiwa katika Registry. Hapa chini ni mifano ya aina kadhaa za thamani za Usajili:

- **Thamani ya Nakala Moja (String Value):** Hii ni thamani ambayo inashikilia data ya maandishi. Inaweza kutumika kuhifadhi habari kama majina ya faili, anwani za barua pepe, au mipangilio ya programu.
- **Thamani ya Binary (Binary Value):** Hii ni thamani ambayo inashikilia data ya binary, kama vile faili za picha au faili za sauti.
- **Thamani ya Nambari (Numeric Value):** Hii ni thamani ambayo inashikilia data ya nambari, kama vile idadi ya toleo la programu au mipangilio ya mtandao.
- **Thamani ya Multi-String (Multi-String Value):** Hii ni thamani ambayo inashikilia orodha ya maandishi. Inaweza kutumika kuhifadhi habari kama orodha ya anwani za IP au orodha ya mipangilio ya programu.

Kwa kawaida, thamani za Usajili zinaweza kusomwa na kuhaririwa na programu au watumiaji wa mfumo. Ni muhimu kuelewa jinsi ya kusoma na kuhariri thamani za Usajili ili kufanya mabadiliko sahihi kwenye mfumo wa Windows.
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
### Thamani za Stack

Katika uwanja wa ughack, stack ni eneo la kumbukumbu ambalo hutumiwa kuhifadhi thamani za pembejeo, anwani za kurudi, na maelezo mengine muhimu. Kwa kawaida, thamani za stack huwekwa katika utaratibu wa "last in, first out" (LIFO), ambapo thamani ya hivi karibuni iliyowekwa ndio ya kwanza kuondolewa.

Kuelewa thamani za stack ni muhimu katika uchambuzi wa kurejesha (reversing) na ughack. Kwa kutumia zana kama angr, unaweza kuchunguza na kubadilisha thamani za stack ili kufikia malengo yako ya ughack.

Kwa mfano, unaweza kutumia angr kuweka thamani maalum kwenye stack ili kudhibiti mzunguko wa programu. Hii inaweza kusaidia katika kubadilisha matokeo ya programu au kuepuka hatua fulani za usalama.

Kwa kumalizia, kuelewa jinsi thamani za stack zinavyofanya kazi na jinsi ya kuzibadilisha ni muhimu katika uchambuzi wa kurejesha na ughack. Zana kama angr zinaweza kuwa na manufaa katika kufikia malengo yako ya ughack kwa kudhibiti thamani za stack.
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
Katika kesi hii, kuingiza ilichukuliwa na `scanf("%u %u")` na thamani `"1 1"` ilitolewa, kwa hivyo thamani **`0x00000001`** ya stack inatoka kwa **kuingiza mtumiaji**. Unaweza kuona jinsi thamani hizi zinaanza katika `$ebp - 8`. Kwa hivyo, katika nambari tumepunguza **baiti 8 kwa `$esp` (kwa sababu wakati huo `$ebp` na `$esp` zilikuwa na thamani sawa)** na kisha tumeboresha BVS.

![](<../../../.gitbook/assets/image (614).png>)

### Thamani za Kumbukumbu za Stesheni (Variables za Kikoa)
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
### Thamani za Kumbukumbu ya Kudumu (Malloc)

Kumbukumbu ya kudumu ni eneo la kumbukumbu ambalo linaweza kutumika kwa uhuru na programu wakati wa utekelezaji wake. Katika muktadha wa uharibifu, tunaweza kutaka kuchunguza thamani za kumbukumbu ya kudumu ili kuelewa jinsi programu inavyofanya kazi na jinsi inavyoshughulikia data.

Kazi ya `malloc` ni kutumika kuomba kumbukumbu ya kudumu wakati wa utekelezaji wa programu. Kwa kawaida, `malloc` inarudi anwani ya kumbukumbu iliyotengwa. Kwa hivyo, tunaweza kutumia anwani hii kuchunguza na kubadilisha thamani za kumbukumbu ya kudumu.

Katika muktadha wa uharibifu, tunaweza kutumia zana kama vile Angr kuchunguza na kubadilisha thamani za kumbukumbu ya kudumu. Angr inaruhusu uchambuzi wa kiotomatiki wa programu na inaweza kutumika kwa uchunguzi wa kumbukumbu ya kudumu.

Kwa kutumia Angr, tunaweza kufuatilia jinsi thamani za kumbukumbu ya kudumu zinavyobadilika wakati wa utekelezaji wa programu. Hii inaweza kutusaidia kugundua mifumo ya usalama na kuchunguza udhaifu katika programu.
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
### Uigaji wa Faili

Angr inaweza kutumika kwa uigaji wa faili ili kuchunguza na kuelewa jinsi programu inavyofanya kazi. Uigaji wa faili unaruhusu mtumiaji kuiga mazingira ya programu na kuchunguza matokeo ya kila hatua ya programu. Hii inaweza kuwa muhimu katika kuelewa jinsi programu inavyojibu kwa pembejeo tofauti au kugundua kasoro na udhaifu.

Kwa kutumia angr, unaweza kuunda mfano wa faili na kuingiza pembejeo tofauti ili kuona jinsi programu inavyojibu. Unaweza kuchunguza hali tofauti za programu na kugundua maeneo ambayo yanaweza kuwa na udhaifu. Hii inaweza kusaidia katika kufanya uchunguzi wa usalama na kuboresha programu yako ili kuwa na nguvu zaidi dhidi ya mashambulizi.

Kwa kufanya uigaji wa faili, unaweza kuchunguza matokeo ya kila hatua ya programu na kuelewa jinsi programu inavyofanya kazi. Hii inaweza kusaidia katika kugundua mifumo ya kudhibiti, kuchambua algorithms, na kuelewa jinsi programu inavyoshughulikia data. Uigaji wa faili pia unaweza kusaidia katika kugundua kasoro za programu na kufanya majaribio ya usalama ili kuboresha programu yako.

Kwa kutumia angr, unaweza kufanya uigaji wa faili kwa njia rahisi na yenye nguvu. Unaweza kuchunguza programu yako na kugundua maeneo ambayo yanaweza kuwa na udhaifu. Hii inaweza kusaidia katika kufanya majaribio ya usalama na kuboresha programu yako ili kuwa na nguvu zaidi dhidi ya mashambulizi.
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
Tafadhali kumbuka kuwa faili ya ishara inaweza pia kuwa na data ya kudumu iliyochanganywa na data ya ishara:
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

### Kuomba Vizuizi

{% hint style="info" %}
Maranyingi, shughuli rahisi za binadamu kama kulinganisha maneno 2 ya urefu wa 16 **herufi kwa herufi** (kwa mzunguko), **gharama** sana kwa **angr** kwa sababu inahitaji kuzalisha matawi **kwa kiasi kikubwa** kwa sababu inazalisha tawi 1 kwa kila if: `2^16`\
Kwa hivyo, ni rahisi zaidi **kuomba angr ifike kwenye hatua ya awali** (ambapo sehemu ngumu ya kweli tayari imefanywa) na **kuweka vizuizi hivyo kwa mkono**.
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
Katika hali fulani unaweza kuamsha **veritesting**, ambayo itaunganisha hali sawa ili kuokoa matawi yasiyofaa na kupata suluhisho: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
Jambo lingine unaloweza kufanya katika hali hizi ni **kufunga kazi ya angr kwa kumpa kitu ambacho angr anaweza kuelewa** kwa urahisi zaidi.
{% endhint %}

### Mameneja wa Uigaji

Baadhi ya mameneja wa uigaji wanaweza kuwa na manufaa zaidi kuliko wengine. Katika mfano uliopita kulikuwa na tatizo kwa sababu matawi mengi muhimu yaliumbwa. Hapa, mbinu ya **veritesting** itaunganisha hayo na kupata suluhisho.\
Mameneja huu wa uigaji pia unaweza kuamshwa kwa: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### Kukwepa/Kupitisha wito mmoja kwa kazi

In some cases, when reverse engineering a binary, you may come across a function call that you want to bypass or modify. This can be achieved using the angr framework.

Katika baadhi ya hali, unapofanya uhandisi wa nyuma kwa faili ya binary, unaweza kukutana na wito wa kazi ambao unataka kuukwepa au kubadilisha. Hii inaweza kufanikishwa kwa kutumia mfumo wa angr.

To hook or bypass a function call, you can use the `simprocedures` feature of angr. Simprocedures allow you to replace or modify the behavior of a function during symbolic execution.

Ili kukwepa au kupitisha wito wa kazi, unaweza kutumia kipengele cha `simprocedures` cha angr. Simprocedures inakuwezesha kubadilisha au kubadilisha tabia ya kazi wakati wa utekelezaji wa ishara.

Here's an example of how to hook a function call using angr:

Hapa kuna mfano wa jinsi ya kukwepa wito wa kazi kwa kutumia angr:

```python
import angr

# Create an angr project
project = angr.Project("/path/to/binary")

# Define a custom simprocedure to replace the function call
class CustomSimProcedure(angr.SimProcedure):
    def run(self, state):
        # Modify the behavior of the function call here
        # You can access the arguments and return value using state.regs
        # You can modify the memory or registers using state.memory and state.regs
        # You can also modify the program counter using state.ip
        pass

# Hook the function call with the custom simprocedure
project.hook_symbol("function_name", CustomSimProcedure())

# Explore the binary with angr
explorer = project.surveyors.Explorer(find=0xdeadbeef, avoid=0xcafebabe)
explorer.run()

# Get the state where the desired address is reached
state = explorer.found[0]

# Print the value of a register at that state
print(state.regs.eax)
```

```python
import angr

# Unda mradi wa angr
project = angr.Project("/path/to/binary")

# Taja simprocedure ya desturi kuchukua nafasi ya wito wa kazi
class CustomSimProcedure(angr.SimProcedure):
    def run(self, state):
        # Badilisha tabia ya wito wa kazi hapa
        # Unaweza kupata hoja na thamani ya kurudi kwa kutumia state.regs
        # Unaweza kubadilisha kumbukumbu au rejista kwa kutumia state.memory na state.regs
        # Unaweza pia kubadilisha kinyume cha programu kwa kutumia state.ip
        pass

# Kukwepa wito wa kazi na simprocedure ya desturi
project.hook_symbol("jina_la_kazi", CustomSimProcedure())

# Tafiti faili ya binary na angr
explorer = project.surveyors.Explorer(find=0xdeadbeef, avoid=0xcafebabe)
explorer.run()

# Pata hali ambapo anwani inayotakiwa imefikiwa
state = explorer.found[0]

# Chapisha thamani ya rejista katika hali hiyo
print(state.regs.eax)
```

In the example above, we create an angr project for the binary and define a custom simprocedure called `CustomSimProcedure`. We then hook the function call with the custom simprocedure using `project.hook_symbol("function_name", CustomSimProcedure())`. Finally, we explore the binary using angr and retrieve the state where the desired address is reached. We can access and modify the registers and memory of that state as needed.

Katika mfano uliotajwa hapo juu, tunatengeneza mradi wa angr kwa faili ya binary na tunatamka simprocedure ya desturi iliyoitwa `CustomSimProcedure`. Kisha tunakwepa wito wa kazi na simprocedure ya desturi kwa kutumia `project.hook_symbol("jina_la_kazi", CustomSimProcedure())`. Hatimaye, tunatafiti faili ya binary kwa kutumia angr na kupata hali ambapo anwani inayotakiwa imefikiwa. Tunaweza kupata na kubadilisha rejista na kumbukumbu ya hali hiyo kama inavyohitajika.
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
### Kufunga kazi / Simprocedure

To hook a function in angr, you can use the `SimProcedure` class. This class allows you to replace the behavior of a function with your own custom code. 

To create a `SimProcedure`, you need to subclass the `SimProcedure` class and override the `run()` method. Inside the `run()` method, you can define the behavior of the function you want to hook.

Here is an example of how to hook the `printf()` function using a `SimProcedure`:

```python
import angr

class MyPrintf(angr.SimProcedure):
    def run(self, fmt, *args):
        # Custom code to replace printf() behavior
        # ...

# Create an angr project
proj = angr.Project("/path/to/binary")

# Hook the printf() function with MyPrintf
proj.hook_symbol("printf", MyPrintf())

# Start the exploration
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore()
```

In the example above, we define a `MyPrintf` class that subclasses `SimProcedure` and overrides the `run()` method. Inside the `run()` method, you can write your own code to replace the behavior of `printf()`. 

Then, we create an angr project and hook the `printf()` function with `MyPrintf` using the `hook_symbol()` method. Finally, we start the exploration by creating an entry state and a simulation manager.

By hooking a function with a `SimProcedure`, you can control the behavior of the function during the execution of the binary. This can be useful for various purposes, such as modifying the function's output or analyzing its behavior.
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
### Linganisha scanf na vigezo kadhaa

Ili kusimulisha scanf na vigezo kadhaa, unaweza kutumia kifurushi cha angr katika Python. Hapa kuna mfano wa jinsi ya kufanya hivyo:

```python
import angr

# Unda mpango wa angr
proj = angr.Project("binary_file")

# Unda kuingia kwa scanf
scanf_input = angr.claripy.BVS("scanf_input", 8 * 4)  # Unda symbolic variable ya 4 bytes

# Pata anwani ya scanf
scanf_addr = proj.loader.find_symbol("scanf").rebased_addr

# Unda hali ya kuanza
state = proj.factory.entry_state(args=["binary_file"])

# Weka kuingia ya scanf kwenye hali ya kuanza
state.memory.store(state.regs.esp + 4, scanf_input)

# Simulate scanf
simgr = proj.factory.simgr(state)
simgr.explore(find=scanf_addr)

# Pata matokeo ya kuingia
found_state = simgr.found[0]
input_value = found_state.solver.eval(scanf_input)

print("Input value:", input_value)
```

Katika mfano huu, tunatumia angr kuunda mpango wa angr kutoka kwa faili ya binary_file. Kisha tunatumia kifurushi cha claripy kutengeneza kuingia ya scanf kama variable ya ishara ya 4 bytes. Tunapata anwani ya scanf kutoka kwa mpango na kuunda hali ya kuanza. Tunaweka kuingia ya scanf kwenye hali ya kuanza na kisha tunasimamia scanf kwa kutumia simgr.explore. Hatimaye, tunapata matokeo ya kuingia kutoka kwa hali iliyopatikana na kuchapisha thamani ya kuingia.
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
### Programu za Kudumu

Programu za kudumu ni faili za binary ambazo zinafanya kazi bila kutegemea mazingira ya nje. Hii inamaanisha kuwa programu hizo zinaweza kufanya kazi kwenye mfumo wowote ambao unalingana na usanidi wao. Kwa mfano, unaweza kuwa na programu ya kudumu ambayo inafanya kazi kwenye mfumo wa Windows na pia kwenye mfumo wa Linux.

Kwa wapenzi wa udukuzi, programu za kudumu ni muhimu sana. Unaweza kuzitumia kuchunguza na kuchambua programu za binary bila kuzitegemea kwenye mazingira ya nje. Hii inamaanisha kuwa unaweza kufanya uchunguzi wako bila kuathiri mfumo wa mwenyeji au kuacha alama zozote.

Kuna zana nyingi za kudumu ambazo unaweza kutumia kwenye uchunguzi wako. Baadhi ya zana hizo ni:

- **IDA Pro**: Hii ni zana maarufu ya uchambuzi wa binary ambayo inaruhusu uchunguzi wa kina wa programu za kudumu. Inatoa vipengele vingi vya kusaidia kama vile uchambuzi wa kiotomatiki na uchambuzi wa kificho.
- **Ghidra**: Hii ni zana ya chanzo wazi ya uchambuzi wa binary ambayo inaruhusu uchunguzi wa kina wa programu za kudumu. Ina vipengele vingi vya kusaidia kama vile uchambuzi wa kiotomatiki na uchambuzi wa kificho.
- **Radare2**: Hii ni zana ya chanzo wazi ya uchambuzi wa binary ambayo inaruhusu uchunguzi wa kina wa programu za kudumu. Ina vipengele vingi vya kusaidia kama vile uchambuzi wa kiotomatiki na uchambuzi wa kificho.

Kwa kutumia zana hizi, unaweza kuchunguza na kuchambua programu za kudumu kwa urahisi na ufanisi. Unaweza kugundua udhaifu na kufanya marekebisho kulingana na mahitaji yako.
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
