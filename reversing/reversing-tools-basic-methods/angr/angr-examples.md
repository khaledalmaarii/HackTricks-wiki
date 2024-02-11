# Angr - Voorbeelde

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

{% hint style="info" %}
As die program `scanf` gebruik om **verskeie waardes gelyktydig van stdin te kry**, moet jy 'n toestand genereer wat begin ná die **`scanf`**.
{% endhint %}

Kodes geneem van [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Inset om adres te bereik (wat die adres aandui)
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
### Inset om adres te bereik (druk aanduidend)
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
### Registervarwaardes

Registervarwaardes is sleutels in die Windows-registreerder wat data bevat wat deur die bedryfstelsel gebruik word. Hier is 'n paar voorbeelde van registervarwaardes:

- **CurrentVersion**: Hierdie registervarwaarde bevat inligting oor die huidige weergawe van die bedryfstelsel.
- **Shell**: Hierdie registervarwaarde bevat die pad na die skilprogram wat gebruik word om die gebruikerskoppelvlak te vertoon.
- **Userinit**: Hierdie registervarwaarde bevat die pad na die program wat uitgevoer word wanneer 'n gebruiker aanmeld.

Dit is belangrik om registervarwaardes te verstaan en te ondersoek, aangesien dit waardevolle inligting kan verskaf vir 'n hacker of pentester.
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
### Stakwaardes

Die stak is 'n belangrike konsep in die programmering. Dit is 'n datastruktuur wat gebruik word om waardes te stoor en te organiseer. In die konteks van die hakwerk, kan die stak gebruik word om waardes te manipuleer en te ondersoek.

Wanneer 'n funksie aangeroep word, word die parameters en die terugkeeradres op die stak geplaas. Die funksie kan dan die waardes van die stak gebruik om sy berekeninge uit te voer. Dit sluit in die gebruik van lokale veranderlikes en die oproep van ander funksies.

Die stakwaardes kan ook gebruik word om foutopsporing te doen. Deur die waardes op die stak te ondersoek, kan 'n hakker insig kry in die uitvoering van 'n program en moontlike kwesbaarhede identifiseer.

Dit is belangrik om te verstaan hoe die stak werk en hoe om die waardes daarop te ondersoek en te manipuleer. Hierdie kennis kan 'n hakker help om die program te verstaan en moontlike aanvalspunte te identifiseer.
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
In hierdie scenario is die inset geneem met `scanf("%u %u")` en die waarde `"1 1"` is gegee, so die waardes **`0x00000001`** van die stapel kom van die **gebruiker inset**. Jy kan sien hoe hierdie waardes begin in `$ebp - 8`. Daarom het ons in die kode **8 byte van `$esp` afgetrek (soos op daardie oomblik `$ebp` en `$esp` dieselfde waarde gehad het)** en toe het ons die BVS gedruk.

![](<../../../.gitbook/assets/image (614).png>)

### Statische geheue waardes (Globale veranderlikes)
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
### Dinamiese Geheue Waardes (Malloc)

Die `malloc` funksie in C word gebruik om dinamiese geheue toe te ken aan 'n program tydens uitvoering. Dit kan handig wees vir die manipulasie van geheue waardes tydens die uitvoering van 'n program. Hier is 'n paar voorbeelde van hoe jy die `malloc` funksie kan gebruik met behulp van die angr raamwerk.

#### Voorbeeld 1: Malloc Waarde Manipulasie

```python
import angr

# Skep 'n angr projek
proj = angr.Project("/path/to/binary")

# Skep 'n angr state
state = proj.factory.entry_state()

# Kry 'n verwysing na die malloc funksie
malloc_addr = proj.loader.find_symbol("malloc").rebased_addr

# Skep 'n simboliese waarde vir die malloc funksie
malloc_size = 8
malloc_value = state.solver.BVS("malloc_value", malloc_size * 8)

# Voeg die simboliese waarde by die geheue van die program
state.memory.store(malloc_addr, malloc_value)

# Los die program op
simgr = proj.factory.simulation_manager(state)
simgr.run()

# Kry die finale waardes van die malloc funksie
final_malloc_value = simgr.deadended[0].solver.eval(malloc_value)

print(f"Final malloc value: {final_malloc_value}")
```

In hierdie voorbeeld word 'n angr projek geskep en 'n angr state word geïnisialiseer. Die `malloc` funksie se adres word verkry deur die `find_symbol` metode te gebruik en die adres word herbasis. 'n Simboliese waarde word geskep vir die `malloc` funksie met behulp van die `BVS` metode. Die simboliese waarde word dan by die geheue van die program gevoeg deur die `store` metode te gebruik. Die program word opgelos en die finale waarde van die `malloc` funksie word verkry deur die `eval` metode te gebruik.

#### Voorbeeld 2: Malloc Waarde Vergelyking

```python
import angr

# Skep 'n angr projek
proj = angr.Project("/path/to/binary")

# Skep 'n angr state
state = proj.factory.entry_state()

# Kry 'n verwysing na die malloc funksie
malloc_addr = proj.loader.find_symbol("malloc").rebased_addr

# Skep 'n simboliese waarde vir die malloc funksie
malloc_size = 8
malloc_value = state.solver.BVS("malloc_value", malloc_size * 8)

# Voeg die simboliese waarde by die geheue van die program
state.memory.store(malloc_addr, malloc_value)

# Los die program op
simgr = proj.factory.simulation_manager(state)
simgr.run()

# Vergelyk die finale waarde van die malloc funksie met 'n konstante waarde
final_malloc_value = simgr.deadended[0].solver.eval(malloc_value)
comparison_value = 42

if final_malloc_value == comparison_value:
    print("Malloc value matches comparison value")
else:
    print("Malloc value does not match comparison value")
```

In hierdie voorbeeld word 'n angr projek geskep en 'n angr state word geïnisialiseer. Die `malloc` funksie se adres word verkry deur die `find_symbol` metode te gebruik en die adres word herbasis. 'n Simboliese waarde word geskep vir die `malloc` funksie met behulp van die `BVS` metode. Die simboliese waarde word dan by die geheue van die program gevoeg deur die `store` metode te gebruik. Die program word opgelos en die finale waarde van die `malloc` funksie word verkry deur die `eval` metode te gebruik. Die finale waarde word dan vergelyk met 'n konstante waarde en die relevante boodskap word gedruk volgens die vergelyking.
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
### Lêersimulasie

Die Angr-raamwerk bied 'n kragtige funksie vir lêersimulasie. Hiermee kan jy 'n virtuele lêerstelsel skep en manipuleer sonder om fisiese lêers op jou stelsel te skep. Dit is baie nuttig vir die analise van programme wat met lêers werk sonder om die werklike lêers te verander.

Om 'n lêersimulasie te skep, begin jy deur 'n `SimState`-objek te skep. Hierdie objek verteenwoordig die toestand van die virtuele masjien waarop die lêerstelsel sal loop. Jy kan dan die lêerstelsel manipuleer deur funksies soos `fs` (vir lêerstelsel) en `memory` te gebruik.

Byvoorbeeld, as jy 'n lêer wil skep met die naam "geheime.txt" en die inhoud "Hierdie is 'n geheime lêer", kan jy die volgende kode gebruik:

```python
import angr

proj = angr.Project("my_binary")

state = proj.factory.simulation_manager().active[0]

fs = state.fs
fs.create("geheime.txt", content="Hierdie is 'n geheime lêer")
```

Hierdie kode skep 'n `SimState`-objek, kry die lêerstelselobjek (`fs`) van die `SimState`-objek, en skep dan die lêer "geheime.txt" met die gewenste inhoud.

Jy kan ook lêers en lêerinhoud verander deur die `fs`-objek te manipuleer. Byvoorbeeld, as jy die inhoud van die lêer "geheime.txt" wil verander na "Nuwe geheime", kan jy die volgende kode gebruik:

```python
fs.write("geheime.txt", "Nuwe geheime")
```

Hierdie kode verander die inhoud van die lêer "geheime.txt" na "Nuwe geheime".

Lêersimulasie is 'n kragtige tegniek wat jou in staat stel om lêerstelsels te manipuleer sonder om fisiese lêers te skep. Dit kan baie nuttig wees vir die analise van programme wat met lêers werk.
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
Let daarop dat die simboliese lêer ook konstante data kan bevat wat saamgevoeg is met simboliese data:
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

### Toepassing van Beperkings

{% hint style="info" %}
Soms kos eenvoudige menslike handelinge, soos die vergelyking van 2 woorde van lengte 16 **karakter vir karakter** (lus), baie vir 'n **angr** omdat dit eksponensieel takke moet genereer omdat dit 1 tak per if genereer: `2^16`\
Daarom is dit makliker om **angr te vra om na 'n vorige punt te gaan** (waar die regte moeilike deel al gedoen is) en **daardie beperkings handmatig in te stel**.
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
In sommige scenario's kan jy **veritesting** aktiveer, wat soortgelyke toestande sal saamvoeg om nuttelose takke te spaar en die oplossing te vind: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
'n Ander ding wat jy in hierdie scenario's kan doen, is om die funksie te **hook** en angr iets te gee wat dit makliker kan verstaan.
{% endhint %}

### Simulasiebestuurders

Sommige simulasiebestuurders kan nuttiger wees as ander. In die vorige voorbeeld was daar 'n probleem omdat baie nuttige takke geskep is. Hier sal die **veritesting** tegniek dit saamvoeg en 'n oplossing vind.\
Hierdie simulasiebestuurder kan ook geaktiveer word met: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### Haak/Bypass een oproep na 'n funksie

Om 'n oproep na 'n spesifieke funksie te haak of te omseil, kan jy die volgende stappe volg:

1. Identifiseer die funksie waarvan jy die oproep wil haak of omseil.
2. Vind die plek in die program waar die oproep na die funksie plaasvind.
3. Gebruik 'n tegniek soos 'n hook of 'n omseiling om die oproep te verander of te omseil.
4. Monitor die program se gedrag om te verseker dat die oproep korrek gehaak of omseil word.

Hier is 'n voorbeeld van hoe jy 'n oproep na 'n funksie kan haak met behulp van die angr-raamwerk:

```python
import angr

# Laai die program in die angr-raamwerk
proj = angr.Project("/pad/na/program")

# Definieer die funksie wat jy wil haak
target_function = "funksie_na_haak"

# Vind die plek waar die oproep na die funksie plaasvind
call_site = proj.loader.find_symbol(target_function).rebased_addr

# Definieer 'n hook-funksie wat die oproep sal vervang
def hook_function(state):
    # Voer jou eie logika uit om die oproep te vervang
    # byvoorbeeld deur 'n ander funksie op te roep
    state.regs.eax = 0x12345678  # Vervang die waarde in die eax-register

# Haak die oproep na die funksie
proj.hook(call_site, hook_function)

# Voer die program uit met die gehaakte oproep
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.run()

# Kry die finale toestand na die uitvoering
final_state = simgr.deadended[0]

# Kry die waarde van die eax-register na die gehaakte oproep
hooked_value = final_state.regs.eax
```

Met hierdie voorbeeld kan jy 'n oproep na 'n spesifieke funksie haak deur die waarde in die eax-register te vervang. Jy kan jou eie logika implementeer om die oproep te vervang met enige gewenste funksie of gedrag.
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
### Haak 'n funksie / Simprocedure

Om 'n funksie te haak of 'n simprocedure te gebruik, kan jy die volgende stappe volg:

1. Identifiseer die funksie wat jy wil haak. Dit kan 'n belangrike funksie wees wat jy wil monitor of manipuleer.
2. Skep 'n simprocedure wat die funksie se gedrag simuleer. Dit kan 'n eenvoudige simulasie wees wat die funksie se oorspronklike gedrag naboots, of dit kan 'n aangepaste simulasie wees wat spesifieke veranderinge aanbring.
3. Haak die funksie deur die simprocedure in te stel as die nuwe implementering van die funksie. Dit sal die oorspronklike funksie vervang met die simulasie wat jy geskep het.
4. Voer die program uit en monitor die gedrag van die gehaakte funksie. Jy kan die simprocedure gebruik om data te manipuleer, te onderskep of te monitor soos nodig.

Dit is 'n kragtige tegniek wat gebruik kan word om die gedrag van 'n program te manipuleer en te ondersoek. Deur funksies te haak en simprosedures te gebruik, kan jy die program se uitvoering beheer en data manipuleer om jou doelwitte te bereik.
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
### Simuleer scanf met verskeie parameters

Om scanf te simuleer met verskeie parameters, kan jy die `simprocedure`-funksie in angr gebruik. Hier is 'n voorbeeld van hoe jy dit kan doen:

```python
import angr

# Definieer die simulasiefunksie
def simulate_scanf(state):
    # Kry die waardes van die parameters
    param1 = state.solver.BVS('param1', 32)
    param2 = state.solver.BVS('param2', 32)
    param3 = state.solver.BVS('param3', 32)

    # Stel die waardes van die parameters in
    state.memory.store(state.regs.esp + 4, param1)
    state.memory.store(state.regs.esp + 8, param2)
    state.memory.store(state.regs.esp + 12, param3)

    # Voer die scanf-funksie uit
    state.regs.eax = state.solver.BVV(3, 32)  # Stel die terugkeerwaarde in

# Laai die program in angr
proj = angr.Project('/path/to/program')

# Definieer die simulasie
simgr = proj.factory.simgr()

# Voer die simulasie uit
simgr.explore(find=simulate_scanf)

# Kry die staat waarin die simulasie voltooi is
state = simgr.found[0]

# Kry die waardes van die parameters
param1_value = state.solver.eval(state.memory.load(state.regs.esp + 4, 4))
param2_value = state.solver.eval(state.memory.load(state.regs.esp + 8, 4))
param3_value = state.solver.eval(state.memory.load(state.regs.esp + 12, 4))

# Druk die waardes van die parameters af
print(f"param1: {param1_value}")
print(f"param2: {param2_value}")
print(f"param3: {param3_value}")
```

In hierdie voorbeeld gebruik ons die `simprocedure`-funksie om 'n simulasie van scanf met verskeie parameters uit te voer. Ons definieer 'n funksie genaamd `simulate_scanf` wat die waardes van die parameters kry en dit in die geheue stoor. Ons stel ook die terugkeerwaarde van scanf in. Ons laai die program in angr en definieer die simulasie. Ons voer die simulasie uit en kry die staat waarin die simulasie voltooi is. Ons kry die waardes van die parameters uit die geheue en druk dit af.
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
### Statische Binêre lêers

'n Statische binêre lêer is 'n uitvoerbare lêer wat alle benodigde biblioteke en hulpbronne bevat om selfstandig te kan hardloop sonder om afhanklik te wees van eksterne bronne. Dit beteken dat alle nodige kode ingesluit is in die lêer self, wat dit maklik maak om die program op verskillende stelsels uit te voer sonder om die biblioteke apart te installeer.

'n Statische binêre lêer kan 'n nuttige hulpmiddel wees vir omgekeerde ingenieurswese, omdat dit die analisering van die program vereenvoudig sonder om te hoef bekommer oor die ontbrekende biblioteke of afhanklikhede. Dit maak dit ook moeiliker vir aanvallers om die program te manipuleer deur die vervanging van biblioteke of die inspuiting van skadelike kode.

Om 'n statiese binêre lêer te skep, kan jy gebruik maak van hulpmiddels soos `gcc` of `ld`. Dit is belangrik om te verseker dat jy die regte biblioteke insluit en dat die lêer korrek gekoppel word. Deur die gebruik van 'n statiese binêre lêer kan jy die program onafhanklik van die omgewing hardloop en dit maak dit makliker om die program te analiseer vir omgekeerde ingenieurswese.
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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
