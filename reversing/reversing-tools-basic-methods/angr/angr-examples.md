# Angr - Primeri

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

{% hint style="info" %}
Ako program koristi `scanf` da bi dobio **nekoliko vrednosti odjednom sa stdin-a**, morate generisati stanje koje počinje nakon **`scanf`**.
{% endhint %}

Kodovi preuzeti sa [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Unos za dostizanje adrese (navođenje adrese)
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
### Ulaz za dostizanje adrese (ukazujući ispis)
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
### Vrednosti registra

Registry vrednosti su ključni elementi u operativnom sistemu Windows. One čuvaju informacije o postavkama sistema, instaliranim aplikacijama i drugim konfiguracijama. Kada se bavite analizom malvera ili istraživanjem sistema, može biti korisno proučiti registry vrednosti kako biste dobili uvid u aktivnosti i konfiguraciju sistema.

Da biste pristupili registry vrednostima, možete koristiti različite alate kao što su `regedit`, `reg`, `PowerShell` ili `WMI`. Ovi alati omogućavaju pregled, izmenu i brisanje registry vrednosti.

Kada se bavite reverznim inženjeringom malvera, možete koristiti angr biblioteku za analizu i manipulaciju registry vrednostima. Angr pruža funkcionalnosti za čitanje, pisanje i praćenje promena registry vrednosti.

Evo nekoliko primera korišćenja angr biblioteke za rad sa registry vrednostima:

1. Čitanje vrednosti registra:

```python
import angr

proj = angr.Project("malware.exe")
registry = proj.simos.syscall_registry

value = registry.read_value("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Malware")
print(value)
```

2. Pisanje vrednosti registra:

```python
import angr

proj = angr.Project("malware.exe")
registry = proj.simos.syscall_registry

registry.write_value("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Malware", "C:\\malware.exe")
```

3. Praćenje promena vrednosti registra:

```python
import angr

proj = angr.Project("malware.exe")
registry = proj.simos.syscall_registry

registry.track_changes(True)

# Izvršavanje malvera...

changes = registry.get_changes()
print(changes)
```

Korišćenje angr biblioteke za rad sa registry vrednostima može biti veoma korisno prilikom analize malvera i istraživanja sistema.
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
### Vrednosti steka

Stack (stek) je struktura podataka koja se koristi za čuvanje privremenih vrednosti tokom izvršavanja programa. U kontekstu reverznog inženjeringa, proučavanje vrednosti steka može biti korisno za razumevanje kako program funkcioniše i pronalaženje ranjivosti.

Da biste proučavali vrednosti steka u programu pomoću angr alata, možete koristiti `state.regs.sp` da biste pristupili trenutnoj vrednosti pokazivača steka (stack pointer). Takođe možete koristiti `state.mem[state.regs.sp].deref` da biste pristupili vrednostima na vrhu steka.

Na primer, ako želite da pristupite vrednosti prvih 4 bajta na vrhu steka, možete koristiti sledeći kod:

```python
top_of_stack = state.mem[state.regs.sp].deref.resolved
value1 = top_of_stack[0:4].int.resolved
value2 = top_of_stack[4:8].int.resolved
value3 = top_of_stack[8:12].int.resolved
value4 = top_of_stack[12:16].int.resolved
```

Ovaj kod će vam omogućiti da pristupite i čitate vrednosti na vrhu steka. Možete prilagoditi kod da biste pristupili drugim delovima steka ili promenili veličinu bajtova koje čitate.

Proučavanje vrednosti steka može biti korisno za pronalaženje osetljivih informacija, kao što su lozinke ili ključevi, koji se mogu slučajno ili namerno ostaviti na steku.
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
U ovom scenariju, unos je uzet pomoću `scanf("%u %u")` i dodeljena je vrednost `"1 1"`, tako da vrednosti **`0x00000001`** na steku potiču od **korisničkog unosa**. Možete videti kako ove vrednosti počinju na `$ebp - 8`. Stoga, u kodu smo **oduzeli 8 bajtova od `$esp` (kako su u tom trenutku `$ebp` i `$esp` imali istu vrednost)**, a zatim smo gurnuli BVS.

![](<../../../.gitbook/assets/image (614).png>)

### Statičke vrednosti memorije (globalne promenljive)
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
### Dinamičke vrednosti memorije (Malloc)

Kada se bavite reverznom inženjeringom, često ćete se susresti sa situacijama u kojima morate analizirati dinamički alociranu memoriju. Jedan od najčešćih načina za alociranje dinamičke memorije u programima je korišćenje funkcije `malloc()`.

Funkcija `malloc()` se koristi za alociranje bloka memorije određene veličine u heapu. Ova funkcija vraća pokazivač na početak alocirane memorije. Kada više ne koristite alociranu memoriju, trebali biste je osloboditi pomoću funkcije `free()` kako biste izbegli curenje memorije.

Kada analizirate program koji koristi `malloc()`, možete pratiti vrednosti dinamički alocirane memorije kako biste razumeli kako se koristi i manipuliše. Ovo može biti korisno za pronalaženje ranjivosti ili razumevanje ponašanja programa.

Angr pruža mogućnost praćenja vrednosti dinamički alocirane memorije. Možete koristiti angr za simuliranje izvršavanja programa i pratiti promene vrednosti memorije tokom izvršavanja.

Da biste pratili vrednosti dinamičke memorije, možete koristiti angr-ovu funkciju `simgr.explore()`. Ova funkcija će simulirati izvršavanje programa i pratiti sve promene vrednosti memorije. Možete pristupiti vrednostima memorije pomoću `state.memory.load()` funkcije.

Na taj način, angr vam omogućava da analizirate dinamički alociranu memoriju i pratite promene vrednosti tokom izvršavanja programa. Ovo može biti korisno za pronalaženje ranjivosti ili razumevanje ponašanja programa.
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
### Simulacija fajlova

Angr pruža mogućnost simulacije fajlova kako bi se analizirao njihov uticaj na izvršavanje programa. Ova funkcionalnost je korisna za istraživanje ponašanja programa u odnosu na različite ulazne fajlove.

Da biste simulirali fajl, prvo morate kreirati instancu `angr.SimFile` klase. Ova klasa omogućava manipulaciju fajlovima i pruža metode za čitanje, pisanje i izvršavanje operacija nad fajlovima.

Evo nekoliko osnovnih metoda koje možete koristiti prilikom simulacije fajlova:

- `read(offset, size)`: Čita podatke iz fajla na određenoj poziciji `offset` i sa određenom veličinom `size`.
- `write(offset, data)`: Upisuje podatke `data` u fajl na određenoj poziciji `offset`.
- `seek(offset)`: Pomeranje trenutne pozicije u fajlu na određenu poziciju `offset`.
- `tell()`: Vraća trenutnu poziciju u fajlu.
- `size()`: Vraća veličinu fajla.

Kada kreirate instancu `angr.SimFile`, možete je koristiti kao argument prilikom kreiranja `angr.SimState` objekta. Na taj način možete simulirati izvršavanje programa sa određenim fajlovima kao ulazom.

```python
import angr

# Kreiranje instance SimFile
file = angr.SimFile("path/to/file.txt", content=b"Hello, World!")

# Kreiranje instance SimState sa fajlom kao ulazom
state = project.factory.entry_state(stdin=file)

# Simulacija izvršavanja programa
simulation = project.factory.simgr(state)
simulation.run()
```

Ova simulacija će izvršiti program koristeći fajl "file.txt" kao ulaz. Možete koristiti različite metode za manipulaciju fajlom tokom simulacije kako biste istražili različite scenarije izvršavanja programa.
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
Imajte na umu da simbolički fajl može takođe sadržati konstantne podatke spojene sa simboličkim podacima:
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

### Примена ограничења

{% hint style="info" %}
Понекад једноставне операције као што је упоређивање две речи дужине 16 **карактер по карактер** (петља), **кошта** много ангру јер мора да генерише гране **експоненцијално** зато што генерише 1 грану по услову: `2^16`\
Зато је лакше **затражити од ангра да се врати на претходну тачку** (где је већ тешки део обављен) и **ручно поставити та ограничења**.
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
U nekim scenarijima možete aktivirati **veritesting**, što će spojiti slične grane kako bi se uštedele beskorisne grane i pronašlo rešenje: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
Još jedna stvar koju možete uraditi u ovim scenarijima je da **hookujete funkciju dajući angr-u nešto što može lakše razumeti**.
{% endhint %}

### Menadžeri simulacija

Neki menadžeri simulacija mogu biti korisniji od drugih. U prethodnom primeru postojao je problem jer je stvoreno puno korisnih grana. Ovde će **veritesting** tehnika spojiti te grane i pronaći rešenje.\
Ovaj menadžer simulacija takođe se može aktivirati sa: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### Hakovanje/Bajpasiranje jednog poziva funkciji

Da biste hakovali ili bajpasirali jedan poziv funkciji, možete koristiti angr kako biste pronašli putanju izvršavanja koja zaobilazi taj poziv. Evo osnovnog postupka:

1. Kreirajte instancu `Project` objekta u angr-u sa ciljnim izvršnim fajlom.
2. Definišite ciljnu funkciju koju želite da hakujete.
3. Kreirajte instancu `PathGroup` objekta sa početnom putanjom koja sadrži poziv ciljne funkcije.
4. Koristite metodu `step()` na `PathGroup` objektu kako biste generisali nove putanje izvršavanja.
5. Proverite svaku novu putanju da biste videli da li sadrži poziv ciljne funkcije.
6. Ako pronađete putanju koja zaobilazi poziv, možete je dalje analizirati ili modifikovati prema potrebi.

Ovaj postupak vam omogućava da hakujete ili bajpasirate specifičan poziv funkciji, pružajući vam veću kontrolu nad izvršavanjem programa.
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
### Hakovanje funkcije / Simprocedura

Kada se radi o reverznom inženjeringu, često je potrebno hakovati ili modifikovati funkcije u ciljanom programu. Jedan od načina za to je korišćenje tehnike poznate kao "hooking" ili "simprocedura".

Hooking je proces umetanja dodatnog koda u funkciju kako bi se promenilo njeno ponašanje. Ovo se može postići na različite načine, ali jedan od popularnih alata koji se koristi za ovo je angr.

Angr je biblioteka za simboličko izvršavanje koja omogućava analizu i manipulaciju binarnih fajlova. Jedna od funkcionalnosti angr-a je mogućnost hookovanja funkcija.

Kada se koristi angr za hookovanje funkcije, prvo je potrebno definisati simproceduru koja će biti pozvana umesto originalne funkcije. Simprocedura je funkcija koja se izvršava umesto ciljne funkcije i može biti korišćena za manipulaciju ulaznih parametara, izvršavanje dodatnog koda ili promenu povratne vrednosti.

Da biste hookovali funkciju pomoću angr-a, prvo morate kreirati instancu angr projekta i odabrati ciljni binarni fajl. Zatim, koristite metodu `hook_symbol()` da biste definisali simproceduru za ciljnu funkciju. Na kraju, pokrenite angr projekat i simprocedura će biti pozvana umesto originalne funkcije.

Ova tehnika je veoma korisna u različitim scenarijima reverznog inženjeringa, kao što su debagovanje, analiza malvera ili modifikacija programa.
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
### Simulirajte scanf sa više parametara

Da biste simulirali funkciju scanf sa više parametara, možete koristiti angr biblioteku. Evo primera kako to možete uraditi:

```python
import angr

# Kreirajte projekat angr
proj = angr.Project("./program")

# Kreirajte simbol za svaki parametar scanf funkcije
param1 = angr.claripy.BVS("param1", 32)
param2 = angr.claripy.BVS("param2", 32)
param3 = angr.claripy.BVS("param3", 32)

# Kreirajte početno stanje sa simbolima kao vrednostima parametara
state = proj.factory.entry_state(args=["./program"], stdin=angr.SimFile)

# Ubacite simbole u registre koji se koriste kao argumenti za scanf
state.regs.eax = param1
state.regs.ebx = param2
state.regs.ecx = param3

# Kreirajte simbol za povratnu vrednost scanf funkcije
ret = angr.claripy.BVS("ret", 32)

# Pozovite scanf funkciju
scanf_addr = 0x12345678  # Adresa scanf funkcije
scanf_call = angr.SIM_PROCEDURES['libc']['scanf'](proj.arch)
state = state.step().successors[0]
state.regs.eip = scanf_addr
state.regs.eax = ret
state = scanf_call(state)

# Rešite simbole kako biste dobili konkretne vrednosti
param1_val = state.solver.eval(param1)
param2_val = state.solver.eval(param2)
param3_val = state.solver.eval(param3)
ret_val = state.solver.eval(ret)

# Ispisujte vrednosti parametara i povratnu vrednost
print("param1:", param1_val)
print("param2:", param2_val)
print("param3:", param3_val)
print("ret:", ret_val)
```

U ovom primeru, simuliramo poziv funkcije scanf sa tri parametra. Kreiramo simbole za svaki parametar i ubacujemo ih u registre koji se koriste kao argumenti za scanf. Zatim pozivamo scanf funkciju i rešavamo simbole kako bismo dobili konkretne vrednosti parametara i povratnu vrednost.
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
### Statički binarni fajlovi

Staticki binarni fajlovi su izvrsni fajlovi koji sadrže sve potrebne biblioteke i zavisnosti unutar samog fajla. To znači da se ne oslanjaju na sistemsku biblioteku prilikom izvršavanja. Ovo može biti korisno u situacijama kada želite da izvršite program na različitim sistemima bez potrebe za instaliranjem dodatnih biblioteka.

Kada se bavite reverznim inženjeringom, rad sa statičkim binarnim fajlovima može biti izazovan. Budući da su sve biblioteke već uključene u fajl, ne možete jednostavno pristupiti izvornom kodu biblioteka kako biste ih analizirali.

Međutim, postoje alati kao što je Angr koji mogu pomoći u analizi statičkih binarnih fajlova. Angr je biblioteka za simboličko izvršavanje koja omogućava analizu i manipulaciju binarnim fajlovima.

Korišćenjem Angr-a, možete izvršiti simboličko izvršavanje statičkog binarnog fajla, što vam omogućava da pratite put izvršavanja programa i analizirate njegovo ponašanje. Takođe možete koristiti Angr za pronalaženje ranjivosti ili za automatizaciju procesa analize.

Angr pruža različite metode za analizu statičkih binarnih fajlova, kao što su simboličko izvršavanje, simboličko izvršavanje sa konkretnim ulazom, simboličko izvršavanje sa ograničenjima i mnoge druge. Ovi alati mogu biti veoma korisni u procesu reverznog inženjeringa i pronalaženju ranjivosti u statičkim binarnim fajlovima.
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

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **cybersecurity kompaniji**? Želite li da vidite vašu **kompaniju reklamiranu na HackTricks-u**? Ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitter-u** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repo](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
