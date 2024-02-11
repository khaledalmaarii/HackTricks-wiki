# Angr - Przykłady

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

{% hint style="info" %}
Jeśli program używa `scanf` do pobrania **kilku wartości naraz ze standardowego wejścia**, musisz wygenerować stan, który rozpoczyna się po **`scanf`**.
{% endhint %}

Kody pobrane z [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Wprowadź dane, aby osiągnąć adres (wskazując adres)
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
### Wejście potrzebne do osiągnięcia adresu (wskazujące na wydruki)

W przypadku osiągnięcia określonego adresu (wskazującego na wydruki), należy podać odpowiednie dane wejściowe.
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
### Wartości rejestru

The Windows registry is a hierarchical database that stores configuration settings and options for the operating system and installed applications. It contains various types of data, including registry values. Registry values are entries within a registry key that store specific information.

Rejestry systemu Windows to hierarchiczna baza danych przechowująca ustawienia konfiguracyjne i opcje dla systemu operacyjnego oraz zainstalowanych aplikacji. Zawiera różne rodzaje danych, w tym wartości rejestru. Wartości rejestru to wpisy w kluczu rejestru, które przechowują określone informacje.

Each registry value has a name and a corresponding data type. The name is used to identify the value within the registry key, while the data type determines the format and interpretation of the value's data.

Każda wartość rejestru ma nazwę i odpowiadający jej typ danych. Nazwa jest używana do identyfikacji wartości wewnątrz klucza rejestru, podczas gdy typ danych określa format i interpretację danych wartości.

Some common data types for registry values include:

Niektóre powszechne typy danych dla wartości rejestru to:

- **REG_SZ**: A null-terminated string.
- **REG_DWORD**: A 32-bit unsigned integer.
- **REG_QWORD**: A 64-bit unsigned integer.
- **REG_BINARY**: Binary data.
- **REG_MULTI_SZ**: An array of null-terminated strings.

- **REG_SZ**: Ciąg znaków zakończony zerem.
- **REG_DWORD**: 32-bitowa liczba całkowita bez znaku.
- **REG_QWORD**: 64-bitowa liczba całkowita bez znaku.
- **REG_BINARY**: Dane binarne.
- **REG_MULTI_SZ**: Tablica ciągów znaków zakończonych zerem.

Understanding the different types of registry values is important when analyzing and modifying registry entries during the reverse engineering process.

Zrozumienie różnych typów wartości rejestru jest ważne podczas analizowania i modyfikowania wpisów rejestru podczas procesu inżynierii wstecznej.
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
### Wartości stosu

The stack is a data structure used by programs to store temporary variables and function call information. In the context of reverse engineering, analyzing the values stored on the stack can provide valuable insights into the program's execution flow and the values being manipulated.

Stack values can be accessed and manipulated using various techniques. One common approach is to use a debugger to pause the program's execution at a specific point and inspect the stack. This allows you to view the values stored on the stack and understand how they are being used by the program.

Another technique is to use a disassembler or decompiler to analyze the program's assembly code or high-level language representation. By examining the instructions or code, you can identify the locations where values are pushed onto the stack and where they are used.

Additionally, dynamic analysis tools like angr can be used to automatically analyze the program's execution and track the values stored on the stack. These tools can provide a more comprehensive view of the program's behavior and help identify potential vulnerabilities or interesting code paths.

Understanding the values stored on the stack is crucial for reverse engineering tasks such as understanding function arguments, identifying local variables, and analyzing function calls. By carefully examining the stack values, you can gain a deeper understanding of the program's logic and behavior.
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
W tym scenariuszu wejście zostało pobrane za pomocą `scanf("%u %u")`, a wartość `"1 1"` została podana, więc wartości **`0x00000001`** na stosie pochodzą od **wejścia użytkownika**. Można zobaczyć, że te wartości zaczynają się od `$ebp - 8`. W związku z tym w kodzie **odejmujemy 8 bajtów od `$esp` (ponieważ w tym momencie `$ebp` i `$esp` miały tę samą wartość)**, a następnie przesuwamy BVS.

![](<../../../.gitbook/assets/image (614).png>)

### Statyczne wartości pamięci (zmienne globalne)
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
### Dynamiczne wartości pamięci (Malloc)

W niektórych przypadkach, podczas analizy programów, możemy napotkać dynamiczne alokacje pamięci za pomocą funkcji `malloc`. Aby zrozumieć, jakie wartości są przechowywane w tej pamięci, możemy skorzystać z narzędzia angr.

#### Przykład 1: Odczytanie wartości z dynamicznie zaalokowanej pamięci

Poniżej przedstawiony jest przykład kodu, który alokuje dynamicznie pamięć za pomocą funkcji `malloc` i zapisuje w niej wartość 42:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int* ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    printf("Value: %d\n", *ptr);
    free(ptr);
    return 0;
}
```

Aby odczytać wartość z dynamicznie zaalokowanej pamięci, możemy skorzystać z angr. Poniżej przedstawiony jest kod angr, który odczytuje wartość z pamięci:

```python
import angr

def main():
    project = angr.Project("./example")
    state = project.factory.entry_state()
    simgr = project.factory.simgr(state)
    simgr.explore(find=0x4005a6)  # Adres instrukcji printf

    if simgr.found:
        found_state = simgr.found[0]
        value = found_state.solver.eval(found_state.memory.load(found_state.regs.rbp - 0x8, 4), cast_to=int)
        print("Value:", value)

if __name__ == "__main__":
    main()
```

Po uruchomieniu tego kodu, otrzymamy wartość `42`, która została odczytana z dynamicznie zaalokowanej pamięci.

#### Przykład 2: Modyfikacja wartości w dynamicznie zaalokowanej pamięci

Możemy również użyć angr do modyfikacji wartości w dynamicznie zaalokowanej pamięci. Poniżej przedstawiony jest kod angr, który zmienia wartość w pamięci na `1337`:

```python
import angr

def main():
    project = angr.Project("./example")
    state = project.factory.entry_state()
    simgr = project.factory.simgr(state)
    simgr.explore(find=0x4005a6)  # Adres instrukcji printf

    if simgr.found:
        found_state = simgr.found[0]
        found_state.memory.store(found_state.regs.rbp - 0x8, 1337, size=4)

        # Zapisz zmienioną pamięć do pliku
        with open("modified_memory", "wb") as f:
            f.write(found_state.memory.load(found_state.regs.rbp - 0x8, 4).eval)

if __name__ == "__main__":
    main()
```

Po uruchomieniu tego kodu, wartość w dynamicznie zaalokowanej pamięci zostanie zmieniona na `1337`, a zmodyfikowana pamięć zostanie zapisana do pliku "modified_memory".
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
### Symulacja pliku

The `angr` framework provides a powerful feature called file simulation, which allows you to analyze the behavior of a program when interacting with files. This can be useful for understanding how a program reads, writes, or manipulates files.

To simulate a file, you first need to create a `SimFile` object using the `angr.SimFile` constructor. This object represents a file in the symbolic execution engine. You can specify the file's name, mode, and other attributes when creating the `SimFile` object.

Once you have created the `SimFile` object, you can use it to perform various file operations, such as reading from or writing to the file. The `SimFile` object provides methods like `read`, `write`, `seek`, and `tell` to perform these operations.

To simulate the behavior of a program when interacting with a file, you need to replace the standard file operations with the `SimFile` object. This can be done using the `angr.SimProcedures` mechanism. By replacing the standard file operations with the corresponding `SimFile` methods, you can control the behavior of the program when it interacts with files.

For example, you can replace the `open` function with a `SimProcedure` that creates a `SimFile` object and returns a file descriptor. You can also replace the `read` function with a `SimProcedure` that reads data from the `SimFile` object instead of a real file.

By simulating file operations, you can analyze how a program behaves when reading or writing files, and you can also manipulate the contents of the files to test different scenarios.

Overall, file simulation is a powerful technique provided by the `angr` framework for analyzing and understanding the behavior of programs when interacting with files.
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
Należy pamiętać, że symboliczny plik może również zawierać dane stałe połączone z danymi symbolicznymi:
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

### Zastosowanie ograniczeń

{% hint style="info" %}
Czasami proste operacje człowieka, takie jak porównanie dwóch słów o długości 16 **znak po znaku** (pętla), **kosztują** dużo dla **angr**, ponieważ musi generować gałęzie **wykładniczo**, ponieważ generuje 1 gałąź na if: `2^16`\
Dlatego łatwiej jest **poprosić angr o powrót do poprzedniego punktu** (gdzie trudna część została już wykonana) i **ustawić te ograniczenia ręcznie**.
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
W niektórych scenariuszach można aktywować **veritesting**, który połączy podobne stany, aby zaoszczędzić niepotrzebne gałęzie i znaleźć rozwiązanie: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
W tych scenariuszach można również **hookować funkcję, aby angr miał coś, czego łatwiej zrozumieć**.
{% endhint %}

### Menedżery symulacji

Niektóre menedżery symulacji mogą być bardziej przydatne niż inne. W poprzednim przykładzie pojawił się problem, ponieważ utworzono wiele przydatnych gałęzi. Tutaj technika **veritesting** połączy je i znajdzie rozwiązanie.\
Ten menedżer symulacji można również aktywować za pomocą: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### Podpięcie/Omijanie jednego wywołania funkcji

Sometimes, during reverse engineering, we may encounter a situation where we want to modify the behavior of a specific function call. This can be achieved using the angr framework.

Czasami, podczas inżynierii wstecznej, możemy napotkać sytuację, w której chcemy zmodyfikować zachowanie konkretnego wywołania funkcji. Możemy to osiągnąć za pomocą frameworku angr.

To hook/bypass a single call to a function, we need to follow these steps:

Aby podpiąć/ominąć pojedyncze wywołanie funkcji, musimy postępować zgodnie z tymi krokami:

1. Create an angr project and load the binary.

   ```python
   import angr

   project = angr.Project("/path/to/binary")
   ```

2. Define a function that will be called instead of the original function.

   ```python
   def hook_function(state):
       # Modify the behavior of the function call here
       pass
   ```

3. Get the address of the function call instruction that we want to hook.

   ```python
   function_call_addr = 0x12345678  # Address of the function call instruction
   ```

4. Create a SimProcedure that will replace the original function call with our hook function.

   ```python
   project.hook(function_call_addr, hook_function)
   ```

5. Explore the binary using angr's exploration techniques.

   ```python
   state = project.factory.entry_state()
   simulation = project.factory.simgr(state)
   simulation.explore()
   ```

6. Analyze the results and observe the modified behavior of the function call.

   ```python
   if simulation.found:
       found_state = simulation.found[0]
       # Analyze the state to observe the modified behavior
   ```

By following these steps, we can effectively hook/bypass a single call to a function and modify its behavior during the reverse engineering process.

Przez postępowanie zgodnie z tymi krokami, możemy skutecznie podpiąć/ominąć pojedyncze wywołanie funkcji i zmodyfikować jej zachowanie podczas procesu inżynierii wstecznej.
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
### Hookowanie funkcji / Simprocedura

In some cases, when reverse engineering a binary, you may encounter a function that you want to modify or intercept its behavior. This can be achieved using a technique called "hooking". 

Hooking involves replacing the original function with your own custom code, allowing you to control the execution flow and manipulate the function's behavior. One way to implement hooking is by using a technique called "simprocedure" in the angr framework.

A simprocedure is a user-defined function that can be used to replace the behavior of a specific function during symbolic execution. By creating a simprocedure, you can define your own custom code that will be executed instead of the original function.

To hook a function using angr, you need to follow these steps:

1. Identify the function you want to hook in the binary.
2. Create a simprocedure that defines the custom code you want to execute.
3. Replace the original function with the simprocedure using the `hook_symbol()` method in angr.

Here is an example of how to hook a function using angr:

```python
import angr

# Load the binary
project = angr.Project("/path/to/binary")

# Identify the function to hook
function_address = 0x12345678

# Create a simprocedure
def custom_code(state):
    # Your custom code here
    ...

# Hook the function with the simprocedure
project.hook_symbol(function_address, custom_code)

# Start symbolic execution
state = project.factory.entry_state()
simulation = project.factory.simgr(state)

# Explore the binary
simulation.explore()

# Access the hooked function
hooked_function = simulation.found[0].globals['hooked_function']

# Manipulate the behavior of the hooked function
hooked_function.some_variable = 42
hooked_function.some_function()

# Continue with the execution
simulation.run()
```

By hooking a function using angr's simprocedure, you can gain control over the function's behavior and manipulate its execution to suit your needs during reverse engineering.
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
### Symulowanie scanf z kilkoma parametrami

Aby symulować funkcję scanf z kilkoma parametrami, możemy skorzystać z narzędzia angr. Poniżej przedstawiam przykład kodu w języku C, który używa scanf z dwoma parametrami:

```c
#include <stdio.h>

int main() {
    int num1, num2;
    
    printf("Podaj dwie liczby: ");
    scanf("%d %d", &num1, &num2);
    
    printf("Wprowadzone liczby: %d i %d\n", num1, num2);
    
    return 0;
}
```

Aby zasymulować tę funkcję za pomocą angr, możemy użyć następującego kodu Python:

```python
import angr

def main():
    project = angr.Project("./program")
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)
    
    simulation.explore(find=0xADDRESS_OF_SUCCESS, avoid=0xADDRESS_OF_FAILURE)
    
    if simulation.found:
        solution_state = simulation.found[0]
        num1 = solution_state.solver.eval(num1_variable)
        num2 = solution_state.solver.eval(num2_variable)
        print("Wprowadzone liczby: {} i {}".format(num1, num2))
    else:
        print("Nie znaleziono rozwiązania.")

if __name__ == "__main__":
    main()
```

W powyższym kodzie, `./program` to ścieżka do skompilowanego pliku wykonywalnego naszego programu. `0xADDRESS_OF_SUCCESS` to adres, który oznacza sukces, czyli moment, w którym chcemy, aby angr zakończył symulację. `0xADDRESS_OF_FAILURE` to adres, który oznacza porażkę, czyli moment, w którym chcemy, aby angr uniknął podczas symulacji.

Po zakończeniu symulacji, jeśli zostanie znalezione rozwiązanie, możemy uzyskać wartości wprowadzonych liczb, korzystając z `solution_state.solver.eval(num1_variable)` i `solution_state.solver.eval(num2_variable)`.

Pamiętaj, że angr jest potężnym narzędziem do analizy binarnej i symulacji, które może być używane w celach badawczych i edukacyjnych. Używanie go w nielegalny sposób jest niezgodne z prawem.
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
### Statyczne pliki binarne

Staticzne pliki binarne to pliki wykonywalne, które zawierają wszystkie niezbędne biblioteki i zależności wewnątrz siebie. Oznacza to, że nie muszą korzystać z zewnętrznych bibliotek systemowych podczas uruchamiania. Dzięki temu są bardziej przenośne i niezależne od konkretnego środowiska.

W przypadku analizy statycznych plików binarnych, możemy użyć narzędzia angr do przeprowadzenia różnych operacji, takich jak odnajdywanie funkcji, analiza struktury kodu, czy odnajdywanie podatności.

Aby użyć angr do analizy statycznych plików binarnych, musimy najpierw utworzyć projekt angr dla danego pliku. Następnie możemy korzystać z różnych funkcji i metod dostępnych w angr do analizy i manipulacji tym plikiem.

Przykład użycia angr do analizy statycznego pliku binarnego może wyglądać następująco:

```python
import angr

# Tworzenie projektu angr dla pliku binarnego
proj = angr.Project('/path/to/binary')

# Odnajdywanie funkcji w pliku binarnym
cfg = proj.analyses.CFG()

# Analiza struktury kodu
cfg.normalize()

# Odnajdywanie podatności
vulns = proj.analyses.Vulnerabilities(cfg)

# Wyświetlanie wyników
for vuln in vulns:
    print(vuln)
```

Dzięki angr możemy przeprowadzać zaawansowaną analizę statycznych plików binarnych, co pozwala nam lepiej zrozumieć ich działanie i odnaleźć potencjalne podatności.
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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
