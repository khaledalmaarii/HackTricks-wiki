# Angr - Esempi

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

{% hint style="info" %}
Se il programma utilizza `scanf` per ottenere **diversi valori contemporaneamente da stdin** è necessario generare uno stato che inizia dopo il **`scanf`**.
{% endhint %}

Codici presi da [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Input per raggiungere l'indirizzo (indicando l'indirizzo)
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
### Input per raggiungere l'indirizzo (indicando le stampe)
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
### Valori del Registro di sistema

The Windows Registry is a hierarchical database that stores configuration settings and options for the operating system and installed applications. It contains various keys and values that control the behavior of the system. In this section, we will explore some common registry values and their significance.

#### **Value Types**

The registry values can have different types, including:

- **REG_SZ**: This type represents a string value.
- **REG_DWORD**: This type represents a 32-bit integer value.
- **REG_QWORD**: This type represents a 64-bit integer value.
- **REG_BINARY**: This type represents binary data.
- **REG_MULTI_SZ**: This type represents a multi-string value.

#### **Common Registry Values**

Here are some common registry values and their meanings:

- **HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run**: This key contains a list of programs that are automatically executed when the system starts up.
- **HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run**: This key contains a list of programs that are automatically executed when a user logs in.
- **HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders**: This key contains the paths to various system folders, such as the Desktop, Start Menu, and Program Files.
- **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services**: This key contains information about system services, including their startup type and parameters.
- **HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon**: This key contains settings related to the Windows logon process, such as the user's default shell and the legal notice text.

Understanding these registry values can be helpful in troubleshooting system issues, analyzing malware, and customizing system behavior.
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
### Valori dello stack

The stack is a data structure used by programs to store temporary variables and function call information. In reverse engineering, understanding the values stored in the stack can provide valuable insights into the program's execution flow and help identify vulnerabilities.

Lo stack è una struttura dati utilizzata dai programmi per memorizzare variabili temporanee e informazioni sulle chiamate di funzione. Nel reverse engineering, comprendere i valori memorizzati nello stack può fornire informazioni preziose sul flusso di esecuzione del programma e aiutare a identificare vulnerabilità.
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
In questo scenario, l'input è stato preso con `scanf("%u %u")` e il valore `"1 1"` è stato fornito, quindi i valori **`0x00000001`** dello stack provengono dall'**input dell'utente**. Puoi vedere come questi valori iniziano in `$ebp - 8`. Pertanto, nel codice abbiamo **sottratto 8 byte a `$esp` (poiché in quel momento `$ebp` e `$esp` avevano lo stesso valore)** e poi abbiamo spinto il BVS.

![](<../../../.gitbook/assets/image (614).png>)

### Valori di memoria statica (variabili globali)
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
### Valori di memoria dinamica (Malloc)

When analyzing a binary, it is often necessary to understand the values stored in dynamically allocated memory. The `malloc` function is commonly used in C programs to allocate memory dynamically. 

To analyze the values stored in dynamically allocated memory, we can use the `angr` framework. `angr` provides a powerful symbolic execution engine that allows us to explore different execution paths and analyze the program's behavior.

To track the values stored in dynamically allocated memory, we can use the `angr.SimMemory` object. This object represents the program's memory and allows us to read and write values at specific memory addresses.

To track the values stored by `malloc`, we can hook the `malloc` function using `angr.SIM_PROCEDURES['libc']['malloc']`. This allows us to intercept calls to `malloc` and analyze the memory allocations made by the program.

Once we have hooked `malloc`, we can use the `angr.SimProcedure` object to define our own behavior for the `malloc` function. In our custom `malloc` function, we can track the allocated memory regions and store their addresses and sizes for further analysis.

Here is an example of how to track the values stored in dynamically allocated memory using `angr`:

```python
import angr

# Create an angr project
project = angr.Project("/path/to/binary")

# Hook the malloc function
malloc = project.hook_symbol('malloc', angr.SIM_PROCEDURES['libc']['malloc']())

# Create a blank state
state = project.factory.blank_state()

# Execute the program until the malloc function is called
simulation = project.factory.simgr(state)
simulation.explore(find=malloc.reached)

# Get the memory object
memory = simulation.found[0].memory

# Read the value at a specific memory address
value = memory.load(0x12345678, 4)

# Print the value
print(value)
```

In this example, we create an `angr` project from a binary file. We then hook the `malloc` function using `angr.SIM_PROCEDURES['libc']['malloc']()`. We create a blank state and execute the program until the `malloc` function is called. Finally, we can access the program's memory using `simulation.found[0].memory` and read the value at a specific memory address using `memory.load(address, size)`.
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
### Simulazione di File

The `angr` framework provides a powerful feature called file simulation, which allows you to analyze the behavior of a program when interacting with files. This feature is particularly useful when reverse engineering binary files or when analyzing the impact of file operations on program execution.

To simulate file operations with `angr`, you can use the `angr.SimFile` class. This class represents a file object and provides methods to perform various file operations such as reading, writing, seeking, and closing.

Here is an example of how to use file simulation with `angr`:

```python
import angr

# Create a blank state
proj = angr.Project("/path/to/binary")

# Create a SimFile object
file = angr.SimFile("/path/to/file", "r")

# Open the file in the state
file.open(proj, flags=angr.storage.file.Flags.O_RDONLY)

# Read data from the file
data = file.read(0x100)

# Print the read data
print(data)

# Close the file
file.close()
```

In this example, we first create a blank state using the `angr.Project` class. Then, we create a `SimFile` object representing a file in read mode. We open the file in the state using the `open` method, specifying the desired flags. Next, we read 0x100 bytes of data from the file using the `read` method. Finally, we print the read data and close the file using the `close` method.

By simulating file operations, you can analyze how a program interacts with files and understand its behavior in different scenarios. This can be helpful in various reverse engineering and analysis tasks.
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
Nota che il file simbolico potrebbe anche contenere dati costanti uniti a dati simbolici:
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

### Applicazione di vincoli

{% hint style="info" %}
A volte, operazioni umane semplici come confrontare due parole di lunghezza 16 **carattere per carattere** (ciclo), **costano molto ad angr** perché deve generare rami **esponenzialmente** poiché genera 1 ramo per ogni if: `2^16`\
Pertanto, è più facile **chiedere ad angr di tornare a un punto precedente** (dove la parte realmente difficile è già stata fatta) e **impostare manualmente questi vincoli**.
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
In alcuni scenari è possibile attivare **veritesting**, che unirà stati simili al fine di eliminare rami inutili e trovare la soluzione: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
Un'altra cosa che puoi fare in questi scenari è **agganciare la funzione dando ad angr qualcosa che può capire** più facilmente.
{% endhint %}

### Gestori di simulazione

Alcuni gestori di simulazione possono essere più utili di altri. Nell'esempio precedente c'era un problema in quanto venivano creati molti rami utili. Qui, la tecnica del **veritesting** unirà questi rami e troverà una soluzione.\
Questo gestore di simulazione può essere attivato anche con: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### Hooking/Bypassing una chiamata a una funzione

Sometimes, during the reverse engineering process, we may encounter a situation where we want to modify the behavior of a specific function call. This can be achieved using the hooking technique in angr.

A volte, durante il processo di reverse engineering, potremmo trovarci in una situazione in cui vogliamo modificare il comportamento di una specifica chiamata di funzione. Questo può essere ottenuto utilizzando la tecnica di hooking in angr.

To hook a function call, we need to create a hook for that function and then apply it to the program's state. The hook can be used to modify the arguments passed to the function, change the return value, or even bypass the function call altogether.

Per effettuare un hook a una chiamata di funzione, dobbiamo creare un hook per quella funzione e poi applicarlo allo stato del programma. L'hook può essere utilizzato per modificare gli argomenti passati alla funzione, cambiare il valore di ritorno o addirittura bypassare completamente la chiamata di funzione.

Here's an example of how to hook a function call using angr:

Ecco un esempio di come effettuare un hook a una chiamata di funzione utilizzando angr:

```python
import angr

# Create an angr project
project = angr.Project("/path/to/binary")

# Define the hook function
def hook_function(state):
    # Modify the arguments or return value as needed
    state.regs.rax = 0x1234

# Get the address of the function to hook
function_address = 0xdeadbeef

# Create a SimProcedure for the hook function
hook = angr.SimProcedure(hook_function)

# Apply the hook to the program's state
project.hook(function_address, hook)

# Explore the program's execution
simulation = project.factory.simgr()
simulation.explore()

# Print the final state
print(simulation.found[0].regs.rax)
```

```python
import angr

# Crea un progetto angr
project = angr.Project("/percorso/al/binary")

# Definisci la funzione di hook
def hook_function(state):
    # Modifica gli argomenti o il valore di ritorno come necessario
    state.regs.rax = 0x1234

# Ottieni l'indirizzo della funzione da hookare
function_address = 0xdeadbeef

# Crea una SimProcedure per la funzione di hook
hook = angr.SimProcedure(hook_function)

# Applica il hook allo stato del programma
project.hook(function_address, hook)

# Esplora l'esecuzione del programma
simulation = project.factory.simgr()
simulation.explore()

# Stampa lo stato finale
print(simulation.found[0].regs.rax)
```

In this example, we create an angr project and define a hook function that modifies the return value of the hooked function to `0x1234`. We then apply the hook to the program's state using the `hook` method. Finally, we explore the program's execution and print the final value of the `rax` register.

In questo esempio, creiamo un progetto angr e definiamo una funzione di hook che modifica il valore di ritorno della funzione hookata a `0x1234`. Applichiamo quindi il hook allo stato del programma utilizzando il metodo `hook`. Infine, esploriamo l'esecuzione del programma e stampiamo il valore finale del registro `rax`.
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
### Hooking di una funzione / Simprocedura

In alcuni casi, potrebbe essere necessario modificare il comportamento di una funzione durante l'esecuzione di un programma. Questo può essere fatto utilizzando la tecnica del "hooking" o utilizzando una "simprocedura".

Il "hooking" è il processo di sostituire una funzione esistente con una propria implementazione personalizzata. Questo può essere utile per intercettare e modificare i dati o il flusso di esecuzione di una funzione specifica.

Una "simprocedura" è una funzione che viene eseguita al posto di una funzione originale. Questo può essere utile per eseguire operazioni personalizzate prima o dopo l'esecuzione della funzione originale.

In entrambi i casi, l'utilizzo di strumenti come Angr può semplificare il processo di hooking o simprocedura. Angr fornisce una serie di metodi e funzioni che consentono di definire e applicare hook o simprocedura a una funzione specifica.

Per esempio, il seguente codice mostra come utilizzare Angr per creare una simprocedura per la funzione `printf`:

```python
import angr

# Definizione della simprocedura
class PrintfSimProcedure(angr.SimProcedure):
    def run(self, fmt, *args):
        # Implementazione personalizzata della funzione printf
        # ...

# Creazione del progetto Angr
proj = angr.Project("/path/to/binary")

# Applicazione della simprocedura alla funzione printf
proj.hook_symbol("printf", PrintfSimProcedure())

# Esecuzione del programma con la simprocedura applicata
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.run()
```

In questo esempio, viene definita una classe `PrintfSimProcedure` che estende la classe `SimProcedure` di Angr. All'interno del metodo `run`, è possibile implementare il comportamento personalizzato per la funzione `printf`.

Successivamente, viene creato un oggetto `Project` utilizzando il percorso del file binario da analizzare. La funzione `hook_symbol` viene utilizzata per applicare la simprocedura alla funzione `printf`.

Infine, viene creato uno stato iniziale e un oggetto `SimulationManager` per eseguire il programma con la simprocedura applicata.

Utilizzando Angr e le tecniche di hooking o simprocedura, è possibile modificare il comportamento delle funzioni durante l'esecuzione di un programma per scopi di analisi o testing.
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
### Simulare scanf con più parametri

Per simulare la funzione `scanf` con più parametri utilizzando Angr, è possibile utilizzare il metodo `simprocedures.SimProcedure` per creare una simulazione personalizzata. Di seguito è riportato un esempio di come farlo:

```python
import angr
import claripy

# Definire la simulazione personalizzata per scanf con più parametri
class SimScanf(angr.SimProcedure):
    def run(self, format_string, var1, var2):
        # Ottenere il valore di input per var1 e var2
        input_var1 = claripy.BVS('input_var1', 32)
        input_var2 = claripy.BVS('input_var2', 32)
        
        # Aggiungere i vincoli per i valori di input
        self.state.add_constraints(var1 == input_var1)
        self.state.add_constraints(var2 == input_var2)
        
        # Restituire il valore di ritorno di scanf
        return self.state.solver.BVV(2, 32)  # 2 rappresenta il numero di elementi correttamente letti

# Creare una nuova istanza di Angr
proj = angr.Project('/path/to/binary')

# Aggiungere la simulazione personalizzata per scanf con più parametri
proj.hook_symbol('scanf', SimScanf())

# Eseguire la simulazione
simgr = proj.factory.simulation_manager()
simgr.explore()

# Ottenere lo stato finale
final_state = simgr.found[0]

# Ottenere i valori di input per var1 e var2
input_var1 = final_state.solver.eval(final_state.memory.load(var1, 4))
input_var2 = final_state.solver.eval(final_state.memory.load(var2, 4))

# Stampa dei valori di input
print(f"Input var1: {input_var1}")
print(f"Input var2: {input_var2}")
```

In questo esempio, viene definita una classe `SimScanf` che estende `angr.SimProcedure` per creare una simulazione personalizzata per la funzione `scanf` con due parametri. All'interno del metodo `run`, vengono creati due symbolic variables (`input_var1` e `input_var2`) per rappresentare i valori di input per `var1` e `var2`. Successivamente, vengono aggiunti i vincoli per garantire che i valori di input corrispondano alle variabili `var1` e `var2`. Infine, viene restituito il valore di ritorno di `scanf` (2 per indicare che due elementi sono stati correttamente letti).

Nel codice principale, viene creato un nuovo oggetto `angr.Project` per il binario di destinazione. Successivamente, viene aggiunta la simulazione personalizzata per `scanf` utilizzando il metodo `hook_symbol`. Infine, viene eseguita la simulazione utilizzando un oggetto `simulation_manager` e viene ottenuto lo stato finale. I valori di input per `var1` e `var2` vengono quindi estratti dallo stato finale e stampati a schermo.
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
### Binari Statici

Gli eseguibili statici sono file binari che contengono tutte le librerie necessarie per l'esecuzione del programma al loro interno. Questo significa che non dipendono da librerie esterne presenti nel sistema operativo in cui vengono eseguiti. I binari statici sono spesso utilizzati per semplificare la distribuzione di un'applicazione, in quanto non richiedono l'installazione di librerie aggiuntive.

Quando si affronta l'analisi di un binario statico, è possibile utilizzare strumenti come `objdump` per ottenere informazioni sulle sezioni del file, i simboli e le istruzioni di assembly. Questi strumenti consentono di esaminare il codice del programma e identificare eventuali vulnerabilità o comportamenti sospetti.

Un altro approccio comune per l'analisi di binari statici è l'utilizzo di strumenti di reverse engineering come `IDA Pro` o `Ghidra`. Questi strumenti consentono di visualizzare il codice sorgente del programma, comprese le funzioni e le variabili utilizzate. Possono anche essere utilizzati per eseguire l'analisi dinamica del programma, consentendo di eseguire il codice in un ambiente controllato e monitorare il suo comportamento.

L'analisi di binari statici può essere utile per identificare vulnerabilità nel codice sorgente, comprese le potenziali falle di sicurezza che potrebbero essere sfruttate da un attaccante. Tuttavia, è importante notare che l'analisi di binari statici può essere un processo complesso e richiede una buona comprensione dei principi di programmazione e delle tecniche di reverse engineering.
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

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
