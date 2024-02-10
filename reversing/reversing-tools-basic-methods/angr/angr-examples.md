# Angr - Beispiele

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

{% hint style="info" %}
Wenn das Programm `scanf` verwendet, um **mehrere Werte gleichzeitig von stdin** zu erhalten, müssen Sie einen Zustand generieren, der nach dem **`scanf`** beginnt.
{% endhint %}

Codes entnommen von [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Eingabe, um eine Adresse zu erreichen (Angabe der Adresse)
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
### Eingabe zum Erreichen der Adresse (zeigt Drucke an)
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
### Registrierungswerte

Registrywerte sind Schlüssel in der Windows-Registrierung, die Informationen über verschiedene Einstellungen und Konfigurationen enthalten. Diese Werte werden von Anwendungen und dem Betriebssystem verwendet, um auf wichtige Informationen zuzugreifen und diese zu speichern. Beim Reverse Engineering können Registrywerte nützlich sein, um Informationen über die Funktionalität einer Anwendung zu erhalten oder um bestimmte Verhaltensweisen zu ändern. Es gibt verschiedene Tools und Techniken, um auf Registrywerte zuzugreifen und mit ihnen zu interagieren.
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
### Stapelwerte

The stack is a data structure used in computer programming to store and manage variables and function calls. In the context of reverse engineering, understanding the values stored in the stack can be crucial for analyzing and manipulating a program.

Der Stapel ist eine Datenstruktur, die in der Computerprogrammierung verwendet wird, um Variablen und Funktionsaufrufe zu speichern und zu verwalten. Im Kontext der Reverse-Engineering ist es wichtig, die Werte zu verstehen, die im Stapel gespeichert sind, um ein Programm zu analysieren und zu manipulieren.
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
In diesem Szenario wurde die Eingabe mit `scanf("%u %u")` entgegengenommen und der Wert `"1 1"` wurde angegeben, daher stammen die Werte **`0x00000001`** des Stacks von der **Benutzereingabe**. Sie können sehen, wie diese Werte in `$ebp - 8` beginnen. Daher haben wir im Code **8 Bytes von `$esp` abgezogen (da zu diesem Zeitpunkt `$ebp` und `$esp` den gleichen Wert hatten)** und dann das BVS gepusht.

![](<../../../.gitbook/assets/image (614).png>)

### Statische Speicherwerte (globale Variablen)
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
### Dynamische Speicherwerte (Malloc)

In this example, we will use angr to analyze a binary that dynamically allocates memory using the `malloc` function. The goal is to find the values stored in the dynamically allocated memory.

```python
import angr

def main():
    # Load the binary
    project = angr.Project("/path/to/binary")

    # Set up the initial state
    state = project.factory.entry_state()

    # Create a simulation manager
    simgr = project.factory.simulation_manager(state)

    # Explore the binary
    simgr.explore()

    # Get the final states
    final_states = simgr.deadended

    # Print the memory values
    for state in final_states:
        # Get the memory address of the dynamically allocated memory
        malloc_address = state.solver.eval(state.regs.rax)

        # Get the value stored at the memory address
        value = state.mem[malloc_address].int.concrete

        # Print the memory address and value
        print(f"Memory Address: {malloc_address}")
        print(f"Value: {value}")

if __name__ == "__main__":
    main()
```

In diesem Beispiel verwenden wir angr, um eine Binärdatei zu analysieren, die den Speicher dynamisch mit der `malloc`-Funktion allokiert. Das Ziel ist es, die Werte zu finden, die im dynamisch allokierten Speicher gespeichert sind.

```python
import angr

def main():
    # Lade die Binärdatei
    project = angr.Project("/Pfad/zur/Binärdatei")

    # Setze den initialen Zustand
    state = project.factory.entry_state()

    # Erstelle einen Simulation Manager
    simgr = project.factory.simulation_manager(state)

    # Erkunde die Binärdatei
    simgr.explore()

    # Hole die finalen Zustände
    final_states = simgr.deadended

    # Gib die Speicherwerte aus
    for state in final_states:
        # Hole die Speicheradresse des dynamisch allokierten Speichers
        malloc_address = state.solver.eval(state.regs.rax)

        # Hole den Wert, der an der Speicheradresse gespeichert ist
        value = state.mem[malloc_address].int.concrete

        # Gib die Speicheradresse und den Wert aus
        print(f"Speicheradresse: {malloc_address}")
        print(f"Wert: {value}")

if __name__ == "__main__":
    main()
```
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
### Dateisimulation

The `angr` framework provides a powerful feature called file simulation, which allows you to analyze the behavior of a program when interacting with files. This feature is particularly useful when reverse engineering or analyzing malware that relies heavily on file operations.

With file simulation, you can create virtual files and specify their properties, such as size, content, and permissions. You can then use these virtual files as inputs to the program being analyzed. This allows you to explore different scenarios and understand how the program behaves under different file conditions.

To perform file simulation with `angr`, you need to use the `angr.SimFile` class. This class represents a virtual file and provides methods to set its properties. You can create a `SimFile` object by specifying the file name and mode (read, write, or append).

Once you have created a `SimFile` object, you can use it as an input to the program being analyzed. `angr` will automatically handle file operations, such as opening, reading, writing, and closing the file. You can also specify the content of the file using the `write` method of the `SimFile` object.

Here is an example of how to perform file simulation with `angr`:

```python
import angr

# Create a SimFile object
file = angr.SimFile("myfile.txt", "r")

# Set the content of the file
file.write(b"Hello, world!")

# Create an angr project
proj = angr.Project("myprogram")

# Create a state with the file as input
state = proj.factory.entry_state(stdin=file)

# Explore the program's behavior
simgr = proj.factory.simulation_manager(state)
simgr.run()
```

In this example, we create a `SimFile` object named "myfile.txt" with read mode. We then set the content of the file to "Hello, world!". Next, we create an `angr` project for the program we want to analyze. We create a state with the `SimFile` object as the input for the program's standard input. Finally, we use a simulation manager to explore the program's behavior.

By using file simulation, you can gain valuable insights into how a program interacts with files and understand its behavior in different file scenarios. This can be particularly useful for analyzing malware or reverse engineering software.
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
Beachten Sie, dass die symbolische Datei auch konstante Daten enthalten kann, die mit symbolischen Daten zusammengeführt wurden:
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

### Anwendung von Einschränkungen

{% hint style="info" %}
Manchmal kosten einfache menschliche Operationen wie das Vergleichen von 2 Wörtern der Länge 16 **Zeichen für Zeichen** (Schleife) **viel** für ein **angr**, weil es exponentiell viele Zweige generieren muss, da es pro if-Anweisung einen Zweig generiert: `2^16`\
Daher ist es einfacher, **angr dazu zu bringen, zu einem früheren Punkt zurückzukehren** (wo der wirklich schwierige Teil bereits erledigt wurde) und diese Einschränkungen manuell festzulegen.
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
In einigen Szenarien können Sie **veritesting** aktivieren, um ähnliche Zustände zusammenzuführen und unnötige Verzweigungen zu vermeiden und die Lösung zu finden: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
Eine weitere Möglichkeit in solchen Szenarien ist es, die Funktion zu **hooken**, um angr etwas zu geben, das es leichter verstehen kann.
{% endhint %}

### Simulation Manager

Einige Simulation Manager können nützlicher sein als andere. Im vorherigen Beispiel gab es ein Problem, da viele nützliche Verzweigungen erstellt wurden. Hier wird die **veritesting** Technik diese zusammenführen und eine Lösung finden.\
Dieser Simulation Manager kann auch aktiviert werden mit: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### Hooking/Bypassing eines Funktionsaufrufs

In einigen Fällen möchten Sie möglicherweise einen bestimmten Funktionsaufruf in einem Programm umgehen oder ändern. Dies kann nützlich sein, um bestimmte Verhaltensweisen zu modifizieren oder um Sicherheitsmechanismen zu umgehen.

Mit der Angr-Bibliothek können Sie dies erreichen, indem Sie den Funktionsaufruf "hooken". Das bedeutet, dass Sie eine benutzerdefinierte Funktion schreiben, die anstelle des ursprünglichen Funktionsaufrufs aufgerufen wird.

Um einen Funktionsaufruf zu hooken, müssen Sie die Adresse der Funktion im Speicher kennen. Sie können dies mithilfe von Angr herausfinden, indem Sie die Funktion `project.loader.find_symbol()` verwenden.

Sobald Sie die Adresse der Funktion haben, können Sie die Funktion `project.hook()` verwenden, um Ihre benutzerdefinierte Funktion als Hook zu registrieren. Ihre benutzerdefinierte Funktion sollte die gleichen Parameter wie die ursprüngliche Funktion akzeptieren und den gleichen Rückgabetyp haben.

Hier ist ein Beispiel, wie Sie einen Funktionsaufruf mit Angr hooken können:

```python
import angr

def my_hooked_function(state):
    # Hier können Sie den Funktionsaufruf modifizieren oder umgehen
    # state.regs.rax enthält den Rückgabewert der Funktion
    # state.regs.rdi, state.regs.rsi, usw. enthalten die Funktionsparameter

    # Beispiel: Umgehen des Funktionsaufrufs und Rückgabe eines festgelegten Werts
    state.regs.rax = 0x1337

project = angr.Project("/path/to/program")

# Adresse der Funktion im Speicher finden
function_address = project.loader.find_symbol("function_name").rebased_addr

# Funktion hooken
project.hook(function_address, my_hooked_function)

# Programm ausführen
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)
simgr.run()

# Den Rückgabewert der Funktion erhalten
print(simgr.deadended[0].regs.rax)
```

In diesem Beispiel wird die Funktion `function_name` gehookt. Die benutzerdefinierte Funktion `my_hooked_function` wird anstelle des ursprünglichen Funktionsaufrufs aufgerufen. Sie können den Funktionsaufruf in `my_hooked_function` modifizieren oder umgehen, indem Sie die Registerwerte ändern.

Bitte beachten Sie, dass das Hooken von Funktionsaufrufen eine fortgeschrittene Technik ist und sorgfältig angewendet werden sollte. Es ist wichtig, die Auswirkungen auf das Programmverhalten zu verstehen und mögliche Nebenwirkungen zu berücksichtigen.
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
### Hooking einer Funktion / Simprocedure

In einigen Fällen möchten Sie möglicherweise eine Funktion in einem Programm "hooken", um ihr Verhalten zu ändern oder Informationen zu sammeln. In der Angr-Plattform können Sie dies mithilfe von Simprocedures erreichen.

Ein Simprocedure ist eine Funktion, die anstelle der ursprünglichen Funktion aufgerufen wird. Sie können den Code des Simprocedures anpassen, um das gewünschte Verhalten zu implementieren. Dies ermöglicht es Ihnen, die Kontrolle über den Programmfluss zu übernehmen und bestimmte Aktionen auszuführen.

Um eine Funktion mit einem Simprocedure zu hooken, müssen Sie die Adresse der Funktion kennen. Sie können dies mithilfe von Symbolen oder anderen Techniken ermitteln. Sobald Sie die Adresse haben, können Sie den Simprocedure erstellen und ihn mit der Funktion verknüpfen.

Hier ist ein Beispiel, wie Sie eine Funktion mit einem Simprocedure in Angr hooken können:

```python
import angr

# Adresse der zu hookenden Funktion
function_address = 0x12345678

# Simprocedure erstellen
def my_simprocedure(state):
    # Code des Simprocedures hier einfügen
    pass

# Angr-Projekt erstellen
proj = angr.Project("/path/to/binary")

# Simprocedure mit der Funktion verknüpfen
proj.hook(function_address, my_simprocedure)

# Angr starten
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.run()
```

In diesem Beispiel wird die Funktion mit der Adresse `0x12345678` gehookt. Der Simprocedure `my_simprocedure` wird anstelle der Funktion aufgerufen. Sie können den Code des Simprocedures anpassen, um Ihre spezifischen Anforderungen zu erfüllen.

Durch das Hooken von Funktionen mit Simprocedures können Sie das Verhalten eines Programms ändern und Informationen sammeln, um Ihre Reverse-Engineering- oder Hacking-Aufgaben zu unterstützen.
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
### Simuliere scanf mit mehreren Parametern

Manchmal müssen wir scanf simulieren, um den Fluss eines Programms zu analysieren oder bestimmte Bedingungen zu überprüfen. Die `simprocedure`-Funktion in Angr ermöglicht es uns, scanf mit mehreren Parametern zu simulieren.

Hier ist ein Beispiel, wie man scanf mit zwei Parametern simuliert:

```python
import angr

def scanf_sim(state):
    # Simuliere scanf mit zwei Parametern
    state.memory.store(state.regs.rdi, state.solver.BVS('input1', 8*8))
    state.memory.store(state.regs.rsi, state.solver.BVS('input2', 8*8))

proj = angr.Project('./binary')
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.Explorer(find=0xdeadbeef))
simgr.run(simprocedure=scanf_sim)
```

In diesem Beispiel wird `scanf_sim` als `simprocedure` verwendet, um scanf zu simulieren. Die Funktion speichert zwei benannte Bit-Vektor-Symbole in den Speicheradressen, die den beiden Parametern von scanf entsprechen.

Durch die Verwendung von `simprocedure` können wir den Fluss des Programms analysieren und bestimmte Bedingungen überprüfen, indem wir die Eingaben für scanf steuern.
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
### Statische Binärdateien

Statische Binärdateien sind ausführbare Dateien, die alle erforderlichen Bibliotheken und Abhängigkeiten enthalten, um unabhängig von der Umgebung ausgeführt zu werden. Im Gegensatz zu dynamischen Binärdateien, die zur Laufzeit auf externe Bibliotheken verweisen, sind statische Binärdateien eigenständig und können auf verschiedenen Systemen ohne zusätzliche Installationen oder Konfigurationen ausgeführt werden.

Das Reverse Engineering von statischen Binärdateien kann hilfreich sein, um deren Funktionsweise zu verstehen, Schwachstellen zu identifizieren oder Sicherheitslücken zu finden. Es gibt verschiedene Tools und Techniken, die beim Reverse Engineering von statischen Binärdateien eingesetzt werden können, um den Code zu analysieren und zu verstehen.

Ein beliebtes Tool für das Reverse Engineering von statischen Binärdateien ist Angr. Angr ist ein mächtiges Framework, das entwickelt wurde, um die Analyse und Manipulation von Binärdateien zu erleichtern. Es bietet eine Vielzahl von Funktionen und Methoden, um den Code zu analysieren, Pfade zu erkunden, Bedingungen zu überprüfen und vieles mehr.

Mit Angr können Sie statische Binärdateien analysieren, um Schwachstellen zu finden oder bestimmte Funktionen zu verstehen. Es ermöglicht Ihnen auch, den Code zu manipulieren, um bestimmte Pfade zu erzwingen oder bestimmte Bedingungen zu erfüllen. Durch die Kombination von Angr mit anderen Tools und Techniken können Sie effektivere Reverse Engineering-Methoden entwickeln und anwenden.

Das Reverse Engineering von statischen Binärdateien erfordert jedoch ein tiefes Verständnis der zugrunde liegenden Architektur und des Codes. Es erfordert auch Geduld und Ausdauer, da das Reverse Engineering oft ein zeitaufwändiger Prozess ist. Dennoch kann das Reverse Engineering von statischen Binärdateien wertvolle Erkenntnisse liefern und Ihnen helfen, Sicherheitslücken zu identifizieren und zu beheben.
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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family).
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com).
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
