<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>

Część tego cheatsheetu oparta jest na [dokumentacji angr](https://docs.angr.io/_/downloads/en/stable/pdf/).

# Instalacja
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Podstawowe działania

In this section, we will cover some basic actions that can be performed using angr.

W tej sekcji omówimy kilka podstawowych działań, które można wykonać za pomocą angr.

## Loading a Binary

## Wczytywanie pliku binarnego

To start analyzing a binary with angr, you need to load it into the project. You can do this using the `angr.Project()` function, passing the path to the binary as an argument.

Aby rozpocząć analizę binarnego pliku za pomocą angr, musisz go wczytać do projektu. Możesz to zrobić za pomocą funkcji `angr.Project()`, przekazując ścieżkę do pliku binarnego jako argument.

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)
```

## Exploring the Control Flow Graph (CFG)

## Badanie grafu przepływu sterowania (CFG)

The Control Flow Graph (CFG) represents the flow of execution within a binary. You can generate the CFG for a specific function or for the entire binary using the `project.analyses.CFG()` function.

Graf przepływu sterowania (CFG) reprezentuje przepływ wykonania wewnątrz pliku binarnego. Możesz wygenerować CFG dla określonej funkcji lub dla całego pliku binarnego za pomocą funkcji `project.analyses.CFG()`.

```python
cfg = project.analyses.CFG()
```

## Finding Functions

## Wyszukiwanie funkcji

To find a specific function within the binary, you can use the `project.kb.functions` attribute. This attribute contains a dictionary where the keys are the addresses of the functions and the values are the corresponding `angr.knowledge_plugins.Function` objects.

Aby znaleźć określoną funkcję wewnątrz pliku binarnego, możesz użyć atrybutu `project.kb.functions`. Ten atrybut zawiera słownik, w którym kluczami są adresy funkcji, a wartościami są odpowiadające im obiekty `angr.knowledge_plugins.Function`.

```python
function_address = 0x12345678
function = project.kb.functions[function_address]
```

## Symbolically Executing the Binary

## Wykonywanie symboliczne pliku binarnego

Symbolic execution allows you to explore all possible paths of execution within a binary. You can perform symbolic execution on a specific function or on the entire binary using the `project.factory` attribute.

Wykonanie symboliczne pozwala na badanie wszystkich możliwych ścieżek wykonania wewnątrz pliku binarnego. Możesz wykonać symboliczne wykonanie na określonej funkcji lub na całym pliku binarnym za pomocą atrybutu `project.factory`.

```python
symbolic_execution = project.factory.simgr()
```

## Analyzing Memory Accesses

## Analiza dostępów do pamięci

To analyze memory accesses within a binary, you can use the `project.factory.block()` function to create a basic block and then access the memory using the `block.memory` attribute.

Aby analizować dostępy do pamięci wewnątrz pliku binarnego, możesz użyć funkcji `project.factory.block()` do utworzenia podstawowego bloku, a następnie uzyskać dostęp do pamięci za pomocą atrybutu `block.memory`.

```python
block = project.factory.block(address)
memory_access = block.memory.load(address, size)
```

## Modifying Memory

## Modyfikowanie pamięci

To modify the memory within a binary, you can use the `project.factory.block()` function to create a basic block and then modify the memory using the `block.memory` attribute.

Aby zmodyfikować pamięć wewnątrz pliku binarnego, możesz użyć funkcji `project.factory.block()` do utworzenia podstawowego bloku, a następnie zmodyfikować pamięć za pomocą atrybutu `block.memory`.

```python
block = project.factory.block(address)
block.memory.store(address, value)
```

## Patching Instructions

## Modyfikowanie instrukcji

To patch instructions within a binary, you can use the `project.factory.block()` function to create a basic block and then modify the instructions using the `block.vex` attribute.

Aby modyfikować instrukcje wewnątrz pliku binarnego, możesz użyć funkcji `project.factory.block()` do utworzenia podstawowego bloku, a następnie modyfikować instrukcje za pomocą atrybutu `block.vex`.

```python
block = project.factory.block(address)
block.vex.instructions[index] = new_instruction
```

These are just a few examples of the basic actions that can be performed using angr. The library provides many more features and functionalities for binary analysis and reverse engineering.

To tylko kilka przykładów podstawowych działań, które można wykonać za pomocą angr. Biblioteka oferuje wiele innych funkcji i możliwości do analizy binarnej i inżynierii wstecznej.
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
# Wczytane dane

The loaded data refers to the information that has been loaded into the program's memory during its execution. This can include variables, functions, libraries, and other resources that are necessary for the program to run properly.

Wczytane dane odnoszą się do informacji, które zostały załadowane do pamięci programu podczas jego wykonywania. Może to obejmować zmienne, funkcje, biblioteki i inne zasoby niezbędne do prawidłowego działania programu.

## Main Object

The main object is the central component of a program. It represents the entry point of the program and is responsible for coordinating the execution of other objects and functions.

Główny obiekt jest centralnym komponentem programu. Reprezentuje punkt wejścia programu i jest odpowiedzialny za koordynację wykonania innych obiektów i funkcji.
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
## Główny cel

The main objective of the angr framework is to provide a powerful and flexible platform for analyzing binary programs. It aims to simplify the process of reverse engineering and vulnerability discovery by automating common tasks and providing a set of powerful analysis tools.

Głównym celem frameworka angr jest dostarczenie potężnej i elastycznej platformy do analizy programów binarnych. Ma na celu uproszczenie procesu inżynierii wstecznej i odkrywania podatności poprzez automatyzację często wykonywanych zadań i dostarczenie zestawu potężnych narzędzi analizy.

## Key Features

### Symbolic Execution

Symbolic execution is a technique used to explore all possible paths of a program by treating inputs as symbolic variables. The angr framework leverages symbolic execution to analyze binary programs and generate a symbolic execution tree, which represents all possible paths through the program.

### Constraint Solving

Constraint solving is the process of finding values for symbolic variables that satisfy a set of constraints. The angr framework uses constraint solving to determine the inputs that lead to specific program behaviors, such as reaching a certain function or triggering a vulnerability.

### Program Analysis

The angr framework provides a wide range of program analysis tools, including static analysis, dynamic analysis, and taint analysis. These tools can be used to extract information about the program's control flow, data flow, and memory access patterns, which can be helpful for understanding its behavior and identifying vulnerabilities.

### Binary Analysis

The angr framework supports binary analysis techniques, such as disassembly, decompilation, and function identification. These techniques can be used to understand the structure and behavior of a binary program, even without access to its source code.

### Exploit Generation

The angr framework can be used to automatically generate exploits for vulnerabilities discovered during analysis. By combining symbolic execution, constraint solving, and program analysis techniques, angr can generate inputs that trigger specific program behaviors, such as executing arbitrary code or leaking sensitive information.

## Installation

To install the angr framework, follow the instructions provided in the [official documentation](https://docs.angr.io/). The documentation provides detailed installation instructions for different platforms and environments.

## Usage

Once installed, the angr framework can be used through its Python API. The API provides a set of high-level functions and classes that can be used to perform various analysis tasks, such as exploring program paths, solving constraints, and generating exploits.

To get started with the angr framework, refer to the [official documentation](https://docs.angr.io/) and the [examples](https://github.com/angr/angr-doc/tree/master/examples) provided in the repository. The documentation and examples cover a wide range of topics, from basic usage to advanced analysis techniques.

## Conclusion

The angr framework is a powerful tool for analyzing binary programs and discovering vulnerabilities. By leveraging symbolic execution, constraint solving, and program analysis techniques, angr simplifies the process of reverse engineering and provides a set of powerful analysis tools. Whether you are a beginner or an experienced researcher, angr can help you in your journey of understanding and exploiting binary programs.
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
## Symbole i relokacje

W kontekście inżynierii wstecznej, symbole i relokacje są ważnymi pojęciami. Symbole są nazwami funkcji, zmiennych i innych elementów programu, które są używane do odwoływania się do nich w kodzie. Relokacje są informacjami o miejscach w kodzie, które muszą zostać dostosowane, gdy program jest ładowany do pamięci.

Podczas analizy programu, angr automatycznie rozpoznaje symbole i relokacje, co ułatwia pracę z kodem. Możemy używać tych informacji do manipulowania programem i wykonywania różnych operacji, takich jak zmiana wartości zmiennych, wywoływanie funkcji, czy zmiana przepływu sterowania.

W angr, symbole i relokacje są reprezentowane jako obiekty `Symbol` i `Relocation`. Możemy uzyskać dostęp do nich za pomocą odpowiednich metod i manipulować nimi w celu osiągnięcia zamierzonych efektów.

## Przykłady użycia

Poniżej przedstawiamy kilka przykładów użycia symoli i relokacji w angr:

### Manipulowanie wartościami zmiennych

Możemy użyć symboli, aby manipulować wartościami zmiennych w programie. Na przykład, jeśli chcemy zmienić wartość zmiennej `x` na 42, możemy utworzyć symbol o nazwie `x` i przypisać mu nową wartość:

```python
import angr

proj = angr.Project("program.bin")
state = proj.factory.entry_state()

x = state.solver.BVS("x", 32)  # Tworzenie symbolu o nazwie "x" i szerokości 32 bitów
state.solver.add(x == 42)  # Przypisanie wartości 42 do symbolu "x"

# Teraz możemy użyć stanu, aby wykonać operacje na programie
```

### Wywoływanie funkcji

Możemy również używać symboli do wywoływania funkcji w programie. Na przykład, jeśli chcemy wywołać funkcję `foo` z argumentem `x`, możemy utworzyć symbol o nazwie `x` i przekazać go jako argument do funkcji:

```python
import angr

proj = angr.Project("program.bin")
state = proj.factory.entry_state()

x = state.solver.BVS("x", 32)  # Tworzenie symbolu o nazwie "x" i szerokości 32 bitów

# Wywołanie funkcji "foo" z argumentem "x"
state.call_state(addr=proj.loader.find_symbol("foo").rebased_addr, args=[x])

# Teraz możemy użyć stanu, aby wykonać operacje na programie
```

### Zmiana przepływu sterowania

Możemy również manipulować przepływem sterowania w programie za pomocą relokacji. Na przykład, jeśli chcemy zmienić miejsce skoku w programie na inny adres, możemy utworzyć relokację i przypisać jej nową wartość:

```python
import angr

proj = angr.Project("program.bin")
state = proj.factory.entry_state()

jmp_reloc = proj.loader.find_relocation("jmp")  # Znalezienie relokacji skoku
jmp_reloc.address = 0xdeadbeef  # Przypisanie nowej wartości do relokacji

# Teraz możemy użyć stanu, aby wykonać operacje na programie
```

## Podsumowanie

Symbole i relokacje są ważnymi pojęciami w inżynierii wstecznej. W angr, możemy używać symboli i relokacji do manipulowania programem i wykonywania różnych operacji. Przykłady użycia obejmują manipulowanie wartościami zmiennych, wywoływanie funkcji i zmianę przepływu sterowania.
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
## Bloki

Blocks are the basic units of code that angr analyzes. They represent a sequence of instructions that are executed together. Each block starts with an instruction that has a known address and ends with a branch instruction that transfers control to another block.

Bloki są podstawowymi jednostkami kodu analizowanymi przez angr. Reprezentują sekwencję instrukcji, które są wykonywane razem. Każdy blok zaczyna się od instrukcji o znanym adresie i kończy się instrukcją skoku, która przenosi kontrolę do innego bloku.

## CFG (Control Flow Graph)

CFG is a graph representation of a program's control flow. It consists of nodes that represent basic blocks and edges that represent the flow of control between these blocks. The CFG is a useful tool for understanding the structure and behavior of a program.

CFG to graficzna reprezentacja przepływu sterowania programu. Składa się z węzłów, które reprezentują bloki podstawowe, oraz krawędzi, które reprezentują przepływ sterowania między tymi blokami. CFG jest przydatnym narzędziem do zrozumienia struktury i zachowania programu.

## State

A state in angr represents the program's execution at a specific point in time. It includes information such as the program counter, register values, and memory contents. States are used by angr to explore different paths through a program and analyze its behavior.

Stan w angr reprezentuje wykonanie programu w określonym punkcie czasu. Zawiera informacje takie jak licznik programu, wartości rejestrów i zawartość pamięci. Stany są używane przez angr do eksplorowania różnych ścieżek przez program i analizowania jego zachowania.

## Exploration Techniques

Exploration techniques in angr are used to search for specific program states or properties. These techniques include symbolic execution, concolic execution, and taint analysis. They allow angr to automatically explore different paths through a program and find vulnerabilities or other interesting behavior.

Techniki eksploracji w angr są używane do wyszukiwania określonych stanów programu lub właściwości. Techniki te obejmują wykonanie symboliczne, wykonanie konkolowe i analizę zanieczyszczeń. Pozwalają one angr na automatyczne eksplorowanie różnych ścieżek przez program i znajdowanie podatności lub innych interesujących zachowań.

## Symbolic Execution

Symbolic execution is a technique used by angr to explore different paths through a program by treating inputs as symbolic variables. It allows angr to reason about all possible inputs and generate test cases that exercise different parts of the program. Symbolic execution is particularly useful for finding vulnerabilities such as buffer overflows or SQL injection.

Wykonanie symboliczne to technika używana przez angr do eksplorowania różnych ścieżek przez program, traktując dane wejściowe jako zmienne symboliczne. Pozwala to angr na rozważanie wszystkich możliwych danych wejściowych i generowanie przypadków testowych, które testują różne części programu. Wykonanie symboliczne jest szczególnie przydatne do znajdowania podatności, takich jak przepełnienie bufora lub wstrzyknięcie SQL.

## Concolic Execution

Concolic execution is a combination of concrete and symbolic execution. It uses concrete values for inputs that are known and symbolic values for inputs that are unknown. Concolic execution allows angr to explore different paths through a program while also generating test cases that exercise different parts of the program. It is particularly useful for finding vulnerabilities that depend on specific input values.

Wykonanie konkolowe to połączenie wykonania konkretnego i symbolicznego. Wykorzystuje konkretne wartości dla znanych danych wejściowych i symboliczne wartości dla nieznanych danych wejściowych. Wykonanie konkolowe pozwala angr na eksplorowanie różnych ścieżek przez program, jednocześnie generując przypadki testowe, które testują różne części programu. Jest szczególnie przydatne do znajdowania podatności, które zależą od określonych wartości wejściowych.

## Taint Analysis

Taint analysis is a technique used by angr to track the flow of user-controlled data through a program. It marks certain variables or memory locations as tainted and propagates this information through the program's execution. Taint analysis allows angr to identify potential sources of user input and track how this input is used throughout the program. It is particularly useful for finding vulnerabilities such as command injection or cross-site scripting.

Analiza zanieczyszczeń to technika używana przez angr do śledzenia przepływu danych kontrolowanych przez użytkownika przez program. Oznacza określone zmienne lub lokalizacje pamięci jako zanieczyszczone i propaguje tę informację przez wykonanie programu. Analiza zanieczyszczeń pozwala angr na identyfikację potencjalnych źródeł danych wejściowych użytkownika i śledzenie sposobu wykorzystania tych danych wejściowych w całym programie. Jest szczególnie przydatna do znajdowania podatności, takich jak wstrzyknięcie poleceń lub skryptów międzywitrynowych.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Symulacja menedżera, stany

The Simulation Manager in angr is responsible for managing the execution of the binary and keeping track of the program's state during the analysis. It allows us to explore different paths and make decisions based on the program's behavior.

The program's state in angr represents the current snapshot of the program's execution. It includes information such as the values of registers and memory, the program counter, and the symbolic expressions associated with variables.

By manipulating the program's state, we can control the execution flow and explore different paths in the program. For example, we can modify the values of registers or memory to force the program to take a specific branch or to trigger a specific behavior.

The Simulation Manager uses a technique called symbolic execution to explore different paths in the program. Symbolic execution allows us to reason about the program's behavior without actually executing it. Instead of using concrete values, symbolic execution uses symbolic expressions to represent the program's inputs and outputs.

During the analysis, the Simulation Manager creates a tree-like structure called the execution tree. Each node in the tree represents a different path in the program. By exploring the execution tree, we can analyze the program's behavior and identify vulnerabilities or interesting behaviors.

Overall, the Simulation Manager and the concept of states are fundamental components of angr that allow us to dynamically analyze binaries and understand their behavior. By manipulating the program's state and exploring different paths, we can uncover hidden functionalities, identify vulnerabilities, and gain a deeper understanding of the program's inner workings.
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
## Wywoływanie funkcji

* Możesz przekazać listę argumentów za pomocą `args` oraz słownik zmiennych środowiskowych za pomocą `env` do konstruktorów `entry_state` i `full_init_state`. Wartości w tych strukturach mogą być ciągami znaków lub bitwektorami i zostaną zserializowane do stanu jako argumenty i środowisko dla symulowanego wykonania. Domyślna wartość `args` to pusta lista, więc jeśli analizowany program oczekuje, że znajdzie przynajmniej `argv[0]`, zawsze powinieneś to dostarczyć!
* Jeśli chcesz, aby `argc` było symboliczne, możesz przekazać symboliczny bitwektor jako `argc` do konstruktorów `entry_state` i `full_init_state`. Bądź jednak ostrożny: jeśli to zrobisz, powinieneś również dodać ograniczenie do wynikowego stanu, że wartość `argc` nie może być większa niż liczba argumentów przekazanych do `args`.
* Aby użyć stanu wywołania, powinieneś go wywołać za pomocą `.call_state(addr, arg1, arg2, ...)`, gdzie `addr` to adres funkcji, którą chcesz wywołać, a `argN` to N-ty argument tej funkcji, jako liczba całkowita, ciąg znaków, tablica lub bitwektor w języku Python. Jeśli chcesz zaalokować pamięć i faktycznie przekazać wskaźnik do obiektu, powinieneś go opakować w `angr.PointerWrapper("point to me!")`. Wyniki tego interfejsu API mogą być nieco nieprzewidywalne, ale nad tym pracujemy.

## Bitwektory
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Symboliczne BitVectors i ograniczenia

Symboliczne BitVectors są podstawowym narzędziem w angr do modelowania i manipulowania symbolicznymi wartościami. Symboliczne BitVectors reprezentują wartości bitowe, które mogą mieć zarówno konkretne wartości, jak i symboliczne zmienne.

Ograniczenia są warunkami, które można nałożyć na symboliczne BitVectors. Ograniczenia pozwalają na modelowanie zależności między symbolicznymi wartościami i manipulowanie nimi. Przykładowe ograniczenia to równość, nierówność, większość, mniejszość, itp.

Symboliczne BitVectors i ograniczenia są kluczowe w analizie statycznej i dynamicznej programów. Pozwalają na badanie ścieżek wykonania programu, identyfikowanie podatności i znajdowanie błędów.

W angr można tworzyć symboliczne BitVectors, manipulować nimi za pomocą operacji bitowych i stosować ograniczenia do tych symbolicznych wartości. Dzięki temu można modelować różne scenariusze i analizować zachowanie programu w zależności od różnych wartości wejściowych.

Symboliczne BitVectors i ograniczenia są niezwykle potężnym narzędziem w dziedzinie odwracania oprogramowania. Pozwalają na automatyczne rozwiązywanie problemów, takich jak odnajdywanie wartości wejściowych, które prowadzą do określonego stanu programu, czy odnajdywanie podatności w kodzie źródłowym.
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
## Hookowanie

Hookowanie jest techniką polegającą na modyfikowaniu działania programu poprzez przechwytywanie i zmienianie jego funkcji. Jest to przydatne narzędzie w analizie odwrotnej, które umożliwia manipulację zachowaniem programu bez konieczności modyfikacji jego kodu źródłowego.

### Typy hookowania

1. **Hookowanie funkcji**: Polega na przechwyceniu wywołań określonej funkcji i zastąpieniu jej własną implementacją. Pozwala to na kontrolowanie przepływu programu i manipulację danymi.

2. **Hookowanie bibliotek**: Polega na przechwyceniu wywołań funkcji z określonej biblioteki. Może być używane do monitorowania i analizy zachowania programu, a także do zmiany jego działania.

3. **Hookowanie systemowe**: Polega na przechwyceniu wywołań systemowych funkcji. Pozwala to na kontrolowanie interakcji programu z systemem operacyjnym i manipulację danymi przekazywanymi między nimi.

### Narzędzia do hookowania

Istnieje wiele narzędzi do hookowania, które ułatwiają implementację tej techniki. Oto kilka popularnych narzędzi:

- **Frida**: Framework do dynamicznego hookowania aplikacji na różnych platformach.

- **Xposed**: Framework do hookowania aplikacji na systemie Android.

- **Cydia Substrate**: Framework do hookowania aplikacji na systemie iOS.

- **Detours**: Biblioteka do hookowania funkcji na platformie Windows.

- **DTrace**: Narzędzie do hookowania i monitorowania aplikacji na systemach Unix.

### Zastosowanie hookowania

Hookowanie ma wiele zastosowań w analizie odwrotnej i testowaniu penetracyjnym. Oto kilka przykładów:

- **Monitorowanie i analiza**: Hookowanie może być używane do monitorowania i analizy zachowania programu w celu zidentyfikowania potencjalnych zagrożeń lub podatności.

- **Manipulacja danych**: Hookowanie umożliwia manipulację danymi przekazywanymi między programem a systemem operacyjnym, co może być przydatne w celu zmiany działania programu.

- **Bypassing zabezpieczeń**: Hookowanie może być używane do obejścia zabezpieczeń programu, umożliwiając dostęp do chronionych funkcji lub danych.

- **Tworzenie narzędzi diagnostycznych**: Hookowanie może być używane do tworzenia narzędzi diagnostycznych, które umożliwiają analizę i debugowanie programu.

### Podsumowanie

Hookowanie jest potężną techniką, która umożliwia modyfikację zachowania programu poprzez przechwytywanie i zmienianie jego funkcji. Jest to przydatne narzędzie w analizie odwrotnej i testowaniu penetracyjnym, które pozwala na kontrolowanie przepływu programu i manipulację danymi. Istnieje wiele narzędzi do hookowania, które ułatwiają implementację tej techniki.
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
Ponadto, możesz użyć `proj.hook_symbol(name, hook)`, podając nazwę symbolu jako pierwszy argument, aby podłączyć adres, pod którym znajduje się symbol.

# Przykłady

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
