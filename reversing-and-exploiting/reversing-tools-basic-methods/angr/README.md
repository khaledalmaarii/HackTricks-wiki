<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Parte di questa cheatsheet si basa sulla [documentazione di angr](https://docs.angr.io/_/downloads/en/stable/pdf/).

# Installazione
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Azioni di base

In this section, we will cover some basic actions that can be performed using angr. These actions include loading a binary, creating a project, and exploring the program's control flow.

## Loading a Binary

To start analyzing a binary with angr, you need to load it into a project. This can be done using the `angr.Project()` function, which takes the path to the binary as an argument. For example:

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)
```

## Creating a Project

Once the binary is loaded, you can create a project object that represents the binary and its execution environment. This project object provides various methods and attributes for analyzing and manipulating the binary. For example:

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)

# Accessing project attributes
entry_point = project.entry
arch = project.arch

# Accessing project methods
cfg = project.analyses.CFGFast()
symbol_table = project.loader.main_object.symbols
```

## Exploring Control Flow

One of the main features of angr is its ability to explore the control flow of a program. This can be done using the `explorer` object, which represents a state of the program at a specific point in its execution. The explorer object provides methods for navigating the program's control flow, such as `step()`, `run()`, and `run_until()`. For example:

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)

# Create an explorer object
explorer = project.factory.simulation_manager()

# Explore the control flow
explorer.step()  # Step to the next basic block
explorer.run()  # Run until the program exits
explorer.run_until(0x401234)  # Run until a specific address is reached
```

These are just a few examples of the basic actions that can be performed using angr. The library provides many more features and functionalities for advanced binary analysis and reverse engineering.
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
# Dati caricati

When analyzing a binary with angr, the first step is to load the binary into an angr project. This can be done using the `angr.Project()` function, which takes the path to the binary as an argument.

Durante l'analisi di un binario con angr, il primo passo è caricare il binario in un progetto angr. Ciò può essere fatto utilizzando la funzione `angr.Project()`, che prende come argomento il percorso del binario.

```python
import angr

# Load the binary into an angr project
project = angr.Project('/path/to/binary')
```

Once the binary is loaded, we can access various information about the loaded binary using the `project.loader` object. This object provides access to information such as the entry point address, the base address, and the sections of the binary.

Una volta caricato il binario, possiamo accedere a varie informazioni sul binario caricato utilizzando l'oggetto `project.loader`. Questo oggetto fornisce accesso a informazioni come l'indirizzo del punto di ingresso, l'indirizzo di base e le sezioni del binario.

```python
# Get the entry point address of the binary
entry_point = project.loader.main_object.entry

# Get the base address of the binary
base_address = project.loader.main_object.mapped_base

# Get the sections of the binary
sections = project.loader.main_object.sections
```

## Main Object

The `project.loader.main_object` object represents the main binary being analyzed. It provides access to various information about the binary, such as its entry point address, base address, and sections.

Oggetto principale

L'oggetto `project.loader.main_object` rappresenta il binario principale in fase di analisi. Fornisce accesso a varie informazioni sul binario, come l'indirizzo del punto di ingresso, l'indirizzo di base e le sezioni.

```python
# Get the entry point address of the main binary
entry_point = project.loader.main_object.entry

# Get the base address of the main binary
base_address = project.loader.main_object.mapped_base

# Get the sections of the main binary
sections = project.loader.main_object.sections
```
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
## Obiettivo principale

The main objective of the angr framework is to provide a powerful and flexible platform for analyzing and reverse engineering binary programs. It aims to automate the process of analyzing binaries by providing a set of tools and methods that can be used to explore and understand their behavior.

## Obiettivo principale

L'obiettivo principale del framework angr è fornire una piattaforma potente e flessibile per l'analisi e l'ingegneria inversa di programmi binari. Si propone di automatizzare il processo di analisi dei binari fornendo un insieme di strumenti e metodi che possono essere utilizzati per esplorare e comprendere il loro comportamento.
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
## Simboli e Rilocazioni

When reversing a binary, understanding symbols and relocations is crucial. Symbols are names or labels associated with specific addresses or memory locations in the binary. They can represent functions, variables, or other important elements of the program.

Relocations, on the other hand, are instructions or data that need to be modified or adjusted when the binary is loaded into memory. They are used to ensure that the binary can be executed correctly regardless of its actual memory location.

In the context of reverse engineering, symbols and relocations provide valuable information about the binary's structure and functionality. By analyzing symbols, you can identify important functions or variables that are relevant to your analysis. Relocations, on the other hand, can help you understand how the binary is linked and loaded into memory.

To work with symbols and relocations, you can use various tools and techniques. For example, you can use a disassembler or a debugger to view and analyze symbols in the binary. You can also use a tool like `objdump` to extract symbol information from the binary.

Understanding symbols and relocations is an essential skill for reverse engineers. It allows you to navigate and analyze binaries more effectively, enabling you to uncover hidden functionality or vulnerabilities. By mastering the use of tools and techniques for working with symbols and relocations, you can enhance your reverse engineering capabilities and become a more proficient hacker.
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
## Blocchi

---

### Basic Block

A basic block is a sequence of instructions with a single entry point and a single exit point. It is a fundamental unit of analysis in reverse engineering and program analysis. In an executable binary, basic blocks are usually identified by their starting addresses.

### Control Flow Graph (CFG)

A control flow graph is a graphical representation of the flow of control within a program. It consists of nodes, which represent basic blocks, and edges, which represent the flow of control between the basic blocks. The CFG provides a high-level view of the program's control flow and can be used to analyze the program's behavior.

### Function

A function is a self-contained block of code that performs a specific task. In reverse engineering, functions are often the focus of analysis, as they encapsulate the logic and behavior of a program. Functions can be identified by their entry points and can be analyzed to understand how they work.

### Procedure

A procedure is a sequence of instructions that performs a specific task within a function. Procedures are often used to implement higher-level functionality within a program. In reverse engineering, procedures can be analyzed to understand the inner workings of a function.

### Basic Block Graph (BBG)

A basic block graph is a graphical representation of the control flow within a function. It consists of nodes, which represent basic blocks, and edges, which represent the flow of control between the basic blocks. The BBG provides a detailed view of the control flow within a function and can be used to analyze the function's behavior.

---

### Blocco di base

Un blocco di base è una sequenza di istruzioni con un unico punto di ingresso e un unico punto di uscita. È un'unità fondamentale di analisi nell'ingegneria inversa e nell'analisi dei programmi. In un binario eseguibile, i blocchi di base sono di solito identificati dai loro indirizzi di inizio.

### Grafo di flusso di controllo (CFG)

Un grafo di flusso di controllo è una rappresentazione grafica del flusso di controllo all'interno di un programma. È composto da nodi, che rappresentano i blocchi di base, e da archi, che rappresentano il flusso di controllo tra i blocchi di base. Il CFG fornisce una visione ad alto livello del flusso di controllo del programma e può essere utilizzato per analizzare il comportamento del programma.

### Funzione

Una funzione è un blocco di codice autonomo che svolge un compito specifico. Nell'ingegneria inversa, le funzioni sono spesso il focus dell'analisi, in quanto racchiudono la logica e il comportamento di un programma. Le funzioni possono essere identificate dai loro punti di ingresso e possono essere analizzate per capire come funzionano.

### Procedura

Una procedura è una sequenza di istruzioni che svolge un compito specifico all'interno di una funzione. Le procedure sono spesso utilizzate per implementare funzionalità di livello superiore all'interno di un programma. Nell'ingegneria inversa, le procedure possono essere analizzate per comprendere il funzionamento interno di una funzione.

### Grafo dei blocchi di base (BBG)

Un grafo dei blocchi di base è una rappresentazione grafica del flusso di controllo all'interno di una funzione. È composto da nodi, che rappresentano i blocchi di base, e da archi, che rappresentano il flusso di controllo tra i blocchi di base. Il BBG fornisce una visione dettagliata del flusso di controllo all'interno di una funzione e può essere utilizzato per analizzare il comportamento della funzione.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Analisi dinamica

## Gestore di simulazione, Stati

Il gestore di simulazione è il componente principale di angr che si occupa di eseguire la simulazione di un programma. Gestisce gli stati, che rappresentano i diversi punti di esecuzione del programma durante la simulazione.

Gli stati sono oggetti che contengono tutte le informazioni necessarie per rappresentare lo stato di un programma in un determinato punto di esecuzione. Queste informazioni includono il valore dei registri, la memoria, il puntatore di istruzioni e altre informazioni di contesto.

Il gestore di simulazione utilizza una struttura dati chiamata Simulation Manager per gestire gli stati durante la simulazione. Il Simulation Manager tiene traccia degli stati attivi, cioè gli stati che sono ancora in esecuzione, e degli stati completati, cioè gli stati che hanno terminato l'esecuzione.

Durante la simulazione, il gestore di simulazione può creare nuovi stati a partire da uno stato esistente, ad esempio quando viene eseguita un'istruzione di salto condizionale. Inoltre, il gestore di simulazione può prendere decisioni sul percorso di esecuzione da seguire, ad esempio quando si incontra un'istruzione di salto condizionale.

Il Simulation Manager utilizza una strategia di ricerca per determinare il percorso di esecuzione da seguire durante la simulazione. Ci sono diverse strategie di ricerca disponibili, come la ricerca in ampiezza (BFS) e la ricerca in profondità (DFS). Queste strategie possono essere utilizzate per esplorare diversi percorsi di esecuzione e trovare vulnerabilità o comportamenti indesiderati nel programma.

Inoltre, il Simulation Manager può essere configurato per eseguire diverse tecniche di analisi dinamica, come l'iniezione di input o la traccia delle chiamate di sistema. Queste tecniche possono essere utilizzate per analizzare il comportamento del programma durante la simulazione e identificare eventuali vulnerabilità o comportamenti anomali.

In conclusione, il gestore di simulazione e gli stati sono componenti fondamentali di angr che consentono di eseguire l'analisi dinamica di un programma. Utilizzando il Simulation Manager e le diverse tecniche di analisi dinamica disponibili, è possibile identificare vulnerabilità e comportamenti indesiderati nel programma e migliorare la sicurezza complessiva del sistema.
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
## Chiamare funzioni

* Puoi passare una lista di argomenti tramite `args` e un dizionario di variabili d'ambiente tramite `env` in `entry_state` e `full_init_state`. I valori in queste strutture possono essere stringhe o bitvectors e verranno serializzati nello stato come argomenti e ambiente per l'esecuzione simulata. L'`args` predefinito è una lista vuota, quindi se il programma che stai analizzando si aspetta di trovare almeno un `argv[0]`, dovresti sempre fornirlo!
* Se desideri che `argc` sia simbolico, puoi passare un bitvector simbolico come `argc` ai costruttori `entry_state` e `full_init_state`. Tuttavia, fai attenzione: se lo fai, dovresti anche aggiungere un vincolo allo stato risultante che il valore di argc non può essere maggiore del numero di argomenti che hai passato in `args`.
* Per utilizzare lo stato di chiamata, devi chiamarlo con `.call_state(addr, arg1, arg2, ...)`, dove `addr` è l'indirizzo della funzione che desideri chiamare e `argN` è l'N-esimo argomento di quella funzione, sia come intero, stringa o array python, o come bitvector. Se desideri allocare memoria e passare effettivamente un puntatore a un oggetto, dovresti incapsularlo in un PointerWrapper, ad esempio `angr.PointerWrapper("puntami!")`. I risultati di questa API possono essere un po' imprevedibili, ma stiamo lavorando su di esso.

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## BitVector simbolici e vincoli

Gli **Symbolic BitVectors** (vettori di bit simbolici) sono una rappresentazione astratta dei dati binari utilizzati nell'analisi simbolica. Questi vettori di bit possono rappresentare sia valori concreti che simbolici.

I **vincoli** sono condizioni che vengono imposte sui Symbolic BitVectors per limitare i possibili valori che possono assumere. I vincoli possono essere utilizzati per modellare le restrizioni di un programma o di un algoritmo specifico.

L'uso di Symbolic BitVectors e vincoli consente di eseguire operazioni simboliche sui dati, come ad esempio l'aggiunta, la sottrazione o la moltiplicazione, senza dover conoscere i valori concreti dei bit. Questo è particolarmente utile nell'analisi di programmi o algoritmi complessi, in cui i valori concreti potrebbero essere sconosciuti o difficili da determinare.

Gli Symbolic BitVectors e i vincoli sono ampiamente utilizzati nell'analisi simbolica e nella reverse engineering per risolvere problemi complessi e ottenere informazioni utili sui programmi o sui sistemi che si stanno analizzando.
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

Il **hooking** è una tecnica utilizzata nel reverse engineering per intercettare e modificare il comportamento di un'applicazione. Consiste nell'inserire del codice personalizzato (noto come "hook") all'interno di un'applicazione esistente, al fine di monitorare o alterare il flusso di esecuzione del programma.

### Tipi di hooking

Esistono diversi tipi di hooking, tra cui:

- **API hooking**: intercetta le chiamate alle API di sistema e sostituisce la funzionalità originale con una personalizzata.
- **Function hooking**: intercetta le chiamate alle funzioni all'interno di un'applicazione e sostituisce il loro comportamento con uno personalizzato.
- **Inline hooking**: modifica direttamente il codice dell'applicazione per intercettare e modificare il flusso di esecuzione.
- **Message hooking**: intercetta i messaggi inviati tra le finestre di un'applicazione per monitorare o alterare il loro comportamento.

### Utilizzo di hooking con Angr

Angr è un framework di analisi binaria che può essere utilizzato per eseguire hooking su un'applicazione. Per utilizzare Angr per il hooking, è necessario seguire i seguenti passaggi:

1. Caricare il file binario dell'applicazione all'interno di Angr.
2. Identificare la funzione o l'API che si desidera intercettare.
3. Creare un hook personalizzato per sostituire il comportamento originale.
4. Applicare il hook all'applicazione utilizzando le funzioni fornite da Angr.
5. Eseguire l'applicazione con il hook applicato e monitorare il suo comportamento modificato.

L'utilizzo di hooking con Angr può essere utile per scopi di reverse engineering, come l'analisi del comportamento di un'applicazione o l'individuazione di vulnerabilità. Tuttavia, è importante utilizzare questa tecnica in modo etico e nel rispetto delle leggi locali.
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
Inoltre, è possibile utilizzare `proj.hook_symbol(name, hook)`, fornendo il nome di un simbolo come primo argomento, per agganciare l'indirizzo in cui si trova il simbolo.

# Esempi

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, consulta i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
