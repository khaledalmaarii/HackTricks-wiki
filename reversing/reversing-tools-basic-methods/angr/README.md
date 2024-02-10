<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>

Ein Teil dieses Spickzettels basiert auf der [angr-Dokumentation](https://docs.angr.io/_/downloads/en/stable/pdf/).

# Installation
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Grundlegende Aktionen

## Load Binary

## Binärdatei laden

To start using angr, you need to load a binary file. You can do this by using the `angr.Project` class and passing the path to the binary as a parameter. Angr will automatically analyze the binary and create a project object that you can use to perform various actions.

Um angr zu verwenden, müssen Sie eine Binärdatei laden. Dies können Sie tun, indem Sie die Klasse `angr.Project` verwenden und den Pfad zur Binärdatei als Parameter übergeben. Angr analysiert automatisch die Binärdatei und erstellt ein Projektobjekt, das Sie für verschiedene Aktionen verwenden können.

```python
import angr

# Load the binary
project = angr.Project("/path/to/binary")
```

## Symbolically Execute Code

## Code symbolisch ausführen

One of the main features of angr is its ability to symbolically execute code. Symbolic execution allows you to explore all possible paths through a program, even if you don't have concrete input values. This can be useful for analyzing and understanding the behavior of a program.

Eine der Hauptfunktionen von angr ist die symbolische Ausführung von Code. Die symbolische Ausführung ermöglicht es Ihnen, alle möglichen Pfade durch ein Programm zu erkunden, auch wenn Sie keine konkreten Eingabewerte haben. Dies kann nützlich sein, um das Verhalten eines Programms zu analysieren und zu verstehen.

```python
# Symbolically execute the code
state = project.factory.entry_state()

# Explore all possible paths
simgr = project.factory.simgr(state)
simgr.explore()
```

## Find Functions

## Funktionen finden

Angr provides a convenient way to find functions within a binary. You can use the `project.kb.functions` attribute to access a dictionary of all the functions in the binary. Each function is represented by an `angr.knowledge_plugins.Function` object, which contains information such as the function's address, name, and arguments.

Angr bietet eine bequeme Möglichkeit, Funktionen in einer Binärdatei zu finden. Sie können das Attribut `project.kb.functions` verwenden, um auf ein Wörterbuch aller Funktionen in der Binärdatei zuzugreifen. Jede Funktion wird durch ein `angr.knowledge_plugins.Function`-Objekt repräsentiert, das Informationen wie die Adresse, den Namen und die Argumente der Funktion enthält.

```python
# Find all functions in the binary
functions = project.kb.functions

# Iterate over the functions
for function in functions.values():
    print(function.name)
```

## Find Basic Blocks

## Grundblöcke finden

In addition to functions, angr can also help you find basic blocks within a binary. A basic block is a sequence of instructions with a single entry point and a single exit point. You can use the `project.factory.block` method to retrieve a basic block at a specific address.

Neben Funktionen kann angr Ihnen auch dabei helfen, Grundblöcke in einer Binärdatei zu finden. Ein Grundblock ist eine Sequenz von Anweisungen mit einem einzigen Einstiegspunkt und einem einzigen Ausgangspunkt. Sie können die Methode `project.factory.block` verwenden, um einen Grundblock an einer bestimmten Adresse abzurufen.

```python
# Find a basic block at a specific address
block = project.factory.block(0x400000)

# Print the instructions in the basic block
for instruction in block.instructions:
    print(instruction)
```

## Find Memory References

## Speicherreferenzen finden

Angr can also help you find memory references within a binary. You can use the `project.factory.memory` attribute to access a representation of the binary's memory. This representation allows you to query the memory for specific addresses and retrieve the values stored at those addresses.

Angr kann Ihnen auch dabei helfen, Speicherreferenzen in einer Binärdatei zu finden. Sie können das Attribut `project.factory.memory` verwenden, um auf eine Darstellung des Speichers der Binärdatei zuzugreifen. Diese Darstellung ermöglicht es Ihnen, den Speicher nach bestimmten Adressen abzufragen und die Werte abzurufen, die an diesen Adressen gespeichert sind.

```python
# Access the binary's memory
memory = project.factory.memory

# Read a value from a specific address
value = memory.load(0x400000)
```

## Manipulate Memory

## Speicher manipulieren

In addition to reading values from memory, angr also allows you to manipulate the memory of a binary. You can use the `project.factory.memory.store` method to store a value at a specific address in the binary's memory.

Neben dem Lesen von Werten aus dem Speicher ermöglicht es angr Ihnen auch, den Speicher einer Binärdatei zu manipulieren. Sie können die Methode `project.factory.memory.store` verwenden, um einen Wert an einer bestimmten Adresse im Speicher der Binärdatei zu speichern.

```python
# Store a value at a specific address
memory.store(0x400000, 42)
```

## Solve Constraints

## Bedingungen lösen

Angr can also help you solve constraints within a binary. Constraints are conditions that must be satisfied for a specific path through the program to be taken. You can use the `project.factory.path_group` method to create a group of paths and then use the `group.satisfiable` method to check if the constraints are satisfiable.

Angr kann Ihnen auch dabei helfen, Bedingungen in einer Binärdatei zu lösen. Bedingungen sind Bedingungen, die erfüllt sein müssen, damit ein bestimmter Pfad durch das Programm eingenommen wird. Sie können die Methode `project.factory.path_group` verwenden, um eine Gruppe von Pfaden zu erstellen, und dann die Methode `group.satisfiable` verwenden, um zu überprüfen, ob die Bedingungen erfüllbar sind.

```python
# Create a group of paths
group = project.factory.path_group()

# Check if the constraints are satisfiable
satisfiable = group.satisfiable()
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
# Geladene Daten

The loaded data refers to the information that is loaded into the memory when a program is executed. This includes the program's code, libraries, and any other resources that are required for its execution.

Die geladenen Daten beziehen sich auf die Informationen, die in den Speicher geladen werden, wenn ein Programm ausgeführt wird. Dies umfasst den Programmcode, Bibliotheken und alle anderen Ressourcen, die für die Ausführung erforderlich sind.

## Main Object

The main object is the entry point of a program. It is the first object that is executed when the program starts running. The main object typically contains the main function, which is responsible for initiating the program's execution.

Das Hauptobjekt ist der Einstiegspunkt eines Programms. Es ist das erste Objekt, das ausgeführt wird, wenn das Programm gestartet wird. Das Hauptobjekt enthält in der Regel die Hauptfunktion, die für die Initiierung der Programmausführung verantwortlich ist.
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
## Hauptziel

The main objective of this document is to provide an introduction to the basic usage of angr, a powerful binary analysis framework. This guide will cover the installation process, basic concepts, and common use cases of angr. By the end of this document, you should have a good understanding of how to use angr to analyze and manipulate binary files. 

## Hauptziel

Das Hauptziel dieses Dokuments ist es, eine Einführung in die grundlegende Verwendung von angr zu bieten, einem leistungsstarken Framework zur Analyse von Binärdateien. Diese Anleitung behandelt den Installationsprozess, grundlegende Konzepte und häufige Anwendungsfälle von angr. Am Ende dieses Dokuments sollten Sie ein gutes Verständnis dafür haben, wie Sie angr verwenden können, um Binärdateien zu analysieren und zu manipulieren.
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
## Symbole und Relokationen

Symbole und Relokationen sind wichtige Konzepte in der Reverse Engineering-Welt. Sie helfen dabei, den Code zu verstehen und zu analysieren.

### Symbole

Symbole sind Namen, die bestimmten Speicheradressen zugeordnet sind. Sie dienen dazu, Funktionen, Variablen und andere Codeelemente zu identifizieren. Symbole können in verschiedenen Formen auftreten, wie zum Beispiel Funktionssymbole, Variablensymbole oder Konstantensymbole.

Die Verwendung von Symbolen erleichtert die Lesbarkeit und Analyse des Codes erheblich. Anstatt sich mit reinen Speicheradressen auseinandersetzen zu müssen, können wir uns auf die Namen der Symbole beziehen, um den Code besser zu verstehen.

### Relokationen

Relokationen sind Anweisungen im Code, die es dem Betriebssystem ermöglichen, den Code an unterschiedliche Speicheradressen zu verschieben. Dies ist besonders wichtig, wenn der Code in eine andere Umgebung geladen wird, wie zum Beispiel bei der Ausführung einer ausführbaren Datei.

Relokationen werden verwendet, um die Adressen von Symbolen anzupassen, wenn der Code an eine neue Speicheradresse verschoben wird. Dadurch bleibt der Code funktionsfähig, unabhängig von der tatsächlichen Speicheradresse.

Beim Reverse Engineering ist es wichtig, Relokationen zu verstehen, um den Code korrekt zu analysieren. Durch die Analyse der Relokationen können wir die ursprünglichen Speicheradressen der Symbole ermitteln und den Code besser verstehen.

### Zusammenfassung

Symbole und Relokationen sind grundlegende Konzepte im Reverse Engineering. Symbole helfen dabei, den Code lesbarer zu machen, indem sie Namen für Speicheradressen bereitstellen. Relokationen ermöglichen es dem Code, an unterschiedliche Speicheradressen angepasst zu werden, um seine Funktionalität beizubehalten. Das Verständnis von Symbole und Relokationen ist entscheidend, um den Code erfolgreich zu analysieren.
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
## Blöcke

Blocks sind die grundlegenden Bausteine in der angr-Bibliothek. Ein Block repräsentiert einen Abschnitt des Programms, der von einer bestimmten Adresse aus ausgeführt wird. Jeder Block enthält eine Anweisung, die an dieser Adresse ausgeführt wird, und einen Satz von Nachfolgerblöcken, die die möglichen nächsten Anweisungen darstellen.

Ein Block kann verschiedene Arten von Anweisungen enthalten, wie z.B. bedingte Sprünge, unbedingte Sprünge oder Rückkehrbefehle. Die Nachfolgerblöcke eines Blocks werden durch die möglichen Pfade bestimmt, die das Programm von diesem Block aus nehmen kann.

Die angr-Bibliothek ermöglicht es Ihnen, Blöcke zu erstellen, zu manipulieren und zu analysieren. Sie können Blöcke verwenden, um den Programmfluss zu modellieren und verschiedene Analysetechniken anzuwenden, um Informationen über das Programm zu gewinnen.

Die angr-Bibliothek bietet auch Funktionen zum Durchlaufen von Blöcken und zum Sammeln von Informationen über die Anweisungen in jedem Block. Sie können diese Informationen verwenden, um den Programmfluss zu verfolgen, Bedingungen zu analysieren und andere Reverse-Engineering-Aufgaben durchzuführen.

Insgesamt sind Blöcke ein wichtiges Konzept in der angr-Bibliothek und spielen eine zentrale Rolle bei der Analyse und Manipulation von Programmen.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Simulation Manager, Zustände

Der Simulation Manager ist ein zentrales Konzept in der Angr-Bibliothek. Er ist verantwortlich für die Verwaltung der Zustände während der Ausführung einer binären Datei. Ein Zustand repräsentiert den aktuellen Zustand der Ausführung, einschließlich des Programmzählers, der Registerwerte und des Speicherinhalts.

Der Simulation Manager ermöglicht es uns, verschiedene Aktionen auf den Zuständen auszuführen, wie z.B. das Setzen von Eingabewerten, das Auslösen von Ereignissen und das Überwachen von Speicherzugriffen. Darüber hinaus kann der Simulation Manager mehrere Zustände gleichzeitig verwalten und zwischen ihnen wechseln, um verschiedene Pfade der Ausführung zu erkunden.

## Execution Enginges

Die Angr-Bibliothek unterstützt verschiedene Ausführungsmotoren, die die Ausführung der binären Datei steuern. Jeder Ausführungsmotor implementiert eine bestimmte Methode zur Ausführung der Anweisungen und zur Verwaltung der Zustände.

Einige der unterstützten Ausführungsmotoren sind:

- **VEX**: Ein leistungsstarker und flexibler Ausführungsmotor, der auf der VEX-IR (Intermediate Representation) basiert.
- **Unicorn**: Ein CPU-Emulator, der die Ausführung von Maschinencode ermöglicht.
- **SimuVEX**: Eine Kombination aus VEX und Unicorn, die die Vorteile beider Ausführungsmotoren vereint.

Jeder Ausführungsmotor hat seine eigenen Vor- und Nachteile, und die Wahl des richtigen Motors hängt von den spezifischen Anforderungen des Reverse Engineering-Projekts ab.

## Symbolic Execution

Symbolische Ausführung ist eine Technik, die es uns ermöglicht, den Programmfluss zu analysieren, indem wir symbolische Werte anstelle konkreter Werte verwenden. Anstatt tatsächliche Eingabewerte zu verwenden, verwenden wir symbolische Symbole, um den Wertebereich der Eingabe zu repräsentieren.

Die Angr-Bibliothek unterstützt symbolische Ausführung durch die Verwendung von Symbolic Expressions. Eine Symbolic Expression ist eine abstrakte Darstellung einer Berechnung, die symbolische Symbole enthält. Durch die Manipulation von Symbolic Expressions können wir Bedingungen und Einschränkungen auf die Eingabe definieren und den Programmfluss analysieren, um bestimmte Pfade zu erreichen oder zu vermeiden.

Symbolische Ausführung ist besonders nützlich für die Suche nach Schwachstellen in einer binären Datei, da sie es uns ermöglicht, verschiedene Eingabewerte zu testen und potenzielle Sicherheitslücken zu identifizieren.

## Concolic Execution

Concolic Execution ist eine Kombination aus konkreter und symbolischer Ausführung. Bei der konkreten Ausführung werden tatsächliche Eingabewerte verwendet, um den Programmfluss zu steuern. Bei der symbolischen Ausführung werden symbolische Symbole verwendet, um den Wertebereich der Eingabe zu repräsentieren.

Die Angr-Bibliothek unterstützt Concolic Execution durch die Verwendung von Concolic Tracers. Ein Concolic Tracer zeichnet den Programmfluss auf und speichert Informationen über die konkreten und symbolischen Werte, die während der Ausführung verwendet werden.

Concolic Execution ist besonders nützlich für die automatische Generierung von Testfällen und die Suche nach Sicherheitslücken, da sie es uns ermöglicht, den Programmfluss zu analysieren und potenzielle Schwachstellen zu identifizieren, indem wir verschiedene Eingabewerte testen.
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
## Aufrufen von Funktionen

* Sie können eine Liste von Argumenten über `args` und ein Wörterbuch von Umgebungsvariablen über `env` an `entry_state` und `full_init_state` übergeben. Die Werte in diesen Strukturen können Zeichenketten oder Bitvektoren sein und werden als Argumente und Umgebung in den Zustand serialisiert, um die simulierte Ausführung durchzuführen. Das Standard-`args` ist eine leere Liste, daher sollten Sie immer mindestens ein `argv[0]` bereitstellen, wenn das von Ihnen analysierte Programm erwartet, dass es vorhanden ist!
* Wenn Sie möchten, dass `argc` symbolisch ist, können Sie einen symbolischen Bitvektor als `argc` an die Konstruktoren `entry_state` und `full_init_state` übergeben. Seien Sie jedoch vorsichtig: Wenn Sie dies tun, sollten Sie auch eine Einschränkung für den resultierenden Zustand hinzufügen, dass Ihr Wert für `argc` nicht größer sein darf als die Anzahl der Argumente, die Sie in `args` übergeben haben.
* Um den Aufrufzustand zu verwenden, sollten Sie ihn mit `.call_state(addr, arg1, arg2, ...)` aufrufen, wobei `addr` die Adresse der Funktion ist, die Sie aufrufen möchten, und `argN` das N-te Argument für diese Funktion ist, entweder als Python-Integer, Zeichenkette oder Array oder als Bitvektor. Wenn Sie Speicher zuweisen und tatsächlich einen Zeiger auf ein Objekt übergeben möchten, sollten Sie ihn in einen PointerWrapper einwickeln, d.h. `angr.PointerWrapper("zeige auf mich!")`. Die Ergebnisse dieser API können etwas unvorhersehbar sein, aber wir arbeiten daran.

## Bitvektoren
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Symbolische Bitvektoren & Einschränkungen

Symbolische Bitvektoren sind ein wichtiges Konzept in der Angr-Toolbox. Sie ermöglichen es uns, den Zustand eines Programms symbolisch zu repräsentieren, anstatt konkrete Werte anzunehmen. Dies ermöglicht es uns, komplexe Bedingungen und Einschränkungen zu modellieren und zu analysieren.

Ein symbolischer Bitvektor besteht aus einer Sequenz von Bits, die entweder konkrete Werte oder symbolische Variablen repräsentieren können. Konkrete Werte sind bekannte Werte, während symbolische Variablen unbekannte Werte darstellen. Durch die Verwendung von symbolischen Bitvektoren können wir Bedingungen wie "x > 5" oder "y == z" darstellen, ohne die genauen Werte von x, y und z zu kennen.

Einschränkungen sind Bedingungen, die auf symbolische Bitvektoren angewendet werden. Sie können verwendet werden, um bestimmte Pfade im Programmfluss zu erzwingen oder um Bedingungen zu modellieren, die erfüllt sein müssen, damit ein bestimmtes Verhalten auftritt. Einschränkungen können mit logischen Operatoren wie AND, OR und NOT kombiniert werden, um komplexe Bedingungen zu erstellen.

Die Angr-Toolbox ermöglicht es uns, symbolische Bitvektoren zu erstellen, Einschränkungen zu definieren und sie auf verschiedene Weisen zu manipulieren. Wir können Einschränkungen lösen, um konkrete Werte für symbolische Variablen zu finden, oder wir können Einschränkungen kombinieren, um neue Einschränkungen zu erstellen. Dies ermöglicht es uns, verschiedene Szenarien zu modellieren und zu analysieren, um Schwachstellen in einem Programm zu finden.

Die Verwendung von symbolischen Bitvektoren und Einschränkungen ist ein leistungsstarkes Werkzeug in der Reverse-Engineering- und Sicherheitsforschung. Es ermöglicht uns, komplexe Programme zu analysieren und zu verstehen, indem wir den Programmfluss und die Bedingungen, die zu bestimmten Verhaltensweisen führen, modellieren. Durch die Kombination von symbolischen Bitvektoren und Einschränkungen können wir Schwachstellen und Sicherheitslücken identifizieren, die sonst schwer zu finden wären.
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

Hooking ist eine Technik, bei der der normale Ablauf einer Anwendung geändert wird, um bestimmte Funktionen zu überwachen oder zu modifizieren. Dies wird oft von Hackern verwendet, um den Code einer Anwendung zu manipulieren und unerwünschte Aktionen auszuführen.

Es gibt verschiedene Arten von Hooks, darunter:

- **Function Hooking**: Hierbei wird der Code einer bestimmten Funktion geändert, um zusätzlichen Code einzufügen oder den ursprünglichen Code zu ersetzen. Dies ermöglicht es Hackern, den Fluss der Anwendung zu kontrollieren und bestimmte Aktionen auszuführen.

- **System Call Hooking**: Bei dieser Methode werden Systemaufrufe abgefangen und modifiziert, um den Zugriff auf bestimmte Ressourcen oder Funktionen zu steuern. Dies kann verwendet werden, um Sicherheitsmechanismen zu umgehen oder unerwünschte Aktionen auszuführen.

- **Inline Hooking**: Hierbei wird der Code einer Anwendung direkt im Speicher geändert, um den Fluss der Anwendung zu beeinflussen. Dies ermöglicht es Hackern, bestimmte Funktionen zu überwachen oder zu modifizieren, ohne den ursprünglichen Code zu ändern.

- **Message Hooking**: Diese Methode wird verwendet, um Nachrichten zwischen Anwendungen abzufangen und zu modifizieren. Dies kann verwendet werden, um die Kommunikation zwischen Anwendungen zu überwachen oder zu manipulieren.

Das Hooking kann sowohl für legitime Zwecke als auch für bösartige Aktivitäten eingesetzt werden. Es ist wichtig, sich der potenziellen Risiken bewusst zu sein und geeignete Sicherheitsmaßnahmen zu ergreifen, um unerwünschte Manipulationen zu verhindern.
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
Darüber hinaus können Sie `proj.hook_symbol(name, hook)` verwenden, wobei Sie den Namen eines Symbols als ersten Argument angeben, um die Adresse zu haken, an der das Symbol vorhanden ist.

# Beispiele

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
