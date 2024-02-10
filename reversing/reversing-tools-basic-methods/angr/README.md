<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

# Installation

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!Dujeychugh, AWS hacking jatlhlaHmeH</strong></a><strong>!</strong></summary>

**HackTricks** vItlhutlh **ghItlhvam**:

* **HackTricks** vItlhutlh **ghItlhvam** **company** **advertised** **tlhIngan** **HackTricks** **download** **tlhIngan** **PDF** **Check** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* **official PEASS & HackTricks swag** **ghItlhvam** [**peass.creator-spring.com**](https://peass.creator-spring.com)
* **The PEASS Family** **ghItlhvam** [**opensea.io/collection/the-peass-family**](https://opensea.io/collection/the-peass-family), **collection** **exclusive NFTs** **ghItlhvam** [**opensea.io/collection/the-peass-family**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 **Discord group** **ghItlhvam** [**discord.gg/hRep4RUj7f**](https://discord.gg/hRep4RUj7f) **telegram group** **ghItlhvam** [**t.me/peass**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) **HackTricks Cloud** **ghItlhvam** [**github repos**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# QaStaHvIS

## Introduction

The `angr` framework is a powerful tool for binary analysis and reverse engineering. It provides a wide range of functionalities to assist in understanding and manipulating binary executables. This section will cover some of the basic actions that can be performed using `angr`.

## Loading a Binary

To start analyzing a binary with `angr`, you need to load it into the framework. This can be done using the `angr.Project()` function, which takes the path to the binary as an argument. For example:

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)
```

## Exploring the Control Flow Graph (CFG)

The Control Flow Graph (CFG) represents the flow of execution within a binary. `angr` allows you to explore and analyze the CFG of a binary using the `project.analyses.CFG()` function. This function returns an object that provides various methods to navigate and query the CFG. For example:

```python
cfg = project.analyses.CFG()
```

## Finding Functions

`angr` provides a convenient way to find functions within a binary. The `project.kb.functions` attribute contains a dictionary of all the functions discovered during the analysis. You can access a specific function by its address or name. For example:

```python
function_address = 0x12345678
function = project.kb.functions[function_address]
```

## Symbolic Execution

Symbolic execution is a technique used in binary analysis to explore all possible paths of execution within a program. `angr` allows you to perform symbolic execution using the `project.factory.simulation_manager()` function. This function returns a `SimulationManager` object that can be used to explore different execution paths. For example:

```python
sim_manager = project.factory.simulation_manager()
```

## Finding Vulnerabilities

`angr` can be used to find vulnerabilities in a binary by analyzing its code. For example, you can use symbolic execution to identify potential buffer overflows or format string vulnerabilities. By exploring different execution paths, you can uncover potential security issues.
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
# yIqej je 'ej lo'laHbe' vItlhutlh

## yIqej vItlhutlh
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
## QaD jImej

---


## Introduction

The main objective of this document is to provide a comprehensive guide on using angr, a powerful binary analysis framework, for reverse engineering tasks. This guide will cover the basic methods and techniques for using angr effectively.

---

## tlhIngan Hol Translation

## QaD jImej

---

## Introduction

QaD jImej vItlhutlhlaHchugh angr, nIvbogh binary analysis framework, vaj reverse engineering ngeHbej vItlhutlhlaHchugh jImej. QaD jImej Hoch vItlhutlhlaHchugh jImej je techniques vaj methods vItlhutlhlaHchugh angr vItlhutlhlaHchugh jImej.
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
## pIqaD je relo' Hoch

When reverse engineering a binary, understanding symbols and relocations is crucial. Symbols are identifiers used by the compiler to represent functions, variables, and other program elements. Relocations, on the other hand, are instructions that modify the addresses of symbols during the linking process.

### Symbols

Symbols provide meaningful names to various program elements, making it easier for developers to understand and work with the code. They can be functions, variables, constants, or even labels within the code.

In Klingon, we refer to symbols as **pIqaD je**. These **pIqaD je** are essential for identifying and referencing different parts of a program during the reverse engineering process.

### Relocations

Relocations are instructions that adjust the addresses of symbols when the binary is loaded into memory. They ensure that the program can access the correct memory locations for its symbols, regardless of where it is loaded.

In Klingon, we call relocations **relo' Hoch**. These **relo' Hoch** are crucial for correctly resolving the addresses of symbols during the reverse engineering process.

Understanding symbols and relocations is fundamental for reverse engineers, as they provide valuable information about the structure and behavior of a binary. By analyzing symbols and relocations, reverse engineers can gain insights into how the program works and identify potential vulnerabilities or areas of interest.
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
## QIch

### QIch 'oH

QIch 'oH 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh. QIch 'oH 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhutlh 'e' vItlhut
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# qImHa' Qap

## qIbHom Qap, qo'noS

The Simulation Manager in angr is responsible for managing the execution of the binary and keeping track of the program's state. It allows you to explore different paths and analyze the behavior of the program dynamically.

The States in angr represent the different possible states of the program during execution. Each state contains information such as the program counter, memory, and registers. By manipulating the states, you can control the execution flow and explore different program paths.

The Simulation Manager uses a technique called symbolic execution to explore all possible paths of the program. It starts with an initial state and explores each path by making symbolic choices at each branch point. This allows you to analyze the program's behavior without actually executing it.

During the execution, the Simulation Manager keeps track of the constraints on the program's inputs. These constraints are used to solve symbolic expressions and determine the possible values of variables at each point in the program. This information can be used to find vulnerabilities or analyze the program's behavior.

By using the Simulation Manager and manipulating the states, you can perform various dynamic analysis techniques such as taint analysis, symbolic execution, and concolic execution. These techniques can help you understand the program's behavior, identify vulnerabilities, and find solutions to security problems.
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
## Calling functions

* **tlhIngan Hol translation not available**
* **tlhIngan Hol translation not available**
* **tlhIngan Hol translation not available**
* **tlhIngan Hol translation not available**
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Symbolic BitVectors & Constraints

### tlhIngan Hol Translation:

## Symbolic BitVectors & Constraints

### tlhIngan Hol Translation: 

## Symbolic BitVectors & Constraints
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

### tlhIngan Hol:

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan Hol: 

## Hooking

### tlhIngan
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
Qatlh, `proj.hook_symbol(name, hook)` vItlhutlh, vItlhutlh symbol vItlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhutlh vItlhutlhut
