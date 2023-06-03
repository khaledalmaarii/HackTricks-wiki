# Installation

## Introduction

`angr` is a Python framework for analyzing binaries. It combines both static and dynamic symbolic ("concolic") analysis, making it applicable to a variety of tasks.

## Installation

### Dependencies

`angr` requires Python 3.6 or later. It also requires several Python packages, which can be installed via `pip`:

```bash
pip install angr
```

### Optional Dependencies

`angr` has several optional dependencies that can be installed via `pip`:

- `angr-management`: a GUI for `angr`
- `angr-doc`: documentation for `angr`
- `angr-dev`: development tools for `angr`

To install all of the optional dependencies, run:

```bash
pip install angr[angr-management,angr-doc,angr-dev]
```

## Usage

Once `angr` is installed, you can use it in your Python scripts by importing it:

```python
import angr
```

## Resources

- [angr documentation](https://docs.angr.io/)
- [angr GitHub repository](https://github.com/angr/angr)
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Actions de base

## Load a binary

## Charger un binaire

To load a binary into an angr project, you can use the `angr.Project` constructor.

Pour charger un binaire dans un projet angr, vous pouvez utiliser le constructeur `angr.Project`.

```python
import angr

project = angr.Project("/path/to/binary")
```

## Find entry point

## Trouver le point d'entrée

To find the entry point of a binary, you can use the `entry_state` property of the angr project.

Pour trouver le point d'entrée d'un binaire, vous pouvez utiliser la propriété `entry_state` du projet angr.

```python
entry_point = project.entry_state.addr
```

## Find functions

## Trouver des fonctions

To find all the functions in a binary, you can use the `project.kb.functions` property.

Pour trouver toutes les fonctions dans un binaire, vous pouvez utiliser la propriété `project.kb.functions`.

```python
functions = project.kb.functions
```

## Find basic blocks

## Trouver des blocs de base

To find all the basic blocks in a function, you can use the `blocks` property of the function.

Pour trouver tous les blocs de base dans une fonction, vous pouvez utiliser la propriété `blocks` de la fonction.

```python
function = project.kb.functions.get("function_name")
basic_blocks = function.blocks
```

## Find instructions

## Trouver des instructions

To find all the instructions in a basic block, you can use the `capstone.insns` property of the basic block.

Pour trouver toutes les instructions dans un bloc de base, vous pouvez utiliser la propriété `capstone.insns` du bloc de base.

```python
basic_block = function.get_block(0x1234)
instructions = basic_block.capstone.insns
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
# Informations sur les objets chargés et principaux

## Données chargées
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
## Objectif principal
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
## Symboles et Réadressages
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
## Blocs
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Analyse Dynamique

## Gestionnaire de Simulation, États
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
## Appel de fonctions

* Vous pouvez passer une liste d'arguments via `args` et un dictionnaire de variables d'environnement via `env` dans `entry_state` et `full_init_state`. Les valeurs dans ces structures peuvent être des chaînes de caractères ou des vecteurs de bits, et seront sérialisées dans l'état en tant qu'arguments et environnement pour l'exécution simulée. Par défaut, `args` est une liste vide, donc si le programme que vous analysez s'attend à trouver au moins un `argv[0]`, vous devez toujours le fournir !
* Si vous souhaitez que `argc` soit symbolique, vous pouvez passer un vecteur de bits symbolique en tant que `argc` aux constructeurs `entry_state` et `full_init_state`. Cependant, soyez prudent : si vous faites cela, vous devez également ajouter une contrainte à l'état résultant que votre valeur pour argc ne peut pas être supérieure au nombre d'arguments que vous avez passés dans `args`.
* Pour utiliser l'état d'appel, vous devez l'appeler avec `.call_state(addr, arg1, arg2, ...)`, où `addr` est l'adresse de la fonction que vous voulez appeler et `argN` est le N-ième argument de cette fonction, soit en tant qu'entier, chaîne de caractères ou tableau Python, soit en tant que vecteur de bits. Si vous voulez allouer de la mémoire et réellement passer un pointeur vers un objet, vous devez l'envelopper dans un PointerWrapper, c'est-à-dire `angr.PointerWrapper("point to me!")`. Les résultats de cette API peuvent être un peu imprévisibles, mais nous y travaillons.

## Vecteurs de bits
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## BitVectors symboliques et contraintes

Les BitVectors symboliques sont des variables qui représentent des bits. Les contraintes sont des équations ou des inégalités qui lient ces variables. Les contraintes peuvent être utilisées pour restreindre les valeurs possibles des variables symboliques. 

Par exemple, si nous avons une variable symbolique `x` qui représente un octet, nous pouvons ajouter une contrainte `x < 10` pour limiter les valeurs possibles de `x` à des nombres inférieurs à 10. 

Les contraintes peuvent également être utilisées pour modéliser des conditions de programme. Par exemple, si nous avons une instruction `if (x == 0)`, nous pouvons ajouter une contrainte `x == 0` pour représenter le chemin d'exécution où la condition est vraie. 

Les contraintes peuvent être combinées à l'aide d'opérateurs logiques tels que `&` (et), `|` (ou) et `~` (non). Par exemple, nous pouvons combiner les contraintes `x < 10` et `x > 5` en utilisant l'opérateur `&` pour obtenir la contrainte `5 < x < 10`. 

Les BitVectors symboliques et les contraintes sont utilisés dans angr pour représenter l'état d'un programme à un moment donné. En utilisant des contraintes, angr peut explorer toutes les branches possibles d'un programme et trouver des chemins d'exécution qui mènent à des états souhaités, tels que des fuites de données ou des points d'entrée de fonctions sensibles.
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

Le hooking est une technique qui permet de modifier le comportement d'un programme en interceptant et en modifiant les appels de fonctions. Cette technique est souvent utilisée pour contourner les protections de sécurité ou pour effectuer des analyses de programmes.

Il existe plusieurs types de hooking, notamment le hooking d'importation, le hooking d'exportation et le hooking de fonction. Le hooking d'importation consiste à remplacer une fonction importée par une autre fonction, tandis que le hooking d'exportation consiste à remplacer une fonction exportée par une autre fonction. Le hooking de fonction consiste à intercepter les appels d'une fonction spécifique et à les rediriger vers une autre fonction.

Le hooking peut être réalisé à l'aide de différentes techniques, telles que l'injection de code, la modification de la table des fonctions virtuelles (VFT) ou la modification de la table des adresses de fonctions (IAT). Cependant, le hooking peut être détecté par des techniques de détection de hooking, telles que la vérification de l'intégrité du code ou la surveillance des appels de fonctions.

Dans le contexte de l'analyse de programmes, le hooking peut être utilisé pour tracer les appels de fonctions et pour collecter des informations sur le comportement du programme. Cependant, il est important de noter que le hooking peut également être utilisé à des fins malveillantes, telles que l'installation de logiciels malveillants ou la collecte de données sensibles.
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
De plus, vous pouvez utiliser `proj.hook_symbol(name, hook)` en fournissant le nom d'un symbole en tant que premier argument pour accrocher l'adresse où le symbole se trouve.

# Exemples

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
