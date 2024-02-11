<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

'n Gedeelte van hierdie spiekbrief is gebaseer op die [angr-dokumentasie](https://docs.angr.io/_/downloads/en/stable/pdf/).

# Installasie
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Basiese Aksies

In this section, we will cover some basic actions that can be performed using the angr framework.

## Loading a Binary

To start analyzing a binary with angr, you need to load it into the framework. This can be done using the `angr.Project()` function, which takes the path to the binary as an argument. For example:

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)
```

## Finding Entry Point

The entry point of a binary is the address where the execution starts. You can find the entry point using the `project.entry` attribute. For example:

```python
entry_point = project.entry
```

## Exploring the Control Flow Graph (CFG)

The Control Flow Graph (CFG) represents the flow of execution within a binary. You can generate the CFG using the `project.analyses.CFG()` function. For example:

```python
cfg = project.analyses.CFG()
```

## Finding Functions

To find the functions within a binary, you can use the `project.kb.functions` attribute. This attribute contains a dictionary where the keys are the addresses of the functions and the values are the corresponding `angr.knowledge.Function` objects. For example:

```python
functions = project.kb.functions
```

## Finding Basic Blocks

Basic blocks are sequences of instructions that have a single entry point and a single exit point. To find the basic blocks within a function, you can use the `function.blocks` attribute. For example:

```python
basic_blocks = function.blocks
```

## Analyzing Function Arguments

To analyze the arguments of a function, you can use the `function.arguments` attribute. This attribute contains a list of `angr.knowledge.FunctionArgument` objects, where each object represents an argument of the function. For example:

```python
arguments = function.arguments
```

These are some of the basic actions that can be performed using the angr framework. By understanding and utilizing these actions, you can effectively analyze and manipulate binaries for various purposes.
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
# Gelaai Data

The loaded data refers to the information that is loaded into the memory when a program is executed. This can include variables, functions, libraries, and other resources that are necessary for the program to run.

Die gelaai data verwys na die inligting wat in die geheue gelaai word wanneer 'n program uitgevoer word. Dit kan veranderlikes, funksies, biblioteke en ander hulpbronne insluit wat nodig is vir die program om te loop.

## Main Object

The main object is the entry point of a program. It is the first object that is executed when the program starts running. The main object typically contains the main function, which is responsible for controlling the flow of the program.

Die hoofobjek is die toegangspunt van 'n program. Dit is die eerste objek wat uitgevoer word wanneer die program begin loop. Die hoofobjek bevat gewoonlik die hooffunksie, wat verantwoordelik is vir die beheer van die vloei van die program.
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
## Hoofdoel

Die hoofdoel van die angr-raamwerk is om outomatiese analise en manipulasie van binêre programme moontlik te maak. Dit bied 'n kragtige en veelsydige omgewing vir die ontleed en verstaan van programgedrag. Die raamwerk maak gebruik van die konsepte van statiese en dinamiese analise om die programuitvoering te ondersoek en te manipuleer.

## Installering

Om angr te installeer, kan jy die volgende opdrag in die opdraglyn uitvoer:

```
pip install angr
```

## Gebruik

Om angr te gebruik, moet jy 'n Python-skripsie skep en die nodige funksies en metodes van die raamwerk invoer. Jy kan dan die funksies en metodes gebruik om binêre programme te ontleed en te manipuleer.

Hier is 'n voorbeeld van hoe om angr te gebruik om 'n binêre program te ontleed:

```python
import angr

# Laai die binêre program in
proj = angr.Project("/pad/na/binêre/program")

# Definieer die beginpunt van die program
entry_point = proj.entry

# Skep 'n nuwe simboliese uitvoering
state = proj.factory.entry_state()

# Voer die simboliese uitvoering uit
simgr = proj.factory.simulation_manager(state)
simgr.run()

# Kry die finale toestand van die uitvoering
final_state = simgr.deadended[0]

# Kry die finale geheue-inhoud
memory = final_state.memory.load(0x400000, 10)

# Druk die geheue-inhoud af
print(memory)
```

Hierdie voorbeeld demonstreer die basiese gebruik van angr om 'n binêre program te ontleed en die finale geheue-inhoud af te druk. Jy kan verskeie ander funksies en metodes van die raamwerk gebruik om meer gevorderde analise en manipulasie van binêre programme uit te voer.

## Beperkings

Dit is belangrik om te besef dat angr nie 'n outomatiese oplossing vir alle probleme is nie. Daar is sekere beperkings en uitdagings wat jy kan teëkom wanneer jy die raamwerk gebruik. Hier is 'n paar belangrike beperkings om in gedagte te hou:

- angr is nie 100% akkuraat nie en kan foute maak tydens die ontleedproses.
- Die ontleedproses kan baie tydrowend wees, veral vir groot en komplekse programme.
- Sommige programme kan spesifieke tegnieke gebruik om die ontleedproses te omseil of te vertraag.
- angr kan nie altyd die korrekte programgedrag voorspel nie, veral as die program afhanklik is van eksterne faktore soos gebruikerinsette of netwerkverbindings.

Dit is belangrik om hierdie beperkings in gedagte te hou en om ander analise- en verifikasietegnieke te gebruik om die resultate van angr te bevestig en te verifieer.
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
## Simbole en Herlokasies

Simbole en herlokasies is belangrike konsepte in die omkeerproses van 'n program. Hierdie konsepte help om die program se struktuur en funksionaliteit te verstaan.

### Simbole

Simbole is verwysings na spesifieke plekke in die program se geheue. Dit kan funksies, globale veranderlikes, konstantes en ander belangrike dele van die program verteenwoordig. Simbole maak dit moontlik om na hierdie dele te verwys en om hulle te manipuleer tydens die omkeerproses.

### Herlokasies

Herlokasies is instruksies in die program se kode wat verwys na simbole. Hierdie instruksies vertel die program om na 'n spesifieke simbool te spring of om 'n spesifieke simbool te gebruik vir 'n berekening. Herlokasies is nodig omdat die finale plek van simbole in die geheue dikwels nie vooraf bepaal kan word nie.

By die omkeerproses is dit belangrik om simbole en herlokasies te identifiseer en te verstaan. Dit kan help om die program se werking te analiseer en om veranderinge aan te bring vir spesifieke doeleindes, soos foutopsporing of om sekuriteitslekke te verhoed.

In die volgende afdelings sal ons kyk na verskillende tegnieke en hulpmiddels wat gebruik kan word om simbole en herlokasies te ontleed en te manipuleer.
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
## Blokke
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Dinamiese Analise

## Simulasiebestuurder, State
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
## Oproep van funksies

* Jy kan 'n lys van argumente deur `args` en 'n woordeboek van omgewingsveranderlikes deur `env` in `entry_state` en `full_init_state` stuur. Die waardes in hierdie strukture kan strings of bitvectors wees, en sal geserializeer word in die toestand as die argumente en omgewing vir die gesimuleerde uitvoering. Die verstekwaarde vir `args` is 'n leë lys, so as die program wat jy analiseer verwag om ten minste 'n `argv[0]` te vind, moet jy dit altyd voorsien!
* As jy wil hê dat `argc` simbolies moet wees, kan jy 'n simboliese bitvector as `argc` aan die `entry_state` en `full_init_state` konstruksies stuur. Wees egter versigtig: as jy dit doen, moet jy ook 'n beperking by die resulterende toestand voeg dat jou waarde vir argc nie groter kan wees as die aantal argumente wat jy in `args` gestuur het nie.
* Om die oproep toestand te gebruik, moet jy dit oproep met `.call_state(addr, arg1, arg2, ...)`, waar `addr` die adres van die funksie is wat jy wil oproep en `argN` die Nde argument vir daardie funksie is, óf as 'n python-integer, string, of array, óf as 'n bitvector. As jy geheue wil toewys en werklik 'n verwysing na 'n voorwerp wil stuur, moet jy dit in 'n PointerWrapper verpak, d.w.s. `angr.PointerWrapper("verwys na my!")`. Die resultate van hierdie API kan 'n bietjie onvoorspelbaar wees, maar ons werk daaraan. 

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Simboliese BitVectors & Beperkings

`angr` ondersteun simboliese BitVectors en beperkings as 'n manier om komplekse probleme in reverse engineering op te los. Hierdie funksionaliteit maak dit moontlik om simboliese waardes te verteenwoordig en beperkings op te lê aan hierdie waardes.

### Simboliese BitVectors

'n Simboliese BitVector is 'n abstrakte voorstelling van 'n reeks bits waarvan die waardes onbekend is. Dit word gebruik om onbekende waardes te verteenwoordig en om operasies op hierdie waardes uit te voer sonder om hul werklike waardes te ken. Simboliese BitVectors kan gebruik word om die uitvoer van 'n program te simuleer sonder om dit fisies uit te voer.

### Beperkings

Beperkings word gebruik om beperkings op te lê aan simboliese waardes. Dit stel ons in staat om spesifieke voorwaardes te definieer wat die simboliese waardes moet bevredig. Byvoorbeeld, ons kan 'n beperking plaas op 'n simboliese BitVector om te sê dat dit nie 'n sekere waarde mag hê nie, of dat dit aan 'n sekere voorwaarde moet voldoen.

Deur simboliese BitVectors en beperkings te gebruik, kan ons komplekse probleme in reverse engineering oplos. Ons kan simboliese waardes manipuleer en beperkings plaas om die gewenste uitvoer te verkry. Hierdie tegniek is baie nuttig vir die analise van moeilike probleme waarvan die werklike waardes nie bekend is nie.
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

Hooking is 'n tegniek wat gebruik word in die veld van omgekeerde ingenieurswese om die gedrag van 'n program te verander deur die inspuiting van eksterne kode. Dit behels die oorheersing van die uitvoering van 'n program deur die invoeging van spesifieke funksies of instruksies wat uitgevoer word voordat of na die oorspronklike program se funksies of instruksies.

Daar is verskillende tipes hooking, insluitend:

- **Function Hooking**: Hierdie tipe hooking behels die oorheersing van 'n spesifieke funksie in 'n program deur die vervanging daarvan met 'n aangepaste funksie wat deur die aanvaller geskryf is. Dit stel die aanvaller in staat om die funksie se gedrag te verander of om data te onderskep voordat dit verwerk word.
- **API Hooking**: Hierdie tipe hooking behels die oorheersing van 'n spesifieke API (Application Programming Interface) wat deur 'n program gebruik word. Dit stel die aanvaller in staat om die data wat deur die API gestuur word te manipuleer of te onderskep.
- **Inline Hooking**: Hierdie tipe hooking behels die oorheersing van 'n spesifieke instruksie in 'n program deur dit te vervang met 'n spronginstruksie na 'n aangepaste funksie wat deur die aanvaller geskryf is. Dit stel die aanvaller in staat om die uitvoering van die program te beheer en spesifieke aksies uit te voer voordat of na die oorspronklike instruksie uitgevoer word.

Hooking is 'n kragtige tegniek wat deur omgekeerde ingenieurswese en kwaadwillige aanvallers gebruik kan word om die gedrag van 'n program te manipuleer. Dit kan gebruik word vir verskeie doeleindes, insluitend die onderskepping van data, die omseil van sekuriteitsmaatreëls en die uitvoering van kwaadwillige aksies.
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
Verder kan jy `proj.hook_symbol(name, hook)` gebruik, waar jy die naam van 'n simbool as die eerste argument verskaf, om die adres waar die simbool leef te koppel.

# Voorbeelde

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
