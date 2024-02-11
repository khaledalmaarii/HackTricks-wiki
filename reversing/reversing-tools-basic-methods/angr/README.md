<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

Sehemu ya karatasi hii ya kufanya udanganyifu imejengwa kwa msingi wa [hati ya angr](https://docs.angr.io/_/downloads/en/stable/pdf/).

# Usanidi
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Hatua za Msingi

## Introduction

In this section, we will cover some basic actions that can be performed using the angr framework. These actions include loading a binary, exploring its control flow, and analyzing its functions.

## Loading a Binary

To load a binary into an angr project, you can use the `angr.Project()` function. This function takes the path to the binary as an argument and returns a project object that represents the binary.

```python
import angr

# Load the binary
project = angr.Project('/path/to/binary')
```

## Exploring Control Flow

Once the binary is loaded, you can explore its control flow by creating a state object and stepping through the program. The `project.factory.entry_state()` function creates an initial state at the entry point of the binary.

```python
# Create an initial state
state = project.factory.entry_state()

# Step through the program
while True:
    # Perform symbolic execution
    successors = project.factory.successors(state)

    # Check if there are any successors
    if len(successors) == 0:
        break

    # Select the first successor
    state = successors[0].state
```

## Analyzing Functions

To analyze the functions in a binary, you can use the `project.kb.functions` attribute. This attribute contains a dictionary where the keys are the addresses of the functions and the values are `angr.knowledge_plugins.Function` objects.

```python
# Analyze the functions
for addr, func in project.kb.functions.items():
    # Print the address and name of the function
    print(f"Function: {hex(addr)} - {func.name}")
```

## Conclusion

These are some of the basic actions that can be performed using the angr framework. By loading a binary, exploring its control flow, and analyzing its functions, you can gain a better understanding of its behavior and potentially discover vulnerabilities or other interesting information.
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
# Data iliyopakiwa

The loaded data refers to the information that has been loaded into the memory during the execution of a program. This can include variables, functions, libraries, and other resources that are necessary for the program to run.

Data iliyopakiwa inahusu habari ambayo imepakiwa kwenye kumbukumbu wakati wa utekelezaji wa programu. Hii inaweza kujumuisha pembejeo, kazi, maktaba, na rasilimali zingine ambazo ni muhimu kwa programu kuendesha. 

## Main Object

The main object is the entry point of a program. It is the first object that is executed when the program starts running. The main object typically contains the main function, which is responsible for controlling the flow of the program.

Kipengele kikuu ni sehemu ya kuingia ya programu. Ni kipengele cha kwanza kinachotekelezwa wakati programu inaanza kukimbia. Kipengele kikuu kawaida kina kazi kuu, ambayo inahusika na kudhibiti mtiririko wa programu.
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
## Kusudi Kuu

The main objective of this document is to provide an introduction to the angr framework and its basic methods for reverse engineering. The angr framework is a powerful tool used for binary analysis and symbolic execution. By understanding the basic methods of angr, you will be able to effectively analyze and reverse engineer binary files. This document will cover the installation process of angr, as well as the basic usage of its key components such as the Project, State, and Explorer. Additionally, it will explain how to perform symbolic execution and solve constraints using angr. By the end of this document, you will have a solid understanding of the angr framework and its basic methods for reverse engineering.
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
## Ishara na Uhamishaji

Ishara na uhamishaji ni sehemu muhimu katika mchakato wa kurekebisha programu. Ishara ni alama za kipekee zinazowakilisha anwani za kumbukumbu au vitendo vya programu. Uhamishaji, kwa upande mwingine, ni mchakato wa kubadilisha anwani za kumbukumbu au vitendo vya programu ili kuzifanya ziwe sahihi kwa mazingira fulani.

Katika muktadha wa uharibifu, kuelewa ishara na uhamishaji ni muhimu kwa sababu inaweza kusaidia kubadilisha anwani za kumbukumbu au vitendo vya programu ili kufikia malengo ya uharibifu. Kwa mfano, unaweza kutumia uhamishaji ili kubadilisha anwani ya kumbukumbu ya kazi ya programu ili kufikia sehemu zilizohifadhiwa za kumbukumbu na kusababisha matokeo yasiyotarajiwa.

Kuna njia mbili za kufanya ishara na uhamishaji: ishara ya wakati wa kutekelezwa (runtime) na ishara ya wakati wa kubuni (compile-time). Ishara ya wakati wa kutekelezwa inahusisha kubadilisha anwani za kumbukumbu au vitendo vya programu wakati programu inatekelezwa. Ishara ya wakati wa kubuni, kwa upande mwingine, inahusisha kubadilisha anwani za kumbukumbu au vitendo vya programu wakati wa mchakato wa kubuni programu.

Kwa kufahamu ishara na uhamishaji, unaweza kuwa na uwezo wa kubadilisha programu kwa njia ambayo inafaa kwa malengo yako ya uharibifu. Hii inaweza kuhusisha kubadilisha anwani za kumbukumbu, kubadilisha vitendo vya programu, au hata kubadilisha njia ya kutekeleza programu.
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
## Vitengo

Blocks ni sehemu muhimu katika programu ya angr. Kwa kifupi, block ni kipande cha msimbo ambacho kinaweza kutekelezwa bila kuingiliwa. Kila block ina anwani ya kuanzia na anwani ya mwisho, na inaweza kuwa na maagizo kadhaa ya kutekelezwa.

Katika angr, unaweza kutumia Blocks kufanya uchambuzi wa msimbo na kufanya operesheni kama vile kutafuta njia za kufikia sehemu maalum ya msimbo, kuchunguza maagizo yaliyotekelezwa, na kugundua mifumo ya kudhibiti.

Kuna njia kadhaa za kupata Blocks katika angr. Moja ya njia hizo ni kutumia `project.factory.block()` ambapo unaweza kutoa anwani ya kuanzia ya block unayotaka kupata. Pia, unaweza kutumia `project.factory.simgr.explore()` ili kugundua Blocks zote zinazopatikana katika programu.

Kwa kifupi, Blocks ni sehemu muhimu katika uchambuzi wa msimbo na angr inatoa njia mbalimbali za kupata na kutumia Blocks hizo.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Meneja wa Uigaji, Hali

Meneja wa Uigaji ni kipengele muhimu katika zana ya angr ambayo inaruhusu uchambuzi wa kina wa programu. Inafanya kazi kwa kuchukua programu na kuigiza hali tofauti za kutekelezwa. Kwa kufanya hivyo, inawezesha uchunguzi wa tabia ya programu katika mazingira tofauti.

Meneja wa Uigaji hutumia hali za angr, ambazo ni maelezo ya hali ya kumbukumbu na hali ya usanidi wa programu wakati wa utekelezaji. Kwa kubadilisha hali hizi, meneja wa uigaji anaweza kuchunguza matokeo tofauti ya programu na kugundua maelezo muhimu kama vile maeneo ya kumbukumbu yanayobadilika na matokeo ya kawaida.

Kwa kutumia meneja wa uigaji, unaweza kufanya uchambuzi wa kina wa programu na kugundua maelezo muhimu ambayo yanaweza kusaidia katika kubaini kasoro au kufanya marekebisho ya programu.
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
## Kuita kazi

* Unaweza kupitisha orodha ya hoja kupitia `args` na kamusi ya mazingira kupitia `env` ndani ya `entry_state` na `full_init_state`. Thamani katika muundo huu inaweza kuwa herufi au bitvectors, na itaandikwa kwenye hali kama hoja na mazingira kwa utekelezaji ulioigwa. `args` ya chaguo-msingi ni orodha tupu, kwa hivyo ikiwa programu unayochambua inatarajia kupata angalau `argv[0]`, unapaswa kutoa hiyo kila wakati!
* Ikiwa ungependa kuwa na `argc` kuwa ishara, unaweza kupitisha bitvector ishara kama `argc` kwa waundaji wa `entry_state` na `full_init_state`. Lakini kuwa mwangalifu: ikiwa utafanya hivi, unapaswa pia kuongeza kizuizi kwenye hali inayopatikana kwamba thamani yako ya argc haiwezi kuwa kubwa kuliko idadi ya hoja uliyoipitisha kwenye `args`.
* Ili kutumia hali ya wito, unapaswa kuipiga na `.call_state(addr, arg1, arg2, ...)`, ambapo `addr` ni anwani ya kazi unayotaka kuita na `argN` ni hoja ya Nth kwa kazi hiyo, iwe kama nambari ya python, herufi, au safu, au bitvector. Ikiwa unataka kuwa na kumbukumbu iliyotengwa na kwa kweli upitishe kidole kwa kitu, unapaswa kuifunga kwenye PointerWrapper, yaani `angr.PointerWrapper("point to me!")`. Matokeo ya API hii yanaweza kuwa kidogo yasiyotabirika, lakini tunafanya kazi juu yake.

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Alama za BitVectors za Kihisabati na Vizuizi

Angr uses symbolic execution to analyze and understand the behavior of binary programs. One of the key components of symbolic execution is the use of symbolic BitVectors and constraints.

Angr represents program variables as symbolic BitVectors, which are essentially mathematical representations of binary data. These BitVectors can have a fixed size, such as 32 bits or 64 bits, and can be manipulated using various operations like addition, subtraction, and bitwise operations.

Constraints are logical expressions that define relationships between symbolic BitVectors. These expressions can include conditions like equality, inequality, and arithmetic operations. Constraints are used to model the program's behavior and to guide the symbolic execution process.

During symbolic execution, Angr collects constraints based on the program's control flow and the operations performed on symbolic BitVectors. These constraints are then solved using constraint solvers to determine the possible values of the symbolic BitVectors at different program points.

By analyzing the constraints and the possible values of symbolic BitVectors, Angr can reason about the program's behavior, identify vulnerabilities, and explore different execution paths.

Overall, symbolic BitVectors and constraints are fundamental concepts in Angr's symbolic execution engine, enabling powerful analysis and exploration of binary programs.
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
## Kufunga Kitanzi

Hooking ni mbinu ya kuingilia kati na kubadilisha tabia ya programu ili kufuatilia au kubadilisha data inayopita kupitia programu hiyo. Kwa kufunga kitanzi, tunaweza kuchunguza na kubadilisha matokeo ya programu bila kuhitaji kubadilisha msimbo wake wa asili.

Kuna aina mbili za kufunga kitanzi: kufunga kitanzi cha kuingilia na kufunga kitanzi cha kurejelea.

### Kufunga Kitanzi cha Kuingilia (Inline Hooking)

Kufunga kitanzi cha kuingilia kunahusisha kuingilia kati katika msimbo wa programu na kubadilisha sehemu fulani ya msimbo ili kufanya kitendo maalum. Hii inaweza kufanyika kwa kubadilisha maagizo ya kikusanyaji au kwa kuongeza maagizo mapya.

Kufunga kitanzi cha kuingilia kunaweza kutumika kwa madhumuni mbalimbali, kama vile kufuatilia matokeo ya programu, kurekodi shughuli za mtumiaji, au kubadilisha matokeo ya programu.

### Kufunga Kitanzi cha Kurejelea (API Hooking)

Kufunga kitanzi cha kurejelea kunahusisha kubadilisha kumbukumbu ya kurejelea ya programu ili kuelekeza wito wa kazi fulani kwa kazi nyingine. Hii inaruhusu kudhibiti jinsi programu inavyotumia kazi fulani na inaweza kutumika kwa madhumuni kama vile kufuatilia shughuli za mtumiaji au kurekodi matokeo ya programu.

Kufunga kitanzi cha kurejelea inaweza kufanywa kwa njia mbalimbali, kama vile kubadilisha kumbukumbu ya kurejelea moja kwa moja au kwa kutumia teknolojia kama vile DLL injection.

Kwa kufunga kitanzi, tunaweza kuchunguza na kubadilisha tabia ya programu kwa njia isiyo ya kawaida na yenye nguvu. Hii inaweza kuwa na manufaa katika uchunguzi wa usalama, upimaji wa programu, au kufanya mabadiliko maalum katika programu.
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
Zaidi ya hayo, unaweza kutumia `proj.hook_symbol(name, hook)` kwa kutoa jina la ishara kama hoja ya kwanza, ili kufunga anwani ambapo ishara inapatikana.

# Mifano

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
