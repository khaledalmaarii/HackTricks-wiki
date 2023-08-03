<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 安装
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# 基本操作

## Load a Binary

## 加载二进制文件

To start using angr, you need to load a binary file. You can do this by using the `angr.Project` class and passing the path to the binary as a parameter. Angr will automatically analyze the binary and create a project object that you can use to perform various actions.

要开始使用angr，您需要加载一个二进制文件。您可以使用`angr.Project`类来完成这个操作，将二进制文件的路径作为参数传递给它。Anger将自动分析二进制文件并创建一个项目对象，您可以使用该对象执行各种操作。

```python
import angr

# Load the binary
project = angr.Project('/path/to/binary')
```

## Explore the Control Flow Graph (CFG)

## 探索控制流图（CFG）

The Control Flow Graph (CFG) represents the flow of execution of a program. Angr allows you to explore the CFG of a binary by using the `project.analyses.CFGFast()` method. This method will analyze the binary and create a CFG object that you can use to navigate through the different basic blocks and edges of the program.

控制流图（CFG）表示程序的执行流程。Anger允许您使用`project.analyses.CFGFast()`方法来探索二进制文件的CFG。该方法将分析二进制文件并创建一个CFG对象，您可以使用该对象来浏览程序的不同基本块和边。

```python
# Explore the CFG
cfg = project.analyses.CFGFast()
```

## Find Functions

## 查找函数

Angr provides a way to find functions in a binary by using the `project.kb.functions` attribute. This attribute contains a dictionary where the keys are the addresses of the functions and the values are the corresponding function objects.

Anger提供了一种在二进制文件中查找函数的方法，可以使用`project.kb.functions`属性。该属性包含一个字典，其中键是函数的地址，值是相应的函数对象。

```python
# Find functions
functions = project.kb.functions
```

## Symbolically Execute the Binary

## 对二进制文件进行符号执行

Symbolic execution is a technique used in reverse engineering to explore all possible paths of a program. Angr allows you to symbolically execute a binary by using the `project.factory.simulation_manager()` method. This method will create a simulation manager object that you can use to explore the different paths of the program.

符号执行是逆向工程中用于探索程序所有可能路径的一种技术。Anger允许您使用`project.factory.simulation_manager()`方法对二进制文件进行符号执行。该方法将创建一个模拟管理器对象，您可以使用该对象来探索程序的不同路径。

```python
# Symbolically execute the binary
sim_manager = project.factory.simulation_manager()
```

## Find Vulnerabilities

## 查找漏洞

Angr can be used to find vulnerabilities in a binary by analyzing its control flow and symbolic execution. By exploring the CFG and symbolically executing the binary, you can identify potential security flaws such as buffer overflows, format string vulnerabilities, and integer overflows.

通过分析控制流和符号执行，可以使用Anger查找二进制文件中的漏洞。通过探索CFG和符号执行二进制文件，您可以识别出潜在的安全漏洞，如缓冲区溢出、格式化字符串漏洞和整数溢出。

## Conclusion

## 结论

These are some of the basic actions you can perform with angr. By loading a binary, exploring the CFG, finding functions, symbolically executing the binary, and finding vulnerabilities, you can gain a deeper understanding of how a program works and identify potential security issues.

这些是您可以使用Anger执行的一些基本操作。通过加载二进制文件、探索CFG、查找函数、对二进制文件进行符号执行和查找漏洞，您可以更深入地了解程序的工作原理，并识别潜在的安全问题。
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
# 加载的数据

The loaded data refers to the information that has been loaded into the memory during the execution of a program. This can include variables, functions, libraries, and other resources that are necessary for the program to run.

加载的数据是指在程序执行过程中加载到内存中的信息。这可以包括变量、函数、库和其他程序运行所必需的资源。

## Main Object

The main object is the entry point of a program. It is the first object that is executed when the program starts running. In most programming languages, the main object is typically a function or a method that is called to begin the execution of the program.

主对象是程序的入口点。它是程序启动时首先执行的对象。在大多数编程语言中，主对象通常是一个函数或方法，用于开始执行程序。

## Information Extraction

Extracting information from the loaded data and the main object is an important step in reverse engineering and analysis. This information can provide insights into the program's functionality, structure, and behavior.

提取加载的数据和主对象中的信息是逆向工程和分析的重要步骤。这些信息可以提供有关程序功能、结构和行为的见解。

## Tools and Methods

There are various tools and methods available for extracting information from the loaded data and the main object. One popular tool is angr, which is a binary analysis framework that can be used for symbolic execution, concolic execution, and other analysis techniques.

工具和方法

有多种工具和方法可用于从加载的数据和主对象中提取信息。一个流行的工具是angr，它是一个二进制分析框架，可用于符号执行、混合执行和其他分析技术。

## Conclusion

Understanding the loaded data and the main object is crucial for reverse engineering and analysis. By extracting information from these sources, analysts can gain valuable insights into the inner workings of a program and uncover potential vulnerabilities or weaknesses.
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
## 主要目标

The main objective of the angr tool is to provide a framework for analyzing binary programs. It aims to automate the process of reverse engineering and vulnerability discovery. The tool is designed to be highly modular and extensible, allowing users to easily build their own analysis tools on top of it.

angr has several key features that make it a powerful tool for binary analysis:

- **Symbolic Execution**: angr can perform symbolic execution on binary programs, allowing it to explore all possible paths of execution and analyze the program's behavior without actually running it.

- **Binary Analysis**: angr can analyze binary programs to extract information such as control flow graphs, function calls, and data references. This information can be used to understand the program's structure and behavior.

- **Vulnerability Discovery**: angr can be used to discover vulnerabilities in binary programs by analyzing their behavior and identifying potential security flaws.

- **Exploit Generation**: angr can generate exploits for discovered vulnerabilities, allowing users to test the security of their programs and develop patches.

- **Integration with Other Tools**: angr can be easily integrated with other analysis tools, such as disassemblers and debuggers, to provide a comprehensive analysis environment.

Overall, angr is a powerful and flexible tool for binary analysis and reverse engineering, making it a valuable asset for security researchers and penetration testers.
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
## 符号和重定位

Symbols and relocations are important concepts in reverse engineering and binary analysis. They play a crucial role in understanding the structure and behavior of a binary executable.

符号和重定位是逆向工程和二进制分析中的重要概念。它们在理解二进制可执行文件的结构和行为方面起着关键作用。

### Symbols

### 符号

Symbols are names that are associated with specific addresses or data in a binary executable. They provide a way to refer to specific locations or variables within the binary. Symbols can include function names, variable names, and other identifiers.

符号是与二进制可执行文件中特定地址或数据相关联的名称。它们提供了一种引用二进制文件中特定位置或变量的方式。符号可以包括函数名、变量名和其他标识符。

Symbols are typically defined in the binary itself or in external symbol files. They are used by the compiler and linker to resolve references to functions and variables during the compilation and linking process.

符号通常在二进制文件本身或外部符号文件中定义。它们由编译器和链接器在编译和链接过程中用于解析对函数和变量的引用。

In reverse engineering, symbols can be extremely useful for understanding the code and identifying specific functions or variables. They can be used to navigate the binary, set breakpoints, and analyze the behavior of the program.

在逆向工程中，符号对于理解代码和识别特定函数或变量非常有用。它们可以用于导航二进制文件、设置断点和分析程序的行为。

### Relocations

### 重定位

Relocations are instructions or records in a binary executable that specify how to modify the binary's code or data to account for differences in memory layout between the compilation and execution environments.

重定位是二进制可执行文件中的指令或记录，用于指定如何修改二进制代码或数据以适应编译和执行环境之间的内存布局差异。

During the compilation process, the compiler generates machine code that assumes a specific memory layout. However, when the binary is loaded and executed, the actual memory layout may be different. Relocations provide a way to adjust the code or data to match the actual memory layout.

在编译过程中，编译器生成的机器代码假设特定的内存布局。然而，当二进制文件被加载和执行时，实际的内存布局可能会有所不同。重定位提供了一种调整代码或数据以匹配实际内存布局的方式。

Relocations are typically performed by the linker during the linking process. The linker resolves references to symbols and applies the necessary modifications to the binary's code and data.

重定位通常由链接器在链接过程中执行。链接器解析对符号的引用，并对二进制代码和数据应用必要的修改。

In reverse engineering, understanding relocations can help in analyzing how the binary's code and data are modified at runtime. This can be useful for understanding the behavior of the program and identifying potential vulnerabilities or weaknesses.

在逆向工程中，理解重定位可以帮助分析二进制代码和数据在运行时如何被修改。这对于理解程序的行为并识别潜在的漏洞或弱点非常有用。
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
## 块

Blocks are the basic units of code that angr analyzes. They represent a sequence of instructions that are executed together. Each block starts with an instruction that has a known address and ends with a branch instruction that transfers control to another block.

块是angr分析的代码的基本单元。它们代表一系列一起执行的指令。每个块以一个具有已知地址的指令开始，并以一个分支指令结束，将控制转移到另一个块。
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# 动态分析

## 模拟管理器，状态

The simulation manager is a key component of the angr framework. It is responsible for managing the execution of the binary and keeping track of the program's state.

模拟管理器是angr框架的一个关键组件。它负责管理二进制文件的执行并跟踪程序的状态。

The simulation manager uses a technique called symbolic execution to explore all possible paths of execution in the binary. It starts with an initial state and explores different paths by making symbolic choices at each branch instruction.

模拟管理器使用一种称为符号执行的技术来探索二进制文件中的所有可能执行路径。它从一个初始状态开始，并通过在每个分支指令处进行符号选择来探索不同的路径。

Each state in the simulation manager represents a different execution path. It contains information about the program's memory, registers, and other runtime data.

模拟管理器中的每个状态表示不同的执行路径。它包含有关程序的内存、寄存器和其他运行时数据的信息。

The simulation manager can create new states by forking existing states. This allows it to explore multiple paths simultaneously.

模拟管理器可以通过分叉现有状态来创建新状态。这使得它能够同时探索多条路径。

By analyzing the states generated by the simulation manager, we can gain insights into the behavior of the binary and identify vulnerabilities or interesting code paths.

通过分析模拟管理器生成的状态，我们可以了解二进制文件的行为，并识别出漏洞或有趣的代码路径。
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
## 调用函数

* 你可以通过`args`传递参数列表，通过`env`传递环境变量字典到`entry_state`和`full_init_state`中。这些结构中的值可以是字符串或位向量，并且将被序列化为状态的参数和环境，用于模拟执行。默认的`args`是一个空列表，所以如果你分析的程序期望至少找到一个`argv[0]`，你应该总是提供它！
* 如果你想让`argc`是符号的，你可以将一个符号位向量作为`argc`传递给`entry_state`和`full_init_state`构造函数。不过要小心：如果你这样做了，你还应该在结果状态中添加一个约束，即你的argc的值不能大于你传递给`args`的参数数量。
* 要使用调用状态，你应该使用`.call_state(addr, arg1, arg2, ...)`来调用它，其中`addr`是你想要调用的函数的地址，`argN`是该函数的第N个参数，可以是Python整数、字符串、数组或位向量。如果你想要分配内存并实际传递一个指向对象的指针，你应该将它包装在一个PointerWrapper中，即`angr.PointerWrapper("point to me!")`。这个API的结果可能有点不可预测，但我们正在努力改进。


## 位向量
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## 符号位向量和约束

The symbolic execution engine of angr represents program states using symbolic bitvectors. A symbolic bitvector is a representation of a value that can take on multiple possible concrete values. These symbolic bitvectors can be used to model program variables, memory locations, and other program state elements.

angr uses constraints to reason about the possible values that symbolic bitvectors can take on. Constraints are logical expressions that define relationships between symbolic bitvectors. For example, a constraint might state that two symbolic bitvectors must be equal, or that a symbolic bitvector must be less than a certain value.

By using symbolic bitvectors and constraints, angr can perform powerful operations such as symbolic execution and symbolic taint analysis. Symbolic execution allows angr to explore all possible paths through a program, even those that are difficult or impossible to reach through traditional concrete execution. Symbolic taint analysis allows angr to track the flow of tainted data through a program, which can be useful for identifying potential security vulnerabilities.

Overall, symbolic bitvectors and constraints are fundamental concepts in angr that enable advanced program analysis and manipulation techniques. By leveraging these concepts, angr can provide powerful capabilities for reverse engineering, vulnerability discovery, and other security-related tasks.
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

Hooking（钩子）是一种在软件中插入自定义代码的技术，用于修改或扩展软件的行为。通过使用钩子，我们可以拦截和修改应用程序的函数调用、消息传递或事件处理等操作。

### 静态钩子

静态钩子是在程序加载时直接修改函数指针或跳转指令的地址，从而将控制权转移到我们自定义的代码中。这种钩子通常用于修改函数的行为或监视特定的操作。

### 动态钩子

动态钩子是在运行时通过修改内存中的函数指针或跳转指令的地址来实现的。与静态钩子不同，动态钩子可以在程序运行时动态地插入和移除，从而更灵活地控制程序的行为。

### API 钩子

API 钩子是一种特殊类型的钩子，用于拦截和修改应用程序与操作系统或其他应用程序之间的 API 调用。通过使用 API 钩子，我们可以监视和修改应用程序与外部资源的交互，从而实现各种功能，如日志记录、调试和安全增强。

### 内核钩子

内核钩子是在操作系统内核级别实现的钩子。这种钩子可以拦截和修改操作系统的核心功能，如文件系统、网络通信和进程管理等。内核钩子通常用于实现安全增强、行为监控和恶意代码检测等功能。

### 钩子的应用

钩子技术在软件开发、调试、安全研究和恶意代码分析等领域都有广泛的应用。通过使用钩子，我们可以修改软件的行为、监视和记录关键操作、实现调试和逆向工程等任务。然而，钩子技术也可能被恶意用户或恶意软件滥用，因此在使用钩子时需要谨慎并遵守法律和道德规范。
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
此外，您可以使用`proj.hook_symbol(name, hook)`，将符号的名称作为第一个参数提供，以钩住符号所在的地址。

# 示例

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
