<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출하세요.**

</details>

이 치트시트의 일부는 [angr 문서](https://docs.angr.io/_/downloads/en/stable/pdf/)를 기반으로 합니다.

# 설치
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# 기본 동작

## Load a Binary

## 바이너리 로드

To start using angr, you need to load a binary. This can be done using the `angr.Project` class. The `angr.Project` class takes the path to the binary as an argument and returns a `Project` object that represents the binary.

angr을 사용하기 위해서는 바이너리를 로드해야 합니다. 이는 `angr.Project` 클래스를 사용하여 수행할 수 있습니다. `angr.Project` 클래스는 바이너리의 경로를 인자로 받고, 바이너리를 나타내는 `Project` 객체를 반환합니다.

```python
import angr

# Load the binary
project = angr.Project("/path/to/binary")
```

## Analyze the Binary

## 바이너리 분석

Once you have loaded the binary, you can perform various analysis tasks on it. Some of the basic analysis tasks include:

바이너리를 로드한 후에는 다양한 분석 작업을 수행할 수 있습니다. 일부 기본 분석 작업은 다음과 같습니다:

### Symbolic Execution

### 심볼릭 실행

Symbolic execution is a technique used to explore all possible paths of a program by replacing concrete values with symbolic values. This allows you to reason about the program's behavior without actually executing it. To perform symbolic execution in angr, you can use the `project.factory.simulation_manager()` method.

심볼릭 실행은 구체적인 값을 심볼릭 값으로 대체하여 프로그램의 모든 가능한 경로를 탐색하는 기술입니다. 이를 통해 프로그램의 동작에 대해 실행하지 않고 추론할 수 있습니다. angr에서 심볼릭 실행을 수행하려면 `project.factory.simulation_manager()` 메서드를 사용할 수 있습니다.

```python
# Perform symbolic execution
simgr = project.factory.simulation_manager()
```

### Control Flow Graph (CFG) Generation

### 제어 흐름 그래프 (CFG) 생성

The control flow graph (CFG) is a representation of all possible paths that a program can take during its execution. It shows the flow of control between basic blocks in the program. To generate the CFG of a binary in angr, you can use the `project.analyses.CFG()` method.

제어 흐름 그래프 (CFG)는 프로그램이 실행되는 동안 프로그램이 취할 수 있는 모든 경로를 나타내는 표현입니다. 이는 프로그램의 기본 블록 간의 제어 흐름을 보여줍니다. angr에서 바이너리의 CFG를 생성하려면 `project.analyses.CFG()` 메서드를 사용할 수 있습니다.

```python
# Generate the CFG
cfg = project.analyses.CFG()
```

### Function Identification

### 함수 식별

Identifying functions in a binary is an important step in reverse engineering. It allows you to understand the structure of the program and the relationships between different parts of the code. To identify functions in a binary using angr, you can use the `project.kb.functions` attribute.

바이너리에서 함수를 식별하는 것은 리버스 엔지니어링에서 중요한 단계입니다. 이를 통해 프로그램의 구조와 코드의 다른 부분 간의 관계를 이해할 수 있습니다. angr을 사용하여 바이너리에서 함수를 식별하려면 `project.kb.functions` 속성을 사용할 수 있습니다.

```python
# Identify functions
functions = project.kb.functions
```

## Explore the Binary

## 바이너리 탐색

Once you have performed the initial analysis tasks, you can start exploring the binary further. Some of the basic exploration tasks include:

초기 분석 작업을 수행한 후에는 바이너리를 더 탐색할 수 있습니다. 일부 기본 탐색 작업은 다음과 같습니다:

### State Exploration

### 상태 탐색

State exploration involves exploring the different states that a program can be in during its execution. This includes exploring different paths, inputs, and outputs of the program. To explore states in angr, you can use the `simgr.explore()` method.

상태 탐색은 프로그램이 실행되는 동안 프로그램이 가질 수 있는 다른 상태를 탐색하는 것을 의미합니다. 이는 프로그램의 다른 경로, 입력 및 출력을 탐색하는 것을 포함합니다. angr에서 상태를 탐색하려면 `simgr.explore()` 메서드를 사용할 수 있습니다.

```python
# Explore states
simgr.explore()
```

### Path Exploration

### 경로 탐색

Path exploration involves exploring the different paths that a program can take during its execution. This includes exploring different branches, loops, and function calls in the program. To explore paths in angr, you can use the `simgr.step()` method.

경로 탐색은 프로그램이 실행되는 동안 프로그램이 취할 수 있는 다른 경로를 탐색하는 것을 의미합니다. 이는 프로그램의 다른 분기, 반복문 및 함수 호출을 탐색하는 것을 포함합니다. angr에서 경로를 탐색하려면 `simgr.step()` 메서드를 사용할 수 있습니다.

```python
# Explore paths
simgr.step()
```

### Constraint Solving

### 제약 해결

Constraint solving involves solving constraints that are encountered during the execution of a program. Constraints can be used to model conditions that must be satisfied for a certain behavior to occur. To solve constraints in angr, you can use the `simgr.active[0].solver` attribute.

제약 해결은 프로그램 실행 중에 발견되는 제약 조건을 해결하는 것을 의미합니다. 제약 조건은 특정 동작이 발생하기 위해 만족해야 하는 조건을 모델링하는 데 사용될 수 있습니다. angr에서 제약 조건을 해결하려면 `simgr.active[0].solver` 속성을 사용할 수 있습니다.

```python
# Solve constraints
solver = simgr.active[0].solver
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
# 로드된 데이터

When analyzing a binary file, it is important to understand the loaded data. This includes information about the sections and segments that are loaded into memory when the binary is executed.

### Sections

Sections are portions of the binary file that contain specific types of data, such as code, data, or resources. Each section has a name and a virtual address, which represents the memory location where the section is loaded.

### Segments

Segments are collections of sections that are loaded together into memory. They define the memory layout of the binary file. Each segment has a virtual address and a size, which determine where the segment is loaded and how much memory it occupies.

## Main Object

The main object is the entry point of the binary file. It is the first code that is executed when the binary is run. The main object contains information about the program's execution flow and is responsible for initializing the program's environment.

Understanding the loaded data and the main object is crucial for reverse engineering and analyzing binary files. It allows us to identify important sections and segments, as well as understand the program's execution flow.
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
## 주요 목표

The main objective of this document is to provide an introduction to the angr framework and its basic methods for binary analysis and reverse engineering. The angr framework is a powerful tool that can be used to analyze and manipulate binary files, such as executables, libraries, and firmware.

이 문서의 주요 목표는 angr 프레임워크와 이를 사용한 이진 분석 및 역공학의 기본적인 방법을 소개하는 것입니다. angr 프레임워크는 실행 파일, 라이브러리, 펌웨어와 같은 이진 파일을 분석하고 조작하는 데 사용할 수 있는 강력한 도구입니다.

## Introduction to angr

angr is a powerful binary analysis framework that allows you to analyze and manipulate binary files. It provides a wide range of features and tools for reverse engineering, including symbolic execution, concolic execution, and binary lifting.

angr는 이진 파일을 분석하고 조작할 수 있는 강력한 이진 분석 프레임워크입니다. 심볼릭 실행, 콘콜릭 실행, 이진 리프팅을 포함한 다양한 기능과 도구를 제공합니다.

## Basic Methods

### Loading a Binary

To start analyzing a binary with angr, you first need to load the binary into an angr project. This can be done using the `angr.Project()` method, which takes the path to the binary as an argument.

```python
import angr

binary_path = "/path/to/binary"
project = angr.Project(binary_path)
```

### Exploring the Control Flow Graph (CFG)

The Control Flow Graph (CFG) is a representation of the program's control flow. It shows the possible paths that the program can take during execution. You can generate the CFG of a binary using the `project.analyses.CFG()` method.

```python
cfg = project.analyses.CFG()
```

### Symbolic Execution

Symbolic execution is a technique used to explore all possible paths of a program by replacing concrete values with symbolic variables. This allows you to reason about the program's behavior without actually executing it. You can perform symbolic execution on a binary using the `project.factory.simulation_manager()` method.

```python
simgr = project.factory.simulation_manager()
simgr.explore()
```

### Finding Vulnerabilities

Once you have performed symbolic execution, you can use angr's analysis capabilities to find vulnerabilities in the binary. For example, you can use the `project.analyses.VulnerabilityAnalysis()` method to search for common vulnerability patterns.

```python
vuln_analysis = project.analyses.VulnerabilityAnalysis()
vuln_analysis.run()
```

### Patching Binaries

angr also provides methods for patching binaries. You can use the `project.loader` object to modify the binary's memory, registers, and other properties.

```python
project.loader.memory.write_bytes(address, data)
project.loader.registers.store(register, value)
```

## Conclusion

This document has provided an overview of the angr framework and its basic methods for binary analysis and reverse engineering. By using angr, you can effectively analyze and manipulate binary files to uncover vulnerabilities and understand their behavior.
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
## 심볼과 재배치

Symbols and relocations are important concepts in reverse engineering and binary analysis. They play a crucial role in understanding the structure and behavior of a binary executable.

심볼과 재배치는 리버스 엔지니어링과 이진 분석에서 중요한 개념입니다. 이들은 이진 실행 파일의 구조와 동작을 이해하는 데 핵심적인 역할을 합니다.

### Symbols

심볼은 코드나 데이터의 주소를 나타내는 이름입니다. 이는 함수, 변수, 상수 등과 같은 프로그램의 요소를 식별하는 데 사용됩니다. 심볼은 이진 파일의 심볼 테이블에 저장되어 있으며, 이를 통해 프로그램의 구조를 파악할 수 있습니다.

### Relocations

재배치는 이진 파일이 메모리에 로드될 때 주소를 조정하는 과정입니다. 이는 이진 파일이 다른 주소로 로드될 때 심볼과의 연결을 유지하기 위해 필요합니다. 재배치 정보는 이진 파일의 재배치 테이블에 저장되어 있으며, 이를 통해 이진 파일이 올바른 주소로 로드될 수 있습니다.

### Symbol Resolution

심볼 해결은 이진 파일의 심볼과 실제 주소 간의 매핑을 의미합니다. 이는 프로그램이 실행될 때 동적으로 수행되며, 심볼 해결기(symbol resolver)가 이를 담당합니다. 심볼 해결은 프로그램의 실행 흐름을 추적하고, 심볼에 해당하는 주소를 찾아내는 데 사용됩니다.

### Symbolic Execution and Relocation

심볼릭 실행과 재배치는 이진 파일을 분석하는 데 유용한 기술입니다. 심볼릭 실행은 프로그램의 입력을 심볼로 대체하여 실행 경로를 탐색하는 것을 의미하며, 재배치는 이러한 실행 경로를 실제 주소로 변환하는 과정을 말합니다. 이러한 기술을 사용하면 이진 파일의 동작을 이해하고 취약점을 찾을 수 있습니다.
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
## 블록

A block is a basic unit of code in the angr framework. It represents a sequence of instructions that are executed sequentially. Each block starts with an instruction and ends with a branch instruction or a return instruction. Blocks are the building blocks of the control flow graph (CFG) in angr.

In angr, blocks are represented by the `Block` class. Each block has a unique address, a list of instructions, and a set of successors and predecessors. The address of a block is the address of its first instruction.

To create a block in angr, you can use the `Block` class constructor and pass the address and instructions as arguments. You can also add successors and predecessors to a block using the `add_successor()` and `add_predecessor()` methods.

Once you have created a block, you can access its address, instructions, successors, and predecessors using the corresponding attributes of the `Block` class.

Blocks are an essential concept in reverse engineering and program analysis. They allow you to analyze the control flow of a program and understand how instructions are executed. By working with blocks, you can perform various tasks such as finding vulnerabilities, identifying loops, and analyzing program behavior.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# 동적 분석

## 시뮬레이션 매니저, 상태

시뮬레이션 매니저는 angr의 핵심 기능 중 하나로, 프로그램의 동적 분석을 위해 사용됩니다. 시뮬레이션 매니저는 프로그램의 상태를 추적하고, 다양한 상황에서 프로그램의 실행 경로를 조작할 수 있습니다.

상태는 프로그램의 실행 상태를 나타내며, 메모리, 레지스터, 스택 등의 정보를 포함합니다. 시뮬레이션 매니저는 여러 개의 상태를 관리하며, 각 상태는 프로그램의 특정 실행 경로를 나타냅니다.

시뮬레이션 매니저를 사용하여 프로그램을 실행하면, 프로그램의 동작을 시뮬레이션하고 분석할 수 있습니다. 이를 통해 프로그램의 동작을 이해하고, 취약점을 찾거나 보안 문제를 해결할 수 있습니다.
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
## 함수 호출

* `args`를 통해 인수 목록을 전달하고 `env`를 통해 환경 변수의 사전을 `entry_state`와 `full_init_state`에 전달할 수 있습니다. 이러한 구조체의 값은 문자열 또는 비트벡터가 될 수 있으며, 실행 시뮬레이션의 인수 및 환경으로 상태에 직렬화됩니다. 기본 `args`는 빈 목록이므로 분석 중인 프로그램이 적어도 `argv[0]`을 찾을 것으로 예상되는 경우 항상 제공해야 합니다!
* `argc`를 심볼릭하게 사용하려면 `entry_state`와 `full_init_state` 생성자에 심볼릭 비트벡터로 `argc`를 전달할 수 있습니다. 그러나 주의해야 할 점은 `args`에 전달한 인수의 수보다 argc 값이 크지 않도록 결과 상태에 제약 조건을 추가해야 한다는 것입니다.
* 호출 상태를 사용하려면 `.call_state(addr, arg1, arg2, ...)`와 같이 호출해야 합니다. 여기서 `addr`은 호출하려는 함수의 주소이고 `argN`은 해당 함수의 N번째 인수입니다. 이는 파이썬 정수, 문자열 또는 배열 또는 비트벡터로 표현될 수 있습니다. 메모리를 할당하고 실제로 객체에 대한 포인터를 전달하려면 PointerWrapper로 래핑해야 합니다. 즉, `angr.PointerWrapper("point to me!")`입니다. 이 API의 결과는 예측하기 어려울 수 있지만, 이에 대해 작업 중입니다.

## 비트벡터
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## 심볼릭 비트벡터 및 제약 조건

Angr uses symbolic execution to analyze and understand binary programs. One of the key components of symbolic execution is the use of symbolic bitvectors and constraints.

Symbolic bitvectors are representations of binary data that can take on multiple values simultaneously. Unlike concrete bitvectors, which have fixed values, symbolic bitvectors can represent unknown or variable values. This allows angr to reason about the program's behavior in a more abstract and flexible manner.

Constraints, on the other hand, are logical expressions that define relationships between symbolic bitvectors. These expressions can be used to model conditions and constraints within the program. Angr uses constraints to guide the symbolic execution and explore different paths through the program.

By combining symbolic bitvectors and constraints, angr can perform powerful operations such as solving equations, finding inputs that satisfy certain conditions, and exploring different program paths. This enables angr to analyze and understand the behavior of binary programs in a dynamic and flexible way.

Overall, symbolic bitvectors and constraints are fundamental concepts in angr's symbolic execution engine. They provide the foundation for reasoning about binary programs and enable angr to perform advanced analysis and exploration.
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
## 후킹

Hooking은 소프트웨어나 하드웨어의 동작을 변경하거나 감시하기 위해 사용되는 기술입니다. 후킹은 주로 디버깅, 모니터링, 프로파일링, 악성 코드 탐지 등 다양한 목적으로 사용됩니다. 후킹은 주로 다음과 같은 방법으로 구현됩니다.

### 함수 후킹

함수 후킹은 프로그램이 특정 함수를 호출할 때 해당 함수의 동작을 변경하거나 감시하는 것을 의미합니다. 이를 통해 함수의 인자, 반환 값, 호출 시간 등을 추적하거나 수정할 수 있습니다. 함수 후킹은 주로 디버깅, 프로파일링, 악성 코드 탐지 등에 사용됩니다.

### API 후킹

API 후킹은 운영 체제나 프레임워크에서 제공하는 API 함수의 동작을 변경하거나 감시하는 것을 의미합니다. 이를 통해 악성 코드의 실행을 방지하거나 모니터링할 수 있습니다. API 후킹은 주로 보안 솔루션, 디버깅 도구, 시스템 모니터링 등에 사용됩니다.

### 메모리 후킹

메모리 후킹은 프로그램이 메모리를 읽거나 쓸 때 해당 동작을 변경하거나 감시하는 것을 의미합니다. 이를 통해 메모리 액세스를 모니터링하거나 수정할 수 있습니다. 메모리 후킹은 주로 디버깅, 악성 코드 탐지, 메모리 보호 등에 사용됩니다.

### 네트워크 후킹

네트워크 후킹은 네트워크 트래픽을 감시하거나 수정하는 것을 의미합니다. 이를 통해 네트워크 통신을 모니터링하거나 악성 트래픽을 차단할 수 있습니다. 네트워크 후킹은 주로 침입 탐지 시스템, 패킷 분석 도구, 보안 솔루션 등에 사용됩니다.

### 이벤트 후킹

이벤트 후킹은 운영 체제나 응용 프로그램에서 발생하는 이벤트를 감지하거나 수정하는 것을 의미합니다. 이를 통해 응용 프로그램의 동작을 변경하거나 감시할 수 있습니다. 이벤트 후킹은 주로 자동화 도구, UI 테스팅, 시스템 모니터링 등에 사용됩니다.

후킹은 다양한 분야에서 유용하게 활용되는 기술이지만, 악용될 수도 있으므로 신중하게 사용해야 합니다.
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
또한, `proj.hook_symbol(name, hook)`을 사용하여 심볼의 이름을 첫 번째 인수로 제공하여 심볼이 있는 주소를 후킹할 수 있습니다.

# 예제

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
