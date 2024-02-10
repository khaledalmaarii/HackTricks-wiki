# Angr - 예제

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하세요.

</details>

{% hint style="info" %}
프로그램이 `scanf`를 사용하여 **stdin에서 한 번에 여러 값을 가져오는 경우**에는 **`scanf`** 이후에 시작하는 상태를 생성해야 합니다.
{% endhint %}

코드는 [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)에서 가져왔습니다.

### 주소에 도달하기 위한 입력 (주소를 나타냄)
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
### 주소에 도달하기 위한 입력 (출력을 나타냄)

The `angr` framework provides a powerful way to analyze and solve binary programs. One common use case is to find inputs that can reach a specific address in the program, which can be useful for understanding program behavior or finding vulnerabilities.

To achieve this, you can use the `angr` framework to create a symbolic execution path that starts from the program's entry point and explores different paths until it reaches the desired address. During the exploration, you can set constraints on the input variables to guide the symbolic execution towards the target address.

Here is an example of how to use `angr` to find inputs that can reach a specific address in a program:

```python
import angr

# Load the binary
project = angr.Project("/path/to/program")

# Set the desired address to reach
target_address = 0x12345678

# Create an initial state with symbolic input
initial_state = project.factory.entry_state()

# Create a simulation manager
simulation = project.factory.simgr(initial_state)

# Explore paths until the target address is reached
simulation.explore(find=target_address)

# Check if a path to the target address was found
if simulation.found:
    # Get the input that reaches the target address
    solution_state = simulation.found[0]
    solution_input = solution_state.posix.dumps(0)

    # Print the solution input
    print("Solution input:", solution_input)
else:
    print("No solution found")
```

In this example, we first load the binary program using `angr.Project()`. Then, we set the desired address to reach by assigning the target address to the `target_address` variable. We create an initial state with symbolic input using `project.factory.entry_state()`. Next, we create a simulation manager using `project.factory.simgr()` and pass the initial state to it.

We then use the `simulation.explore()` method to explore different paths until the target address is reached. The `find` parameter is set to the target address, indicating that we want to find a path that reaches this address.

After the exploration, we check if a path to the target address was found using `simulation.found`. If a path was found, we retrieve the solution state from `simulation.found[0]` and get the input that reaches the target address using `solution_state.posix.dumps(0)`. Finally, we print the solution input.

If no path to the target address is found, we simply print "No solution found".

By using `angr` in this way, you can efficiently find inputs that can reach a specific address in a binary program, which can be helpful for various reverse engineering and vulnerability analysis tasks.
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
### 레지스트리 값

The Windows Registry is a hierarchical database that stores configuration settings and options for the operating system and installed applications. It contains various keys and values that control the behavior of the system. In this section, we will explore some common registry values and their significance.

#### Default Value

The default value represents the initial value assigned to a registry key when it is created. It serves as a fallback option if no other value is specified.

#### String Value

A string value is a sequence of characters stored as a registry entry. It is commonly used to store textual information such as user names, file paths, or configuration settings.

#### Binary Value

A binary value is a sequence of bytes stored as a registry entry. It is often used to store binary data such as encryption keys or device driver settings.

#### DWORD Value

A DWORD (Double Word) value is a 32-bit integer stored as a registry entry. It is frequently used to store numerical data such as network settings or system configurations.

#### QWORD Value

A QWORD (Quad Word) value is a 64-bit integer stored as a registry entry. It is similar to the DWORD value but can store larger numerical values.

#### Expandable String Value

An expandable string value is a string that can contain variables or references to other environment variables. It allows for dynamic content within the registry.

#### Multi-String Value

A multi-string value is a sequence of strings stored as a registry entry. It is commonly used to store lists of values such as program paths or installed software.

Understanding these registry values is essential for analyzing and modifying the Windows Registry during the reverse engineering process.
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
### 스택 값

The stack is a data structure used in computer programming to store and manage variables and function calls. In the context of reverse engineering, understanding the values stored in the stack can be crucial for analyzing and manipulating a program.

스택은 컴퓨터 프로그래밍에서 변수와 함수 호출을 저장하고 관리하기 위해 사용되는 데이터 구조입니다. 역공학의 맥락에서 스택에 저장된 값들을 이해하는 것은 프로그램을 분석하고 조작하는 데 있어서 중요할 수 있습니다.
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
이 시나리오에서는 `scanf("%u %u")`를 사용하여 입력을 받았으며, 값 `"1 1"`이 주어졌으므로 스택의 값 **`0x00000001`**은 **사용자 입력**에서 가져온 것입니다. 이 값들이 `$ebp - 8`에서 시작되는 것을 볼 수 있습니다. 따라서 코드에서는 **`$esp`에서 8바이트를 뺀 다음 (그 순간 `$ebp`와 `$esp`가 동일한 값을 가지고 있었기 때문에)** BVS를 푸시했습니다.

![](<../../../.gitbook/assets/image (614).png>)

### 정적 메모리 값 (전역 변수)
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
### 동적 메모리 값 (Malloc)

angr은 동적 메모리 할당 함수인 `malloc`을 분석하는 데 사용될 수 있습니다. `malloc`은 프로그램에서 동적으로 메모리를 할당하는 데 사용되는 함수입니다. 이 함수를 분석하면 할당된 메모리 영역에 대한 정보를 얻을 수 있습니다.

다음은 `malloc` 함수를 분석하는 예제입니다.

```python
import angr

# 바이너리 파일을 로드합니다.
project = angr.Project("/path/to/binary")

# 초기 상태를 설정합니다.
state = project.factory.entry_state()

# 동적 메모리 할당 함수를 호출합니다.
malloc_addr = 0x12345678
size = 32
state.memory.store(malloc_addr, state.solver.BVV(size, 32))

# 메모리 할당을 시뮬레이션합니다.
simulation = project.factory.simgr(state)
simulation.explore()

# 할당된 메모리 영역에 대한 정보를 얻습니다.
memory = simulation.found[0].memory.load(malloc_addr, size)
print(memory)
```

위 예제에서는 `malloc` 함수를 호출하여 메모리를 할당하고, 할당된 메모리 영역에 대한 정보를 얻기 위해 `memory.load` 함수를 사용합니다. 이를 통해 할당된 메모리 영역의 값을 확인할 수 있습니다.
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
### 파일 시뮬레이션

파일 시뮬레이션은 angr을 사용하여 파일 시스템의 동작을 모델링하는 방법입니다. 이를 통해 프로그램이 파일을 어떻게 조작하는지 이해하고, 파일 조작에 따른 프로그램의 동작을 예측할 수 있습니다.

파일 시뮬레이션은 angr의 `SimFile` 객체를 사용하여 수행됩니다. 이 객체는 파일의 내용과 속성을 나타내는데 사용됩니다. 파일 시뮬레이션을 위해 다음과 같은 작업을 수행할 수 있습니다.

- 파일 생성: `SimFile` 객체를 사용하여 새 파일을 생성할 수 있습니다.
- 파일 열기: `SimFile` 객체를 사용하여 기존 파일을 열 수 있습니다.
- 파일 읽기: `SimFile` 객체의 `read` 메서드를 사용하여 파일에서 데이터를 읽을 수 있습니다.
- 파일 쓰기: `SimFile` 객체의 `write` 메서드를 사용하여 파일에 데이터를 쓸 수 있습니다.
- 파일 닫기: `SimFile` 객체의 `close` 메서드를 사용하여 파일을 닫을 수 있습니다.

파일 시뮬레이션을 통해 프로그램이 파일 조작에 따라 어떻게 동작하는지 분석할 수 있습니다. 이를 통해 취약점을 발견하거나 프로그램의 동작을 예측하는 데 도움이 될 수 있습니다.
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
심볼릭 파일에는 심볼릭 데이터와 병합된 상수 데이터가 포함될 수도 있다는 점을 유의하세요:
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

### 제약 조건 적용하기

{% hint style="info" %}
가끔은 16자 길이의 두 단어를 **문자별로** 비교하는 단순한 인간 작업은 **angr**에게 많은 비용이 들 수 있습니다. 왜냐하면 **지수적으로** 분기를 생성해야 하기 때문에 각 if문마다 1개의 분기를 생성합니다: `2^16`\
따라서, **angr가 이전 지점으로 돌아가도록 요청**하고 **수동으로 제약 조건을 설정하는 것이 더 쉽습니다** (실제로 어려운 부분이 이미 완료된 지점).
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
일부 시나리오에서는 유사한 상태를 병합하여 불필요한 분기를 제거하고 해결책을 찾기 위해 **veritesting**을 활성화할 수 있습니다: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
이러한 시나리오에서 할 수 있는 다른 방법은 angr에게 이해하기 쉬운 형태로 함수를 **hook**하는 것입니다.
{% endhint %}

### 시뮬레이션 매니저

일부 시뮬레이션 매니저는 다른 것보다 더 유용할 수 있습니다. 이전 예제에서는 많은 유용한 분기가 생성되어 문제가 발생했습니다. 여기에서는 **veritesting** 기법을 사용하여 이러한 분기를 병합하고 해결책을 찾을 수 있습니다.\
이 시뮬레이션 매니저는 다음과 같이 활성화할 수도 있습니다: `simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### 함수의 하나의 호출을 후킹/바이패스하기

In this example, we will use angr to hook or bypass a specific call to a function in a binary. 

이 예제에서는 angr을 사용하여 이진 파일에서 특정 함수의 호출을 후킹하거나 바이패스할 것입니다.

First, we need to create an angr project and load the binary:

먼저, angr 프로젝트를 생성하고 이진 파일을 로드해야 합니다.

```python
import angr

# Create an angr project
proj = angr.Project("/path/to/binary")

# Get the address of the function call to hook/bypass
call_addr = 0x12345678

# Set up the initial state
state = proj.factory.entry_state()

# Hook the function call
proj.hook(call_addr, your_hook_function)

# Explore the binary
simgr = proj.factory.simgr(state)
simgr.explore()
```

Next, we define the `your_hook_function` that will be called when the function call is reached:

다음으로, 함수 호출이 도달되었을 때 호출될 `your_hook_function`을 정의합니다.

```python
def your_hook_function(state):
    # Modify the state or perform any desired actions
    # before or after the function call
    pass
```

Inside the `your_hook_function`, you can modify the state or perform any desired actions before or after the function call.

`your_hook_function` 내부에서는 함수 호출 전후에 상태를 수정하거나 원하는 작업을 수행할 수 있습니다.

By hooking the function call, you can intercept the execution flow and modify the behavior of the binary.

함수 호출을 후킹함으로써 실행 흐름을 가로채고 이진 파일의 동작을 수정할 수 있습니다.
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
### 함수 후킹 / 시뮬레이션 프로시저

In some cases, you may want to modify the behavior of a specific function during the execution of a binary. This can be useful for various purposes, such as bypassing certain checks or altering the program's flow. One way to achieve this is by hooking the function using a technique called simprocedure.

시나리오에 따라서는 이진 파일의 실행 중에 특정 함수의 동작을 수정하고 싶을 수 있습니다. 이는 특정 검사를 우회하거나 프로그램의 흐름을 변경하는 등 다양한 목적으로 유용할 수 있습니다. 이를 위해 simprocedure라는 기술을 사용하여 함수를 후킹하는 방법이 있습니다.

Simprocedure is a feature provided by angr that allows you to replace the execution of a function with your own custom code. This can be done by creating a subclass of angr's SimProcedure class and overriding the relevant methods.

Simprocedure는 angr이 제공하는 기능으로, 함수의 실행을 사용자 정의 코드로 대체할 수 있습니다. 이를 위해 angr의 SimProcedure 클래스의 하위 클래스를 생성하고 관련 메서드를 재정의하는 방식으로 수행할 수 있습니다.

To hook a function using simprocedure, you need to follow these steps:

simprocedure를 사용하여 함수를 후킹하려면 다음 단계를 따라야 합니다:

1. Identify the function you want to hook. This can be done by analyzing the binary or using tools like IDA Pro or Ghidra.

1. 후킹하려는 함수를 식별합니다. 이는 이진 파일을 분석하거나 IDA Pro 또는 Ghidra와 같은 도구를 사용하여 수행할 수 있습니다.

2. Create a subclass of angr's SimProcedure class and override the relevant methods. The most commonly overridden method is `run()`, where you can define your custom code.

2. angr의 SimProcedure 클래스의 하위 클래스를 생성하고 관련 메서드를 재정의합니다. 가장 일반적으로 재정의하는 메서드는 `run()`이며, 여기에서 사용자 정의 코드를 정의할 수 있습니다.

3. Use angr's `hook_symbol()` method to replace the original function with your simprocedure. This method takes the name of the function and the simprocedure subclass as arguments.

3. angr의 `hook_symbol()` 메서드를 사용하여 원래 함수를 simprocedure로 대체합니다. 이 메서드는 함수의 이름과 simprocedure 하위 클래스를 인수로 사용합니다.

By hooking a function using simprocedure, you can modify its behavior to suit your needs without modifying the original binary. This can be a powerful technique for reverse engineering and vulnerability analysis.

simprocedure를 사용하여 함수를 후킹함으로써 원본 바이너리를 수정하지 않고도 원하는 대로 함수의 동작을 수정할 수 있습니다. 이는 리버스 엔지니어링과 취약점 분석에 유용한 기술일 수 있습니다.
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
### 여러 매개변수를 사용하여 scanf 시뮬레이션하기

To simulate the `scanf` function with several parameters, you can use the `angr` framework. The `angr` framework is a powerful binary analysis tool that allows you to perform symbolic execution and solve complex constraints.

Here is an example of how you can simulate `scanf` with multiple parameters using `angr`:

```python
import angr

# Create an angr project
project = angr.Project("/path/to/binary")

# Define the symbolic input variables
input1 = angr.claripy.BVS("input1", 8)
input2 = angr.claripy.BVS("input2", 8)

# Create a state with symbolic input
state = project.factory.entry_state(stdin=angr.SimFile(fd=0, content=input1+input2))

# Create a simulation manager
simgr = project.factory.simulation_manager(state)

# Explore the program's execution
simgr.explore(find=0xADDRESS_OF_SUCCESS, avoid=0xADDRESS_OF_FAILURE)

# Get the successful state
success_state = simgr.found[0]

# Get the concrete values of the symbolic inputs
concrete_input1 = success_state.solver.eval(input1)
concrete_input2 = success_state.solver.eval(input2)

# Print the concrete values
print("Input 1:", concrete_input1)
print("Input 2:", concrete_input2)
```

In this example, we create an `angr` project from the binary file. We define two symbolic input variables, `input1` and `input2`, using the `angr.claripy.BVS` function. We then create a state with symbolic input by passing the symbolic inputs to the `stdin` parameter of the `entry_state` function.

Next, we create a simulation manager and explore the program's execution using the `explore` function. We specify the addresses of the success and failure conditions using the `find` and `avoid` parameters.

Once the exploration is complete, we retrieve the successful state from the simulation manager. We can then use the `solver.eval` function to obtain the concrete values of the symbolic inputs.

Finally, we print the concrete values of `input1` and `input2`.

By simulating `scanf` with multiple parameters using `angr`, you can analyze and understand the behavior of the program without actually executing it. This can be useful for reverse engineering and vulnerability analysis purposes.
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
### 정적 바이너리

정적 바이너리는 실행 파일이 컴파일된 시점에서 모든 종속성을 포함하는 바이너리입니다. 이는 실행 파일이 다른 라이브러리나 외부 파일에 의존하지 않고 독립적으로 실행될 수 있음을 의미합니다. 정적 바이너리는 이식성이 높고, 실행 환경에 대한 의존성이 적으며, 보안 측면에서도 이점이 있습니다.

정적 바이너리를 분석하는 경우, 실행 파일의 내부 구조와 동작을 이해하는 데 도움이 되는 도구를 사용할 수 있습니다. 이러한 도구 중 하나가 angr입니다.

### angr을 사용한 정적 바이너리 분석

angr은 바이너리 분석 및 역공학 도구로, 정적 바이너리의 분석을 위해 사용될 수 있습니다. angr은 바이너리의 제어 흐름을 분석하고, 실행 경로를 탐색하며, 입력 조건을 찾아내는 등 다양한 분석 작업을 수행할 수 있습니다.

angr을 사용하여 정적 바이너리를 분석하는 기본적인 방법은 다음과 같습니다:

1. 바이너리를 로드하고, 분석할 프로젝트를 생성합니다.
2. 분석할 함수 또는 코드 블록을 식별합니다.
3. 분석 작업을 수행하기 위해 angr의 기능을 활용합니다. 예를 들어, 제어 흐름 분석, 실행 경로 탐색, 입력 조건 탐색 등을 수행할 수 있습니다.
4. 분석 결과를 확인하고, 원하는 정보를 추출합니다.

angr은 정적 바이너리 분석에 유용한 도구 중 하나이며, 다양한 분석 작업을 수행할 수 있습니다. 이를 통해 바이너리의 동작을 이해하고, 취약점을 찾거나 보안 강화를 위한 조치를 취할 수 있습니다.
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유해주세요.

</details>
