# Angr - 示例

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

{% hint style="info" %}
如果程序使用 \*\*`scanf` \*\* 从 stdin 中**一次获取多个值**，你需要生成一个在 **`scanf`** 之后开始的状态。
{% endhint %}

### 输入以到达地址（指示地址）
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
### 输入以到达地址（指示打印）
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
### 注册表值

Registry values, also known as keys, are a fundamental component of the Windows operating system. They store configuration settings and other important information that is used by the system and various applications. Understanding how to work with registry values is essential for many hacking and reverse engineering tasks.

注册表值，也被称为键，是Windows操作系统的基本组成部分。它们存储系统和各种应用程序使用的配置设置和其他重要信息。了解如何处理注册表值对于许多黑客和逆向工程任务至关重要。
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
### 栈值

The stack is a data structure used in computer programming to store and manage variables and function calls. In the context of reverse engineering, understanding the values stored in the stack can be crucial for analyzing and manipulating a program.

栈是计算机编程中用于存储和管理变量和函数调用的数据结构。在逆向工程的背景下，理解存储在栈中的值对于分析和操作程序至关重要。

When a function is called, its local variables and function arguments are typically stored on the stack. As the function executes, it pushes and pops values onto and from the stack.

当调用函数时，其局部变量和函数参数通常存储在栈上。随着函数的执行，它会将值推入栈上或从栈上弹出。

To analyze the stack values, you can use tools like angr. Angr is a powerful binary analysis framework that allows you to explore and manipulate programs at the binary level.

要分析栈值，可以使用诸如 angr 的工具。angr 是一个强大的二进制分析框架，可以让您在二进制级别上探索和操作程序。

With angr, you can load a binary and simulate its execution. This allows you to track the values stored in the stack as the program runs.

使用 angr，您可以加载一个二进制文件并模拟其执行。这样，您就可以在程序运行时跟踪存储在栈中的值。

By analyzing the stack values, you can gain insights into how the program works and potentially identify vulnerabilities or areas of interest for further analysis.

通过分析栈值，您可以深入了解程序的工作原理，并可能识别出漏洞或进一步分析的感兴趣的领域。
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
在这种情况下，输入是使用`scanf("%u %u")`获取的，并且给出了值`"1 1"`，因此栈上的值**`0x00000001`**来自**用户输入**。您可以看到这些值从`$ebp - 8`开始。因此，在代码中，我们**从`$esp`减去了8个字节（因为在那个时刻`$ebp`和`$esp`具有相同的值）**，然后我们推入了BVS。

![](<../../../.gitbook/assets/image (614).png>)

### 静态内存值（全局变量）
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
### 动态内存值（Malloc）

When analyzing a binary, it is often necessary to understand the values stored in dynamically allocated memory. The `malloc` function is commonly used in C programs to allocate memory dynamically. By analyzing the memory values returned by `malloc`, we can gain insights into how the program works and potentially discover vulnerabilities.

To analyze the dynamic memory values, we can use the angr framework. Angr provides a powerful symbolic execution engine that allows us to explore the program's execution path and track the values of memory locations.

To start, we need to create an angr project for the binary we want to analyze. We can do this by specifying the path to the binary file:

```python
import angr

project = angr.Project('/path/to/binary')
```

Next, we can use the `factory` method provided by angr to create a state representing the program's initial state:

```python
state = project.factory.entry_state()
```

We can then use the `state.memory` object to access the memory and track the values stored in dynamically allocated memory. For example, if we want to track the value stored at address `0x804a000`, we can do the following:

```python
value = state.memory.load(0x804a000, 4)
```

In this example, we are loading a 4-byte value from the address `0x804a000`. The `load` method returns a symbolic expression representing the value stored at the specified address.

We can also track the values stored in dynamically allocated memory regions. For example, if we want to track the values stored in a dynamically allocated buffer of size 32, we can do the following:

```python
buffer_address = state.solver.BVS('buffer', 32 * 8)
state.memory.store(buffer_address, state.solver.BVV(0, 32 * 8))
```

In this example, we are creating a symbolic variable `buffer` representing the address of the dynamically allocated buffer. We then use the `store` method to store a symbolic expression representing the value `0` at the specified address.

By tracking the values stored in dynamically allocated memory, we can gain a deeper understanding of the program's behavior and potentially identify vulnerabilities such as buffer overflows or use-after-free bugs.
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
### 文件模拟

The `angr` framework provides a powerful feature called file simulation, which allows you to analyze the behavior of a program when interacting with files. This feature is particularly useful when reverse engineering or analyzing malware that heavily relies on file operations.

To simulate file operations, `angr` provides the `SimFile` class, which represents a file object. You can create a `SimFile` object by specifying the file path, mode, and other attributes. Once you have created the `SimFile` object, you can use it to perform various file operations such as reading, writing, seeking, and closing.

Here is an example that demonstrates how to use file simulation in `angr`:

```python
import angr

# Create a SimFile object
file_path = "/path/to/file"
file_mode = "r"
file_size = 1024
file_data = b"file contents"
file_obj = angr.SimFile(file_path, file_mode, size=file_size, content=file_data)

# Open the file in the program under analysis
proj = angr.Project("/path/to/program")
state = proj.factory.entry_state(stdin=file_obj)

# Perform file operations
file_obj.seek(0)
file_obj.read(10)
file_obj.write(b"new contents")
file_obj.close()

# Explore the program's behavior
simgr = proj.factory.simgr(state)
simgr.explore()

# Print the final state of the file
final_file_obj = simgr.found[0].posix.stdin
print(final_file_obj.content)
```

In this example, we create a `SimFile` object representing a file with a specified path, mode, size, and content. We then open the program under analysis with the `SimFile` object as the input. We perform various file operations on the `SimFile` object and explore the program's behavior using `angr`'s symbolic execution engine. Finally, we print the content of the file after the program has finished executing.

File simulation in `angr` allows you to gain insights into how a program interacts with files, which can be valuable for understanding its behavior and identifying potential vulnerabilities or malicious activities.
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
请注意，符号文件中还可以包含与符号数据合并的常量数据：
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

### 应用约束条件

{% hint style="info" %}
有时候，像逐个字符比较两个长度为16的单词这样的简单人类操作，对于angr来说代价很大，因为它需要指数级地生成分支，因为它每个if生成一个分支：`2^16`\
因此，更容易让angr回到之前的一个点（在那里已经完成了真正困难的部分），然后手动设置这些约束条件。
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
在某些情况下，您可以激活**veritesting**，它将合并相似的状态，以节省无用的分支并找到解决方案：`simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
在这些情况下，您可以通过**hook函数**来给angr提供更容易理解的内容。
{% endhint %}

### 模拟管理器

某些模拟管理器比其他管理器更有用。在前面的示例中，存在一个问题，即创建了许多有用的分支。在这里，**veritesting**技术将合并这些分支并找到解决方案。\
可以使用以下方式激活此模拟管理器：`simulation = project.factory.simgr(initial_state, veritesting=True)`
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
### 钩住/绕过对函数的一次调用

In this example, we will use angr to hook and bypass a specific call to a function in a binary. The goal is to modify the behavior of the program by redirecting the call to a different function or skipping it altogether.

```python
import angr

# Load the binary
project = angr.Project("/path/to/binary")

# Define the address of the function to hook
function_address = 0x12345678

# Create a blank state
state = project.factory.blank_state()

# Set the program counter to the address of the function to hook
state.regs.pc = function_address

# Create a SimProcedure to replace the hooked function
class HookedFunction(angr.SimProcedure):
    def run(self):
        # Modify the behavior of the function here
        # ...

# Hook the function by replacing it with the SimProcedure
project.hook(function_address, HookedFunction())

# Create a simulation manager with the initial state
simgr = project.factory.simulation_manager(state)

# Explore the program's execution paths
simgr.explore()

# Get the state where the call to the function is bypassed
bypassed_state = simgr.deadended[0]

# Print the program's output
print(bypassed_state.posix.dumps(1))
```

在这个例子中，我们将使用 angr 来钩住并绕过二进制文件中对特定函数的一次调用。目标是通过重定向调用到另一个函数或完全跳过它来修改程序的行为。

```python
import angr

# 加载二进制文件
project = angr.Project("/path/to/binary")

# 定义要钩住的函数的地址
function_address = 0x12345678

# 创建一个空白状态
state = project.factory.blank_state()

# 将程序计数器设置为要钩住的函数的地址
state.regs.pc = function_address

# 创建一个 SimProcedure 来替换被钩住的函数
class HookedFunction(angr.SimProcedure):
    def run(self):
        # 在这里修改函数的行为
        # ...

# 通过 SimProcedure 来钩住函数
project.hook(function_address, HookedFunction())

# 使用初始状态创建一个模拟管理器
simgr = project.factory.simulation_manager(state)

# 探索程序的执行路径
simgr.explore()

# 获取绕过函数调用的状态
bypassed_state = simgr.deadended[0]

# 打印程序的输出
print(bypassed_state.posix.dumps(1))
```
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
### 钩住一个函数 / Simprocedure

In some cases, you may want to modify the behavior of a specific function during the execution of a binary. This can be achieved using a technique called function hooking. Function hooking allows you to intercept the execution of a function and replace it with your own custom code.

In angr, function hooking is implemented using a feature called simprocedures. A simprocedure is a user-defined function that can be used to replace the behavior of a specific function. When angr encounters a function call, it checks if there is a simprocedure defined for that function. If a simprocedure is found, angr will execute the simprocedure instead of the original function.

To hook a function using a simprocedure, you need to define a new class that inherits from the `SimProcedure` class provided by angr. This class should override the `run()` method, which will be called when the function is executed. Inside the `run()` method, you can define the custom behavior that you want to replace the original function with.

Here is an example of how to hook the `printf()` function using a simprocedure in angr:

```python
from angr import SimProcedure

class HookedPrintf(SimProcedure):
    def run(self, fmt, *args):
        # Custom code to replace printf()
        # ...

# Hook the printf() function
proj.hook_symbol('printf', HookedPrintf())
```

In this example, we define a new class called `HookedPrintf` that inherits from `SimProcedure`. We override the `run()` method to define our custom behavior for the `printf()` function. Finally, we use the `hook_symbol()` method to hook the `printf()` function with our simprocedure.

By hooking a function using a simprocedure, you can modify its behavior to suit your needs during the execution of a binary. This technique is particularly useful for analyzing and manipulating the output of functions, as well as for bypassing certain checks or restrictions imposed by the original function.
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
### 使用多个参数模拟scanf函数

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

In this example, we create an `angr` project from the binary file. We then define two symbolic input variables, `input1` and `input2`, using the `angr.claripy.BVS` function. We create a state with symbolic input by passing the symbolic inputs to the `stdin` parameter of the `entry_state` function.

Next, we create a simulation manager and explore the program's execution using the `explore` function. We specify the addresses of the success and failure conditions using the `find` and `avoid` parameters.

Once the exploration is complete, we retrieve the successful state from the `found` list of the simulation manager. We can then use the `solver.eval` function to obtain the concrete values of the symbolic inputs.

Finally, we print the concrete values of `input1` and `input2`.

By simulating `scanf` with multiple parameters using `angr`, you can analyze and understand the behavior of the program without actually executing it.
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
### 静态二进制文件

Static binaries are executable files that are compiled to include all the necessary libraries and dependencies within the binary itself. This means that the binary can be run on any system without requiring the installation of additional libraries or dependencies.

静态二进制文件是编译后的可执行文件，它包含了所有必要的库和依赖项。这意味着该二进制文件可以在任何系统上运行，而无需安装额外的库或依赖项。

Static binaries are commonly used in situations where portability and ease of deployment are important. They can be particularly useful in scenarios where the target system may not have internet access or where the installation of additional software is not feasible.

静态二进制文件通常在需要可移植性和部署便利性的情况下使用。它们在目标系统可能没有互联网访问权限或无法安装额外软件的情况下特别有用。

When analyzing static binaries, it is important to understand that all the necessary code and libraries are contained within the binary itself. This means that any vulnerabilities or weaknesses in the included libraries can potentially be exploited by an attacker.

在分析静态二进制文件时，重要的是要理解所有必要的代码和库都包含在二进制文件本身中。这意味着包含的库中的任何漏洞或弱点都有可能被攻击者利用。

Static binaries can be analyzed using various reverse engineering techniques and tools, such as disassemblers and debuggers, to understand their functionality and identify any potential security issues.

可以使用各种逆向工程技术和工具（如反汇编器和调试器）来分析静态二进制文件，以了解其功能并识别任何潜在的安全问题。
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
