# Rust 基础知识

### 泛型类型

创建一个结构体，其中一个值可以是任意类型的。
```rust
struct Wrapper<T> {
value: T,
}

impl<T> Wrapper<T> {
pub fn new(value: T) -> Self {
Wrapper { value }
}
}

Wrapper::new(42).value
Wrapper::new("Foo").value, "Foo"
```
### Option, Some & None

Option类型表示值可能是Some类型（表示有值）或None类型（表示没有值）：
```rust
pub enum Option<T> {
None,
Some(T),
}
```
你可以使用`is_some()`或`is_none()`等函数来检查Option的值。

### 宏

宏比函数更强大，因为它们会扩展生成比手动编写的代码更多的代码。例如，函数签名必须声明函数的参数数量和类型。而宏可以接受可变数量的参数：我们可以用一个参数调用`println!("hello")`，或者用两个参数调用`println!("hello {}", name)`。此外，宏在编译器解释代码的含义之前进行扩展，因此宏可以在给定类型上实现trait。而函数则不行，因为函数在运行时被调用，而trait需要在编译时实现。
```rust
macro_rules! my_macro {
() => {
println!("Check out my macro!");
};
($val:expr) => {
println!("Look at this other macro: {}", $val);
}
}
fn main() {
my_macro!();
my_macro!(7777);
}

// Export a macro from a module
mod macros {
#[macro_export]
macro_rules! my_macro {
() => {
println!("Check out my macro!");
};
}
}
```
### 迭代

在编程中，迭代是指重复执行一段代码的过程。在Rust中，有几种方法可以进行迭代。

#### 使用`for`循环进行迭代

`for`循环是一种方便的迭代方法，可以用于遍历集合中的每个元素。以下是一个示例：

```rust
let numbers = vec![1, 2, 3, 4, 5];

for number in numbers {
    println!("Number: {}", number);
}
```

#### 使用`while`循环进行迭代

`while`循环是另一种常用的迭代方法，可以在满足特定条件时重复执行代码块。以下是一个示例：

```rust
let mut count = 0;

while count < 5 {
    println!("Count: {}", count);
    count += 1;
}
```

#### 使用`loop`循环进行迭代

`loop`循环是一种无限循环，可以在满足特定条件时终止。以下是一个示例：

```rust
let mut count = 0;

loop {
    println!("Count: {}", count);
    count += 1;

    if count >= 5 {
        break;
    }
}
```

#### 使用迭代器进行迭代

迭代器是一种特殊的对象，可以用于遍历集合中的元素。Rust提供了多种迭代器方法，如`iter`、`iter_mut`和`into_iter`。以下是一个示例：

```rust
let numbers = vec![1, 2, 3, 4, 5];

for number in numbers.iter() {
    println!("Number: {}", number);
}
```

这些是在Rust中进行迭代的基本方法。根据具体的需求，选择适合的迭代方法来处理数据。
```rust
// Iterate through a vector
let my_fav_fruits = vec!["banana", "raspberry"];
let mut my_iterable_fav_fruits = my_fav_fruits.iter();
assert_eq!(my_iterable_fav_fruits.next(), Some(&"banana"));
assert_eq!(my_iterable_fav_fruits.next(), Some(&"raspberry"));
assert_eq!(my_iterable_fav_fruits.next(), None); // When it's over, it's none

// One line iteration with action
my_fav_fruits.iter().map(|x| capitalize_first(x)).collect()

// Hashmap iteration
for (key, hashvalue) in &*map {
for key in map.keys() {
for value in map.values() {
```
### 递归盒子

A recursive box is a technique used in Rust programming to create self-referential data structures. It involves using the `Box` type to allocate memory on the heap and create a recursive relationship between objects.

一个递归盒子是 Rust 编程中用来创建自引用数据结构的一种技术。它使用 `Box` 类型在堆上分配内存，并在对象之间创建递归关系。

To understand how a recursive box works, let's consider an example of a binary tree. In a binary tree, each node has two child nodes, which can also be binary trees themselves. This creates a recursive structure.

为了理解递归盒子的工作原理，让我们考虑一个二叉树的例子。在二叉树中，每个节点都有两个子节点，这些子节点本身也可以是二叉树。这样就创建了一个递归结构。

In Rust, we can represent a binary tree using a struct that contains two `Option<Box<Node>>` fields for the left and right child nodes. The `Box` type allows us to allocate the child nodes on the heap and create a recursive relationship.

在 Rust 中，我们可以使用一个包含左右子节点的 `Option<Box<Node>>` 字段的结构体来表示二叉树。`Box` 类型允许我们在堆上分配子节点，并创建递归关系。

Here's an example implementation of a binary tree using recursive boxes:

下面是使用递归盒子实现二叉树的示例：

```rust
struct Node {
    value: i32,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

fn main() {
    let root = Node {
        value: 1,
        left: Some(Box::new(Node {
            value: 2,
            left: None,
            right: None,
        })),
        right: Some(Box::new(Node {
            value: 3,
            left: None,
            right: None,
        })),
    };
}
```

In this example, each `Node` struct contains two `Option<Box<Node>>` fields for the left and right child nodes. The `Box::new` function is used to allocate memory on the heap and create a `Box<Node>` object.

在这个例子中，每个 `Node` 结构体都包含了左右子节点的 `Option<Box<Node>>` 字段。`Box::new` 函数用于在堆上分配内存并创建一个 `Box<Node>` 对象。

By using recursive boxes, we can create complex data structures with self-referential relationships in Rust. This technique is particularly useful when dealing with data structures like linked lists, trees, and graphs.

通过使用递归盒子，我们可以在 Rust 中创建具有自引用关系的复杂数据结构。这种技术在处理链表、树和图等数据结构时特别有用。
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### 条件语句

#### if

The `if` statement is used to execute a block of code only if a certain condition is true. It has the following syntax:

```rust
if condition {
    // code to be executed if the condition is true
}
```

If the condition is true, the code inside the block will be executed. If the condition is false, the code will be skipped.

Example:

```rust
fn main() {
    let number = 5;

    if number < 10 {
        println!("The number is less than 10");
    }
}
```

In this example, the code inside the `if` block will be executed because the condition `number < 10` is true. The output will be `The number is less than 10`.
```rust
let n = 5;
if n < 0 {
print!("{} is negative", n);
} else if n > 0 {
print!("{} is positive", n);
} else {
print!("{} is zero", n);
}
```
#### 匹配

The `match` expression in Rust is used to compare a value against a series of patterns and execute the corresponding code block for the first matching pattern. It is similar to a switch statement in other programming languages.

在Rust中，`match`表达式用于将一个值与一系列模式进行比较，并执行与第一个匹配模式对应的代码块。它类似于其他编程语言中的switch语句。

```rust
match value {
    pattern1 => {
        // code block for pattern1
    },
    pattern2 => {
        // code block for pattern2
    },
    // more patterns...
    _ => {
        // code block for default case
    }
}
```

The `value` is compared against each pattern in the order they are defined. If a pattern matches the value, the corresponding code block is executed. If none of the patterns match, the code block for the default case (denoted by `_`) is executed.

`value`会按照定义的顺序与每个模式进行比较。如果某个模式与该值匹配，将执行相应的代码块。如果没有任何模式匹配，将执行默认情况下的代码块（用`_`表示）。

The `match` expression is exhaustive, meaning that all possible cases must be handled. If a pattern is missing, the code will not compile.

`match`表达式是穷尽的，意味着必须处理所有可能的情况。如果缺少某个模式，代码将无法编译通过。

```rust
let number = 5;

match number {
    1 => println!("One"),
    2 => println!("Two"),
    _ => println!("Other")
}
```

In this example, if `number` is `1`, it will print "One". If `number` is `2`, it will print "Two". For any other value of `number`, it will print "Other".
```rust
match number {
// Match a single value
1 => println!("One!"),
// Match several values
2 | 3 | 5 | 7 | 11 => println!("This is a prime"),
// TODO ^ Try adding 13 to the list of prime values
// Match an inclusive range
13..=19 => println!("A teen"),
// Handle the rest of cases
_ => println!("Ain't special"),
}

let boolean = true;
// Match is an expression too
let binary = match boolean {
// The arms of a match must cover all the possible values
false => 0,
true => 1,
// TODO ^ Try commenting out one of these arms
};
```
#### 循环（无限循环）

An infinite loop is a loop that continues indefinitely without a condition to terminate it. It is often used in programming to create processes that run continuously until they are manually stopped or an external event occurs.

In Rust, you can create an infinite loop using the `loop` keyword. The `loop` keyword starts an infinite loop that can only be terminated by using the `break` keyword.

Here is an example of an infinite loop in Rust:

```rust
loop {
    // Code to be executed repeatedly
    // ...
    // Terminate the loop conditionally using the `break` keyword
    if condition {
        break;
    }
}
```

In this example, the code inside the loop will be executed repeatedly until the `condition` is true. Once the `condition` is true, the loop will be terminated using the `break` keyword.

It is important to note that an infinite loop can potentially cause your program to hang or consume excessive resources if not used carefully. Therefore, it is recommended to include a condition or an exit mechanism to prevent unintended consequences.
```rust
loop {
count += 1;
if count == 3 {
println!("three");
continue;
}
println!("{}", count);
if count == 5 {
println!("OK, that's enough");
break;
}
}
```
#### while

`while` 是一种循环结构，它允许您重复执行一段代码，直到指定的条件不再满足为止。

以下是 `while` 循环的语法：

```rust
while condition {
    // code to be executed
}
```

在每次循环迭代中，首先会检查 `condition` 是否为真。如果为真，则执行循环体中的代码。然后再次检查 `condition`，如果仍然为真，则继续执行循环体中的代码。这个过程会一直重复，直到 `condition` 不再为真为止。

以下是一个示例，演示了如何使用 `while` 循环计算 1 到 10 的和：

```rust
fn main() {
    let mut sum = 0;
    let mut i = 1;

    while i <= 10 {
        sum += i;
        i += 1;
    }

    println!("Sum: {}", sum);
}
```

在上面的示例中，我们使用 `while` 循环计算了 1 到 10 的和，并将结果打印出来。在每次循环迭代中，我们将当前的 `i` 值加到 `sum` 中，并将 `i` 的值增加 1。循环将一直执行，直到 `i` 的值大于 10。最后，我们打印出计算得到的和。

`while` 循环非常有用，可以用于处理需要重复执行的任务，直到满足特定条件为止。
```rust
let mut n = 1;
while n < 101 {
if n % 15 == 0 {
println!("fizzbuzz");
} else if n % 5 == 0 {
println!("buzz");
} else {
println!("{}", n);
}
n += 1;
}
```
#### 对于
```rust
for n in 1..101 {
if n % 15 == 0 {
println!("fizzbuzz");
} else {
println!("{}", n);
}
}

// Use "..=" to make inclusive both ends
for n in 1..=100 {
if n % 15 == 0 {
println!("fizzbuzz");
} else if n % 3 == 0 {
println!("fizz");
} else if n % 5 == 0 {
println!("buzz");
} else {
println!("{}", n);
}
}

// ITERATIONS

let names = vec!["Bob", "Frank", "Ferris"];
//iter - Doesn't consume the collection
for name in names.iter() {
match name {
&"Ferris" => println!("There is a rustacean among us!"),
_ => println!("Hello {}", name),
}
}
//into_iter - COnsumes the collection
for name in names.into_iter() {
match name {
"Ferris" => println!("There is a rustacean among us!"),
_ => println!("Hello {}", name),
}
}
//iter_mut - This mutably borrows each element of the collection
for name in names.iter_mut() {
*name = match name {
&mut "Ferris" => "There is a rustacean among us!",
_ => "Hello",
}
}
```
#### 如果 let

`if let` 是 Rust 中的一种条件表达式，用于匹配和解构一个值，并在匹配成功时执行相应的代码块。

```rust
if let Some(value) = some_option {
    // 在 some_option 是 Some(value) 的情况下执行代码
} else {
    // 在 some_option 是 None 的情况下执行代码
}
```

`if let` 语法允许我们检查一个值是否与模式匹配，并且只在匹配成功时执行代码。如果匹配失败，可以选择执行一个备用的代码块。

`if let` 语句的模式可以是任何合法的模式，例如 `Some(value)`、`Ok(value)` 或者自定义的结构体模式。

`if let` 语句的主要优势是它可以简化代码，避免了使用 `match` 表达式时需要编写冗长的模式匹配代码。
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

The `while let` statement in Rust is a shorthand way of writing a loop that continues as long as a pattern matches. It is commonly used when working with `Option` or `Result` types.

Here is the syntax for the `while let` statement:

```rust
while let pattern = expression {
    // code to execute while the pattern matches
}
```

The `pattern` is a pattern that is matched against the value of the `expression`. If the pattern matches, the code block inside the loop is executed. If the pattern does not match, the loop is exited.

Here is an example of using `while let` with an `Option` type:

```rust
let mut stack = vec![1, 2, 3];

while let Some(top) = stack.pop() {
    println!("Popped value: {}", top);
}
```

In this example, the `while let` loop continues as long as the `stack.pop()` method returns `Some` value. The `top` variable is bound to the value inside the `Some` variant, and the code block inside the loop prints the popped value.

The `while let` statement can also be used with `Result` types:

```rust
fn do_something() -> Result<(), String> {
    // code that may return a Result
}

while let Ok(_) = do_something() {
    // code to execute if the Result is Ok
}
```

In this example, the `while let` loop continues as long as the `do_something()` function returns an `Ok` variant. The underscore `_` is used as a placeholder for the value inside the `Ok` variant, as it is not needed in this case.

The `while let` statement provides a concise way of handling patterns in a loop, making the code more readable and expressive.
```rust
let mut optional = Some(0);
// This reads: "while `let` destructures `optional` into
// `Some(i)`, evaluate the block (`{}`). Else `break`.
while let Some(i) = optional {
if i > 9 {
println!("Greater than 9, quit!");
optional = None;
} else {
println!("`i` is `{:?}`. Try again.", i);
optional = Some(i + 1);
}
// ^ Less rightward drift and doesn't require
// explicitly handling the failing case.
}
```
### 特质

为类型创建一个新的方法

```rust
trait MyTrait {
    fn my_method(&self);
}

struct MyStruct;

impl MyTrait for MyStruct {
    fn my_method(&self) {
        println!("Hello, world!");
    }
}

fn main() {
    let my_struct = MyStruct;
    my_struct.my_method();
}
```

在Rust中，特质（Traits）是一种定义方法的方式，可以为类型添加新的行为。要为类型创建一个新的方法，首先需要定义一个特质。在上面的例子中，我们定义了一个名为`MyTrait`的特质，并为其添加了一个名为`my_method`的方法。

接下来，我们创建了一个名为`MyStruct`的结构体，并使用`impl`关键字为其实现了`MyTrait`特质。在`impl`块中，我们实现了`my_method`方法，该方法打印出"Hello, world!"。

最后，在`main`函数中，我们创建了一个`MyStruct`类型的实例`my_struct`，并调用了`my_method`方法。运行程序时，将输出"Hello, world!"。
```rust
trait AppendBar {
fn append_bar(self) -> Self;
}

impl AppendBar for String {
fn append_bar(self) -> Self{
format!("{}Bar", self)
}
}

let s = String::from("Foo");
let s = s.append_bar();
println!("s: {}", s);
```
### 测试

Tests are an essential part of software development. They help ensure that the code functions as expected and can catch any bugs or errors before they reach production. In Rust, tests are written using the built-in testing framework called `test`. 

测试是软件开发的重要组成部分。它们有助于确保代码按预期工作，并能在进入生产环境之前捕获任何错误或漏洞。在Rust中，测试是使用内置的测试框架`test`编写的。

To write tests in Rust, you need to create a separate module for tests within your code file. This module should be annotated with `#[cfg(test)]` to indicate that it contains tests. Inside the test module, you can write individual test functions using the `#[test]` attribute. 

要在Rust中编写测试，您需要在代码文件中创建一个单独的模块来存放测试。该模块应该用`#[cfg(test)]`进行注释，以表示它包含测试。在测试模块内部，您可以使用`#[test]`属性编写单独的测试函数。

Test functions should have a descriptive name and should use assertions to check the expected behavior of the code. Rust provides various assertion macros, such as `assert_eq!` and `assert_ne!`, which can be used to compare values. 

测试函数应具有描述性的名称，并应使用断言来检查代码的预期行为。Rust提供了各种断言宏，例如`assert_eq!`和`assert_ne!`，可用于比较值。

To run the tests, you can use the `cargo test` command. This command will automatically discover and execute all the test functions in your code. It will provide a summary of the test results, indicating whether each test passed or failed. 

要运行测试，您可以使用`cargo test`命令。该命令将自动发现并执行代码中的所有测试函数。它将提供测试结果的摘要，指示每个测试是否通过或失败。

Writing tests and running them regularly can help ensure the stability and correctness of your code. It is a good practice to write tests for all the important functionalities of your software. 

编写测试并定期运行它们可以帮助确保代码的稳定性和正确性。为软件的所有重要功能编写测试是一种良好的实践。
```rust
#[cfg(test)]
mod tests {
#[test]
fn you_can_assert() {
assert!(true);
assert_eq!(true, true);
assert_ne!(true, false);
}
}
```
### 线程

#### Arc

Arc可以使用Clone来创建更多的引用，以便将它们传递给线程。当最后一个引用指向一个值的指针超出作用域时，变量将被丢弃。
```rust
use std::sync::Arc;
let apple = Arc::new("the same apple");
for _ in 0..10 {
let apple = Arc::clone(&apple);
thread::spawn(move || {
println!("{:?}", apple);
});
}
```
#### 线程

在这种情况下，我们将传递给线程一个变量，它将能够修改它。
```rust
fn main() {
let status = Arc::new(Mutex::new(JobStatus { jobs_completed: 0 }));
let status_shared = Arc::clone(&status);
thread::spawn(move || {
for _ in 0..10 {
thread::sleep(Duration::from_millis(250));
let mut status = status_shared.lock().unwrap();
status.jobs_completed += 1;
}
});
while status.lock().unwrap().jobs_completed < 10 {
println!("waiting... ");
thread::sleep(Duration::from_millis(500));
}
}
```

