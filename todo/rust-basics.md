# Rust 기초

### 제네릭 타입

어떤 값이든지 될 수 있는 struct를 생성하세요.
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

Option 타입은 값이 Some (무언가가 있는 경우) 또는 None일 수 있다는 것을 의미합니다:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
옵션의 값을 확인하기 위해 `is_some()` 또는 `is_none()`과 같은 함수를 사용할 수 있습니다.

### 매크로

매크로는 함수보다 강력합니다. 왜냐하면 매크로는 수동으로 작성한 코드보다 더 많은 코드를 생성하기 때문입니다. 예를 들어, 함수 시그니처는 함수가 가지는 매개변수의 수와 유형을 선언해야 합니다. 반면에 매크로는 가변 개수의 매개변수를 사용할 수 있습니다. 예를 들어, `println!("hello")`를 하나의 인수로 호출하거나 `println!("hello {}", name)`을 두 개의 인수로 호출할 수 있습니다. 또한, 매크로는 컴파일러가 코드의 의미를 해석하기 전에 확장되므로 매크로는 주어진 유형에 대해 특성을 구현할 수 있습니다. 함수는 불가능합니다. 왜냐하면 함수는 런타임에서 호출되고 특성은 컴파일 타임에 구현되어야 하기 때문입니다.
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
### 반복하기

Rust에서는 반복 작업을 수행하기 위해 다양한 방법을 제공합니다. 이러한 방법 중 일부는 다음과 같습니다.

#### 1. `for` 루프

`for` 루프는 컬렉션의 각 요소에 대해 반복 작업을 수행하는 데 사용됩니다. 다음은 `for` 루프의 기본 구문입니다.

```rust
for element in collection {
    // 반복 작업 수행
}
```

#### 2. `while` 루프

`while` 루프는 조건이 참인 동안 반복 작업을 수행하는 데 사용됩니다. 다음은 `while` 루프의 기본 구문입니다.

```rust
while condition {
    // 반복 작업 수행
}
```

#### 3. `loop` 루프

`loop` 루프는 조건이 참일 때까지 무한히 반복 작업을 수행하는 데 사용됩니다. 다음은 `loop` 루프의 기본 구문입니다.

```rust
loop {
    // 반복 작업 수행
    if condition {
        break; // 루프 종료
    }
}
```

#### 4. `Iterator` trait

`Iterator` trait은 컬렉션의 요소를 반복하는 데 사용되는 메서드를 정의합니다. `Iterator` trait을 구현한 컬렉션은 `for` 루프와 함께 사용할 수 있습니다. 다음은 `Iterator` trait을 사용하여 반복 작업을 수행하는 예입니다.

```rust
let collection = vec![1, 2, 3, 4, 5];
let mut iterator = collection.iter();

while let Some(element) = iterator.next() {
    // 반복 작업 수행
}
```

Rust에서는 이 외에도 다양한 반복 작업을 수행하는 방법이 있습니다. 이러한 방법을 사용하여 효율적이고 간결한 코드를 작성할 수 있습니다.
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
### 재귀적인 박스

A recursive box is a data structure that contains a reference to itself. This means that the box can be nested within another box of the same type. This concept is often used in programming languages like Rust to create recursive data structures.

In Rust, the `Box<T>` type is used to allocate memory on the heap and store values of type `T`. By using `Box<T>`, we can create a recursive box by defining a struct that contains a `Box<Self>` field. The `Self` keyword refers to the current type, allowing us to create a recursive reference.

Here's an example of how to define a recursive box in Rust:

```rust
struct Node {
    value: i32,
    next: Option<Box<Node>>,
}
```

In this example, the `Node` struct contains a `value` field of type `i32` and a `next` field of type `Option<Box<Node>>`. The `next` field is an `Option` type because it can be `None` to indicate the end of the recursive chain.

To create a recursive box, we can use the `Box::new` function to allocate memory on the heap and create a new `Node` instance. We can then assign the `next` field to another `Box<Node>` to create the recursive reference.

```rust
let node1 = Box::new(Node {
    value: 1,
    next: Some(Box::new(Node {
        value: 2,
        next: None,
    })),
});
```

In this example, `node1` is a recursive box that contains two nodes. The first node has a value of `1` and a `next` field that points to the second node. The second node has a value of `2` and a `next` field that is `None`, indicating the end of the recursive chain.

Recursive boxes are useful for representing recursive data structures like linked lists, trees, and graphs. They allow us to create complex data structures that can be traversed and manipulated recursively.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### if

만약 조건이 참이면, `if` 문은 특정 코드 블록을 실행합니다.

```rust
if 조건 {
    // 코드 블록
}
```

`조건`은 참 또는 거짓으로 평가되는 표현식입니다. 만약 `조건`이 참이면, 코드 블록이 실행됩니다. 그렇지 않으면, 코드 블록은 건너뛰고 다음 코드가 실행됩니다.

```rust
let number = 5;

if number < 10 {
    println!("숫자는 10보다 작습니다.");
}
```

위의 예제에서, `number` 변수의 값은 5입니다. `number < 10` 조건은 참이므로, `println!` 매크로가 실행되어 "숫자는 10보다 작습니다."라는 메시지가 출력됩니다.
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
#### 매치

`match` 키워드는 Rust에서 패턴 매칭을 수행하는 데 사용됩니다. 이는 다른 언어의 `switch` 문과 유사한 기능을 제공합니다. `match` 표현식은 값을 패턴과 비교하고 해당하는 패턴에 따라 다른 코드 블록을 실행합니다.

```rust
match value {
    pattern1 => {
        // code block 1
    },
    pattern2 => {
        // code block 2
    },
    // ...
    _ => {
        // default code block
    }
}
```

위의 예제에서 `value`는 비교할 값이고, `pattern1`, `pattern2` 등은 패턴입니다. 패턴은 값과 일치하는지 여부를 확인하기 위해 사용됩니다. `_`는 와일드카드 패턴으로, 어떤 값과도 일치합니다. `_` 패턴은 일치하는 패턴이 없을 때 실행되는 기본 코드 블록을 정의하는 데 사용됩니다.

`match` 표현식은 패턴 매칭을 통해 코드를 더 명확하고 간결하게 작성할 수 있도록 도와줍니다. 이를 통해 여러 가지 경우에 따라 다른 동작을 수행할 수 있습니다.
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
#### 루프 (무한)

An infinite loop is a loop that continues indefinitely until it is explicitly terminated. It is often used in programming to repeat a certain block of code until a specific condition is met or to continuously perform a certain task. In Rust, you can create an infinite loop using the `loop` keyword.

```rust
loop {
    // Code to be repeated indefinitely
}
```

To exit an infinite loop, you can use the `break` keyword. This will immediately terminate the loop and continue with the execution of the program.

```rust
loop {
    // Code to be repeated indefinitely

    if condition {
        break; // Exit the loop
    }
}
```

In some cases, you may want to skip the current iteration of the loop and continue with the next one. This can be done using the `continue` keyword.

```rust
loop {
    // Code to be repeated indefinitely

    if condition {
        continue; // Skip this iteration and continue with the next one
    }
}
```

In summary, an infinite loop in Rust can be created using the `loop` keyword. To exit the loop, you can use the `break` keyword, and to skip the current iteration, you can use the `continue` keyword.
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

`while` 문은 조건이 참인 동안 반복적으로 코드 블록을 실행하는 데 사용됩니다. 

```rust
while 조건 {
    // 코드 블록
}
```

위의 코드에서 `조건`은 반복을 계속할지 여부를 결정하는 부울 표현식입니다. 조건이 참이면 코드 블록이 실행되고, 다시 조건을 확인한 후에도 참이면 반복이 계속됩니다. 조건이 거짓이면 반복이 종료됩니다.

`while` 문은 반복 횟수를 미리 알 수 없는 경우에 유용합니다. 예를 들어, 사용자로부터 입력을 받아야 하는 상황이나 특정 조건이 충족될 때까지 작업을 반복해야 하는 경우에 사용할 수 있습니다.

```rust
let mut count = 0;

while count < 5 {
    println!("Count: {}", count);
    count += 1;
}
```

위의 예제에서는 `count` 변수가 0부터 시작하여 5보다 작을 때까지 반복하면서 값을 증가시킵니다. 각 반복에서는 현재 `count` 값을 출력합니다.
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
#### 대상

---

Rust is a systems programming language that focuses on safety, speed, and concurrency. It is designed to be memory safe and thread safe, making it a good choice for writing low-level code that requires high performance and reliability.

Rust provides several features that help prevent common programming errors, such as null pointer dereferences, buffer overflows, and data races. These features include a strong static type system, ownership and borrowing rules, and built-in concurrency primitives.

In this section, we will cover the basics of Rust programming, including variables, data types, control flow, functions, and modules. By the end of this section, you should have a good understanding of the fundamentals of Rust and be able to write simple Rust programs.
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
#### if let

만약 변수가 특정한 패턴과 일치하는 경우에만 코드 블록을 실행하려면 `if let` 구문을 사용할 수 있습니다. 이 구문은 `match` 표현식의 간단한 버전으로 볼 수 있습니다. 

```rust
if let Some(value) = some_option {
    // some_option이 Some(value)와 일치하는 경우에만 실행되는 코드
} else {
    // some_option이 None인 경우에 실행되는 코드
}
```

`if let` 구문은 `match` 표현식과 달리 완전한 패턴 매칭을 제공하지 않습니다. 대신, 변수가 특정한 패턴과 일치하는지 여부만을 확인합니다. 이를 통해 코드를 더 간결하게 작성할 수 있습니다.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

`while let`은 패턴 매칭을 사용하여 반복문을 실행하는 Rust의 구문입니다. 이 구문은 `Option` 또는 `Result`와 같은 열거형 타입을 처리할 때 특히 유용합니다.

`while let` 구문은 주어진 패턴이 매치되는 한 반복을 계속합니다. 패턴이 매치되지 않으면 반복이 종료됩니다.

다음은 `while let` 구문의 사용 예시입니다:

```rust
let mut stack = vec![1, 2, 3, 4, 5];

while let Some(top) = stack.pop() {
    println!("Popped element: {}", top);
}
```

위의 예시에서는 `stack` 벡터에서 요소를 하나씩 꺼내어 `top` 변수에 바인딩하고, 해당 요소를 출력합니다. `stack.pop()`은 `Option` 타입을 반환하며, `Some` 패턴과 매치되는 경우에만 반복이 계속됩니다. `stack` 벡터가 비어있을 때는 `None` 패턴과 매치되어 반복이 종료됩니다.

`while let` 구문은 반복문을 간결하게 작성할 수 있도록 도와줍니다. 패턴 매칭을 사용하여 특정 조건을 만족하는 경우에만 반복을 실행할 수 있습니다.
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
### Traits

특정 타입에 대해 새로운 메소드를 생성합니다.
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
### 테스트

테스트는 소프트웨어 개발에서 중요한 부분입니다. 테스트는 코드의 정확성과 안정성을 확인하기 위해 사용됩니다. Rust에서는 테스트를 작성하고 실행하기 위해 `cargo test` 명령을 사용할 수 있습니다.

Rust에서의 테스트는 `#[cfg(test)]` 어노테이션을 사용하여 테스트 모듈을 정의합니다. 테스트 함수는 `#[test]` 어노테이션을 사용하여 정의되며, `assert!` 매크로를 사용하여 테스트 결과를 확인합니다.

Rust의 테스트는 단위 테스트와 통합 테스트로 구분됩니다. 단위 테스트는 개별 함수 또는 모듈의 동작을 테스트하며, 통합 테스트는 여러 모듈 또는 컴포넌트 간의 상호작용을 테스트합니다.

테스트는 `cargo test` 명령을 사용하여 실행할 수 있으며, 테스트 결과는 성공, 실패 또는 무시로 표시됩니다. 테스트 결과는 터미널에 출력되며, 테스트 커버리지 및 성능 프로파일링과 같은 추가 기능도 제공됩니다.

Rust에서는 테스트를 작성하여 코드의 신뢰성을 높이고 버그를 사전에 발견할 수 있습니다. 테스트는 소프트웨어 개발 과정에서 필수적인 요소이며, Rust의 강력한 테스트 기능을 활용하여 안정적이고 신뢰할 수 있는 코드를 작성할 수 있습니다.
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
### 스레딩

#### Arc

Arc는 Clone을 사용하여 객체에 대한 더 많은 참조를 생성하여 스레드에 전달할 수 있습니다. 마지막 참조가 값에 대한 포인터를 벗어나면 변수는 삭제됩니다.
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
#### 스레드

이 경우에는 스레드에 수정할 수 있는 변수를 전달할 것입니다.
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

