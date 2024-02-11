# Podstawy Rusta

### Typy ogólne

Stwórz strukturę, w której jedna z wartości może być dowolnego typu.
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

Typ `Option` oznacza, że wartość może być typu `Some` (coś istnieje) lub `None`:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Możesz użyć funkcji takich jak `is_some()` lub `is_none()` do sprawdzenia wartości Option.

### Makra

Makra są potężniejsze niż funkcje, ponieważ rozszerzają się, aby wygenerować więcej kodu niż kod, który napisałeś ręcznie. Na przykład, sygnatura funkcji musi zadeklarować liczbę i typ parametrów, które funkcja posiada. Makra natomiast mogą przyjmować zmienną liczbę parametrów: możemy wywołać `println!("hello")` z jednym argumentem lub `println!("hello {}", name)` z dwoma argumentami. Ponadto, makra są rozwijane przed tym, jak kompilator interpretuje znaczenie kodu, więc makro może na przykład zaimplementować trait dla danego typu. Funkcja nie może tego zrobić, ponieważ jest wywoływana w czasie wykonania, a trait musi być zaimplementowany w czasie kompilacji.
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
### Iteruj

Iterowanie to proces powtarzania pewnej czynności lub operacji na zbiorze danych. W języku Rust, iterowanie odbywa się za pomocą iteratorów. Iterator to obiekt, który generuje kolejne elementy z danego zbioru danych.

W Rust istnieje wiele metod iteracji, które można używać do przetwarzania danych. Oto kilka podstawowych metod iteracji:

- `iter()`: Metoda `iter()` zwraca iterator, który generuje niezmienne referencje do elementów kolekcji.
- `iter_mut()`: Metoda `iter_mut()` zwraca iterator, który generuje zmienne referencje do elementów kolekcji, umożliwiając ich modyfikację.
- `into_iter()`: Metoda `into_iter()` konwertuje kolekcję na iterator, który generuje wartości, jednocześnie konsumując kolekcję.

Przykład użycia:

```rust
let numbers = vec![1, 2, 3, 4, 5];

// Iterowanie za pomocą iter()
for num in numbers.iter() {
    println!("Liczba: {}", num);
}

// Iterowanie za pomocą iter_mut()
for num in numbers.iter_mut() {
    *num *= 2;
}

// Iterowanie za pomocą into_iter()
for num in numbers.into_iter() {
    println!("Podwojona liczba: {}", num);
}
```

Iterowanie jest niezwykle przydatne podczas przetwarzania danych w języku Rust. Pozwala na łatwe wykonanie operacji na elementach kolekcji i manipulację nimi.
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
### Rekurencyjne pudełko

A recursive box is a data structure in Rust that allows for the creation of self-referential types. It is commonly used when dealing with data structures that have cyclic dependencies.

To create a recursive box, you can use the `Box::new` function provided by Rust's standard library. This function takes a value and returns a box that owns the value on the heap.

Here's an example of how to create a recursive box:

```rust
struct Node {
    value: i32,
    next: Option<Box<Node>>,
}

fn main() {
    let node1 = Node {
        value: 1,
        next: None,
    };

    let node2 = Node {
        value: 2,
        next: Some(Box::new(node1)),
    };

    let node3 = Node {
        value: 3,
        next: Some(Box::new(node2)),
    };

    // Accessing the value of the first node
    if let Some(boxed_node) = node3.next {
        let node1 = *boxed_node;
        println!("Value of the first node: {}", node1.value);
    }
}
```

In this example, we define a `Node` struct that contains a value of type `i32` and an optional `next` field that holds a recursive box. The `next` field is an `Option<Box<Node>>`, which means it can either be `None` or `Some` containing a boxed `Node`.

We create three nodes: `node1`, `node2`, and `node3`. `node1` has no next node, `node2` has `node1` as its next node, and `node3` has `node2` as its next node.

To access the value of the first node (`node1`), we use pattern matching to check if the `next` field of `node3` contains a boxed node. If it does, we dereference the boxed node using the `*` operator and access its value.

By using recursive boxes, we can create complex data structures that have cyclic dependencies without running into issues like infinite recursion or stack overflow.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### jeżeli

```rust
if condition {
    // code to execute if condition is true
}
```

Jeżeli warunek jest spełniony, wykonaj poniższy kod.
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
#### dopasowanie

The `match` expression in Rust is used for pattern matching. It allows you to compare a value against a series of patterns and execute different code based on the matched pattern. The syntax for `match` is as follows:

```rust
match value {
    pattern1 => {
        // code to execute if value matches pattern1
    },
    pattern2 => {
        // code to execute if value matches pattern2
    },
    // more patterns...
    _ => {
        // code to execute if value does not match any of the patterns
    }
}
```

The `value` is the expression that you want to match against the patterns. Each pattern is followed by a block of code to execute if the value matches that pattern. The `_` is a special pattern that matches any value.

The `match` expression is often used with enums to handle different cases. It provides a concise and readable way to handle multiple possible outcomes in your code.
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
#### pętla (nieskończona)

An infinite loop is a programming construct that repeats a block of code indefinitely. It is commonly used when you want a certain piece of code to run continuously until a specific condition is met or until the program is manually terminated. In Rust, you can create an infinite loop using the `loop` keyword.

```rust
loop {
    // code to be executed repeatedly
}
```

To exit the infinite loop, you can use the `break` keyword. This allows you to break out of the loop and continue with the rest of the program execution.

```rust
loop {
    // code to be executed repeatedly

    if condition {
        break; // exit the loop
    }
}
```

In some cases, you may want to skip the current iteration of the loop and continue with the next one. This can be achieved using the `continue` keyword.

```rust
loop {
    // code to be executed repeatedly

    if condition {
        continue; // skip this iteration and continue with the next one
    }
}
```

In summary, the `loop` keyword in Rust allows you to create an infinite loop that repeats a block of code until a specific condition is met or until the loop is manually terminated using `break`. You can also skip iterations using the `continue` keyword.
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
#### podczas

The `while` loop is used to repeatedly execute a block of code as long as a specified condition is true. It is a type of iteration statement that allows you to create a loop that continues until the condition becomes false.

```rust
while condition {
    // code to be executed
}
```

In the above code, `condition` is the expression that is evaluated before each iteration. If the condition is true, the code inside the loop is executed. After each iteration, the condition is checked again, and if it is still true, the loop continues. If the condition becomes false, the loop is terminated, and the program continues with the next statement after the loop.

It is important to ensure that the condition eventually becomes false, otherwise, the loop will continue indefinitely, resulting in an infinite loop. To avoid this, you can modify the condition within the loop or use other control flow statements like `break` to exit the loop.

The `while` loop is useful when you want to repeat a block of code an unknown number of times, as long as a certain condition is met. It provides flexibility and allows you to create dynamic loops based on runtime conditions.
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
#### dla
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
#### jeżeli let

`if let` to skrócona składnia dla instrukcji `match`, która pozwala na sprawdzenie jednego wzorca i wykonanie kodu w przypadku, gdy wzorzec pasuje. Jest to przydatne, gdy chcemy obsłużyć tylko jeden konkretny przypadek i nie jesteśmy zainteresowani pozostałymi.

```rust
let option = Some(5);

if let Some(value) = option {
    println!("Value: {}", value);
}
```

W powyższym przykładzie, jeśli `option` jest typu `Some`, wartość zostanie przypisana do zmiennej `value` i zostanie wyświetlony komunikat "Value: 5". W przeciwnym razie, jeśli `option` jest typu `None`, kod wewnątrz bloku `if let` nie zostanie wykonany.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

`while let` jest konstrukcją pętli w języku Rust, która umożliwia iterację przez kolekcję lub strukturę danych, dopóki warunek jest spełniony. Ta konstrukcja jest szczególnie przydatna, gdy chcemy wykonywać pewne operacje tylko dla określonych elementów kolekcji.

Oto składnia `while let`:

```rust
while let Some(pattern) = expression {
    // wykonaj operacje na pattern
}
```

Gdzie:
- `Some(pattern)` to wzorzec, który dopasowuje wartość z `expression`.
- `expression` to wyrażenie, które zwraca opcję (Option) lub wynik (Result).

Pętla `while let` będzie kontynuować iterację, dopóki `expression` zwraca `Some(pattern)`. W każdej iteracji, wartość z `expression` zostanie dopasowana do wzorca `pattern`, a następnie można wykonać operacje na tym dopasowanym wzorcu.

Przykład użycia `while let`:

```rust
let mut vec = vec![Some(1), Some(2), None, Some(3)];

while let Some(value) = vec.pop() {
    match value {
        Some(num) => println!("Liczba: {}", num),
        None => println!("Brak wartości"),
    }
}
```

W tym przykładzie, pętla `while let` iteruje przez wektor `vec` i w każdej iteracji sprawdza, czy wartość jest `Some`. Jeśli tak, dopasowuje wartość do `value` i wykonuje odpowiednie operacje. Jeśli wartość jest `None`, wypisuje informację o braku wartości.

Pamiętaj, że `while let` jest przydatne, gdy chcemy wykonywać operacje tylko dla określonych elementów kolekcji, które spełniają określony warunek.
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

Tworzenie nowej metody dla typu

```rust
trait MyTrait {
    fn my_method(&self);
}

struct MyStruct;

impl MyTrait for MyStruct {
    fn my_method(&self) {
        // implementation
    }
}

fn main() {
    let my_struct = MyStruct;
    my_struct.my_method();
}
```

W powyższym przykładzie tworzymy nową metodę dla typu `MyStruct` poprzez zaimplementowanie traitu `MyTrait`. Metoda `my_method` jest wywoływana na instancji `MyStruct` i może być dostosowana do potrzeb programu.
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
### Testy

#### Testy jednostkowe

Testy jednostkowe są używane do sprawdzania poprawności pojedynczych jednostek kodu, takich jak funkcje, metody lub klasy. Testy jednostkowe są zazwyczaj pisane przez programistów i służą do weryfikacji, czy dana jednostka kodu działa zgodnie z oczekiwaniami. Testy jednostkowe powinny być niezależne od siebie i powinny być łatwe do uruchomienia i zrozumienia.

#### Testy integracyjne

Testy integracyjne są używane do sprawdzania poprawności interakcji między różnymi jednostkami kodu. Testy integracyjne sprawdzają, czy integracja między poszczególnymi komponentami systemu działa zgodnie z oczekiwaniami. Testy integracyjne mogą obejmować testowanie interfejsów, komunikacji między serwisami lub integracji z zewnętrznymi systemami.

#### Testy akceptacyjne

Testy akceptacyjne są używane do sprawdzania, czy system spełnia wymagania i oczekiwania użytkowników. Testy akceptacyjne są zazwyczaj przeprowadzane przez klientów lub użytkowników końcowych i mają na celu potwierdzenie, czy system działa zgodnie z oczekiwaniami biznesowymi. Testy akceptacyjne mogą obejmować scenariusze użytkowania, testowanie wydajności lub testowanie bezpieczeństwa.

#### Testy wydajnościowe

Testy wydajnościowe są używane do sprawdzania, jak dobrze system działa pod względem wydajności i skalowalności. Testy wydajnościowe mają na celu zidentyfikowanie potencjalnych problemów z wydajnością, takich jak opóźnienia, przeciążenia lub wycieki pamięci. Testy wydajnościowe mogą obejmować testowanie obciążenia, testowanie czasu odpowiedzi lub testowanie skalowalności.

#### Testy bezpieczeństwa

Testy bezpieczeństwa są używane do sprawdzania, czy system jest odporny na ataki i czy spełnia wymagania dotyczące bezpieczeństwa. Testy bezpieczeństwa mają na celu identyfikację potencjalnych luk w zabezpieczeniach systemu, takich jak podatności na ataki XSS, SQL injection lub ataki DDoS. Testy bezpieczeństwa mogą obejmować testowanie penetracyjne, testowanie podatności lub testowanie zgodności z regulacjami.
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
### Wątki

#### Arc

Arc może używać Clone do tworzenia dodatkowych referencji do obiektu, które można przekazać do wątków. Gdy ostatni wskaźnik referencji do wartości wychodzi poza zakres, zmienna jest usuwana.
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
#### Wątki

W tym przypadku przekażemy wątkowi zmienną, którą będzie mógł zmodyfikować.
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

