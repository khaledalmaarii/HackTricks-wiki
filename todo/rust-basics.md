# Rust Temelleri

### Genel Tipler

Herhangi bir tipte olabilen bir değeri içeren bir yapı (struct) oluşturun.
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

Option türü, değerin Some (bir şey var) veya None türünde olabileceği anlamına gelir:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Option'un değerini kontrol etmek için `is_some()` veya `is_none()` gibi fonksiyonları kullanabilirsiniz.

### Makrolar

Makrolar, fonksiyonlardan daha güçlüdür çünkü manuel olarak yazdığınız kodun üzerine daha fazla kod üretmek için genişler. Örneğin, bir fonksiyon imzası, fonksiyonun sahip olduğu parametrelerin sayısını ve türünü bildirmelidir. Makrolar ise değişken sayıda parametre alabilir: `println!("hello")` bir argümanla veya `println!("hello {}", name)` iki argümanla çağrılabilir. Ayrıca, makrolar, derleyicinin kodun anlamını yorumlamadan önce genişletilir, bu nedenle bir makro, örneğin, belirli bir tür üzerinde bir özniteliği uygulayabilir. Bir fonksiyon yapamaz çünkü çalışma zamanında çağrılır ve bir öznitelik derleme zamanında uygulanmalıdır.
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
### Yinele

Yineleme, bir döngü kullanarak bir dizi veya koleksiyon üzerinde tekrarlayarak her bir öğeyi işlemek için kullanılan bir programlama tekniğidir. Rust dilinde, yineleme işlemi çeşitli yollarla gerçekleştirilebilir.

#### `for` Döngüsü

En yaygın kullanılan yineleme yöntemi, `for` döngüsüdür. Bu döngü, bir koleksiyonun her bir öğesini sırayla işlemek için kullanılır. Rust dilinde, `for` döngüsü aşağıdaki şekilde kullanılır:

```rust
for element in collection {
    // Öğe üzerinde yapılacak işlemler
}
```

`element` değişkeni, her bir öğeyi temsil eder ve `collection` ise yinelemek istediğimiz koleksiyonu temsil eder.

#### `while` Döngüsü

`while` döngüsü, belirli bir koşul sağlandığı sürece tekrarlanan bir döngüdür. Rust dilinde, `while` döngüsü aşağıdaki şekilde kullanılır:

```rust
while condition {
    // Koşul sağlandığı sürece yapılacak işlemler
}
```

`condition` ifadesi, döngünün tekrarlanmasını kontrol eden bir koşul ifadesidir.

#### `loop` Döngüsü

`loop` döngüsü, belirli bir koşul sağlanana kadar sürekli olarak tekrarlanan bir döngüdür. Rust dilinde, `loop` döngüsü aşağıdaki şekilde kullanılır:

```rust
loop {
    // Sürekli olarak yapılacak işlemler
    if condition {
        break; // Döngüyü sonlandırmak için kullanılır
    }
}
```

`break` ifadesi, döngüyü sonlandırmak için kullanılır ve belirli bir koşul sağlandığında döngüden çıkılır.

Yineleme, Rust dilinde programlama yaparken sık sık kullanılan bir tekniktir ve çeşitli döngü yapılarıyla gerçekleştirilebilir.
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
### Yinelemeli Kutu

Bir kutunun içinde başka bir kutu bulunabilir. Bu, yinelemeli bir kutu yapısı oluşturur. Yinelemeli kutular, veri yapılarını daha karmaşık hale getirmek için kullanılabilir.

Yinelemeli kutular, birbirine bağlı kutuların bir ağacını oluşturur. Her kutu, içinde başka kutular veya veriler bulunabilecek bir dizi alan içerir. Bu yapı, verileri hiyerarşik bir şekilde düzenlemek için kullanılabilir.

Yinelemeli kutular, özyinelemeli fonksiyonlar gibi davranabilir. Bir kutu, içindeki diğer kutuları veya verileri işleyebilir ve bu işlemi yineleyebilir. Bu, bir algoritmanın yinelemeli olarak çalışmasını sağlar.

Yinelemeli kutular, programlama dillerinde ve veri tabanlarında sıklıkla kullanılır. Örneğin, bir dosya sistemi, yinelemeli kutuların bir örneğidir. Bir klasör, içinde başka klasörler veya dosyalar bulundurabilir. Bu şekilde, dosyalar ve klasörler hiyerarşik bir yapı oluşturur.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### eğer

The `if` statement is used to execute a block of code only if a certain condition is true. It has the following syntax:

```rust
if condition {
    // code to be executed if the condition is true
}
```

The `condition` can be any expression that evaluates to a boolean value (`true` or `false`). If the condition is true, the code inside the block will be executed. If the condition is false, the code inside the block will be skipped.

Here's an example:

```rust
let number = 5;

if number > 0 {
    println!("The number is positive");
}
```

In this example, the code inside the `if` block will be executed because the condition `number > 0` is true. The output will be `The number is positive`.

#### else

The `else` statement is used to execute a block of code if the condition of the `if` statement is false. It has the following syntax:

```rust
if condition {
    // code to be executed if the condition is true
} else {
    // code to be executed if the condition is false
}
```

Here's an example:

```rust
let number = -5;

if number > 0 {
    println!("The number is positive");
} else {
    println!("The number is negative");
}
```

In this example, the condition `number > 0` is false, so the code inside the `else` block will be executed. The output will be `The number is negative`.

#### else if

The `else if` statement is used to chain multiple conditions together. It has the following syntax:

```rust
if condition1 {
    // code to be executed if condition1 is true
} else if condition2 {
    // code to be executed if condition1 is false and condition2 is true
} else {
    // code to be executed if both condition1 and condition2 are false
}
```

Here's an example:

```rust
let number = 0;

if number > 0 {
    println!("The number is positive");
} else if number < 0 {
    println!("The number is negative");
} else {
    println!("The number is zero");
}
```

In this example, the condition `number > 0` is false, and the condition `number < 0` is also false, so the code inside the `else` block will be executed. The output will be `The number is zero`.
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
#### eşleşme

`match` ifadesi, bir değerin farklı durumlarına göre farklı işlemler yapmak için kullanılır. Bu ifade, bir değeri birden fazla desenle karşılaştırır ve eşleşen desene göre belirli bir kod bloğunu çalıştırır.

```rust
match deger {
    desen1 => {
        // desen1 ile eşleşirse burası çalışır
    },
    desen2 => {
        // desen2 ile eşleşirse burası çalışır
    },
    _ => {
        // hiçbir desenle eşleşmezse burası çalışır
    }
}
```

`_` (alt çizgi) deseni, herhangi bir desenle eşleşmeyen durumları temsil eder. Bu, `match` ifadesindeki bir desenin tam olarak eşleşmediği durumlarda çalışacak olan bir "varsayılan" blok sağlar.
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
#### döngü (sonsuz)

An infinite loop is a loop that continues indefinitely until it is explicitly terminated. It is often used in programming to create processes or tasks that need to run continuously without an end condition. In Rust, you can create an infinite loop using the `loop` keyword.

```rust
loop {
    // Code to be executed repeatedly
}
```

In the example above, the code inside the loop will be executed repeatedly until the loop is explicitly terminated. To terminate the loop, you can use the `break` keyword.

```rust
loop {
    // Code to be executed repeatedly

    if condition {
        break; // Terminate the loop
    }
}
```

In the second example, the loop will continue executing the code inside until the `condition` is met, at which point the loop will be terminated using the `break` keyword.

Infinite loops can be useful in certain scenarios, such as when creating server applications that need to listen for incoming connections continuously or when implementing background tasks that need to run indefinitely. However, it is important to ensure that there is a way to terminate the loop to prevent it from running indefinitely and consuming excessive resources.
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

`while` döngüsü, belirli bir koşul doğru olduğu sürece bir bloğu tekrar tekrar çalıştırmak için kullanılır. Döngü, koşul yanlış olduğunda durur.

```rust
while koşul {
    // Kod bloğu
}
```

Yukarıdaki örnekte, `koşul` doğru olduğu sürece kod bloğu tekrar tekrar çalıştırılır. `koşul` yanlış olduğunda döngü sona erer ve program devam eder.

Örneğin, aşağıdaki kod parçası, 1'den 5'e kadar olan sayıları ekrana yazdırır:

```rust
let mut i = 1;
while i <= 5 {
    println!("{}", i);
    i += 1;
}
```

Bu kod parçası, `i` değişkeninin değeri 1'den başlayarak her döngüde 1 artırılır ve `i` değeri 5'e eşit veya daha büyük olduğunda döngü sona erer. Her döngüde, `i` değeri ekrana yazdırılır. Sonuç olarak, 1, 2, 3, 4 ve 5 ekrana yazdırılır.
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
#### için
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
#### eğer let

```rust
if let Some(value) = optional_value {
    // Code to execute if optional_value is Some
} else {
    // Code to execute if optional_value is None
}
```

Bu yapı, bir `Option` değerinin içeriğini kontrol etmek için kullanılır. Eğer `optional_value` `Some` ise, `value` değişkenine atama yapılır ve `Some` durumunda çalıştırılacak kod bloğu çalıştırılır. Eğer `optional_value` `None` ise, `None` durumunda çalıştırılacak kod bloğu çalıştırılır.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

`while let` ifadesi, bir desen eşleşmesi kullanarak bir değerin bir desene uyması durumunda bir döngüyü çalıştırmak için kullanılır. Bu ifade, bir desenin eşleştiği sürece döngüyü tekrar tekrar çalıştırır.

```rust
while let Some(value) = iterator.next() {
    // Döngü gövdesi
}
```

Yukarıdaki örnekte, `iterator.next()` metodu bir `Option` değeri döndürür. Eğer bu değer `Some` ise, `value` değişkenine atama yapılır ve döngü gövdesi çalıştırılır. Eğer değer `None` ise, döngü sona erer.

Bu yapı, bir koleksiyonun elemanlarını işlemek veya bir değerin belirli bir duruma ulaşmasını beklemek gibi durumlarda kullanışlıdır.
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

Bir tür için yeni bir yöntem oluşturun
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
### Testler

Testler, yazılım geliştirme sürecinde önemli bir rol oynar. Bir yazılımın doğru çalıştığından emin olmak için testler kullanılır. Testler, yazılımın beklenen sonuçları üretip üretmediğini kontrol etmek için kullanılır. Testler, hataları tespit etmek ve düzeltmek için kullanılır. Yazılımın güvenilirliğini artırmak ve kullanıcı deneyimini iyileştirmek için testler yapılır.

Testler, genellikle bir test çerçevesi kullanılarak yapılır. Test çerçeveleri, test senaryolarını otomatikleştirmek ve test sürecini kolaylaştırmak için kullanılır. Testler, birim testleri, entegrasyon testleri, kabul testleri ve performans testleri gibi farklı kategorilere ayrılabilir. Her bir test kategorisi, farklı bir amaca hizmet eder ve farklı bir test stratejisi gerektirir.

Testler, yazılımın hatalarını tespit etmek için kullanılır. Hatalar, yazılımın beklenen sonuçları üretmediği durumlarda ortaya çıkar. Testler, hataları tespit etmek ve düzeltmek için kullanılır. Testler, yazılımın güvenilirliğini artırmak ve kullanıcı deneyimini iyileştirmek için yapılır.

Testler, yazılımın doğru çalıştığından emin olmak için kullanılır. Testler, yazılımın beklenen sonuçları üretip üretmediğini kontrol etmek için kullanılır. Testler, yazılımın doğru çalıştığını doğrulamak için yapılır.

Testler, yazılımın performansını ölçmek için kullanılır. Performans testleri, yazılımın belirli bir yük altında nasıl performans gösterdiğini değerlendirmek için yapılır. Performans testleri, yazılımın hızını, ölçeklenebilirliğini ve dayanıklılığını test etmek için kullanılır.

Testler, yazılımın güvenliğini değerlendirmek için kullanılır. Güvenlik testleri, yazılımın potansiyel güvenlik açıklarını tespit etmek ve düzeltmek için yapılır. Güvenlik testleri, yazılımın saldırılara karşı ne kadar dirençli olduğunu değerlendirmek için kullanılır.

Testler, yazılımın uyumluluğunu kontrol etmek için kullanılır. Uyumluluk testleri, yazılımın farklı platformlarda ve ortamlarda nasıl çalıştığını değerlendirmek için yapılır. Uyumluluk testleri, yazılımın farklı işletim sistemleri, tarayıcılar ve cihazlarla uyumlu olup olmadığını kontrol etmek için kullanılır.

Testler, yazılımın kullanılabilirliğini değerlendirmek için kullanılır. Kullanılabilirlik testleri, yazılımın kullanıcı dostu olduğunu ve kullanıcıların ihtiyaçlarını karşıladığını kontrol etmek için yapılır. Kullanılabilirlik testleri, yazılımın kullanıcı arayüzünü, gezinme kolaylığını ve kullanıcı deneyimini değerlendirmek için kullanılır.

Testler, yazılımın kalitesini değerlendirmek için kullanılır. Kalite testleri, yazılımın belirli kalite standartlarını karşılayıp karşılamadığını kontrol etmek için yapılır. Kalite testleri, yazılımın doğruluğunu, güvenilirliğini ve performansını değerlendirmek için kullanılır.
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
### Eşitleme (Threading)

#### Arc

Bir Arc, nesneye daha fazla referans oluşturmak için Clone kullanabilir ve bunları thread'lere iletebilir. Son referansın bir değeri işaret ettiği zaman kapsam dışına çıktığında, değişken düşer.
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
#### İş Parçacıkları

Bu durumda, iş parçacığına değiştirebileceği bir değişken geçireceğiz.
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

