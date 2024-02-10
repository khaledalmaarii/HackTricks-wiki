# Rust Grundlagen

### Generische Typen

Erstellen Sie eine Struktur, bei der einer ihrer Werte jeden beliebigen Typ haben kann.
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

Der Option-Typ bedeutet, dass der Wert entweder vom Typ Some (es gibt etwas) oder None sein kann:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Du kannst Funktionen wie `is_some()` oder `is_none()` verwenden, um den Wert der Option zu überprüfen.

### Makros

Makros sind mächtiger als Funktionen, da sie sich erweitern, um mehr Code zu erzeugen als der Code, den du manuell geschrieben hast. Zum Beispiel muss eine Funktionssignatur die Anzahl und den Typ der Parameter angeben, die die Funktion hat. Makros hingegen können eine variable Anzahl von Parametern entgegennehmen: Wir können `println!("hello")` mit einem Argument aufrufen oder `println!("hello {}", name)` mit zwei Argumenten. Außerdem werden Makros vor der Interpretation des Codes durch den Compiler erweitert, sodass ein Makro beispielsweise ein Trait für einen bestimmten Typ implementieren kann. Eine Funktion kann das nicht, da sie zur Laufzeit aufgerufen wird und ein Trait zur Kompilierungszeit implementiert werden muss.
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
### Iterieren

In Rust gibt es verschiedene Möglichkeiten, um über eine Sammlung von Elementen zu iterieren. Das `for`-Schleifenkonstrukt ist eine der häufigsten Methoden, um dies zu tun. Es kann verwendet werden, um über Arrays, Vektoren, Slices und andere Sammlungen zu iterieren.

```rust
let numbers = [1, 2, 3, 4, 5];

for number in numbers.iter() {
    println!("Number: {}", number);
}
```

Dieser Code iteriert über das Array `numbers` und gibt jedes Element aus. Die `iter()`-Methode wird auf dem Array aufgerufen, um einen Iterator zu erhalten, der über die Elemente des Arrays läuft.

Eine andere Möglichkeit, über eine Sammlung zu iterieren, besteht darin, die `enumerate()`-Methode zu verwenden. Diese Methode gibt ein Tupel zurück, das den Index und das Element enthält.

```rust
let numbers = [1, 2, 3, 4, 5];

for (index, number) in numbers.iter().enumerate() {
    println!("Index: {}, Number: {}", index, number);
}
```

Dieser Code gibt sowohl den Index als auch das Element jedes Elements im Array `numbers` aus.

Es gibt auch andere Iteratormethoden wie `map()`, `filter()` und `fold()`, die verwendet werden können, um Transformationen und Filterungen auf den Elementen einer Sammlung durchzuführen.

```rust
let numbers = [1, 2, 3, 4, 5];

let doubled_numbers: Vec<i32> = numbers.iter().map(|x| x * 2).collect();

println!("Doubled numbers: {:?}", doubled_numbers);
```

Dieser Code verdoppelt jedes Element im Array `numbers` und speichert die verdoppelten Zahlen in einem Vektor. Der `map()`-Operator wird verwendet, um die Verdopplung durchzuführen, und die `collect()`-Methode wird verwendet, um die Ergebnisse in einem Vektor zu sammeln.

Die Iteration über eine Sammlung in Rust ist einfach und flexibel, und die verschiedenen Iteratormethoden bieten eine Vielzahl von Möglichkeiten zur Transformation und Filterung von Daten.
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
### Rekursive Box

Eine rekursive Box ist eine Technik, bei der eine Box in einer Box verschachtelt wird, um eine Kette von Aktionen auszuführen. Dies wird oft verwendet, um komplexe Aufgaben zu automatisieren oder um wiederholte Aktionen auf mehreren Ebenen durchzuführen.

Die rekursive Box kann verwendet werden, um eine Reihe von Befehlen oder Aktionen auszuführen, indem sie sich selbst aufruft. Dies ermöglicht es, dass eine Aktion wiederholt ausgeführt wird, bis eine bestimmte Bedingung erfüllt ist oder ein bestimmtes Ergebnis erzielt wird.

Die rekursive Box kann auch verwendet werden, um eine Hierarchie von Aktionen zu erstellen, bei der jede Aktion eine andere Aktion aufruft. Dies ermöglicht es, komplexe Aufgaben in kleinere, leichter zu handhabende Schritte zu unterteilen.

Die Verwendung einer rekursiven Box erfordert ein gutes Verständnis der Programmierung und der Logik, um sicherzustellen, dass die rekursive Funktion ordnungsgemäß funktioniert und nicht in einer Endlosschleife stecken bleibt.

Es ist wichtig, die Abbruchbedingung sorgfältig zu definieren, um sicherzustellen, dass die rekursive Box nicht unendlich weiterläuft. Eine schlecht definierte Abbruchbedingung kann zu einem Absturz des Systems oder zu unerwünschten Ergebnissen führen.

Die rekursive Box ist eine leistungsstarke Technik, die in verschiedenen Bereichen der Softwareentwicklung und des Hackings eingesetzt werden kann. Sie ermöglicht die Automatisierung von Aufgaben und die effiziente Verarbeitung von Daten.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### if

Die `if`-Anweisung wird verwendet, um eine Bedingung zu überprüfen und Code auszuführen, wenn die Bedingung wahr ist. Der Code innerhalb der `if`-Anweisung wird nur ausgeführt, wenn die Bedingung erfüllt ist.

Die Syntax für die `if`-Anweisung in Rust ist wie folgt:

```rust
if Bedingung {
    // Code, der ausgeführt wird, wenn die Bedingung wahr ist
}
```

Hier ist ein Beispiel:

```rust
fn main() {
    let zahl = 5;

    if zahl > 0 {
        println!("Die Zahl ist positiv");
    }
}
```

In diesem Beispiel wird der Code innerhalb der `if`-Anweisung nur ausgeführt, wenn die Variable `zahl` größer als 0 ist.
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
#### Übereinstimmung

Die `match`-Anweisung in Rust ermöglicht es, einen Wert mit verschiedenen Mustern zu vergleichen und entsprechende Aktionen auszuführen, basierend auf dem übereinstimmenden Muster. Es ähnelt dem `switch`-Statement in anderen Programmiersprachen.

Die Syntax für `match` sieht folgendermaßen aus:

```rust
match Wert {
    Muster1 => {
        // Aktionen für Muster1
    },
    Muster2 => {
        // Aktionen für Muster2
    },
    // Weitere Muster und Aktionen
    _ => {
        // Standardaktion, wenn kein Muster übereinstimmt
    }
}
```

Hier sind einige wichtige Punkte zu beachten:

- Jedes Muster kann entweder ein Wert, eine Variable oder ein Platzhalter sein.
- Das `_`-Muster wird als Platzhalter verwendet, um alle anderen Fälle abzudecken, die nicht explizit angegeben sind.
- Die Aktionen für jedes Muster werden in geschweiften Klammern `{}` definiert.
- Nachdem eine Aktion ausgeführt wurde, wird die `match`-Anweisung beendet.

Die `match`-Anweisung ist eine leistungsstarke Möglichkeit, verschiedene Fälle zu behandeln und den Code lesbarer zu machen. Es ist besonders nützlich, wenn Sie mit Enumerationen arbeiten, da Sie alle möglichen Varianten abdecken können.
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
#### Schleife (unendlich)

Eine unendliche Schleife ist eine Schleife, die ohne eine Bedingung, die sie beendet, immer wieder ausgeführt wird. Dies kann nützlich sein, um bestimmte Aufgaben kontinuierlich auszuführen, wie z.B. das Überwachen von Ereignissen oder das Warten auf bestimmte Bedingungen.

In Rust kann eine unendliche Schleife mit dem Schlüsselwort `loop` erstellt werden. Der Code innerhalb der Schleife wird immer wieder ausgeführt, bis er explizit unterbrochen wird. Dies kann durch die Verwendung von `break` erreicht werden, um die Schleife zu verlassen, oder durch die Verwendung von `return`, um die Funktion zu verlassen, in der sich die Schleife befindet.

Hier ist ein Beispiel für eine unendliche Schleife in Rust:

```rust
loop {
    // Code, der immer wieder ausgeführt wird
}
```

Es ist wichtig, sicherzustellen, dass es eine Möglichkeit gibt, die Schleife zu beenden, da sonst das Programm in einer Endlosschleife stecken bleiben kann.
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
#### während

The `while` statement is used in Rust to create a loop that continues executing as long as a certain condition is true. It is a control flow construct that allows you to repeat a block of code multiple times.

Die `while` Anweisung wird in Rust verwendet, um eine Schleife zu erstellen, die so lange ausgeführt wird, wie eine bestimmte Bedingung wahr ist. Es handelt sich um eine Kontrollflusskonstruktion, die es ermöglicht, einen Codeblock mehrmals zu wiederholen.
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
#### für

---

#### Variables

##### Declaration

```rust
let x: i32 = 5;
```

##### Mutable

```rust
let mut y: i32 = 10;
```

##### Constants

```rust
const Z: i32 = 15;
```

---

#### Data Types

##### Integer

```rust
let a: i8 = 127;
let b: i16 = 32767;
let c: i32 = 2147483647;
let d: i64 = 9223372036854775807;
let e: i128 = 170141183460469231731687303715884105727;
```

##### Unsigned Integer

```rust
let f: u8 = 255;
let g: u16 = 65535;
let h: u32 = 4294967295;
let i: u64 = 18446744073709551615;
let j: u128 = 340282366920938463463374607431768211455;
```

##### Floating Point

```rust
let k: f32 = 3.14;
let l: f64 = 3.141592653589793;
```

##### Boolean

```rust
let m: bool = true;
let n: bool = false;
```

##### Character

```rust
let o: char = 'a';
```

##### String

```rust
let p: &str = "Hello, World!";
let q: String = String::from("Hello, World!");
```

---

#### Operators

##### Arithmetic

```rust
let sum = 5 + 3;
let difference = 5 - 3;
let product = 5 * 3;
let quotient = 5 / 3;
let remainder = 5 % 3;
```

##### Comparison

```rust
let equal = 5 == 3;
let not_equal = 5 != 3;
let greater_than = 5 > 3;
let less_than = 5 < 3;
let greater_than_or_equal = 5 >= 3;
let less_than_or_equal = 5 <= 3;
```

##### Logical

```rust
let and = true && false;
let or = true || false;
let not = !true;
```

##### Assignment

```rust
let mut x = 5;
x += 3;
x -= 3;
x *= 3;
x /= 3;
x %= 3;
```

---

#### Control Flow

##### If-else

```rust
let x = 5;

if x > 10 {
    println!("x is greater than 10");
} else if x < 10 {
    println!("x is less than 10");
} else {
    println!("x is equal to 10");
}
```

##### Loop

```rust
let mut x = 0;

loop {
    println!("x is {}", x);
    x += 1;

    if x == 5 {
        break;
    }
}
```

##### While

```rust
let mut x = 0;

while x < 5 {
    println!("x is {}", x);
    x += 1;
}
```

##### For

```rust
let numbers = [1, 2, 3, 4, 5];

for number in numbers.iter() {
    println!("The number is {}", number);
}
```

---

#### Functions

```rust
fn add(x: i32, y: i32) -> i32 {
    x + y
}

fn main() {
    let result = add(5, 3);
    println!("The result is {}", result);
}
```
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

Die `if let`-Anweisung in Rust ermöglicht es, ein Muster mit einem Wert zu vergleichen und den Codeblock auszuführen, wenn das Muster übereinstimmt. Es ist eine verkürzte Schreibweise für das `match`-Statement, das nur einen Fall abdeckt.

Die Syntax für `if let` ist wie folgt:

```rust
if let pattern = expression {
    // Codeblock, der ausgeführt wird, wenn das Muster übereinstimmt
}
```

Hier ist ein Beispiel, um das Konzept zu verdeutlichen:

```rust
fn main() {
    let value = Some(5);

    if let Some(x) = value {
        println!("Der Wert ist: {}", x);
    }
}
```

In diesem Beispiel wird überprüft, ob `value` den Wert `Some` enthält. Wenn ja, wird der Wert in `x` gebunden und der Codeblock innerhalb des `if let`-Statements wird ausgeführt. In diesem Fall wird "Der Wert ist: 5" gedruckt.

Die `if let`-Anweisung ist besonders nützlich, wenn Sie nur an einem bestimmten Fall interessiert sind und nicht alle möglichen Fälle abdecken müssen. Es kann den Code lesbarer machen, indem es unnötige Verzweigungen vermeidet.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

Die `while let`-Schleife ist eine spezielle Art der `while`-Schleife in Rust, die verwendet wird, um eine Schleife auszuführen, solange ein bestimmtes Pattern mit einem Wert übereinstimmt. 

Die Syntax für die `while let`-Schleife ist wie folgt:

```rust
while let pattern = expression {
    // Code, der ausgeführt wird, solange das Pattern übereinstimmt
}
```

Hier ist eine kurze Erklärung, wie die `while let`-Schleife funktioniert:

1. Die `expression` wird ausgewertet.
2. Wenn das Pattern mit dem Wert der `expression` übereinstimmt, wird der Code innerhalb der Schleife ausgeführt.
3. Nachdem der Code ausgeführt wurde, wird die `expression` erneut ausgewertet.
4. Wenn das Pattern immer noch mit dem Wert der `expression` übereinstimmt, wird der Code erneut ausgeführt.
5. Dieser Vorgang wird wiederholt, bis das Pattern nicht mehr mit dem Wert der `expression` übereinstimmt.

Die `while let`-Schleife ist besonders nützlich, wenn Sie eine Schleife ausführen möchten, solange ein bestimmtes Pattern mit einem Wert übereinstimmt, und Sie den Wert innerhalb der Schleife verwenden möchten.
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

Eine neue Methode für einen Typen erstellen
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
### Tests

Tests sind ein wesentlicher Bestandteil der Softwareentwicklung. Sie dienen dazu, die Funktionalität und Korrektheit des Codes zu überprüfen. In Rust können Tests mit der `#[test]`-Annotation geschrieben werden. Diese Annotation kennzeichnet eine Funktion als Testfunktion. Um die Tests auszuführen, kann das `cargo test`-Kommando verwendet werden.

#### Einfacher Test

Ein einfacher Test in Rust könnte wie folgt aussehen:

```rust
#[test]
fn test_addition() {
    assert_eq!(2 + 2, 4);
}
```

In diesem Beispiel wird die Funktion `test_addition` als Testfunktion markiert. Die `assert_eq!`-Makro wird verwendet, um zu überprüfen, ob die Addition von 2 und 2 gleich 4 ergibt. Wenn der Test erfolgreich ist, wird keine Ausgabe erzeugt. Wenn der Test fehlschlägt, wird eine Fehlermeldung angezeigt.

#### Testergebnisse

Beim Ausführen von Tests gibt Rust Informationen über die Anzahl der Tests, die erfolgreich waren, die fehlgeschlagen sind und die übersprungen wurden. Diese Informationen werden in einer übersichtlichen Zusammenfassung angezeigt.

#### Testabdeckung

Rust bietet auch die Möglichkeit, die Testabdeckung zu überprüfen. Mit dem `--coverage`-Flag kann das `cargo test`-Kommando ausgeführt werden, um Informationen über den Prozentsatz des Codes anzuzeigen, der von den Tests abgedeckt wird.

#### Testorganisation

Um den Code besser zu organisieren, können Tests in separate Module gruppiert werden. Dies kann mit dem `mod`-Schlüsselwort erreicht werden. Hier ist ein Beispiel:

```rust
mod math {
    #[test]
    fn test_addition() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_subtraction() {
        assert_eq!(4 - 2, 2);
    }
}
```

In diesem Beispiel werden die Tests für die Addition und Subtraktion in einem separaten Modul namens `math` gruppiert. Dies erleichtert die Organisation und Lesbarkeit des Codes.

#### Testfixtures

Manchmal ist es erforderlich, vor jedem Test bestimmte Vorbereitungen zu treffen. Dies kann mit Testfixtures erreicht werden. Testfixtures sind Funktionen, die vor oder nach jedem Test ausgeführt werden. Sie können verwendet werden, um beispielsweise Datenbankverbindungen herzustellen oder Testdaten zu initialisieren.

```rust
#[test]
fn test_with_fixture() {
    setup();
    // Testcode
    teardown();
}

fn setup() {
    // Vorbereitungen vor dem Test
}

fn teardown() {
    // Aufräumarbeiten nach dem Test
}
```

In diesem Beispiel wird die Funktion `setup` vor jedem Test und die Funktion `teardown` nach jedem Test ausgeführt. Dadurch können spezifische Vorbereitungen und Aufräumarbeiten durchgeführt werden, um sicherzustellen, dass die Tests in einer sauberen Umgebung ausgeführt werden.

#### Testparameter

Manchmal ist es nützlich, Tests mit verschiedenen Parametern auszuführen. Dies kann mit Testparametern erreicht werden. Testparameter sind Funktionen, die als Parameter an Testfunktionen übergeben werden. Dadurch können Tests mit verschiedenen Eingabewerten ausgeführt werden.

```rust
#[test]
#[cfg(test)]
fn test_with_parameter() {
    for param in get_params() {
        assert_eq!(param + 2, 4);
    }
}

fn get_params() -> Vec<i32> {
    vec![2, 3, 4]
}
```

In diesem Beispiel wird die Funktion `get_params` verwendet, um eine Liste von Parametern zurückzugeben. Die Testfunktion `test_with_parameter` wird dann für jeden Parameter in der Liste ausgeführt. Dadurch können Tests mit verschiedenen Eingabewerten durchgeführt werden.
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
### Threading

#### Arc

Ein Arc kann Clone verwenden, um weitere Referenzen auf das Objekt zu erstellen und sie an die Threads zu übergeben. Wenn der letzte Referenzzeiger auf einen Wert außerhalb des Gültigkeitsbereichs liegt, wird die Variable verworfen.
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
#### Threads

In diesem Fall übergeben wir dem Thread eine Variable, die er ändern kann.
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

