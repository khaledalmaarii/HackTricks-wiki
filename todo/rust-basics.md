# Rust Basiese Beginsels

### Generiese Tipes

Skep 'n struktuur waarvan 1 van hul waardes enige tipe kan wees
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
### Opsie, Iets & Niks

Die Opsie-tipe beteken dat die waarde dalk van die tipe Iets (daar is iets) of Niks kan wees:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Jy kan funksies soos `is_some()` of `is_none()` gebruik om die waarde van die Opsie te kontroleer.

### Makros

Makros is kragtiger as funksies omdat hulle uitbrei om meer kode te produseer as die kode wat jy handmatig geskryf het. Byvoorbeeld, 'n funksiehandtekening moet die aantal en tipe parameters wat die funksie het, verklaar. Makros kan daarenteen 'n veranderlike aantal parameters neem: ons kan `println!("hello")` met een argument of `println!("hello {}", name)` met twee argumente noem. Verder word makros uitgebrei voordat die vertaler die betekenis van die kode interpreteer, so 'n makro kan byvoorbeeld 'n eienskap op 'n gegewe tipe implementeer. 'n Funksie kan nie, omdat dit by uitvoering geroep word en 'n eienskap by vertalingstyd geïmplementeer moet word nie.
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
### Iterasie

Iterasie is 'n belangrike konsep in die programmering van Rust. Dit verwys na die proses waarin 'n sekere blok kode herhaaldelik uitgevoer word. Dit kan gedoen word met behulp van lusse soos `for` en `while`.

In Rust is daar verskillende maniere om te itereer. Die mees algemene maniere is om te itereer oor 'n reeks elemente of om te itereer totdat 'n sekere voorwaarde waar is.

#### Iterasie oor 'n reeks elemente

Om te itereer oor 'n reeks elemente, kan jy die `for` sleutelwoord gebruik. Hier is 'n voorbeeld:

```rust
let reeks = [1, 2, 3, 4, 5];

for element in reeks.iter() {
    println!("Element: {}", element);
}
```

In hierdie voorbeeld sal die kode die waarde van elke element in die reeks druk. Die `iter()` metode word gebruik om 'n iterator oor die reeks te verkry.

#### Iterasie totdat 'n voorwaarde waar is

Om te itereer totdat 'n sekere voorwaarde waar is, kan jy die `while` sleutelwoord gebruik. Hier is 'n voorbeeld:

```rust
let mut telling = 0;

while telling < 5 {
    println!("Telling: {}", telling);
    telling += 1;
}
```

In hierdie voorbeeld sal die kode die waarde van `telling` druk totdat dit gelyk is aan 5. Die `while` sleutelwoord word gebruik om die lus voort te sit totdat die voorwaarde nie meer waar is nie.

Dit is die basiese beginsels van iterasie in Rust. Dit is 'n kragtige konsep wat jou in staat stel om herhaalde aksies uit te voer en jou kode effektief te maak.
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
### Herhalende Boks

'n Herhalende boks is 'n boks wat homself bevat. Dit beteken dat die boks 'n verwysing na 'n ander boks van dieselfde tipe binne-in homself bevat. Hierdie konsep van herhalende bokse kan gebruik word in die programmeringstaal Rust.

'n Herhalende boks kan nuttig wees vir situasies waarin jy 'n datastruktuur wil skep wat 'n onbekende aantal elemente kan hanteer. Deur 'n boks binne-in 'n boks te hê, kan jy 'n ketting van bokse skep wat 'n onbepaalde aantal elemente kan bevat.

Hier is 'n voorbeeld van hoe 'n herhalende boks in Rust gedefinieer kan word:

```rust
struct RecursiveBox<T> {
    data: T,
    next: Option<Box<RecursiveBox<T>>>,
}
```

In hierdie voorbeeld bevat die `RecursiveBox`-struktuur 'n veld genaamd `data` wat die data van die boks voorstel, en 'n veld genaamd `next` wat 'n opsionele verwysing na 'n ander `RecursiveBox`-boks bevat.

Om 'n nuwe herhalende boks te skep, kan jy die `Box::new`-funksie gebruik om 'n boks te maak en dit in die `next`-veld van 'n bestaande boks te plaas. Hier is 'n voorbeeld:

```rust
let boks1 = Box::new(RecursiveBox {
    data: 1,
    next: None,
});

let boks2 = Box::new(RecursiveBox {
    data: 2,
    next: Some(boks1),
});
```

In hierdie voorbeeld word 'n nuwe boks `boks1` geskep met die waarde 1 en geen verwysing na 'n ander boks nie. Dan word 'n tweede boks `boks2` geskep met die waarde 2 en 'n verwysing na `boks1`.

Hierdie is 'n basiese voorbeeld van hoe 'n herhalende boks in Rust gebruik kan word. Dit kan egter op verskillende maniere aangepas en uitgebrei word om aan verskillende behoeftes te voldoen.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### as

Die `if`-verklaring word gebruik om 'n spesifieke blok kode uit te voer as 'n sekere voorwaarde waar is. Die sintaks is as volg:

```rust
if voorwaarde {
    // kode om uit te voer as die voorwaarde waar is
}
```

Hier is 'n voorbeeld:

```rust
fn main() {
    let getal = 10;

    if getal > 5 {
        println!("Die getal is groter as 5");
    }
}
```

In hierdie voorbeeld sal die boodskap "Die getal is groter as 5" gedruk word omdat die waarde van die `getal`-veranderlike groter as 5 is.

#### if-else

Die `if-else`-verklaring word gebruik om 'n blok kode uit te voer as 'n voorwaarde waar is, en 'n ander blok kode uit te voer as die voorwaarde nie waar is nie. Die sintaks is as volg:

```rust
if voorwaarde {
    // kode om uit te voer as die voorwaarde waar is
} else {
    // kode om uit te voer as die voorwaarde nie waar is nie
}
```

Hier is 'n voorbeeld:

```rust
fn main() {
    let getal = 3;

    if getal > 5 {
        println!("Die getal is groter as 5");
    } else {
        println!("Die getal is nie groter as 5 nie");
    }
}
```

In hierdie voorbeeld sal die boodskap "Die getal is nie groter as 5 nie" gedruk word omdat die waarde van die `getal`-veranderlike nie groter as 5 is nie.
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
#### ooreenstemming

Die `match` sleutelwoord in Rust word gebruik om 'n waarde te vergelyk met verskillende patrone en die ooreenstemmende aksie uit te voer volgens die eerste ooreenstemmende patroon. Dit is 'n kragtige konstruksie wat gebruik kan word om verskillende gedrag te implementeer op grond van die waarde van 'n bepaalde uitdrukking.

Die sintaksis van die `match`-verklaring is as volg:

```rust
match uitdrukking {
    patroon1 => aksie1,
    patroon2 => aksie2,
    ...
    _ => aksie,
}
```

Hier is 'n paar belangrike punte om in gedagte te hou oor die `match`-verklaring:

- Die `uitdrukking` is die waarde wat vergelyk word met die patrone.
- Elke `patroon` is 'n moontlike waarde wat die `uitdrukking` kan hê.
- Die `aksie` is die kode wat uitgevoer word as die `uitdrukking` ooreenstem met die patroon.
- Die `_` patroon word gebruik as 'n vangnet om enige waarde te dek wat nie ooreenstem met die vorige patrone nie.
- Slegs die eerste ooreenstemmende patroon se aksie sal uitgevoer word.

Die `match`-verklaring is 'n nuttige konstruksie in Rust wat die programmer in staat stel om elegante en leesbare kode te skryf deur verskillende gedrag te implementeer op grond van die waarde van 'n uitdrukking.
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
#### lus (oneindig)
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
#### terwyl
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
#### vir
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
#### as dit
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### terwyl laat

`while let` is 'n konstruksie in Rust wat gebruik word om 'n lus uit te voer terwyl 'n patroon ooreenstem met 'n waarde. Dit is 'n korter sintaksis vir die `loop` lus wat gebruik maak van 'n `match` uitdrukking om die patroon ooreenstemming te bepaal.

Hier is die sintaksis vir `while let`:

```rust
while let Some(value) = optional_value {
    // Voer kode uit solank `optional_value` ooreenstem met `Some(value)`
}
```

In hierdie voorbeeld sal die lus uitgevoer word solank `optional_value` 'n waarde van `Some` het. Die waarde van `Some` sal dan toegewys word aan die `value` veranderlike, en die kode binne die lus sal uitgevoer word.

As `optional_value` `None` is, sal die lus nie uitgevoer word nie en die uitvoering sal voortgaan na die volgende stelling na die lus.

`while let` kan gebruik word met enige patroon wat ooreenstem met die waarde, soos `Some(value)`, `Ok(value)`, of selfs `x @ Some(value)` om die ooreenstemmende waarde aan 'n veranderlike toe te ken.

Hier is 'n voorbeeld van hoe `while let` gebruik kan word om waardes uit 'n vektor te verwyder totdat die vektor leeg is:

```rust
let mut vector = vec![1, 2, 3, 4, 5];

while let Some(value) = vector.pop() {
    println!("Verwyder waarde: {}", value);
}
```

In hierdie voorbeeld sal die lus herhaaldelik uitgevoer word en die waarde wat verwyder is uit die vektor sal gedruk word, totdat die vektor leeg is.
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

Skep 'n nuwe metode vir 'n tipe
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
### Toetse

In die wêreld van sagteware-ontwikkeling is toetse 'n kritieke stap om die funksionaliteit en betroubaarheid van 'n program te verseker. Hierdie afdeling sal 'n oorsig gee van die basiese beginsels van toetsing in die Rust-programmeertaal.

#### Eenheidstoetse

Eenheidstoetse is die laagste vlak van toetse en fokus op die toetsing van individuele eenhede van kode, soos funksies en metodes. Hierdie toetse word geskryf om te verseker dat elke eenheid korrek en onafhanklik van ander eenhede funksioneer.

In Rust kan jy eenheidstoetse skryf deur die `#[cfg(test)]` atribuut bo-aan jou toetsmodule te plaas. Jy kan dan funksies skryf wat die `#[test]` atribuut gebruik om toetse te definieer. Hier is 'n voorbeeld:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn it_adds_two_numbers() {
        assert_eq!(2 + 2, 4);
    }
}
```

In hierdie voorbeeld word 'n eenheidstoets gedefinieer met die naam `it_adds_two_numbers`. Die `assert_eq!` makro word gebruik om te verseker dat die uitdrukking `2 + 2` gelyk is aan `4`. As die toets slaag, sal daar geen uitset wees nie. As die toets misluk, sal daar 'n foutboodskap wees wat aandui waar die fout plaasgevind het.

Om jou eenheidstoetse uit te voer, kan jy die `cargo test` opdrag gebruik. Dit sal al die toetse in jou projek uitvoer en die resultate rapporteer.

#### Integrasiestoetse

Integrasiestoetse is die volgende vlak van toetse en fokus op die toetsing van die interaksie tussen verskillende eenhede van kode. Hierdie toetse word gebruik om te verseker dat die verskillende eenhede korrek saamwerk en die verwagte resultate produseer.

In Rust kan jy integrasiestoetse skryf deur die `#[cfg(test)]` atribuut bo-aan jou toetsmodule te plaas, net soos met eenheidstoetse. Jy kan dan funksies skryf wat die `#[test]` atribuut gebruik om toetse te definieer. Hier is 'n voorbeeld:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn it_concats_two_strings() {
        let result = format!("Hello, {}", "World!");
        assert_eq!(result, "Hello, World!");
    }
}
```

In hierdie voorbeeld word 'n integrasiestoets gedefinieer met die naam `it_concats_two_strings`. Die `format!` makro word gebruik om twee strings saam te voeg. Die `assert_eq!` makro word dan gebruik om te verseker dat die resultaat gelyk is aan die verwagte string. As die toets slaag, sal daar geen uitset wees nie. As die toets misluk, sal daar 'n foutboodskap wees wat aandui waar die fout plaasgevind het.

Net soos met eenheidstoetse, kan jy jou integrasiestoetse uitvoer deur die `cargo test` opdrag te gebruik.

#### Dekkingstoetse

Dekkingstoetse is 'n tegniek wat gebruik word om te meet hoeveel van jou kode deur toetse gedek word. Dit help om te verseker dat jy al jou kode toets en dat daar geen ongetoetste dele is nie.

In Rust kan jy dekkingstoetse uitvoer deur die `cargo tarpaulin` hulpmiddel te gebruik. Hier is 'n voorbeeld van hoe jy dit kan installeer en gebruik:

1. Voeg die volgende lyn by in jou `Cargo.toml` lêer onder die `[dev-dependencies]` afdeling:

   ```toml
   tarpaulin = "0.17.0"
   ```

2. Voer die volgende opdrag uit om die hulpmiddel te installeer:

   ```bash
   cargo install cargo-tarpaulin
   ```

3. Voer die volgende opdrag uit om die dekkingstoetse uit te voer:

   ```bash
   cargo tarpaulin --all
   ```

Hierdie opdrag sal die dekkingstoetse uitvoer en 'n verslag genereer wat wys hoeveel van jou kode gedek word deur toetse.

Dit is belangrik om te onthou dat dekkingstoetse nie altyd 'n volledige aanduiding van die kwaliteit van jou toetse bied nie. Dit is moontlik om 'n hoë dekkingspersentasie te hê, maar steeds belangrike foute te mis. Daarom is dit belangrik om 'n kombinasie van eenheidstoetse, integrasiestoetse en dekkingstoetse te gebruik om 'n volledige beeld van die toestand van jou kode te kry.
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

'n Arc kan Clone gebruik om meer verwysings na die voorwerp te skep om hulle aan die drade oor te dra. Wanneer die laaste verwysing na 'n waarde buite die omvang van die verwysing val, word die veranderlike laat vaal.
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
#### Drade

In hierdie geval sal ons die drade 'n veranderlike oorhandig wat dit kan wysig.
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

