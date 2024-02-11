# Misingi ya Rust

### Aina za Kawaida

Unda muundo ambapo moja ya thamani zake inaweza kuwa aina yoyote
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
### Chaguo, Baadhi & Hakuna

Aina ya Chaguo inamaanisha kuwa thamani inaweza kuwa ya aina ya Baadhi (kuna kitu) au Hakuna:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Unaweza kutumia kazi kama vile `is_some()` au `is_none()` kuangalia thamani ya Chaguo.

### Macros

Macros ni nguvu zaidi kuliko kazi kwa sababu zinaongezeka ili kuzalisha msimbo zaidi kuliko msimbo uliyoandika kwa mkono. Kwa mfano, saini ya kazi lazima itangaze idadi na aina ya vigezo ambavyo kazi ina. Macros, kwa upande mwingine, inaweza kuchukua idadi isiyojulikana ya vigezo: tunaweza kuita `println!("hello")` na hoja moja au `println!("hello {}", jina)` na hoja mbili. Pia, macros zinaongezeka kabla ya mkusanyaji kufasiri maana ya msimbo, kwa hivyo macro inaweza, kwa mfano, kutekeleza tabia kwenye aina iliyoombwa. Kazi haiwezi, kwa sababu inaitwa wakati wa kukimbia na tabia inahitaji kutekelezwa wakati wa kukusanya.
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
### Endelea

Kuendelea ni mchakato wa kurudia hatua au vitendo kwa mfululizo. Katika programu, kuendelea kunahusisha kutumia mzunguko au kisanduku cha kudhibiti ili kurudia hatua au kifungo cha msimbo mara kadhaa. Hii inaweza kuwa muhimu wakati unahitaji kufanya kitendo fulani mara kadhaa au kuchambua data nyingi.

Katika lugha ya programu ya Rust, unaweza kutumia mzunguko wa `loop`, `while`, au `for` kutekeleza kuendelea. Mzunguko wa `loop` unarudia hatua zilizomo ndani yake hadi kisanduku cha kudhibiti kisitishwe. Mzunguko wa `while` unarudia hatua zilizomo ndani yake wakati hali fulani inatimizwa. Mzunguko wa `for` unarudia hatua zilizomo ndani yake kwa kila kipengee katika mkusanyiko uliopewa.

Kwa mfano, hapa kuna jinsi ya kutumia mzunguko wa `loop` katika Rust:

```rust
loop {
    // Hatua zinazorudiwa
    // ...
    if condition {
        break; // Kuvunja mzunguko
    }
}
```

Hapa kuna jinsi ya kutumia mzunguko wa `while` katika Rust:

```rust
while condition {
    // Hatua zinazorudiwa
    // ...
}
```

Hapa kuna jinsi ya kutumia mzunguko wa `for` katika Rust:

```rust
for item in collection {
    // Hatua zinazorudiwa
    // ...
}
```

Kwa kutumia mzunguko huu, unaweza kuendelea kurudia hatua au vitendo kwa urahisi katika programu yako ya Rust.
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
### Sanduku la Kurejesha

Sanduku la kurejesha ni mbinu ya kurejesha kiotomatiki ambayo inaruhusu kazi ya kurejesha kujirudia yenyewe hadi hali ya kutokea itakapokidhiwa. Mbinu hii inategemea wito wa kazi yenyewe ndani ya kazi hiyo hiyo.

Kwa mfano, fikiria una kazi inayoitwa `kazi_yangu` ambayo inahitaji kufanya kitu fulani. Unaweza kutumia sanduku la kurejesha ili kuhakikisha kuwa kazi hiyo inajirudia hadi hali fulani itakapokidhiwa. Hii inaweza kuwa muhimu katika kesi ambapo unahitaji kufanya jaribio la kurejesha kwa muda fulani au kufuatilia hali fulani hadi itakapobadilika.

Kwa kutumia sanduku la kurejesha, unaweza kuandika kificho cha kurejesha ambacho kinajumuisha wito wa kazi yenyewe. Hii inamaanisha kuwa kazi yako itajirudia yenyewe hadi hali fulani itakapokidhiwa. Kwa mfano:

```rust
fn kazi_yangu() {
    // Fanya kitu fulani

    if hali_haijakidhiwa {
        kazi_yangu(); // Rudia kazi yenyewe
    }
}
```

Katika mfano huu, kazi ya `kazi_yangu` itajirudia yenyewe hadi hali ya `hali_haijakidhiwa` itakapokidhiwa. Hii inaruhusu kazi hiyo kujirudia kiotomatiki hadi hali inayotarajiwa itakapofikiwa.

Sanduku la kurejesha ni mbinu muhimu katika programu za kiotomatiki na inaweza kutumika kwa ufanisi katika kazi za kurudia-rudia na kufuatilia hali.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
#### kama

The `if` statement is used to execute a block of code only if a certain condition is true. If the condition is false, the code block is skipped.

Syntax:

```rust
if condition {
    // code to be executed if the condition is true
}
```

Example:

```rust
let number = 10;

if number > 5 {
    println!("The number is greater than 5");
}
```

#### kama

Kauli ya `kama` hutumiwa kutekeleza kikundi cha nambari ikiwa tu hali fulani ni kweli. Ikiwa hali ni ya uwongo, kikundi cha nambari kinapuuzwa.

Muundo:

```rust
kama hali {
    // nambari itakayotekelezwa ikiwa hali ni kweli
}
```

Mfano:

```rust
let number = 10;

kama number > 5 {
    println!("Nambari ni kubwa kuliko 5");
}
```
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
#### kulinganisha

`match` ni neno la msingi katika Rust ambalo linaruhusu kulinganisha thamani ya kipekee na kutekeleza hatua tofauti kulingana na matokeo ya kulinganisha. Inafanana na `switch` katika lugha zingine.

Sintaksia ya `match` ni kama ifuatavyo:

```rust
match expression {
    pattern1 => {
        // Hatua za kuchukua ikiwa expression inalingana na pattern1
    },
    pattern2 => {
        // Hatua za kuchukua ikiwa expression inalingana na pattern2
    },
    // ...
    _ => {
        // Hatua za kuchukua ikiwa expression hailingani na patterns zozote
    }
}
```

Katika mfano huu, `expression` ni thamani ambayo tunataka kulinganisha na `pattern`. Kila `pattern` inalinganishwa kwa utaratibu, na hatua zinazofuata zinatekelezwa kwa `pattern` ya kwanza inayolingana.

Kwa mfano, ikiwa tunataka kuchukua hatua tofauti kulingana na siku ya wiki, tunaweza kutumia `match` kama ifuatavyo:

```rust
fn main() {
    let day = "Jumatatu";

    match day {
        "Jumatatu" => println!("Leo ni Jumatatu!"),
        "Jumanne" => println!("Leo ni Jumanne!"),
        "Jumatano" => println!("Leo ni Jumatano!"),
        "Alhamisi" => println!("Leo ni Alhamisi!"),
        "Ijumaa" => println!("Leo ni Ijumaa!"),
        "Jumamosi" => println!("Leo ni Jumamosi!"),
        "Jumapili" => println!("Leo ni Jumapili!"),
        _ => println!("Hii sio siku ya wiki!"),
    }
}
```

Katika mfano huu, tunalinganisha `day` na kila `pattern` ya siku ya wiki. Ikiwa `day` inalingana na `pattern` fulani, basi hatua inayofuata inatekelezwa. Ikiwa `day` hailingani na patterns zozote, hatua ya mwisho inatekelezwa.
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
#### mzunguko (usio na mwisho)
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
#### wakati

The `while` loop is used to repeatedly execute a block of code as long as a specified condition is true. The condition is checked before each iteration, and if it evaluates to true, the code block is executed. Once the condition becomes false, the loop is terminated and the program continues with the next line of code after the loop.

Syntax:

```rust
while condition {
    // code to be executed
}
```

Example:

```rust
let mut count = 0;

while count < 5 {
    println!("Count: {}", count);
    count += 1;
}
```

In this example, the code block inside the `while` loop will be executed as long as the `count` variable is less than 5. The value of `count` is printed and incremented by 1 in each iteration.
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
#### kwa
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
#### ikiwa let

`if let` ni njia ya kifupi ya kuchunguza na kufanya kitendo ikiwa kuna chaguo moja tu la kufanikiwa. Inafanya kazi kwa kuchunguza ikiwa chaguo linaweza kufanikiwa na kisha kutekeleza kitendo kilichomo ndani ya block ya `if let` ikiwa chaguo linapatikana.

Sintaksia ya `if let` ni kama ifuatavyo:

```rust
if let Some(value) = optional_value {
    // Kitendo kinachotekelezwa ikiwa chaguo linapatikana
} else {
    // Kitendo kinachotekelezwa ikiwa chaguo halipatikani
}
```

Katika mfano huu, `optional_value` ni chaguo ambalo linaweza kuwa na thamani au linaweza kuwa tupu. Ikiwa `optional_value` lina thamani, thamani hiyo itahifadhiwa katika `value` na kitendo kilichomo ndani ya block ya `if let` kitatekelezwa. Ikiwa `optional_value` ni tupu, kitendo kilichomo ndani ya block ya `else` kitatekelezwa badala yake.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### wakati aina

`while let` ni muundo wa kudhibiti wa Rust ambao unaruhusu kutekeleza kifungu cha msimbo wakati aina fulani inalingana na kigezo kilichotolewa. Inafanana na `while` kwa njia ya kawaida, lakini inaruhusu kuchambua na kufikia thamani ya kigezo kwa urahisi.

Muundo wa `while let` ni kama ifuatavyo:

```rust
while let Some(value) = kigezo {
    // Msimbo wa kutekelezwa
}
```

Katika mfano huu, `while let` itaendelea kutekeleza msimbo ndani ya mabano ya wakati thamani ya `kigezo` inalingana na `Some(value)`. `Some(value)` inawakilisha hali ambapo kigezo kina thamani isiyo tupu, na thamani hiyo inapatikana kwa jina `value` ndani ya kifungu cha msimbo.

Kwa mfano, ikiwa tuna kigezo cha aina `Option<i32>` kinachowakilisha nambari au tupu, tunaweza kutumia `while let` kutekeleza msimbo wakati kigezo kina nambari:

```rust
let mut kigezo = Some(5);

while let Some(value) = kigezo {
    println!("Thamani ya kigezo ni: {}", value);
    kigezo = None;
}
```

Katika mfano huu, msimbo ndani ya `while let` utatekelezwa mara moja tu kwa sababu thamani ya `kigezo` ni `Some(5)`. Baada ya kutekeleza msimbo, thamani ya `kigezo` inabadilishwa kuwa tupu (`None`), na kwa hivyo, `while let` haitatekelezwa tena.
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

Unda njia mpya kwa ajili ya aina fulani
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
### Majaribio

Majaribio ni sehemu muhimu ya mchakato wa kupima usalama wa mfumo. Kwa kutumia majaribio, unaweza kugundua kasoro na mapungufu katika mfumo wako na kuchukua hatua za kurekebisha. Kuna aina tofauti za majaribio ambayo unaweza kufanya, kama vile majaribio ya kuingilia kati (interception tests), majaribio ya kuvunja (break tests), na majaribio ya kusimamisha (halt tests).

#### Majaribio ya Kuingilia Kati (Interception Tests)

Majaribio ya kuingilia kati yanahusisha kuchunguza na kurekodi mawasiliano kati ya seva na wateja. Kwa kufanya hivyo, unaweza kugundua ikiwa kuna mawasiliano yoyote yasiyofaa au ya kutiliwa shaka yanayotokea. Unaweza kutumia zana kama Wireshark au tcpdump kufanya majaribio haya.

#### Majaribio ya Kuvunja (Break Tests)

Majaribio ya kuvunja yanahusisha kujaribu kuvunja mfumo wa usalama kwa kutumia mbinu tofauti za kuvunja. Hii inaweza kujumuisha kujaribu kuvunja nywila, kuingia kwa kutumia udhaifu wa programu, au kujaribu kuvunja mfumo wa kizuizi. Kwa kufanya majaribio haya, unaweza kugundua mapungufu katika mfumo wako na kuchukua hatua za kurekebisha.

#### Majaribio ya Kusimamisha (Halt Tests)

Majaribio ya kusimamisha yanahusisha kujaribu kusimamisha au kuharibu mfumo wa kompyuta. Hii inaweza kujumuisha kujaribu kusimamisha huduma muhimu, kuharibu faili muhimu, au kusababisha mfumo kushindwa kufanya kazi. Kwa kufanya majaribio haya, unaweza kugundua udhaifu katika mfumo wako na kuchukua hatua za kuzuia na kurekebisha.
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

Arc inaweza kutumia Clone kuunda marejeleo zaidi juu ya kitu ili kuyapitisha kwenye nyuzi. Wakati kumbukumbu ya mwisho inayoelekeza kwa thamani inatoka kwenye wigo, kivinjari kinatupwa.
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
#### Nyuzi

Katika kesi hii tutapitisha nyuzi kwa kigezo ambacho itaweza kubadilisha
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

