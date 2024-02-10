# Fondamenti di Rust

### Tipi generici

Crea una struttura in cui uno dei suoi valori può essere di qualsiasi tipo.
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

Il tipo Option significa che il valore potrebbe essere di tipo Some (c'è qualcosa) o None:
```rust
pub enum Option<T> {
None,
Some(T),
}
```
Puoi utilizzare le funzioni come `is_some()` o `is_none()` per verificare il valore dell'Opzione.

### Macro

Le macro sono più potenti delle funzioni perché si espandono per produrre più codice rispetto a quello che hai scritto manualmente. Ad esempio, una firma di funzione deve dichiarare il numero e il tipo di parametri che la funzione ha. Le macro, d'altra parte, possono prendere un numero variabile di parametri: possiamo chiamare `println!("ciao")` con un argomento o `println!("ciao {}", nome)` con due argomenti. Inoltre, le macro vengono espandete prima che il compilatore interpreti il significato del codice, quindi una macro può, ad esempio, implementare un trait su un determinato tipo. Una funzione non può farlo, perché viene chiamata a runtime e un trait deve essere implementato a compile time.
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
### Iterare

L'iterazione è un concetto fondamentale nella programmazione. Consiste nel ripetere un blocco di codice per un certo numero di volte o fino a quando una determinata condizione viene soddisfatta. In Rust, ci sono diverse opzioni per implementare l'iterazione.

#### Loop

Il loop è il modo più semplice per iterare in Rust. Puoi utilizzare il costrutto `loop` per creare un ciclo infinito che può essere interrotto manualmente utilizzando l'istruzione `break`. Ad esempio:

```rust
loop {
    // Blocco di codice da eseguire ripetutamente
    if condition {
        break; // Interrompe il ciclo
    }
}
```

#### While

Il ciclo `while` viene utilizzato per eseguire un blocco di codice finché una determinata condizione è vera. Ad esempio:

```rust
while condition {
    // Blocco di codice da eseguire finché la condizione è vera
}
```

#### For

Il ciclo `for` viene utilizzato per iterare su una sequenza di elementi. Può essere utilizzato con una serie di numeri, un iteratore o una collezione. Ad esempio:

```rust
for item in collection {
    // Blocco di codice da eseguire per ogni elemento nella collezione
}
```

#### Iteratori

Gli iteratori sono un concetto potente in Rust che consentono di eseguire operazioni su una sequenza di elementi in modo dichiarativo. Gli iteratori possono essere combinati e concatenati per creare pipeline di elaborazione dei dati. Ad esempio:

```rust
let numbers = vec![1, 2, 3, 4, 5];

let sum: i32 = numbers.iter()
                      .filter(|&x| x % 2 == 0)
                      .map(|x| x * 2)
                      .sum();
```

In questo esempio, viene creato un vettore di numeri e viene calcolata la somma dei numeri pari moltiplicati per 2 utilizzando gli iteratori.

L'iterazione è un concetto fondamentale nella programmazione e comprendere le diverse opzioni disponibili in Rust ti aiuterà a scrivere codice più pulito ed efficiente.
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
### Box Ricorsivo

A recursive box is a data structure in Rust that allows for the creation of self-referential types. It is similar to a regular box, but with the ability to contain a value that refers to itself.

To create a recursive box, you can use the `Rc` (reference counting) or `Arc` (atomic reference counting) types provided by the `std::rc` module. These types allow multiple ownership of a value and keep track of the number of references to that value.

Here is an example of how to create a recursive box using `Rc`:

```rust
use std::rc::Rc;

struct Node {
    value: i32,
    next: Option<Rc<Node>>,
}

fn main() {
    let node1 = Rc::new(Node {
        value: 1,
        next: None,
    });

    let node2 = Rc::new(Node {
        value: 2,
        next: Some(Rc::clone(&node1)),
    });

    // Make node1 refer to node2
    node1.next = Some(Rc::clone(&node2));

    // Access the value of node1
    println!("Value of node1: {}", node1.value);

    // Access the value of node2 through node1
    if let Some(node2) = node1.next {
        println!("Value of node2: {}", node2.value);
    }
}
```

In this example, we define a `Node` struct that contains a value of type `i32` and an optional `Rc<Node>` that represents the next node in the linked list. By using `Rc`, we can create a circular reference between `node1` and `node2`, allowing us to traverse the linked list indefinitely.

Note that `Rc` is not thread-safe, so if you need to share the recursive box across multiple threads, you should use `Arc` instead.
```rust
enum List {
Cons(i32, List),
Nil,
}

let list = Cons(1, Cons(2, Cons(3, Nil)));
```
### Condizioni

#### if
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
#### corrispondenza

La parola chiave `match` in Rust viene utilizzata per eseguire il controllo dei modelli. Consente di confrontare un valore con una serie di modelli e di eseguire il codice corrispondente al modello che viene trovato. La sintassi di base è la seguente:

```rust
match valore {
    modello1 => {
        // codice da eseguire se il valore corrisponde al modello1
    },
    modello2 => {
        // codice da eseguire se il valore corrisponde al modello2
    },
    // altri modelli e codice corrispondente
}
```

È possibile utilizzare il modello `_` per gestire tutti i casi non corrispondenti ai modelli specificati. Ad esempio:

```rust
match valore {
    1 => {
        println!("Il valore è 1");
    },
    2 => {
        println!("Il valore è 2");
    },
    _ => {
        println!("Il valore non è né 1 né 2");
    }
}
```

Il blocco di codice corrispondente al modello che viene trovato viene eseguito e l'esecuzione del `match` termina. Se nessun modello corrisponde al valore, il codice non viene eseguito.
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
#### loop (infinito)

The `loop` keyword in Rust is used to create an infinite loop. The code inside the loop will continue to execute indefinitely until a break statement is encountered.

```rust
loop {
    // code to be executed repeatedly
    // until a break statement is encountered
}
```

Il termine `loop` in Rust viene utilizzato per creare un ciclo infinito. Il codice all'interno del ciclo continuerà ad eseguire indefinitamente fino a quando non viene incontrata un'istruzione di interruzione.

```rust
loop {
    // codice da eseguire ripetutamente
    // fino a quando non viene incontrata un'istruzione di interruzione
}
```
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

Il costrutto `while` in Rust viene utilizzato per eseguire un blocco di codice ripetutamente fintanto che una determinata condizione è vera. La sintassi del costrutto `while` è la seguente:

```rust
while condizione {
    // blocco di codice da eseguire
}
```

La condizione viene valutata all'inizio di ogni iterazione. Se la condizione è vera, il blocco di codice viene eseguito. Dopo l'esecuzione del blocco di codice, la condizione viene nuovamente valutata. Se la condizione è ancora vera, il blocco di codice viene eseguito di nuovo. Questo processo continua finché la condizione diventa falsa.

Ecco un esempio di utilizzo del costrutto `while` in Rust:

```rust
let mut count = 0;

while count < 5 {
    println!("Il valore di count è: {}", count);
    count += 1;
}
```

In questo esempio, il blocco di codice all'interno del costrutto `while` viene eseguito finché il valore di `count` è inferiore a 5. Ad ogni iterazione, viene stampato il valore di `count` e viene incrementato di 1.
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
#### per
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

La sintassi `if let` in Rust è un modo conciso per gestire il pattern matching in una singola istruzione. È utile quando si desidera eseguire un'azione specifica solo se un valore soddisfa un determinato pattern.

La sintassi di base è la seguente:

```rust
if let pattern = expression {
    // codice da eseguire se il pattern corrisponde all'espressione
} else {
    // codice da eseguire se il pattern non corrisponde all'espressione
}
```

In pratica, `if let` controlla se l'espressione corrisponde al pattern specificato. Se corrisponde, il codice all'interno del blocco `if` viene eseguito. In caso contrario, il codice all'interno del blocco `else` viene eseguito.

Ecco un esempio di utilizzo di `if let`:

```rust
let value = Some(5);

if let Some(x) = value {
    println!("Il valore è {}", x);
} else {
    println!("Il valore non è presente");
}
```

In questo esempio, `value` è un'opzione che contiene il valore `5`. Utilizzando `if let`, controlliamo se `value` corrisponde al pattern `Some(x)`. Se corrisponde, il valore `x` viene estratto e stampato a schermo. Altrimenti, viene stampato un messaggio che indica che il valore non è presente.

È possibile utilizzare `if let` anche con altri tipi di pattern, come ad esempio `Some(x)`, `None`, `Ok(x)`, `Err(x)`, ecc. Questa sintassi è particolarmente utile quando si lavora con opzioni, risultati o altri tipi di dati che possono avere valori o errori.
```rust
let optional_word = Some(String::from("rustlings"));
if let word = optional_word {
println!("The word is: {}", word);
} else {
println!("The optional word doesn't contain anything");
}
```
#### while let

Il costrutto `while let` in Rust è un modo conciso per iterare su un'opzione fino a quando non diventa `None`. Questo costrutto è utile quando si desidera eseguire un blocco di codice solo se l'opzione contiene un valore.

Ecco un esempio di come utilizzare `while let`:

```rust
let mut optional_number = Some(5);

while let Some(number) = optional_number {
    println!("Il numero è: {}", number);
    optional_number = None;
}
```

In questo esempio, abbiamo un'opzione `optional_number` che inizialmente contiene il valore `Some(5)`. Utilizzando `while let`, iteriamo sull'opzione finché contiene un valore. All'interno del blocco `while let`, stampiamo il numero e quindi assegnamo `None` all'opzione per terminare il ciclo.

L'output di questo codice sarà:

```
Il numero è: 5
```

Quando l'opzione diventa `None`, il ciclo termina.
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

Creare un nuovo metodo per un tipo

```rust
trait MyTrait {
    fn my_method(&self);
}

struct MyStruct;

impl MyTrait for MyStruct {
    fn my_method(&self) {
        println!("Hello from my_method!");
    }
}

fn main() {
    let my_struct = MyStruct;
    my_struct.my_method();
}
```

Il codice sopra definisce un trait chiamato `MyTrait` che ha un metodo chiamato `my_method`. Successivamente, viene definita una struttura chiamata `MyStruct` e viene implementato il trait `MyTrait` per questa struttura. L'implementazione del metodo `my_method` stampa "Hello from my_method!". Infine, nel metodo `main`, viene creato un'istanza di `MyStruct` chiamata `my_struct` e viene chiamato il metodo `my_method` su di essa.
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
### Test

I test sono una parte essenziale dello sviluppo del software. I test consentono di verificare che il codice funzioni correttamente e che soddisfi i requisiti specificati. Ci sono diversi tipi di test che possono essere eseguiti durante il processo di sviluppo del software.

#### Test di unità

I test di unità sono utilizzati per verificare il corretto funzionamento di singole unità di codice, come funzioni o metodi. Questi test sono solitamente scritti dagli sviluppatori stessi e possono essere eseguiti in modo automatico.

#### Test di integrazione

I test di integrazione sono utilizzati per verificare che le diverse unità di codice funzionino correttamente quando vengono combinate insieme. Questi test sono solitamente scritti dagli sviluppatori o dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di sistema

I test di sistema sono utilizzati per verificare che l'intero sistema funzioni correttamente. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di accettazione

I test di accettazione sono utilizzati per verificare che il sistema soddisfi i requisiti specificati dal cliente o dagli utenti finali. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di regressione

I test di regressione sono utilizzati per verificare che le modifiche apportate al codice non abbiano introdotto nuovi bug o rotto funzionalità esistenti. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di carico

I test di carico sono utilizzati per verificare come il sistema si comporta sotto carichi di lavoro elevati. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di sicurezza

I test di sicurezza sono utilizzati per verificare la sicurezza del sistema e identificare eventuali vulnerabilità o falle di sicurezza. Questi test sono solitamente eseguiti da specialisti in sicurezza informatica o hacker etici.

#### Test di performance

I test di performance sono utilizzati per verificare le prestazioni del sistema, come la velocità di risposta e la scalabilità. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di stress

I test di stress sono utilizzati per verificare come il sistema si comporta in situazioni di stress estreme, come carichi di lavoro molto elevati o risorse limitate. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di usabilità

I test di usabilità sono utilizzati per verificare la facilità d'uso del sistema da parte degli utenti finali. Questi test sono solitamente eseguiti da specialisti in usabilità o dagli ingegneri di test.

#### Test di compatibilità

I test di compatibilità sono utilizzati per verificare che il sistema funzioni correttamente su diverse piattaforme, browser o dispositivi. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di localizzazione

I test di localizzazione sono utilizzati per verificare che il sistema funzioni correttamente in diverse lingue o regioni. Questi test sono solitamente eseguiti da specialisti in localizzazione o dagli ingegneri di test.

#### Test di automazione

I test di automazione sono utilizzati per automatizzare l'esecuzione dei test, riducendo così il tempo e lo sforzo necessari per eseguirli manualmente. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico.

#### Test di copertura

I test di copertura sono utilizzati per verificare quanto del codice è stato testato. Questi test sono solitamente eseguiti dagli strumenti di test e possono essere eseguiti in modo automatico.

#### Test di robustezza

I test di robustezza sono utilizzati per verificare come il sistema si comporta in presenza di input non validi o inaspettati. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di manutenibilità

I test di manutenibilità sono utilizzati per verificare quanto sia facile mantenere e modificare il codice. Questi test sono solitamente eseguiti dagli strumenti di test e possono essere eseguiti in modo automatico.

#### Test di ripristino

I test di ripristino sono utilizzati per verificare che il sistema possa essere ripristinato correttamente dopo un guasto o un'interruzione. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di regressione visiva

I test di regressione visiva sono utilizzati per verificare che le modifiche apportate al sistema non abbiano alterato l'aspetto visivo. Questi test sono solitamente eseguiti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.

#### Test di accessibilità

I test di accessibilità sono utilizzati per verificare che il sistema sia accessibile a persone con disabilità o esigenze speciali. Questi test sono solitamente eseguiti da specialisti in accessibilità o dagli ingegneri di test.

#### Test di uscita

I test di uscita sono utilizzati per verificare che il sistema sia pronto per essere rilasciato in produzione. Questi test sono solitamente scritti dagli ingegneri di test e possono essere eseguiti in modo automatico o manuale.
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

Un Arc può utilizzare Clone per creare ulteriori riferimenti sull'oggetto da passare ai thread. Quando l'ultimo riferimento puntato a un valore esce dallo scope, la variabile viene eliminata.
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

In questo caso passeremo al thread una variabile che sarà in grado di modificare.
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

