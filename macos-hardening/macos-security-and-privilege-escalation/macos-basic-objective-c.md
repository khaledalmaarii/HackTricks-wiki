# macOS Objective-C

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null auf Heldenniveau mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Objective-C

{% hint style="danger" %}
Beachten Sie, dass Programme, die in Objective-C geschrieben sind, ihre Klassendeklarationen beibehalten, wenn sie in [Mach-O-Binärdateien](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) kompiliert werden. Solche Klassendeklarationen enthalten den Namen und Typ von:
{% endhint %}

* Die Klasse
* Die Klassenmethoden
* Die Instanzvariablen der Klasse

Sie können diese Informationen mit [**class-dump**](https://github.com/nygard/class-dump) erhalten:
```bash
class-dump Kindle.app
```
Hinweis: Diese Namen können verschleiert werden, um das Reverse Engineering der Binärdatei zu erschweren.

## Klassen, Methoden & Objekte

### Schnittstelle, Eigenschaften & Methoden
```objectivec
// Declare the interface of the class
@interface MyVehicle : NSObject

// Declare the properties
@property NSString *vehicleType;
@property int numberOfWheels;

// Declare the methods
- (void)startEngine;
- (void)addWheels:(int)value;

@end
```
### **Klasse**
```objectivec
@implementation MyVehicle : NSObject

// No need to indicate the properties, only define methods

- (void)startEngine {
NSLog(@"Engine started");
}

- (void)addWheels:(int)value {
self.numberOfWheels += value;
}

@end
```
### **Objekt & Methodenaufruf**

Um eine Instanz einer Klasse zu erstellen, wird die Methode **`alloc`** aufgerufen, die **Speicher zuweist** für jede **Eigenschaft** und diese Zuweisungen auf **Null setzt**. Anschließend wird **`init`** aufgerufen, um die Eigenschaften auf die **erforderlichen Werte** zu **initialisieren**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Klassenmethoden**

Klassenmethoden werden mit dem **Pluszeichen** (+) definiert, nicht mit dem Bindestrich (-), der bei Instanzmethoden verwendet wird. Wie die Klassenmethode **`stringWithString`** der **NSString**-Klasse:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Um Eigenschaften zu **setzen** und **abzurufen**, können Sie dies entweder mit der **Punktnotation** oder wie bei einem **Methodenaufruf** tun:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Instanzvariablen**

Alternativ zu Setter- und Getter-Methoden können Sie Instanzvariablen verwenden. Diese Variablen haben den gleichen Namen wie die Eigenschaften, beginnen jedoch mit einem "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protokolle

Protokolle sind eine Reihe von Methodendeklarationen (ohne Eigenschaften). Eine Klasse, die ein Protokoll implementiert, implementiert die deklarierten Methoden.

Es gibt 2 Arten von Methoden: **obligatorische** und **optionale**. Standardmäßig ist eine Methode **obligatorisch** (aber du kannst es auch mit einem **`@required`**-Tag angeben). Um anzuzeigen, dass eine Methode optional ist, verwende **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Alles zusammen

In diesem Abschnitt werden einige grundlegende Konzepte der Objective-C-Programmierung auf macOS behandelt. Es wird erläutert, wie Klassen, Methoden, Eigenschaften und Protokolle in Objective-C definiert werden.

#### Klassen

Eine Klasse ist eine Vorlage oder ein Bauplan, der die Eigenschaften und Verhaltensweisen von Objekten definiert. In Objective-C werden Klassen mit dem Schlüsselwort `@interface` eingeführt, gefolgt vom Klassennamen und einer optionalen Elternklasse in Klammern. Die Instanzvariablen der Klasse werden innerhalb der geschweiften Klammern deklariert.

```objective-c
@interface MeineKlasse : Elternklasse
{
    // Instanzvariablen
}
@end
```

#### Methoden

Methoden sind Funktionen, die in einer Klasse definiert sind und von Objekten dieser Klasse aufgerufen werden können. In Objective-C werden Methoden mit dem Schlüsselwort `-(Rückgabetyp)MethodName:(ParameterTyp)parameterName` deklariert. Der Rückgabetyp kann ein beliebiger Datentyp sein, und die Parameter können optional sein.

```objective-c
-(int)addiereZahl1:(int)zahl1 mitZahl2:(int)zahl2;
```

#### Eigenschaften

Eigenschaften sind Attribute einer Klasse, die den Zugriff auf Instanzvariablen steuern. In Objective-C werden Eigenschaften mit dem Schlüsselwort `@property` deklariert, gefolgt von Attributen wie `nonatomic`, `strong`, `weak`, `readonly` usw.

```objective-c
@property (nonatomic, strong) NSString *name;
```

#### Protokolle

Protokolle definieren eine Schnittstelle, die von Klassen implementiert werden kann. Sie legen fest, welche Methoden eine Klasse implementieren muss, um das Protokoll zu erfüllen. In Objective-C werden Protokolle mit dem Schlüsselwort `@protocol` eingeführt.

```objective-c
@protocol MeinProtokoll
-(void)protokollMethode;
@end
```

Diese grundlegenden Konzepte der Objective-C-Programmierung sind wichtig, um das Verständnis von macOS-Sicherheit und Privileg-Eskalation zu vertiefen.
```objectivec
// gcc -framework Foundation test_obj.m -o test_obj
#import <Foundation/Foundation.h>

@protocol myVehicleProtocol
- (void) startEngine; //mandatory
@required
- (void) addWheels:(int)value; //mandatory
@optional
- (void) makeLongTruck; //optional
@end

@interface MyVehicle : NSObject <myVehicleProtocol>

@property int numberOfWheels;

- (void)startEngine;
- (void)addWheels:(int)value;
- (void)makeLongTruck;

@end

@implementation MyVehicle : NSObject

- (void)startEngine {
NSLog(@"Engine started");
}

- (void)addWheels:(int)value {
self.numberOfWheels += value;
}

- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfWheels);
}

@end

int main() {
MyVehicle* mySuperCar = [MyVehicle new];
[mySuperCar startEngine];
mySuperCar.numberOfWheels = 4;
NSLog(@"Number of wheels: %i", mySuperCar.numberOfWheels);
[mySuperCar setNumberOfWheels:3];
NSLog(@"Number of wheels: %i", mySuperCar.numberOfWheels);
[mySuperCar makeLongTruck];
}
```
### Grundlegende Klassen

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Grundlegende Klassen sind **unveränderlich**, daher muss zum Hinzufügen eines Strings zu einem vorhandenen ein **neues NSString erstellt werden**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Oder Sie könnten auch eine **veränderbare** Zeichenkettenklasse verwenden:

{% code overflow="wrap" %}
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
{% endcode %}

#### Nummer

{% code overflow="wrap" %}
```objectivec
// character literals.
NSNumber *theLetterZ = @'Z'; // equivalent to [NSNumber numberWithChar:'Z']

// integral literals.
NSNumber *fortyTwo = @42; // equivalent to [NSNumber numberWithInt:42]
NSNumber *fortyTwoUnsigned = @42U; // equivalent to [NSNumber numberWithUnsignedInt:42U]
NSNumber *fortyTwoLong = @42L; // equivalent to [NSNumber numberWithLong:42L]
NSNumber *fortyTwoLongLong = @42LL; // equivalent to [NSNumber numberWithLongLong:42LL]

// floating point literals.
NSNumber *piFloat = @3.141592654F; // equivalent to [NSNumber numberWithFloat:3.141592654F]
NSNumber *piDouble = @3.1415926535; // equivalent to [NSNumber numberWithDouble:3.1415926535]

// BOOL literals.
NSNumber *yesNumber = @YES; // equivalent to [NSNumber numberWithBool:YES]
NSNumber *noNumber = @NO; // equivalent to [NSNumber numberWithBool:NO]
```
{% endcode %}

#### Array, Sets & Dictionary

{% code overflow="wrap" %}
```objectivec
// Inmutable arrays
NSArray *colorsArray1 = [NSArray arrayWithObjects:@"red", @"green", @"blue", nil];
NSArray *colorsArray2 = @[@"yellow", @"cyan", @"magenta"];
NSArray *colorsArray3 = @[firstColor, secondColor, thirdColor];

// Mutable arrays
NSMutableArray *mutColorsArray = [NSMutableArray array];
[mutColorsArray addObject:@"red"];
[mutColorsArray addObject:@"green"];
[mutColorsArray addObject:@"blue"];
[mutColorsArray addObject:@"yellow"];
[mutColorsArray replaceObjectAtIndex:0 withObject:@"purple"];

// Inmutable Sets
NSSet *fruitsSet1 = [NSSet setWithObjects:@"apple", @"banana", @"orange", nil];
NSSet *fruitsSet2 = [NSSet setWithArray:@[@"apple", @"banana", @"orange"]];

// Mutable sets
NSMutableSet *mutFruitsSet = [NSMutableSet setWithObjects:@"apple", @"banana", @"orange", nil];
[mutFruitsSet addObject:@"grape"];
[mutFruitsSet removeObject:@"apple"];


// Dictionary
NSDictionary *fruitColorsDictionary = @{
@"apple" : @"red",
@"banana" : @"yellow",
@"orange" : @"orange",
@"grape" : @"purple"
};

// In dictionaryWithObjectsAndKeys you specify the value and then the key:
NSDictionary *fruitColorsDictionary2 = [NSDictionary dictionaryWithObjectsAndKeys:
@"red", @"apple",
@"yellow", @"banana",
@"orange", @"orange",
@"purple", @"grape",
nil];

// Mutable dictionary
NSMutableDictionary *mutFruitColorsDictionary = [NSMutableDictionary dictionaryWithDictionary:fruitColorsDictionary];
[mutFruitColorsDictionary setObject:@"green" forKey:@"apple"];
[mutFruitColorsDictionary removeObjectForKey:@"grape"];
```
{% endcode %}

### Blöcke

Blöcke sind **Funktionen, die sich wie Objekte verhalten**, sodass sie an Funktionen übergeben oder in **Arrays** oder **Dictionaries** gespeichert werden können. Außerdem können sie **einen Wert darstellen, wenn ihnen Werte gegeben werden**, ähnlich wie Lambdas.
```objectivec
returnType (^blockName)(argumentType1, argumentType2, ...) = ^(argumentType1 param1, argumentType2 param2, ...){
//Perform operations here
};

// For example

int (^suma)(int, int) = ^(int a, int b){
return a+b;
};
NSLog(@"3+4 = %d", suma(3,4));
```
{% endcode %}

Es ist auch möglich, **einen Blocktyp zu definieren, der als Parameter** in Funktionen verwendet werden soll:
```objectivec
// Define the block type
typedef void (^callbackLogger)(void);

// Create a bloack with the block type
callbackLogger myLogger = ^{
NSLog(@"%@", @"This is my block");
};

// Use it inside a function as a param
void genericLogger(callbackLogger blockParam) {
NSLog(@"%@", @"This is my function");
blockParam();
}
genericLogger(myLogger);

// Call it inline
genericLogger(^{
NSLog(@"%@", @"This is my second block");
});
```
### Dateien

{% code overflow="wrap" %}
```objectivec
// Manager to manage files
NSFileManager *fileManager = [NSFileManager defaultManager];

// Check if file exists:
if ([fileManager fileExistsAtPath:@"/path/to/file.txt" ] == YES) {
NSLog (@"File exists");
}

// copy files
if ([fileManager copyItemAtPath: @"/path/to/file1.txt" toPath: @"/path/to/file2.txt" error:nil] == YES) {
NSLog (@"Copy successful");
}

// Check if the content of 2 files match
if ([fileManager contentsEqualAtPath:@"/path/to/file1.txt" andPath:@"/path/to/file2.txt"] == YES) {
NSLog (@"File contents match");
}

// Delete file
if ([fileManager removeItemAtPath:@"/path/to/file1.txt" error:nil]) {
NSLog(@"Removed successfully");
}
```
{% endcode %}

Es ist auch möglich, Dateien **mit `NSURL`-Objekten anstelle von `NSString`-Objekten** zu verwalten. Die Methodennamen sind ähnlich, aber **mit `URL` anstelle von `Path`**.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
Die meisten grundlegenden Klassen haben eine Methode `writeToFile:<Pfad> atomically:<YES> encoding:<encoding> error:nil`, die es ihnen ermöglicht, direkt in eine Datei geschrieben zu werden:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
