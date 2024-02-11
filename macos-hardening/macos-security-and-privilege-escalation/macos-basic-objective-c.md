# macOS Objective-C

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Objective-C

{% hint style="danger" %}
Let daarop dat programme geskryf in Objective-C **hul klasverklarings behou** wanneer hulle gekompileer word in [Mach-O-binêre](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Sulke klasverklarings **bevat** die naam en tipe van:
{% endhint %}

* Die klas
* Die klasmetodes
* Die klas-instansie-variables

Jy kan hierdie inligting kry deur [**class-dump**](https://github.com/nygard/class-dump) te gebruik:
```bash
class-dump Kindle.app
```
Let wel dat hierdie name geobfuskeer kan word om die omkeer van die binêre kode moeiliker te maak.

## Klasse, Metodes & Objekte

### Koppelvlak, Eienskappe & Metodes
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
### **Klas**
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
### **Objek & Roep Metode Aan**

Om 'n instansie van 'n klas te skep, word die **`alloc`**-metode geroep wat geheue toewys vir elke **eienskap** en dit **nulstel**. Dan word **`init`** geroep, wat die eienskappe **inisialiseer** na die **vereiste waardes**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Klasmetodes**

Klasmetodes word gedefinieer met die **plusteken** (+) en nie die strepie (-) wat gebruik word met instansiemetodes. Soos die **NSString** klasmetode **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Om eienskappe te **stel** en **kry**, kan jy dit doen met 'n **puntnotasie** of asof jy 'n **metode aanroep**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Instansie Veranderlikes**

Alternatiewelik tot setter- en getter-metodes kan jy instansie veranderlikes gebruik. Hierdie veranderlikes het dieselfde naam as die eienskappe, maar begin met 'n "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protokolle

Protokolle is 'n stel metodeverklarings (sonder eienskappe). 'n Klas wat 'n protokol implementeer, implementeer die verklaarde metodes.

Daar is 2 tipes metodes: **verpligtend** en **opsioneel**. Standaard is 'n metode **verpligtend** (maar jy kan dit ook aandui met 'n **`@required`** etiket). Om aan te dui dat 'n metode opsioneel is, gebruik **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Alles saam

Hier is 'n oorsig van die belangrikste aspekte van die Objective-C-programmeertaal:

#### Klasdefinisies

Klasdefinisies word gebruik om die eienskappe en gedrag van 'n objek te beskryf. Dit sluit in die definisie van instansie- en klasmetodes, eienskappe en protokolle.

#### Metodes

Metodes is funksies wat spesifieke gedrag aan 'n objek toeken. Dit kan instansie- of klasmetodes wees.

#### Eienskappe

Eienskappe is veranderlikes wat die toestand van 'n objek voorstel. Dit kan openbaar of privaat wees.

#### Protokolle

Protokolle definieer 'n stel vereistes wat 'n klas moet nakom. Dit maak interaksie tussen klasse moontlik sonder om 'n gemeenskaplike basisimplementering te vereis.

#### Inhouding

Inhouding is die proses waarin 'n klas die eienskappe en metodes van 'n ander klas erwe. Dit maak hergebruik van kode moontlik en bevorder die herbruikbaarheid en onderhoudbaarheid van programme.

#### Polimorfisme

Polimorfisme verwys na die vermoë van 'n objek om verskillende vorme aan te neem. Dit maak dit moontlik om 'n enkele metode te gebruik om verskillende tipes objekte te hanteer.

#### Geheuebestuur

Objective-C maak gebruik van handmatige geheuebestuur. Dit beteken dat die ontwikkelaar verantwoordelik is vir die toekenning en vrylating van geheue vir objekte.

#### Uitsonderingshantering

Objective-C bied 'n stelsel vir die hantering van uitsonderings. Dit maak dit moontlik om fouttoestande te hanteer en te herstel.

#### Delegasie

Delegasie is 'n ontwerppatroon wat gebruik word om die verantwoordelikhede van 'n objek na 'n ander objek te skuif. Dit bevorder die herbruikbaarheid en modulariteit van kode.

#### Kategorieë

Kategorieë maak dit moontlik om bestaande klasse uit te brei sonder om die oorspronklike bronkode te wysig. Dit bied 'n manier om funksionaliteit by te voeg sonder om 'n nuwe klasse te skep.

#### Blokke

Blokke is stukke kode wat as argumente aan metodes kan oorgedra word. Dit maak dit moontlik om funksionaliteit dinamies te verander en te hergebruik.

Hierdie konsepte is van kritieke belang vir die begrip van Objective-C en sal jou help om effektief te programmeer in hierdie taal.
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
### Basiese Klasse

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Basiese klasse is **onveranderlik**, so om 'n string by 'n bestaande een te voeg, moet 'n **nuwe NSString geskep word**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Of jy kan ook 'n **veranderlike** string klas gebruik:

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

#### Nommer

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
#### Reeks, Stelle & Woordeboek

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

### Blokke

Blokke is **funksies wat as objekte optree**, sodat hulle aan funksies kan word oorgedra of in **arrays** of **woordeboeke** kan word **gestoor**. Hulle kan ook **'n waarde verteenwoordig as daar waardes aan hulle gegee word**, so dit is soortgelyk aan lambdas.
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

Dit is ook moontlik om **'n blok tipe te definieer wat as 'n parameter gebruik kan word** in funksies:
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
### Lêers

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

Dit is ook moontlik om lêers te bestuur **deur gebruik te maak van `NSURL`-voorwerpe in plaas van `NSString`-voorwerpe**. Die metode name is soortgelyk, maar **met `URL` in plaas van `Path`**.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
Die meeste basiese klasse het 'n metode `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` wat dit moontlik maak om hulle direk na 'n lêer te skryf:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
