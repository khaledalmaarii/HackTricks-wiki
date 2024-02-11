# macOS Objective-C

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Objective-C

{% hint style="danger" %}
Tafadhali kumbuka kuwa programu zilizoandikwa kwa Objective-C **huzingatia** tamko la darasa **wakati** **zinafanywa** kuwa [Mach-O binaries](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tamko hilo la darasa **linajumuisha** jina na aina ya:
{% endhint %}

* Darasa
* Njia za darasa
* Viwango vya kipekee vya darasa

Unaweza kupata habari hii kwa kutumia [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Tafadhali kumbuka kuwa majina haya yanaweza kufichwa ili kufanya kurejesha ya binary iwe ngumu zaidi.

## Madarasa, Njia & Vitu

### Kiolesura, Mali & Njia
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
### **Darasa**
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
### **Kitu & Piga Njia**

Ili kuunda kipengele cha darasa, njia ya **`alloc`** inaitwa ambayo **hutenga kumbukumbu** kwa kila **mali** na **kuzifuta** kumbukumbu hizo. Kisha **`init`** inaitwa, ambayo **inaweka mali** kwa **thamani zinazohitajika**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Njia za Darasa**

Njia za darasa zinatambulishwa na ishara ya **alama ya plus** (+) badala ya alama ya nukta (hyphen) (-) inayotumiwa na njia za kipengee. Kama njia ya darasa ya **NSString** njia ya darasa **`stringWithString`**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setteri na Getteri

Kuweka na kupata mali, unaweza kufanya hivyo kwa kutumia **notation ya dot** au kama vile unaita **njia**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Majina ya Kipekee**

Badala ya kutumia njia za kuweka na kupata, unaweza kutumia majina ya kipekee. Majina haya yanafanana na mali lakini yananza na "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Itifaki

Itifaki ni seti ya matangazo ya njia (bila mali). Darasa ambalo linatekeleza itifaki linatekeleza njia zilizotangazwa.

Kuna aina 2 za njia: **lazima** na **hiari**. Kwa **kawaida** njia ni **lazima** (lakini unaweza pia kuonyesha hilo na lebo ya **`@required`**). Ili kuonyesha kuwa njia ni hiari, tumia **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Pamoja yote

Kwa kuzingatia usalama wa macOS na kuongeza mamlaka, kuna mambo kadhaa ya kuzingatia. Hapa kuna orodha ya vitu muhimu vya kufanya:

1. **Sasisha mfumo wa uendeshaji**: Hakikisha kuwa macOS yako imeboreshwa na toleo la hivi karibuni la mfumo wa uendeshaji. Sasisha mara kwa mara ili kupata maboresho ya usalama na kurekebisha kasoro zilizojulikana.

2. **Tumia nenosiri lenye nguvu**: Chagua nenosiri lenye nguvu na lisiloweza kutabiriwa kwa akaunti yako ya mtumiaji. Tumia mchanganyiko wa herufi za juu na za chini, nambari, na alama za kipekee.

3. **Washa firewall**: Weka firewall ya macOS kuwezesha ulinzi wa ziada dhidi ya mashambulizi ya mtandao. Hakikisha kuwa mipangilio ya firewall imeboreshwa na inazuia trafiki isiyohitajika.

4. **Tumia encryption**: Tumia encryption kwenye diski yako ili kuhakikisha kuwa data yako iko salama hata kama kifaa chako kimeibiwa au kupotea. Unaweza kutumia FileVault kwenye macOS kuanzisha encryption ya diski.

5. **Washa Gatekeeper**: Gatekeeper ni huduma ya usalama inayopatikana kwenye macOS ambayo inazuia ufungaji wa programu kutoka kwa vyanzo visivyoaminika. Hakikisha Gatekeeper imeamilishwa ili kuzuia programu zisizoaminika kufanya kazi kwenye mfumo wako.

6. **Tumia ufunguo wa kuingia**: Badilisha kuingia kwa akaunti yako ya mtumiaji kutoka kwa nenosiri hadi ufunguo wa kuingia. Ufunguo wa kuingia ni njia salama zaidi ya kuthibitisha utambulisho wako.

7. **Tumia programu za antivirus**: Sakinisha programu ya antivirus yenye sifa nzuri kwenye macOS yako ili kuchunguza na kuzuia vitisho vya usalama. Fanya uhakiki wa mara kwa mara ili kuhakikisha kuwa mfumo wako haujathiriwa na programu hasidi.

8. **Zima huduma zisizotumiwa**: Funga huduma zisizotumiwa kwenye macOS yako ili kupunguza hatari ya mashambulizi. Kagua mipangilio ya mfumo wako na zima huduma ambazo hazihitajiki.

9. **Tumia akaunti ya mtumiaji mdogo**: Tumia akaunti ya mtumiaji mdogo badala ya akaunti ya msimamizi kwa shughuli za kawaida. Hii inapunguza hatari ya kutokea kwa makosa yanayoweza kusababisha uharibifu mkubwa.

10. **Fuatilia shughuli za mfumo**: Tumia zana za ufuatiliaji kama vile Console.app kuchunguza shughuli za mfumo na kugundua shughuli zisizo za kawaida au za kushuku.

Kwa kufuata hatua hizi, unaweza kuimarisha usalama wa macOS yako na kupunguza hatari ya kuvuja kwa data au kushambuliwa na wahalifu mtandaoni.
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
### Darasa za Msingi

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Darasa za msingi ni **zisizobadilika**, kwa hivyo ili kuongeza herufi kwenye herufi iliyopo, **NSString mpya inahitaji kuundwa**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Au unaweza kutumia pia darasa la herufi inayoweza kubadilishwa:

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

#### Nambari

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
#### Mfumo wa Array, Sets & Dictionary

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

### Vitengo

Vitengo ni **kazi ambazo hufanya kama vitu** hivyo vinaweza kupitishwa kwa kazi au **kuhifadhiwa** katika **makundi** au **orodha**. Pia, vinaweza **kuwakilisha thamani ikiwa wanapewa thamani** hivyo ni sawa na lambdas.
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

Pia ni **wakati mwingine inawezekana kufafanua aina ya kizuizi** itakayotumiwa kama parameter katika kazi:
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
### Faili

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

Pia niwezekano wa kusimamia faili **kwa kutumia vitu vya `NSURL` badala ya vitu vya `NSString`**. Majina ya njia ni sawa, lakini **badala ya `Path` tumia `URL`**.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
Darasa kuu zaidi lina njia `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` iliyofafanuliwa ambayo inaruhusu kuandikwa moja kwa moja kwenye faili:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
