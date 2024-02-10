# macOS Objective-C

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Objective-C

{% hint style="danger" %}
Objective-C ile yazılan programlar, [Mach-O ikili dosyalarına](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) derlendiklerinde **sınıf bildirimlerini korurlar**. Bu sınıf bildirimleri aşağıdaki bilgileri içerir:
{% endhint %}

* Sınıf
* Sınıf yöntemleri
* Sınıf örnek değişkenleri

Bu bilgilere [**class-dump**](https://github.com/nygard/class-dump) kullanarak erişebilirsiniz:
```bash
class-dump Kindle.app
```
Bu isimler, ikili dosyanın tersine çevrilmesini zorlaştırmak için gizlenebilir.

## Sınıflar, Metotlar ve Nesneler

### Arayüz, Özellikler ve Metotlar
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
### **Sınıf**
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
### **Nesne ve Çağrı Yöntemi**

Bir sınıfın bir örneğini oluşturmak için **`alloc`** yöntemi çağrılır, bu yöntem her bir **özelliğe bellek tahsis eder** ve bu tahsisleri **sıfırlar**. Ardından **`init`** çağrılır, bu yöntem özellikleri **gereken değerlere başlatır**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Sınıf Metotları**

Sınıf metotları, örnek metotlarla kullanılan tire (-) yerine artı işareti (+) ile tanımlanır. Örneğin, **NSString** sınıfının **`stringWithString`** metodu:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter ve Getter

Özellikleri **ayarlamak** ve **almak** için, bunu bir **nokta gösterimi** veya bir **metod çağırıyormuş gibi** yapabilirsiniz:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Örnek Değişkenler**

Setter ve getter yöntemlerine alternatif olarak, örnek değişkenlerini kullanabilirsiniz. Bu değişkenler, özelliklerle aynı isme sahip olup "\_" ile başlar:
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Protokoller

Protokoller, özellikleri olmayan yöntem bildirimlerinin bir kümesidir. Bir protokolü uygulayan bir sınıf, bildirilen yöntemleri uygular.

Yöntemlerin 2 türü vardır: **zorunlu** ve **isteğe bağlı**. **Varsayılan olarak** bir yöntem **zorunlu**dur (ancak **`@required`** etiketiyle de belirtilebilir). Bir yöntemin isteğe bağlı olduğunu belirtmek için **`@optional`** kullanın.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Hepsi Bir Arada

Bu bölümde, Objective-C programlama dilinin temellerini öğreneceğiz. Objective-C, macOS işletim sisteminde yaygın olarak kullanılan bir programlama dilidir. Bu dil, macOS uygulamalarının geliştirilmesinde sıkça kullanılır ve bu nedenle macOS güvenliği ve ayrıcalık yükseltme tekniklerini anlamak için Objective-C hakkında temel bir anlayışa sahip olmak önemlidir.

Objective-C, C programlama diline dayanır ve nesne yönelimli programlama (OOP) özelliklerini içerir. Bu dilde, sınıflar, nesneler ve mesajlar kullanılarak programlar oluşturulur. Sınıflar, nesnelerin şablonlarını tanımlar ve nesneler, sınıfların örnekleridir. Mesajlar ise nesneler arasında iletişimi sağlar.

Objective-C'de, sınıflar ve nesneler arasındaki ilişkiyi belirlemek için "inheritance" (miras alma) ve "polymorphism" (çok biçimlilik) gibi OOP kavramları kullanılır. Miras alma, bir sınıfın başka bir sınıftan özelliklerini ve davranışlarını devralmasını sağlar. Çok biçimlilik ise aynı isimdeki farklı metotların farklı davranışlar sergilemesini sağlar.

Objective-C'de, sınıflar ve nesneler arasındaki iletişim mesajlar aracılığıyla gerçekleştirilir. Bir nesneye mesaj göndermek, o nesnenin belirli bir metotunu çağırmak anlamına gelir. Mesajlar, nesnelerin davranışlarını kontrol etmek için kullanılır.

Objective-C, macOS güvenliği ve ayrıcalık yükseltme tekniklerini anlamak için önemlidir çünkü birçok macOS uygulaması Objective-C dilini kullanır. Bu nedenle, Objective-C'nin temel yapılarını ve çalışma prensiplerini anlamak, macOS üzerindeki güvenlik açıklarını tespit etmek ve ayrıcalık yükseltme saldırıları gerçekleştirmek için önemlidir.
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
### Temel Sınıflar

#### String (Dize)

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Temel sınıflar **değiştirilemez** olduğundan, mevcut bir dizeye bir dize eklemek için **yeni bir NSString oluşturulması gerekir**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Veya ayrıca bir **değiştirilebilir** dize sınıfı da kullanabilirsiniz:

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

#### Numara

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

#### Dizi, Kümeler ve Sözlükler

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

### Bloklar

Bloklar, **nesne gibi davranan fonksiyonlardır**, bu nedenle fonksiyonlara geçirilebilir veya **dizilerde** veya **sözlüklerde** **saklanabilir**. Ayrıca, değerler verildiğinde bir değeri temsil edebilirler, bu nedenle lambdalara benzerler.
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

Ayrıca, işlevlerde kullanılmak üzere bir parametre olarak kullanılmak üzere bir blok türü tanımlamak da mümkündür:
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
### Dosyalar

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

Ayrıca, dosyaları `NSString` nesneleri yerine `NSURL` nesneleri kullanarak yönetmek de mümkündür. Yöntem isimleri benzerdir, ancak `Path` yerine `URL` kullanılır.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
En temel sınıfların çoğu, doğrudan bir dosyaya yazılmalarına izin veren `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` adında bir yönteme sahiptir:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
