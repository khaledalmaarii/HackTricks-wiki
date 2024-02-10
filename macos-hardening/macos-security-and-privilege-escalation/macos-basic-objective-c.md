# macOS Objective-C

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## Objective-C

{% hint style="danger" %}
Objective-C로 작성된 프로그램은 [Mach-O 이진 파일](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)로 컴파일될 때 **클래스 선언을 유지**합니다. 이러한 클래스 선언에는 다음이 포함됩니다:
{% endhint %}

* 클래스
* 클래스 메서드
* 클래스 인스턴스 변수

[class-dump](https://github.com/nygard/class-dump)를 사용하여 이 정보를 얻을 수 있습니다:
```bash
class-dump Kindle.app
```
## 클래스, 메서드 및 객체

### 인터페이스, 속성 및 메서드
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
### **클래스**
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
### **객체 및 메소드 호출**

클래스의 인스턴스를 생성하기 위해 **`alloc`** 메소드를 호출합니다. 이 메소드는 각 **속성에 메모리를 할당**하고 해당 할당을 **0으로 초기화**합니다. 그런 다음 **`init`**이 호출되어 속성을 **필요한 값으로 초기화**합니다.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **클래스 메서드**

클래스 메서드는 인스턴스 메서드와는 다른 **더하기 기호** (+)를 사용하여 정의됩니다. **NSString** 클래스의 **`stringWithString`** 메서드와 같이 사용됩니다.
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

속성을 **설정**하고 **얻기** 위해서는 **도트 표기법**을 사용하거나 마치 **메소드를 호출하는 것처럼** 할 수 있습니다:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **인스턴스 변수**

세터 및 게터 메서드 대신 인스턴스 변수를 사용할 수도 있습니다. 이 변수들은 속성과 동일한 이름을 가지지만 "\_"로 시작합니다.
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### 프로토콜

프로토콜은 메서드 선언의 집합입니다(속성 없이). 프로토콜을 구현하는 클래스는 선언된 메서드를 구현합니다.

메서드에는 **필수**와 **선택적** 두 가지 유형이 있습니다. **기본적으로** 메서드는 **필수**입니다(하지만 **`@required`** 태그로도 표시할 수 있습니다). 메서드가 선택적임을 나타내려면 **`@optional`**을 사용하세요.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### 모두 함께

Objective-C is a programming language commonly used for macOS and iOS development. Understanding the basics of Objective-C can be helpful for macOS security and privilege escalation.

#### Objective-C Basics

Objective-C is an object-oriented programming language that extends the C programming language. It adds features such as dynamic typing, message passing, and runtime reflection.

##### Classes and Objects

In Objective-C, classes are used to define objects. An object is an instance of a class. Classes define the properties and behaviors of objects.

##### Methods and Messages

Methods are functions defined within a class that perform specific tasks. In Objective-C, methods are called by sending messages to objects. Messages are requests for objects to perform a specific method.

##### Properties

Properties are attributes of an object. They define the state of an object and can be accessed and modified using getter and setter methods.

##### Memory Management

Objective-C uses reference counting for memory management. When an object is created, its reference count is set to 1. When the object is no longer needed, its reference count is decremented. When the reference count reaches 0, the object is deallocated.

##### Inheritance

Objective-C supports inheritance, allowing classes to inherit properties and behaviors from other classes. This promotes code reuse and modularity.

##### Categories

Categories allow you to add methods to existing classes without modifying their original implementation. This can be useful for extending the functionality of built-in classes.

##### Protocols

Protocols define a set of methods that a class can implement. They are similar to interfaces in other programming languages and allow for polymorphism.

#### Conclusion

Understanding the basics of Objective-C is essential for macOS security and privilege escalation. It provides a foundation for analyzing and exploiting vulnerabilities in macOS applications.
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
### 기본 클래스

#### 문자열 (String)

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

기본 클래스는 **불변**이므로 기존 문자열에 문자열을 추가하려면 **새로운 NSString을 생성해야 합니다**.

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

또는 **가변** 문자열 클래스를 사용할 수도 있습니다:

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

#### 번호

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
#### 배열, 집합 및 사전

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

### 블록

블록은 **객체로 동작하는 함수**이므로 함수에 전달하거나 **배열**이나 **사전**에 **저장**할 수 있습니다. 또한 값이 주어지면 값으로 **표현**될 수 있으므로 람다와 유사합니다.

{% code overflow="wrap" %}
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

함수의 매개변수로 사용될 블록 유형을 **정의하는 것도 가능**합니다:
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
### 파일

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

`NSString` 대신 `NSURL` 객체를 사용하여 파일을 관리하는 것도 가능합니다. 메서드 이름은 유사하지만 `Path` 대신 `URL`을 사용합니다.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
가장 기본적인 클래스들은 `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` 메서드를 가지고 있어서 직접 파일에 쓸 수 있습니다:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
