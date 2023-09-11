# macOS Objective-C

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Objective-C

{% hint style="danger" %}
请注意，使用Objective-C编写的程序在编译为[Mach-O二进制文件](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)时会**保留**它们的类声明。这些类声明包括以下信息：
{% endhint %}

* 类
* 类方法
* 类实例变量

您可以使用[class-dump](https://github.com/nygard/class-dump)获取这些信息：
```bash
class-dump Kindle.app
```
注意，这些名称可能会被混淆，以使二进制文件的逆向更加困难。

## 类、方法和对象

### 接口、属性和方法
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
### **类**

In Objective-C, a class is a blueprint for creating objects. It defines the properties and behaviors that an object of that class will have. A class is composed of instance variables, methods, and properties.

在Objective-C中，类是创建对象的蓝图。它定义了该类的对象将具有的属性和行为。一个类由实例变量、方法和属性组成。

### **Instance Variables**

Instance variables are the data members of a class. They hold the state or data of an object. Each object of a class has its own set of instance variables.

实例变量是类的数据成员。它们保存对象的状态或数据。每个类的对象都有自己的一组实例变量。

### **Methods**

Methods are the functions defined within a class. They define the behavior of an object. Methods can be classified into two types: instance methods and class methods.

方法是在类内定义的函数。它们定义了对象的行为。方法可以分为两种类型：实例方法和类方法。

- **Instance Methods**: Instance methods are associated with an instance of a class. They can access and modify the instance variables of that instance.

- **实例方法**：实例方法与类的实例相关联。它们可以访问和修改该实例的实例变量。

- **Class Methods**: Class methods are associated with the class itself rather than an instance of the class. They can only access and modify class variables.

- **类方法**：类方法与类本身相关联，而不是类的实例。它们只能访问和修改类变量。

### **Properties**

Properties provide a way to define the attributes of an object. They are used to encapsulate instance variables and provide getter and setter methods to access and modify them.

属性提供了定义对象属性的方式。它们用于封装实例变量，并提供getter和setter方法来访问和修改它们。

Properties can be declared as read-only, read-write, or write-only. They can also have custom accessors and mutators.

属性可以声明为只读、读写或只写。它们还可以具有自定义的访问器和修改器。

### **Inheritance**

Inheritance is a mechanism in which one class inherits the properties and behaviors of another class. The class that inherits is called the subclass, and the class from which it inherits is called the superclass.

继承是一种机制，其中一个类继承另一个类的属性和行为。继承的类称为子类，继承的类称为父类。

The subclass can access the instance variables, methods, and properties of the superclass. It can also override the methods of the superclass to provide its own implementation.

子类可以访问父类的实例变量、方法和属性。它还可以重写父类的方法，以提供自己的实现。

### **Polymorphism**

Polymorphism is the ability of an object to take on many forms. In Objective-C, polymorphism is achieved through method overriding and method overloading.

多态是对象具有多种形式的能力。在Objective-C中，通过方法重写和方法重载实现多态。

- **Method Overriding**: Method overriding allows a subclass to provide a different implementation of a method that is already defined in its superclass.

- **方法重写**：方法重写允许子类提供一个与其父类中已定义的方法不同的实现。

- **Method Overloading**: Method overloading allows multiple methods with the same name but different parameters to coexist in a class.

- **方法重载**：方法重载允许在一个类中存在多个具有相同名称但参数不同的方法。

### **Conclusion**

Understanding the basic concepts of classes, instance variables, methods, properties, inheritance, and polymorphism is essential for developing applications in Objective-C.

理解类、实例变量、方法、属性、继承和多态的基本概念对于在Objective-C中开发应用程序至关重要。
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
### **对象和调用方法**

要创建一个类的实例，需要调用**`alloc`**方法，该方法为每个**属性**分配内存并将这些分配清零。然后调用**`init`**方法，该方法将属性**初始化为所需的值**。
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **类方法**

类方法使用加号（+）而不是用于实例方法的连字符（-）进行定义。就像**NSString**类方法**`stringWithString`**一样：
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

要设置和获取属性，可以使用**点表示法**或者像调用方法一样：
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **实例变量**

除了使用setter和getter方法之外，您还可以使用实例变量。这些变量与属性具有相同的名称，但以“\_”开头：
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### 协议

协议是一组方法声明（不包含属性）。实现协议的类需要实现声明的方法。

方法有两种类型：**必须的**和**可选的**。默认情况下，方法是**必须的**（但也可以使用**`@required`**标签来指示）。要指示方法是可选的，请使用**`@optional`**标签。
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### 全部在一起

在本章中，我们已经学习了Objective-C的基础知识，以及如何在macOS上使用Objective-C进行开发。我们还了解了Objective-C的一些重要概念，如类、对象、方法和消息传递。

我们还学习了如何使用Objective-C的运行时库来动态创建类和对象，并了解了Objective-C的内存管理机制。

此外，我们还介绍了Objective-C的一些高级特性，如协议、分类和块。

最后，我们还讨论了Objective-C在macOS安全和特权升级方面的一些注意事项。我们了解了如何使用Objective-C来执行特权操作，并学习了如何在Objective-C代码中实现安全性和防御性编程。

通过掌握Objective-C的基础知识和高级特性，我们可以更好地理解和开发macOS应用程序，并在安全性方面做出更明智的决策。
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
### 基本类

#### 字符串

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
基本类是**不可变的**，所以要将字符串追加到现有字符串中，需要**创建一个新的NSString**。

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

或者你也可以使用一个**可变**的字符串类：

{% code overflow="wrap" %}
```objectivec
NSMutableString *mutableString = [NSMutableString stringWithString:@"The book "];
[mutableString appendString:bookTitle];
[mutableString appendString:@" was written by "];
[mutableString appendString:bookAuthor];
[mutableString appendString:@" and published in "];
[mutableString appendString:bookPublicationYear];
```
#### 数字

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
#### 数组、集合和字典

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
### 块

块是**行为像对象的函数**，因此它们可以被传递给函数或**存储**在**数组**或**字典**中。此外，如果给定值，它们可以**表示一个值**，因此类似于lambda函数。

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

还可以**定义一个块类型来作为函数的参数**：
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
### 文件

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

也可以使用`NSURL`对象而不是`NSString`对象来管理文件。方法名称相似，但是使用`URL`而不是`Path`。
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
大多数基本类都定义了一个名为`writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil`的方法，允许直接将它们写入文件：

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
