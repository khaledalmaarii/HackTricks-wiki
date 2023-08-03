# macOS基础Objective-C

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Objective-C

{% hint style="danger" %}
请注意，使用Objective-C编写的程序在编译为[Mach-O二进制文件](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)时会**保留**它们的类声明。这些类声明包括以下内容的名称和类型：
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

除了使用setter和getter方法之外，您还可以使用实例变量。这些变量与属性具有相同的名称，但以"\_"开头：
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### 协议

协议是一组方法声明（不包含属性）。实现协议的类需要实现声明的方法。

方法有两种类型：**必须的**和**可选的**。默认情况下，方法是**必须的**（但也可以使用**`@required`**标签来指示）。要指示方法是可选的，请使用**`@optional`**。
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

在Objective-C中，我们可以使用一些技术来实现各种攻击和提升特权的目标。下面是一些常见的技术：

#### 1. Method Swizzling（方法交换）

方法交换是一种技术，可以在运行时更改类的方法实现。这可以用于修改现有方法的行为，甚至可以替换掉原始方法。这对于实现各种攻击非常有用，例如劫持方法调用，窃取敏感信息等。

#### 2. Method Injection（方法注入）

方法注入是一种技术，可以在运行时向类中添加新的方法。这可以用于在目标类中注入恶意代码，以实现各种攻击，例如执行远程命令，窃取敏感信息等。

#### 3. Class Swizzling（类交换）

类交换是一种技术，可以在运行时更改类的实现。这可以用于修改类的行为，例如替换掉原始类的实现，或者在类的方法中添加额外的逻辑。这对于实现各种攻击非常有用，例如劫持类的行为，窃取敏感信息等。

#### 4. Dynamic Method Resolution（动态方法解析）

动态方法解析是一种技术，可以在运行时动态地为类添加缺失的方法实现。这可以用于在运行时创建新的方法，以实现各种攻击，例如执行远程命令，窃取敏感信息等。

#### 5. Method Forwarding（方法转发）

方法转发是一种技术，可以在运行时将未知的方法调用转发给其他对象来处理。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 6. Instance Variable Manipulation（实例变量操作）

实例变量操作是一种技术，可以在运行时直接访问和修改类的实例变量。这可以用于实现各种攻击，例如窃取敏感信息，修改对象状态等。

#### 7. Class Clusters（类簇）

类簇是一种技术，可以使用抽象类来隐藏具体实现的细节。这可以用于实现各种攻击，例如劫持类的行为，窃取敏感信息等。

#### 8. Method Chaining（方法链式调用）

方法链式调用是一种技术，可以通过在方法中返回`self`来实现连续调用多个方法。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 9. KVO (Key-Value Observing)（键值观察）

键值观察是一种技术，可以在运行时监视对象属性的变化。这可以用于实现各种攻击，例如窃取敏感信息，修改对象状态等。

#### 10. NSNotificationCenter（通知中心）

通知中心是一种技术，可以在运行时发送和接收通知。这可以用于实现各种攻击，例如窃取敏感信息，修改对象状态等。

#### 11. Method Hooking（方法钩子）

方法钩子是一种技术，可以在运行时拦截和修改方法的调用。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 12. Method Tracing（方法追踪）

方法追踪是一种技术，可以在运行时跟踪方法的调用和执行。这可以用于分析和调试代码，也可以用于实现各种攻击，例如窃取敏感信息，修改对象状态等。

#### 13. Method Serialization（方法序列化）

方法序列化是一种技术，可以将方法的调用序列化为数据，并在需要时重新执行。这可以用于实现各种攻击，例如远程命令执行，窃取敏感信息等。

#### 14. Method Overriding（方法重写）

方法重写是一种技术，可以在子类中重新定义父类的方法实现。这可以用于修改方法的行为，例如替换掉原始方法的实现，或者在方法中添加额外的逻辑。这对于实现各种攻击非常有用，例如劫持方法调用，窃取敏感信息等。

#### 15. Method Delegation（方法委托）

方法委托是一种技术，可以将方法的实现委托给其他对象来处理。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 16. Method Caching（方法缓存）

方法缓存是一种技术，可以在运行时缓存方法的实现，以提高方法的调用速度。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 17. Method Dispatch（方法分派）

方法分派是一种技术，可以在运行时根据对象的类型和方法的签名来选择合适的方法实现。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 18. Method Filtering（方法过滤）

方法过滤是一种技术，可以在运行时过滤掉不需要的方法调用。这可以用于实现各种攻击，例如劫持方法调用，窃取敏感信息等。

#### 19. Method Validation（方法验证）

方法验证是一种技术，可以在运行时验证方法的参数和返回值。这可以用于实现各种攻击，例如窃取敏感信息，修改对象状态等。

#### 20. Method Encryption（方法加密）

方法加密是一种技术，可以在运行时对方法的实现进行加密，以保护方法的机密性。这可以用于实现各种攻击，例如防止方法被劫持，防止敏感信息泄漏等。

这些技术可以单独使用，也可以组合使用，以实现更复杂的攻击和特权提升。了解这些技术可以帮助我们更好地理解Objective-C的内部工作原理，并为我们的攻击和防御提供更多的选择。
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
基本类是**不可变的**，所以要将一个字符串追加到现有字符串中，需要**创建一个新的NSString**。

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
{% endcode %}

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

// Sets
NSSet *fruitsSet1 = [NSSet setWithObjects:@"apple", @"banana", @"orange", nil];
NSSet *fruitsSet2 = [NSSet setWithArray:@[@"apple", @"banana", @"orange"]];

// Inmutable sets
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

块是**行为像对象的函数**，因此它们可以被传递给函数，或者存储在数组或字典中。此外，如果给定值，它们可以**表示一个值**，因此类似于lambda函数。

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

还可以**定义一个块类型作为函数的参数**：
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
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
