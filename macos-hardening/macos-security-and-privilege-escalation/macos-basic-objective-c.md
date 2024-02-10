# macOS Objective-C

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Objective-C

{% hint style="danger" %}
Σημειώστε ότι τα προγράμματα που γράφονται σε Objective-C **διατηρούν** τις δηλώσεις των κλάσεών τους **όταν** **μεταγλωττίζονται** σε [Mach-O δυαδικά αρχεία](macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Αυτές οι δηλώσεις κλάσης περιλαμβάνουν το όνομα και τον τύπο των:
{% endhint %}

* Η κλάση
* Οι μέθοδοι της κλάσης
* Οι μεταβλητές παρουσίας της κλάσης

Μπορείτε να αποκτήσετε αυτές τις πληροφορίες χρησιμοποιώντας το [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Σημείωση ότι αυτά τα ονόματα μπορεί να έχουν κρυπτογραφηθεί για να δυσκολέψει την αντίστροφη μηχανική του δυαδικού.

## Κλάσεις, Μέθοδοι και Αντικείμενα

### Διεπαφή, Ιδιότητες και Μέθοδοι
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
### **Κλάση**
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
### **Αντικείμενο & Κλήση Μεθόδου**

Για να δημιουργηθεί μια περίπτωση μιας κλάσης, καλείται η μέθοδος **`alloc`** η οποία **δεσμεύει μνήμη** για κάθε **ιδιότητα** και **μηδενίζει** αυτές τις δεσμεύσεις. Στη συνέχεια, καλείται η **`init`**, η οποία **αρχικοποιεί τις ιδιότητες** με τις **απαιτούμενες τιμές**.
```objectivec
// Something like this:
MyVehicle *newVehicle = [[MyVehicle alloc] init];

// Which is usually expressed as:
MyVehicle *newVehicle = [MyVehicle new];

// To call a method
// [myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]
[newVehicle addWheels:4];
```
### **Μέθοδοι Κλάσης**

Οι μέθοδοι κλάσης ορίζονται με το **σύμβολο του συν** (+) και όχι με το παύλα (-) που χρησιμοποιείται για τις μεθόδους παραδείγματος. Όπως η μέθοδος κλάσης **`stringWithString`** της κλάσης **NSString**:
```objectivec
+ (id)stringWithString:(NSString *)aString;
```
### Setter & Getter

Για να **ορίσετε** και **πάρετε** ιδιότητες, μπορείτε να το κάνετε με τη **σημειογραφία με τελεία** ή σαν να **καλείτε μια μέθοδο**:
```objectivec
// Set
newVehicle.numberOfWheels = 2;
[newVehicle setNumberOfWheels:3];

// Get
NSLog(@"Number of wheels: %i", newVehicle.numberOfWheels);
NSLog(@"Number of wheels: %i", [newVehicle numberOfWheels]);
```
### **Μεταβλητές Παραδείγματος**

Εναλλακτικά με τις μεθόδους setter και getter, μπορείτε να χρησιμοποιήσετε μεταβλητές παραδείγματος. Αυτές οι μεταβλητές έχουν το ίδιο όνομα με τις ιδιότητες, αλλά ξεκινούν με ένα "\_":
```objectivec
- (void)makeLongTruck {
_numberOfWheels = +10000;
NSLog(@"Number of wheels: %i", self.numberOfLeaves);
}
```
### Πρωτόκολλα

Τα πρωτόκολλα είναι σύνολο δηλώσεων μεθόδων (χωρίς ιδιότητες). Μια κλάση που υλοποιεί ένα πρωτόκολλο υλοποιεί τις δηλωμένες μεθόδους.

Υπάρχουν 2 τύποι μεθόδων: **υποχρεωτικές** και **προαιρετικές**. Από προεπιλογή, μια μέθοδος είναι **υποχρεωτική** (αλλά μπορείτε επίσης να το υποδείξετε με την ετικέτα **`@required`**). Για να υποδείξετε ότι μια μέθοδος είναι προαιρετική, χρησιμοποιήστε το **`@optional`**.
```objectivec
@protocol myNewProtocol
- (void) method1; //mandatory
@required
- (void) method2; //mandatory
@optional
- (void) method3; //optional
@end
```
### Όλα μαζί

Σε αυτήν την ενότητα θα εξετάσουμε μερικές βασικές έννοιες της γλώσσας προγραμματισμού Objective-C που είναι απαραίτητες για την κατανόηση των τεχνικών ασφάλειας και εκμετάλλευσης προνομίων στο macOS. Αυτές οι έννοιες περιλαμβάνουν την αντικειμενοστραφή προγραμματισμό, την ανάλυση αντικειμένων, την ανάκτηση πληροφοριών από αντικείμενα και την εκτέλεση κώδικα Objective-C. Αυτές οι γνώσεις θα μας βοηθήσουν να κατανοήσουμε καλύτερα τις ευπάθειες του macOS και να αναπτύξουμε τεχνικές για την εκμετάλλευσή τους. 

Ας ξεκινήσουμε με μια εισαγωγή στην αντικειμενοστραφή προγραμματισμό. Ο αντικειμενοστραφής προγραμματισμός είναι μια μεθοδολογία προγραμματισμού που βασίζεται στην έννοια των αντικειμένων. Σε αυτήν την προσέγγιση, ο κώδικας οργανώνεται σε αντικείμενα, τα οποία είναι συλλογές δεδομένων που περιέχουν μεταβλητές και συναρτήσεις που λειτουργούν πάνω σε αυτές τις μεταβλητές. Οι αντικειμενοστραφείς γλώσσες προγραμματισμού, όπως η Objective-C, χρησιμοποιούν αυτήν τη μεθοδολογία για την ανάπτυξη εφαρμογών.

Στη συνέχεια, θα εξετάσουμε την ανάλυση αντικειμένων. Η ανάλυση αντικειμένων είναι η διαδικασία της αναγνώρισης και της κατανόησης των αντικειμένων που χρησιμοποιούνται σε μια εφαρμογή. Αυτό μας επιτρέπει να ανακτήσουμε πληροφορίες για τη δομή και τη λειτουργία των αντικειμένων, καθώς και να εντοπίσουμε ευπάθειες που μπορούν να εκμεταλλευτούμε.

Στη συνέχεια, θα εξετάσουμε την ανάκτηση πληροφοριών από αντικείμενα. Η ανάκτηση πληροφοριών από αντικείμενα είναι η διαδικασία της ανάκτησης ευαίσθητων πληροφοριών από τα αντικείμενα μιας εφαρμογής. Αυτό μπορεί να περιλαμβάνει την ανάκτηση κρυπτογραφημένων δεδομένων, κλειδιών πρόσβασης ή άλλων ευαίσθητων πληροφοριών που αποθηκεύονται στη μνήμη των αντικειμένων.

Τέλος, θα εξετάσουμε την εκτέλεση κώδικα Objective-C. Η εκτέλεση κώδικα Objective-C είναι η διαδικασία της εκτέλεσης κώδικα που γράφτηκε σε Objective-C. Αυτό μας επιτρέπει να εκτελέσουμε κώδικα που εκμεταλλεύεται ευπάθειες του macOS ή που προκαλεί εκτελέσιμο κώδικα με προνόμια που δεν θα έπρεπε να έχει ο χρήστης.

Αυτές οι βασικές έννοιες της Objective-C θα μας βοηθήσουν να κατανοήσουμε καλύτερα την ασφάλεια και την εκμετάλλευση προνομίων στο macOS. Με τη χρήση αυτών των γνώσεων, μπορούμε να αναπτύξουμε αποτελεσματικές τεχνικές για την εκμετάλλευση ευπαθειών και την απόκτηση προνομίων σε ένα σύστημα macOS.
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
### Βασικές Κλάσεις

#### String

{% code overflow="wrap" %}
```objectivec
// NSString
NSString *bookTitle = @"The Catcher in the Rye";
NSString *bookAuthor = [[NSString alloc] initWithCString:"J.D. Salinger" encoding:NSUTF8StringEncoding];
NSString *bookPublicationYear = [NSString stringWithCString:"1951" encoding:NSUTF8StringEncoding];
```
{% endcode %}

Οι βασικές κλάσεις είναι **αμετάβλητες**, οπότε για να προσθέσετε ένα συμβολοσειρά σε μια υπάρχουσα πρέπει να δημιουργηθεί **νέο NSString**. 

{% code overflow="wrap" %}
```objectivec
NSString *bookDescription = [NSString stringWithFormat:@"%@ by %@ was published in %@", bookTitle, bookAuthor, bookPublicationYear];
```
{% endcode %}

Ή μπορείτε επίσης να χρησιμοποιήσετε μια κλάση συμβολοσειράς **μεταβλητής**:

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

#### Αριθμός

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

#### Πίνακες, Σύνολα και Λεξικά

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

### Μπλοκ

Τα μπλοκ είναι **συναρτήσεις που συμπεριφέρονται ως αντικείμενα**, έτσι μπορούν να περάσουν σε συναρτήσεις ή να **αποθηκευτούν** σε **πίνακες** ή **λεξικά**. Επίσης, μπορούν να **αναπαραστήσουν μια τιμή αν τους δοθούν τιμές**, οπότε είναι παρόμοια με τις λάμδα.
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

Είναι επίσης δυνατόν να **ορίσετε έναν τύπο μπλοκ για χρήση ως παράμετρο** σε συναρτήσεις:
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
### Αρχεία

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

Είναι επίσης δυνατόν να διαχειριστείτε αρχεία **χρησιμοποιώντας αντικείμενα `NSURL` αντί για αντικείμενα `NSString`**. Τα ονόματα των μεθόδων είναι παρόμοια, αλλά **με `URL` αντί για `Path`**.
```objectivec
NSURL *fileSrc = [NSURL fileURLWithPath:@"/path/to/file1.txt"];
NSURL *fileDst = [NSURL fileURLWithPath:@"/path/to/file2.txt"];
[fileManager moveItemAtURL:fileSrc toURL:fileDst error: nil];
```
Οι περισσότερες βασικές κλάσεις έχουν ορισμένη μια μέθοδο `writeToFile:<path> atomically:<YES> encoding:<encoding> error:nil` που τους επιτρέπει να γραφούν απευθείας σε ένα αρχείο:

{% code overflow="wrap" %}
```objectivec
NSString* tmp = @"something temporary";
[tmp writeToFile:@"/tmp/tmp1.txt" atomically:YES encoding:NSASCIIStringEncoding error:nil];
```
{% endcode %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
