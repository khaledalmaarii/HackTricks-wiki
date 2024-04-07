# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

**Grand Central Dispatch (GCD),** également connu sous le nom de **libdispatch**, est disponible à la fois sur macOS et iOS. Il s'agit d'une technologie développée par Apple pour optimiser le support des applications pour l'exécution concurrente (multithread) sur un matériel multicœur.

**GCD** fournit et gère des **files d'attente FIFO** auxquelles votre application peut **soumettre des tâches** sous forme d'**objets de bloc**. Les blocs soumis aux files d'attente de répartition sont **exécutés sur un pool de threads** entièrement géré par le système. GCD crée automatiquement des threads pour exécuter les tâches dans les files d'attente de répartition et planifie l'exécution de ces tâches sur les cœurs disponibles.

{% hint style="success" %}
En résumé, pour exécuter du code en **parallèle**, les processus peuvent envoyer des **blocs de code à GCD**, qui se chargera de leur exécution. Par conséquent, les processus ne créent pas de nouveaux threads ; **GCD exécute le code donné avec son propre pool de threads**.
{% endhint %}

Cela est très utile pour gérer avec succès l'exécution parallèle, réduisant considérablement le nombre de threads que les processus créent et optimisant l'exécution parallèle. C'est idéal pour les tâches qui nécessitent une **grande parallélisme** (force brute ?) ou pour les tâches qui ne doivent pas bloquer le thread principal : par exemple, le thread principal sur iOS gère les interactions UI, donc toute autre fonctionnalité qui pourrait faire planter l'application (recherche, accès à un site web, lecture d'un fichier...) est gérée de cette manière.

## Objective-C

En Objective-C, il existe différentes fonctions pour envoyer un bloc à exécuter en parallèle :

- [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async) : Soumet un bloc pour une exécution asynchrone sur une file d'attente de répartition et retourne immédiatement.
- [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync) : Soumet un objet de bloc pour exécution et retourne une fois que ce bloc a fini d'exécuter.
- [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once) : Exécute un objet de bloc une seule fois pendant la durée de vie d'une application.
- [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait) : Soumet un élément de travail pour exécution et ne retourne qu'après son exécution. Contrairement à [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), cette fonction respecte tous les attributs de la file d'attente lorsqu'elle exécute le bloc.

Ces fonctions attendent ces paramètres : [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Voici la **structure d'un bloc** :
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
Et voici un exemple d'utilisation de **parallélisme** avec **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** est une bibliothèque qui fournit des **liaisons Swift** au framework Grand Central Dispatch (GCD) qui est initialement écrit en C.\
La bibliothèque **`libswiftDispatch`** enveloppe les API C GCD dans une interface plus conviviale pour Swift, facilitant ainsi le travail des développeurs Swift avec GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Exemple de code**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

Le script Frida suivant peut être utilisé pour **s'interférer dans plusieurs fonctions `dispatch`** et extraire le nom de la file d'attente, la trace de la pile et le bloc : [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Actuellement, Ghidra ne comprend ni la structure ObjectiveC **`dispatch_block_t`**, ni celle de **`swift_dispatch_block`**.

Donc, si vous voulez qu'il les comprenne, vous pouvez simplement les **déclarer** :

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Ensuite, trouvez un endroit dans le code où ils sont **utilisés** :

{% hint style="success" %}
Notez toutes les références à "block" pour comprendre comment vous pourriez déterminer que la structure est utilisée.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Cliquez avec le bouton droit sur la variable -> Retype Variable et sélectionnez dans ce cas **`swift_dispatch_block`** :

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra réécrira automatiquement tout :

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>
