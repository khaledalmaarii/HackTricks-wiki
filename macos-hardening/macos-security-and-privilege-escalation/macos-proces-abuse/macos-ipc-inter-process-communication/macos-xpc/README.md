# macOS XPC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

XPC代表XNU（macOS使用的内核）进程间通信，是macOS和iOS之间进行**进程间通信的框架**。XPC提供了一种在系统上进行**安全的异步方法调用的机制**。它是苹果安全范例的一部分，允许创建**权限分离的应用程序**，其中每个**组件**仅以其工作所需的权限运行，从而限制了受损进程可能造成的潜在损害。

XPC使用一种进程间通信（IPC）的形式，这是一组不同程序在同一系统上发送和接收数据的方法。

XPC的主要优点包括：

1. **安全性**：通过将工作分成不同的进程，每个进程只能被授予其所需的权限。这意味着即使进程被入侵，它也只能有限地造成损害。
2. **稳定性**：XPC有助于将崩溃隔离到发生崩溃的组件。如果一个进程崩溃，可以重新启动而不影响系统的其他部分。
3. **性能**：XPC允许轻松并发，因为不同的任务可以在不同的进程中同时运行。

唯一的**缺点**是将一个应用程序分成多个进程，通过XPC进行通信**效率较低**。但在今天的系统中，这几乎不可察觉，而且好处更多。

## 应用程序特定的XPC服务

应用程序的XPC组件位于**应用程序本身内部**。例如，在Safari中，您可以在**`/Applications/Safari.app/Contents/XPCServices`**中找到它们。它们的扩展名为**`.xpc`**（例如**`com.apple.Safari.SandboxBroker.xpc`**），并且也是**包**，其中包含主二进制文件：`/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`，以及一个`Info.plist：/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

正如您可能想到的，**XPC组件将具有不同的授权和权限**，与其他XPC组件或主应用程序二进制文件不同。除非XPC服务在其**Info.plist**文件中将[**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession)设置为“True”。在这种情况下，XPC服务将在与调用它的应用程序**相同的安全会话中运行**。

XPC服务在需要时由**launchd**启动，并在所有任务完成后**关闭**以释放系统资源。**应用程序特定的XPC组件只能被应用程序利用**，从而降低了与潜在漏洞相关的风险。

## 系统范围的XPC服务

系统范围的XPC服务对所有用户都可访问。这些服务可以是launchd或Mach类型，需要在指定目录中的plist文件中**定义**，例如**`/System/Library/LaunchDaemons`**、**`/Library/LaunchDaemons`**、**`/System/Library/LaunchAgents`**或**`/Library/LaunchAgents`**。

这些plist文件将具有名为**`MachServices`**的键，其值为服务的名称，以及名为**`Program`**的键，其值为二进制文件的路径：
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
**`LaunchDameons`**中的进程由root用户运行。因此，如果非特权进程能够与其中一个进程通信，就有可能提升权限。

## XPC事件消息

应用程序可以**订阅**不同的事件**消息**，使其能够在发生此类事件时**按需启动**。这些服务的设置是在**与前面的文件相同的目录中**的**launchd plist文件**中完成的，其中包含额外的**`LaunchEvent`**键。

### XPC连接进程检查

当进程尝试通过XPC连接调用方法时，**XPC服务应该检查该进程是否被允许连接**。以下是常见的检查方法和常见的陷阱：

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

## XPC授权

Apple还允许应用程序**配置某些权限以及如何获取这些权限**，因此如果调用进程具有这些权限，它将被**允许调用XPC服务的方法**：

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC嗅探器

要嗅探XPC消息，可以使用[**xpcspy**](https://github.com/hot3eed/xpcspy)，它使用**Frida**。
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## C代码示例

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% tab title="xpc_client.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        
        if (type == XPC_TYPE_DICTIONARY) {
            const char *description = xpc_dictionary_get_string(event, "description");
            printf("Received event: %s\n", description);
        }
    });
    
    xpc_connection_resume(connection);
    
    dispatch_main();
    
    return 0;
}
```

{% endtab %}

{% tab title="xpc_server.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% tab title="xyz.hacktricks.service.plist" %}xyz.hacktricks.service.plist是一个属性列表文件，用于配置macOS系统中的服务。它定义了一个名为xyz.hacktricks.service的服务，并指定了该服务的属性和行为。

以下是xyz.hacktricks.service.plist文件的示例内容：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>xyz.hacktricks.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/xyz.hacktricks.service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

在这个示例中，`Label`键指定了服务的名称为`xyz.hacktricks.service`。`ProgramArguments`键指定了服务的可执行文件路径为`/path/to/xyz.hacktricks.service`。`RunAtLoad`键和`KeepAlive`键都设置为`true`，表示服务在系统启动时运行，并且在意外终止后会自动重启。

要安装和加载这个服务，可以使用`launchctl`命令：

```bash
launchctl load /path/to/xyz.hacktricks.service.plist
```

这将会将服务添加到系统的启动项中，并在系统启动时自动运行。

请注意，为了加载和运行服务，您需要具有管理员权限。

```

请注意，为了加载和运行服务，您需要具有管理员权限。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
## Objective-C 代码示例

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% tab title="oc_xpc_client.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% tab title="xyz.hacktricks.svcoc.plist" %}

## xyz.hacktricks.svcoc.plist

This file is a property list file used by macOS to configure and manage XPC services. XPC (Cross-Process Communication) is a mechanism that allows processes to communicate with each other in a secure and efficient manner.

The `xyz.hacktricks.svcoc.plist` file contains configuration settings for the `xyz.hacktricks.svcoc` XPC service. By modifying this file, you can potentially abuse the XPC service to escalate privileges or perform other malicious actions.

To analyze the `xyz.hacktricks.svcoc.plist` file, you can use a property list editor or a text editor to view its contents. Look for any sensitive information, such as file paths, command line arguments, or environment variables, that could be leveraged for privilege escalation or other attacks.

Additionally, you can also look for any custom methods or functions defined in the XPC service that could be abused to execute arbitrary code or manipulate system resources.

Keep in mind that modifying or abusing XPC services can have serious consequences and may violate the terms of service or legal agreements. Always ensure that you have proper authorization and follow ethical guidelines when performing any security assessments or penetration testing.

{% endtab %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## 在 Dylb 代码中的客户端

The client code inside a Dylb is responsible for establishing a connection with the server and sending requests. It is an essential component of the inter-process communication (IPC) mechanism in macOS.

Dylb (Dynamic Library) 是 macOS 中的一个动态库，其中的客户端代码负责与服务器建立连接并发送请求。它是 macOS 中进程间通信 (IPC) 机制的一个重要组成部分。

### Usage

To use the Dylb client code, follow these steps:

1. Import the necessary frameworks and libraries.
2. Create an instance of the `NSXPCConnection` class.
3. Set the appropriate interface for the connection.
4. Set the connection's delegate.
5. Establish the connection using the `resume()` method.
6. Send requests to the server using the connection's `remoteObjectProxy` property.

### 用法

要使用 Dylb 客户端代码，请按照以下步骤进行操作：

1. 导入所需的框架和库。
2. 创建 `NSXPCConnection` 类的实例。
3. 为连接设置适当的接口。
4. 设置连接的代理。
5. 使用 `resume()` 方法建立连接。
6. 使用连接的 `remoteObjectProxy` 属性向服务器发送请求。

```swift
import Foundation
import XPC

let connection = NSXPCConnection(serviceName: "com.example.MyService")
connection.remoteObjectInterface = NSXPCInterface(with: MyServiceProtocol.self)
connection.resume()

let proxy = connection.remoteObjectProxy
proxy?.performAction(with: data) { response in
    // Handle the response from the server
}
```

### Security Considerations

When using the Dylb client code, it is important to consider security measures to protect against potential vulnerabilities. Here are some recommendations:

- Validate and sanitize user input to prevent injection attacks.
- Implement proper authentication and authorization mechanisms.
- Encrypt sensitive data before sending it over the network.
- Regularly update and patch the Dylb code to address any security vulnerabilities.

### 安全注意事项

在使用 Dylb 客户端代码时，重要的是要考虑安全措施，以防止潜在的漏洞。以下是一些建议：

- 验证和清理用户输入，以防止注入攻击。
- 实施适当的身份验证和授权机制。
- 在发送敏感数据之前对其进行加密。
- 定期更新和修补 Dylb 代码，以解决任何安全漏洞。
```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
