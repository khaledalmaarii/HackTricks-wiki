# Serviços e Protocolos de Rede no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Serviços de Acesso Remoto

Estes são os serviços comuns do macOS para acessá-los remotamente.\
Você pode ativar/desativar esses serviços em `Configurações do Sistema` --> `Compartilhamento`

* **VNC**, conhecido como “Compartilhamento de Tela” (tcp:5900)
* **SSH**, chamado de “Login Remoto” (tcp:22)
* **Apple Remote Desktop** (ARD), ou “Gerenciamento Remoto” (tcp:3283, tcp:5900)
* **AppleEvent**, conhecido como “Evento Apple Remoto” (tcp:3031)

Verifique se algum está ativado executando:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Teste de Penetração em ARD

(Esta parte foi [**retirada deste post do blog**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html))

É basicamente um [VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing) modificado com alguns **recursos específicos do macOS**.\
No entanto, a **opção de Compartilhamento de Tela** é apenas um servidor **VNC básico**. Há também uma opção avançada de ARD ou Gerenciamento Remoto para **definir uma senha de controle de tela** que tornará o ARD **compatível com clientes VNC**. No entanto, há uma fraqueza neste método de autenticação que **limita** esta **senha** a um **buffer de autenticação de 8 caracteres**, tornando muito fácil **forçar a entrada** com uma ferramenta como [Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) ou [GoRedShell](https://github.com/ahhh/GoRedShell/) (também **não há limites de taxa por padrão**).\
Você pode identificar **instâncias vulneráveis de Compartilhamento de Tela** ou Gerenciamento Remoto com **nmap**, usando o script `vnc-info`, e se o serviço suportar `Autenticação VNC (2)`, então é provável que sejam **vulneráveis a força bruta**. O serviço truncará todas as senhas enviadas pela rede para 8 caracteres, de modo que, se você definir a autenticação VNC para "password", tanto "passwords" quanto "password123" serão autenticados.

<figure><img src="../../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

Se você quiser habilitá-lo para escalar privilégios (aceitar prompts TCC), acessar com uma GUI ou espionar o usuário, é possível habilitá-lo com:

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

Você pode alternar entre o modo de **observação**, **controle compartilhado** e **controle total**, passando de espiar um usuário para assumir o controle de sua área de trabalho com um clique. Além disso, se você conseguir acesso a uma sessão ARD, essa sessão permanecerá aberta até que seja encerrada, mesmo que a senha do usuário seja alterada durante a sessão.

Você também pode **enviar comandos unix diretamente** pelo ARD e pode especificar o usuário root para executar coisas como root se você for um usuário administrativo. Você pode até usar este método de comando unix para agendar tarefas remotas para serem executadas em um horário específico, no entanto, isso ocorre como uma conexão de rede no horário especificado (em vez de ser armazenado e executado no servidor alvo). Finalmente, o Spotlight remoto é uma das minhas funcionalidades favoritas. É realmente interessante porque você pode realizar uma busca indexada de baixo impacto de forma rápida e remota. Isso é valioso para procurar por arquivos sensíveis porque é rápido, permite que você execute buscas simultaneamente em várias máquinas e não vai sobrecarregar a CPU.

## Protocolo Bonjour

**Bonjour** é uma tecnologia projetada pela Apple que permite que computadores e **dispositivos localizados na mesma rede descubram serviços oferecidos** por outros computadores e dispositivos. É projetado de tal forma que qualquer dispositivo ciente do Bonjour pode ser conectado a uma rede TCP/IP e ele irá **escolher um endereço IP** e fazer com que outros computadores na rede **fiquem cientes dos serviços que oferece**. Bonjour às vezes é referido como Rendezvous, **Zero Configuration** ou Zeroconf.\
A Rede de Configuração Zero, como o Bonjour oferece:

* Deve ser capaz de **obter um Endereço IP** (mesmo sem um servidor DHCP)
* Deve ser capaz de fazer **tradução de nome para endereço** (mesmo sem um servidor DNS)
* Deve ser capaz de **descobrir serviços na rede**

O dispositivo receberá um **endereço IP na faixa 169.254/16** e verificará se algum outro dispositivo está usando esse endereço IP. Se não, ele manterá o endereço IP. Macs mantêm uma entrada em sua tabela de roteamento para essa sub-rede: `netstat -rn | grep 169`

Para DNS, o **protocolo Multicast DNS (mDNS) é usado**. [**Serviços mDNS** escutam na porta **5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md), usam **consultas DNS regulares** e usam o **endereço multicast 224.0.0.251** em vez de enviar a solicitação apenas para um endereço IP. Qualquer máquina que escutar essas solicitações responderá, geralmente para um endereço multicast, para que todos os dispositivos possam atualizar suas tabelas.\
Cada dispositivo irá **selecionar seu próprio nome** ao acessar a rede, o dispositivo escolherá um nome **terminado em .local** (pode ser baseado no nome do host ou um completamente aleatório).

Para **descobrir serviços, o DNS Service Discovery (DNS-SD)** é usado.

O requisito final da Rede de Configuração Zero é atendido pelo **DNS Service Discovery (DNS-SD)**. O DNS Service Discovery usa a sintaxe dos registros DNS SRV, mas utiliza **registros DNS PTR para que múltiplos resultados possam ser retornados** se mais de um host oferecer um serviço específico. Um cliente solicita a busca PTR para o nome `<Service>.<Domain>` e **recebe** uma lista de zero ou mais registros PTR do formato `<Instance>.<Service>.<Domain>`.

O binário `dns-sd` pode ser usado para **anunciar serviços e realizar buscas** por serviços:
```bash
#Search ssh services
dns-sd -B _ssh._tcp

Browsing for _ssh._tcp
DATE: ---Tue 27 Jul 2021---
12:23:20.361  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
12:23:20.362  Add        3   1 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        3  10 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        2  16 local.               _ssh._tcp.           M-C02C934RMD6R
```

```bash
#Announce HTTP service
dns-sd -R "Index" _http._tcp . 80 path=/index.html

#Search HTTP services
dns-sd -B _http._tcp
```
Quando um novo serviço é iniciado, o **novo serviço transmite sua presença para todos** na sub-rede. O ouvinte não precisou perguntar; ele só precisava estar ouvindo.

Você pode usar [**esta ferramenta**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12) para ver os **serviços oferecidos** na sua rede local atual.\
Ou você pode escrever seus próprios scripts em python com [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf):
```python
from zeroconf import ServiceBrowser, Zeroconf


class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
Se você achar que o Bonjour pode ser mais seguro **desativado**, você pode fazer isso com:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
