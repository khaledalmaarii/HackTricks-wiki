# Serviços e Protocolos de Rede do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Serviços de Acesso Remoto

Estes são os serviços comuns do macOS para acessá-los remotamente.\
Você pode habilitar/desabilitar esses serviços em `Configurações do Sistema` --> `Compartilhamento`

* **VNC**, conhecido como “Compartilhamento de Tela” (tcp:5900)
* **SSH**, chamado de “Login Remoto” (tcp:22)
* **Apple Remote Desktop** (ARD), ou “Gerenciamento Remoto” (tcp:3283, tcp:5900)
* **AppleEvent**, conhecido como “Evento Remoto da Apple” (tcp:3031)

Verifique se algum está habilitado executando:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Teste de penetração ARD

O Apple Remote Desktop (ARD) é uma versão aprimorada do [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptada para o macOS, oferecendo recursos adicionais. Uma vulnerabilidade notável no ARD é o seu método de autenticação para a senha da tela de controle, que utiliza apenas os primeiros 8 caracteres da senha, tornando-a suscetível a [ataques de força bruta](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) com ferramentas como Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), pois não há limites de taxa padrão.

Instâncias vulneráveis podem ser identificadas usando o script `vnc-info` do **nmap**. Serviços que suportam `VNC Authentication (2)` são especialmente suscetíveis a ataques de força bruta devido à truncagem da senha de 8 caracteres.

Para habilitar o ARD para várias tarefas administrativas como escalonamento de privilégios, acesso à GUI ou monitoramento de usuários, utilize o seguinte comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornece níveis de controle versáteis, incluindo observação, controle compartilhado e controle total, com sessões persistindo mesmo após alterações de senha do usuário. Permite o envio direto de comandos Unix, executando-os como root para usuários administrativos. O agendamento de tarefas e a busca remota do Spotlight são recursos notáveis, facilitando buscas remotas de baixo impacto para arquivos sensíveis em várias máquinas.


## Protocolo Bonjour

Bonjour, uma tecnologia projetada pela Apple, permite que **dispositivos na mesma rede detectem os serviços oferecidos uns pelos outros**. Conhecido também como Rendezvous, **Zero Configuration** ou Zeroconf, ele permite que um dispositivo se junte a uma rede TCP/IP, **escolha automaticamente um endereço IP** e transmita seus serviços para outros dispositivos de rede.

A Rede de Configuração Zero, fornecida pelo Bonjour, garante que os dispositivos possam:
* **Obter automaticamente um endereço IP** mesmo na ausência de um servidor DHCP.
* Realizar **tradução de nome para endereço** sem a necessidade de um servidor DNS.
* **Descobrir serviços** disponíveis na rede.

Dispositivos que usam o Bonjour se atribuirão um **endereço IP da faixa 169.254/16** e verificarão sua singularidade na rede. Os Macs mantêm uma entrada na tabela de roteamento para esta sub-rede, verificável via `netstat -rn | grep 169`.

Para DNS, o Bonjour utiliza o **protocolo Multicast DNS (mDNS)**. O mDNS opera sobre a **porta 5353/UDP**, empregando **consultas DNS padrão** mas direcionando para o **endereço de multicast 224.0.0.251**. Esse método garante que todos os dispositivos ouvintes na rede possam receber e responder às consultas, facilitando a atualização de seus registros.

Ao ingressar na rede, cada dispositivo seleciona automaticamente um nome, geralmente terminando em **.local**, que pode ser derivado do nome do host ou gerado aleatoriamente.

A descoberta de serviços dentro da rede é facilitada pelo **Serviço de Descoberta de DNS (DNS-SD)**. Aproveitando o formato dos registros SRV DNS, o DNS-SD usa **registros PTR DNS** para permitir a listagem de vários serviços. Um cliente que busca um serviço específico solicitará um registro PTR para `<Serviço>.<Domínio>`, recebendo em troca uma lista de registros PTR formatados como `<Instância>.<Serviço>.<Domínio>` se o serviço estiver disponível em vários hosts.


O utilitário `dns-sd` pode ser utilizado para **descobrir e anunciar serviços de rede**. Aqui estão alguns exemplos de seu uso:

### Pesquisando por Serviços SSH

Para pesquisar por serviços SSH na rede, o seguinte comando é utilizado:
```bash
dns-sd -B _ssh._tcp
```
Este comando inicia a busca por serviços _ssh._tcp e exibe detalhes como timestamp, flags, interface, domínio, tipo de serviço e nome da instância.

### Publicando um Serviço HTTP

Para publicar um serviço HTTP, você pode usar:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Este comando registra um serviço HTTP chamado "Index" na porta 80 com um caminho de `/index.html`.

Para então procurar por serviços HTTP na rede:
```bash
dns-sd -B _http._tcp
```
Quando um serviço é iniciado, ele anuncia sua disponibilidade para todos os dispositivos na sub-rede por meio de multicast. Dispositivos interessados nesses serviços não precisam enviar solicitações, apenas ouvir esses anúncios.

Para uma interface mais amigável, o aplicativo ****Discovery - DNS-SD Browser** disponível na Apple App Store pode visualizar os serviços oferecidos em sua rede local.

Alternativamente, scripts personalizados podem ser escritos para navegar e descobrir serviços usando a biblioteca `python-zeroconf`. O script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstra a criação de um navegador de serviços para serviços `_http._tcp.local.`, imprimindo serviços adicionados ou removidos:
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
### Desativando o Bonjour
Se houver preocupações com a segurança ou outros motivos para desativar o Bonjour, ele pode ser desligado usando o seguinte comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
