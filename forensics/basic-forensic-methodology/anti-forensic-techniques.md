<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# Timestamps

Um atacante pode estar interessado em **alterar os timestamps dos arquivos** para evitar ser detectado.\
É possível encontrar os timestamps dentro do MFT nos atributos `$STANDARD_INFORMATION` __ e __ `$FILE_NAME`.

Ambos os atributos têm 4 timestamps: **Modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

O **explorador do Windows** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

## TimeStomp - Ferramenta Anti-forense

Esta ferramenta **modifica** as informações de timestamp dentro de **`$STANDARD_INFORMATION`** **mas** **não** as informações dentro de **`$FILE_NAME`**. Portanto, é possível **identificar** **atividades suspeitas**.

## Usnjrnl

O **USN Journal** (Update Sequence Number Journal), ou Change Journal, é um recurso do sistema de arquivos do Windows NT (NTFS) que **mantém um registro de alterações feitas no volume**.\
É possível usar a ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) para procurar modificações neste registro.

![](<../../.gitbook/assets/image (449).png>)

A imagem anterior é a **saída** mostrada pela **ferramenta** onde pode ser observado que algumas **alterações foram feitas** no arquivo.

## $LogFile

Todas as alterações de metadados em um sistema de arquivos são registradas para garantir a recuperação consistente das estruturas críticas do sistema de arquivos após uma falha do sistema. Isso é chamado de [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging).\
Os metadados registrados são armazenados em um arquivo chamado “**$LogFile**”, que é encontrado em um diretório raiz de um sistema de arquivos NTFS.\
É possível usar ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analisar este arquivo e encontrar alterações.

![](<../../.gitbook/assets/image (450).png>)

Novamente, na saída da ferramenta é possível ver que **algumas alterações foram feitas**.

Usando a mesma ferramenta, é possível identificar a **que horas os timestamps foram modificados**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Hora de criação do arquivo
* ATIME: Hora de modificação do arquivo
* MTIME: Modificação do registro MFT do arquivo
* RTIME: Hora de acesso ao arquivo

## Comparação de `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra maneira de identificar arquivos modificados suspeitos seria comparar o tempo em ambos os atributos em busca de **inconsistências**.

## Nanosegundos

Os timestamps do **NTFS** têm uma **precisão** de **100 nanosegundos**. Portanto, encontrar arquivos com timestamps como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

## SetMace - Ferramenta Anti-forense

Esta ferramenta pode modificar ambos os atributos `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário um sistema operacional ativo para modificar essas informações.

# Ocultação de Dados

O NTFS usa um cluster e o tamanho mínimo de informação. Isso significa que se um arquivo ocupar um cluster e meio, o **meio restante nunca será usado** até que o arquivo seja excluído. Portanto, é possível **ocultar dados neste espaço ocioso**.

Existem ferramentas como slacker que permitem ocultar dados neste espaço "oculto". No entanto, uma análise do `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![](<../../.gitbook/assets/image (452).png>)

Então, é possível recuperar o espaço ocioso usando ferramentas como FTK Imager. Observe que esse tipo de ferramenta pode salvar o conteúdo obfuscado ou até mesmo criptografado.

# UsbKill

Esta é uma ferramenta que **desligará o computador se qualquer alteração nas portas USB** for detectada.\
Uma maneira de descobrir isso seria inspecionar os processos em execução e **revisar cada script Python em execução**.

# Distribuições Linux ao Vivo

Essas distribuições são **executadas dentro da memória RAM**. A única maneira de detectá-las é **caso o sistema de arquivos NTFS seja montado com permissões de gravação**. Se for montado apenas com permissões de leitura, não será possível detectar a intrusão.

# Exclusão Segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configuração do Windows

É possível desativar vários métodos de registro do Windows para tornar a investigação forense muito mais difícil.

## Desativar Timestamps - UserAssist

Esta é uma chave de registro que mantém datas e horas quando cada executável foi executado pelo usuário.

Desativar o UserAssist requer dois passos:

1. Definir duas chaves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambos para zero para sinalizar que queremos o UserAssist desativado.
2. Limpar os subárvores do registro que se parecem com `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Desativar Timestamps - Prefetch

Isso salvará informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, isso também pode ser útil para práticas forenses.

* Execute `regedit`
* Selecione o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Clique com o botão direito em ambos `EnablePrefetcher` e `EnableSuperfetch`
* Selecione Modificar em cada um deles para alterar o valor de 1 (ou 3) para 0
* Reinicie

## Desativar Timestamps - Último Horário de Acesso

Sempre que uma pasta é aberta de um volume NTFS em um servidor Windows NT, o sistema leva tempo para **atualizar um campo de timestamp em cada pasta listada**, chamado de último horário de acesso. Em um volume NTFS muito usado, isso pode afetar o desempenho.

1. Abra o Editor de Registro (Regedit.exe).
2. Navegue até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procure por `NtfsDisableLastAccessUpdate`. Se não existir, adicione este DWORD e defina seu valor como 1, o que desativará o processo.
4. Feche o Editor de Registro e reinicie o servidor.

## Excluir Histórico USB

Todas as **Entradas de Dispositivos USB** são armazenadas no Registro do Windows sob a chave do registro **USBSTOR** que contém subchaves que são criadas sempre que você conecta um Dispositivo USB ao seu PC ou Laptop. Você pode encontrar esta chave aqui H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Excluindo isso** você excluirá o histórico USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) para ter certeza de que os excluiu (e para excluí-los).

Outro arquivo que salva informações sobre os USBs é o arquivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Isso também deve ser excluído.

## Desativar Cópias de Sombra

**Liste** as cópias de sombra com `vssadmin list shadowstorage`\
**Exclua** executando `vssadmin delete shadow`

Você também pode excluí-los via GUI seguindo as etapas propostas em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar as cópias de sombra:

1. Vá para o botão Iniciar do Windows e digite "services" na caixa de pesquisa de texto; abra o programa Serviços.
2. Localize "Volume Shadow Copy" na lista, destaque-o e clique com o botão direito > Propriedades.
3. No menu suspenso "Tipo de inicialização", selecione Desativado e clique em Aplicar e OK.

![](<../../.gitbook/assets/image (453).png>)

Também é possível modificar a configuração de quais arquivos serão copiados na cópia de sombra no registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Sobrescrever arquivos excluídos

* Você pode usar uma **ferramenta do Windows**: `cipher /w:C` Isso indicará ao cipher para remover quaisquer dados do espaço de disco não utilizado disponível dentro da unidade C.
* Você também pode usar ferramentas como [**Eraser**](https://eraser.heidi.ie)

## Excluir logs de eventos do Windows

* Windows + R --> eventvwr.msc --> Expandir "Logs do Windows" --> Clique com o botão direito em cada categoria e selecione "Limpar Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Desativar logs de eventos do Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Dentro da seção de serviços, desative o serviço "Log de Eventos do Windows"
* `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

## Desativar $UsnJrnl

* `fsutil usn deletejournal /d c:`

</details>
