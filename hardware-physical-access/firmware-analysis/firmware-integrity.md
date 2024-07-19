## Firmware Integrity

**Özel firmware ve/veya derlenmiş ikili dosyalar, bütünlük veya imza doğrulama hatalarını istismar etmek için yüklenebilir.** Aşağıdaki adımlar arka kapı bind shell derlemesi için izlenebilir:

1. Firmware, firmware-mod-kit (FMK) kullanılarak çıkarılabilir.
2. Hedef firmware mimarisi ve endianlık belirlenmelidir.
3. Ortam için uygun yöntemler kullanılarak Buildroot ile bir çapraz derleyici oluşturulabilir.
4. Arka kapı, çapraz derleyici kullanılarak oluşturulabilir.
5. Arka kapı, çıkarılan firmware /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU ikili dosyası, çıkarılan firmware rootfs'ye kopyalanabilir.
7. Arka kapı, chroot ve QEMU kullanılarak taklit edilebilir.
8. Arka kapıya netcat aracılığıyla erişilebilir.
9. QEMU ikili dosyası, çıkarılan firmware rootfs'den kaldırılmalıdır.
10. Değiştirilen firmware, FMK kullanılarak yeniden paketlenebilir.
11. Arka kapılı firmware, firmware analiz araç seti (FAT) ile taklit edilerek ve hedef arka kapı IP'sine ve portuna netcat kullanarak bağlanarak test edilebilir.

Eğer dinamik analiz, önyükleyici manipülasyonu veya donanım güvenlik testi yoluyla bir root shell elde edilmişse, implantlar veya ters shell gibi önceden derlenmiş kötü niyetli ikili dosyalar çalıştırılabilir. Metasploit çerçevesi ve 'msfvenom' gibi otomatik yük/implant araçları aşağıdaki adımlar kullanılarak yararlanılabilir:

1. Hedef firmware mimarisi ve endianlık belirlenmelidir.
2. Msfvenom, hedef yükü, saldırgan ana bilgisayar IP'sini, dinleme port numarasını, dosya türünü, mimariyi, platformu ve çıktı dosyasını belirtmek için kullanılabilir.
3. Yük, ele geçirilmiş cihaza aktarılabilir ve yürütme izinlerinin olduğu garanti edilmelidir.
4. Metasploit, msfconsole başlatarak ve ayarları yükleye göre yapılandırarak gelen istekleri işlemek için hazırlanabilir.
5. Meterpreter ters shell, ele geçirilmiş cihazda çalıştırılabilir.
