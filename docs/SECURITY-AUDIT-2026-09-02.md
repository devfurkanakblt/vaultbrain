# Vault Brain — Faz Tamamlama ve Siber Güvenlik Denetimi

**Denetim tarihi:** 2 Eylül 2026

**İncelenen sürüm:** `e5ce271` (`feat/phase-4-knowledge-views`)
**Sonuç:** **YÜKSEK RİSKLİ BULGULAR VAR / 1.0 VE GÜVENİLMEYEN SENKRONİZASYON İÇİN YAYIN BLOKE**

## 1. Yönetici özeti

Kod, belgeler, testler, bağımlılıklar ve başlıca saldırı yüzeyleri incelendi. Faz 0–5'in yol haritasındaki teslimleri uygulama ve testlerle büyük ölçüde tutarlıdır. Faz 6 tamamlanmamıştır: eklenti işlemlerinin değişiklik günlüğüne alınması, cihaz kaydı/çıkarma, anahtar rotasyonu, güvenilmeyen relay, çoklu cihaz ve mobil istemciler ile harici güvenlik denetimi/kurtarma tatbikatı/stabil 1.0 formatı açıktır.

Denetimde **kritik bulgu yok**, **5 yüksek**, **6 orta** ve **3 düşük/sertleştirme bulgusu** kaydedildi. En önemli sonuçlar:

1. 30 saniyeden uzun süren geçerli bir yazma işlemi sırasında kasa kilidi başka bir süreç tarafından “bayat” sayılıp silinebiliyor. Yarış durumu geçici bir kasada yeniden üretildi.
2. Eklenti yetkileri ayrıcalıklı Rust IPC sınırında yeniden doğrulanmıyor. İptal/disable değişikliği çalışan eklentiye yalnızca UI yenilemesinde uygulanıyor.
3. Kullanıcı kontrollü `text/html`, SVG-benzeri metin ve PDF ekleri `sandbox` olmayan bir `iframe` içinde açılıyor. Ayrıcalıklı WebView bağlamında aktif içerik riski var.
4. MCP grant dosyası yoksa bütün anahtarlar varsayılan olarak erişilebilir. Bu davranış belgelenmiş eski uyumluluk davranışı olsa da ürünün “ayrıcalıklı işlemler varsayılan reddedilir” güvenlik sözleşmesiyle çelişiyor.
5. Faz 6 senkronizasyon temeli, cihaz kimliği/iptali/anahtar rotasyonu ve rollback/freshness güvencesi olmadan güvenilmeyen relay veya üretim tipi çoklu cihaz kullanımı için hazır değil.

Olumlu tarafta AES-256-GCM kullanımı, AAD bağlama, atomik yazımlar, yol normalizasyonu, dar Tauri CSP'si, eklenti imzaları, senkronizasyon DAG/HMAC doğrulaması ve test kapsamı güçlüdür. `npm audit` ve RustSec veritabanında doğrudan istismar edilebilir bilinen bir bağımlılık CVE'si bulunmadı; ancak Rust tarafında koşullu bir unsound uyarısı ve 16 bakımsız bağımlılık uyarısı vardır.

## 2. Faz tamamlama denetimi

Depoda `.planning/` ve faz başına `VERIFICATION.md`, `SUMMARY.md`, `VALIDATION.md` veya `SECURITY.md` bulunmuyor. Bu yüzden sonuç, `docs/ROADMAP.md`, README, gerçek kod, git geçmişi ve çalışan testlerden yeniden oluşturuldu. Resmî GSD kanıt zincirinin yokluğu ayrıca bir izlenebilirlik eksikliğidir.

| Faz | Yol haritası | Denetim sonucu | Kanıt / not |
|---|---:|---|---|
| 0 — Ürün ve güvenlik sözleşmesi | Tamamlandı | Doğrulandı | Ürün, mimari ve güvenlik belgeleri mevcut. |
| 1 — Güçlendirilmiş uyumluluk çekirdeği | Tamamlandı | Doğrulandı, fakat SEC-01 ve SEC-06 var | Yol güvenliği, atomik yazım, audit ve kurtarma testleri çalışıyor; canlı kilidin alınması güvenceyi zayıflatıyor. |
| 2 — Şifreli belge motoru | Tamamlandı | Doğrulandı | Not, ek, bağlantı, arama, geçmiş ve performans testleri geçti. |
| 3 — Masaüstü çalışma alanı | Tamamlandı | Doğrulandı, fakat SEC-03 var | Tauri uygulaması, kilit/idle/clipboard ve UI testleri geçti; ek önizleme sınırı güçlendirilmeli. |
| 4 — Bilgi görünümleri | Tamamlandı | Doğrulandı | Grafik, canvas, özellik tablosu, görünüm ve workspace testleri geçti. |
| 5 — Kontrollü ekosistem ve AI | Tamamlandı | **Kısmen güvenli; yayın engelleyici kusurlar var** | Özellikler mevcut, fakat SEC-02 ve SEC-04 güvenlik sözleşmesini ihlal ediyor. |
| 6 — Şifreli sync ve mobil | **Tamamlanmadı** | **Açıkça eksik** | Yalnızca immutable change/DAG temelinin bir bölümü var; cihaz yaşam döngüsü, relay, çoklu cihaz/mobil ve dış denetim açık. |

### Faz 6'da açık kalan maddeler

- Eklenti paketi ve eklenti politikası işlemlerinin senkronizasyon günlüğüne alınması.
- Cihaz kaydı, cihaz çıkarma ve anahtar rotasyonu.
- Güvenilmeyen relay sunucusu ve self-hosted seçenek.
- Masaüstü çoklu cihaz sürümü ile iOS/Android istemcileri.
- Harici güvenlik denetimi, kurtarma tatbikatı ve stabil 1.0 veri formatı.

**Karar:** “Tüm fazlar tamamlandı” denemez. Faz 0–5 işlevsel olarak teslim edilmiş olsa da Faz 5'in güvenlik iddiaları için SEC-02/04 kapatılmalı; Faz 6 yol haritası gereği tamamlanmamıştır.

## 3. Uygulanan doğrulamalar

| Denetim | Sonuç |
|---|---|
| `npm run quality` | Başarılı: lint, Prettier, TypeScript, 94 çekirdek test, 79 masaüstü test ve Vite production build. |
| Rust `cargo fmt`, `clippy -D warnings`, `cargo test --lib` | Başarılı: 41 Rust testi. Eski mutlak yol içeren yerel `target` önbelleği nedeniyle ilk çalışma bozuldu; temiz geçici target ile doğrulandı. |
| Toplam otomatik test | **214 test başarılı**. |
| `npm run package:check` | Başarılı; yayımlanacak npm paketi 28 beklenen dosyayla sınırlı. |
| `npm audit --json` | 472 bağımlılıkta 0 bilinen açık. |
| `cargo audit` / güncel RustSec DB | 466 kilitli crate içinde 0 vulnerability; 1 unsound ve 16 unmaintained uyarısı. |
| Yüksek güvenli sır/desen taraması | Çalışma ağacı ve erişilebilir git geçmişinde gerçek anahtar/token/parola bulunmadı. Test parolaları fixture olarak işaretli. |
| `npm run benchmark:100k` | Başarılı; 100.000 not performans kapıları geçti. Toplu üretim 465.688 ms sürdü. |
| Kilit yarış durumu PoC'si | Başarılı yeniden üretim: 1. süreç kilidi bırakmadan 898 ms önce 2. süreç aynı kilidi aldı. |

Vite yalnızca editör chunk'ının 500 KiB eşiğini aştığını bildirdi; bu bir güvenlik hatası değildir.

## 4. Tehdit modeli ve kapsam

İncelenen saldırgan sınıfları:

- Kasa dizinine okuyabilen veya dosya değiştirebilen yerel saldırgan/malware.
- Aynı kasa üzerinde paralel çalışan CLI, MCP ve masaüstü süreçleri.
- Kötü niyetli veya sonradan ele geçirilmiş imzalı eklenti.
- MCP istemcisi/agent ve yanlış yapılandırılmış grant politikası.
- Kötü amaçlı ek dosya veya Obsidian import girdisi.
- Güvenilmeyen relay, ele geçirilmiş cihaz ve replay/fork/rollback saldırıları.
- Bağımlılık, CI ve release tedarik zinciri saldırıları.
- Büyük/bozuk şifreli dosyalarla bellek, CPU ve disk tüketimi.

Kasa açıkken aynı kullanıcı hesabını tamamen ele geçirmiş bir saldırgana karşı süreç belleğini korumak hedef dışıdır. Bununla birlikte gereksiz bellek/argv sızıntıları sertleştirme bulgusu olarak kaydedildi.

## 5. Ayrıntılı bulgular

### SEC-01 — Canlı kasa kilidi 30 saniye sonra ele geçirilebiliyor

- **Önem:** Yüksek
- **Tür:** CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization
- **Etkilenen yerler:** `src/vault-lock.ts:7,46-49,94-96`; `src-tauri/src/lib.rs:80,650-658,686-687`
- **Durum:** Doğrulandı ve yeniden üretildi

Hem Node hem Rust kilidi yalnızca duvar saatiyle oluşturulma zamanına bakıyor. Varsayılan 30 saniye geçince kilit kaydı içindeki PID/host'un hâlâ canlı olup olmadığı denetlenmeden dosya siliniyor. Heartbeat/lease yenilemesi yok.

**Saldırı/hata senaryosu:** 100 bin not importu, büyük ek yazımı veya uzun senkronizasyon doğrulaması 30 saniyeyi aşar. İkinci CLI/MCP/masaüstü süreci aynı kasaya yazar; ilk işlem hâlâ çalışırken kilidi silip kendi kilidini alır. İki süreç indeks, journal ve şifreli nesneler üzerinde aynı anda değişiklik yapar.

**Etki:** Veri kaybı, kayıp güncelleme, bozuk indeks/journal, kurtarma sırasında belirsiz durum. Kötü niyetli yerel süreç bunu zamanlayarak tetikleyebilir; normal kullanım da tetikleyebilir.

**PoC kanıtı:** Güvenli geçici kasada eşik 100 ms'ye indirildi. İlk süreç 1.000 ms kilidi tuttu. İkinci süreç ilk kilitten 118 ms sonra kilidi aldı ve ilk sürecin bırakmasından yaklaşık 898 ms önce kritik bölgeye girdi. Ayrıca gerçek 100 bin not benchmark'ı 465 saniye sürdü; yani varsayılan eşiğin çok üstünde meşru işler vardır.

**Düzeltme:**

1. İşletim sistemi seviyesinde exclusive lock veya iyi denetlenmiş lockfile kütüphanesi kullanın.
2. Lease kullanılıyorsa benzersiz ownership token, periyodik heartbeat ve atomik yenileme ekleyin.
3. Aynı host'ta canlı PID'ye ait kilidi asla otomatik kaldırmayın; bilinmeyen host kilidi için açık kullanıcı kurtarma akışı kullanın.
4. Duvar saati gerilemesine güvenmeyin; mümkün yerde monotonic süre kullanın.
5. 30 saniyeyi aşan işlem + paralel ikinci süreç için Node/Rust çapraz süreç regresyon testi ekleyin.

### SEC-02 — Eklenti yetkisi ayrıcalıklı IPC sınırında uygulanmıyor

- **Önem:** Yüksek
- **Tür:** CWE-602 / CWE-863 — Client-Side Enforcement of Server-Side Security; Incorrect Authorization
- **Etkilenen yerler:** `desktop/src/plugins/host.ts:83-280`; `desktop/src/App.tsx:220-296`; `src-tauri/capabilities/main.json`
- **Durum:** Doğrulandı

Eklenti manifest yetkisi Web Worker mesajını alan tarayıcı kodunda `permits(...)` ile kontrol ediliyor. Ardından genel `get_note`, `save_note`, `read_attachment` benzeri Tauri komutları çağrılıyor. Rust komutu plugin kimliği, çalışan instance/revision veya talep edilen capability bilgisini almadığı için politika, signer revocation ve enabled durumu ayrıcalıklı sınırda yeniden doğrulanamıyor.

Çalışan eklentiler yalnızca `refreshPlugins()` çağrıldığında güncelleniyor. CLI veya başka bir süreç signer'ı iptal eder ya da eklentiyi kapatırsa çalışan worker, kullanıcı plugin ekranına girene/yenileyene, kasayı kilitleyene veya uygulamayı yeniden başlatana kadar eski manifest ile çağrı yapmayı sürdürebilir.

**Etki:** İptal edilmiş veya kapatılmış eklenti not/ek okuma ve yazma yetkisini sürdürebilir. UI katmanı atlanabilirse tüm ana pencere IPC yüzeyi erişilebilir olur. Bu, “Rust command layer gerçek güvenlik sınırıdır” mimari hedefiyle uyumsuzdur.

**Düzeltme:** Genel kasa IPC'sini plugin çağrıları için kullanmayın. Tek bir `plugin_call(plugin_id, instance_token, revision, method, params)` komutu oluşturun; Rust her çağrıda veya güvenli kısa ömürlü cache ile imza, signer iptali, enabled/revision ve capability kontrolü yapsın. Politika dosyası değişikliklerini izleyen cross-process invalidation ekleyin. Çalışan eklentinin out-of-band revocation sonrasında ilk sonraki çağrıda reddedildiğini test edin.

### SEC-03 — Güvenilmeyen ekler sandbox'sız iframe içinde aktif önizleniyor

- **Önem:** Yüksek (WebView2 blob-origin davranışına bağlı koşullu)
- **Tür:** CWE-79 — Improper Neutralization of Input During Web Page Generation
- **Etkilenen yerler:** `desktop/src/AttachmentLibrary.tsx:33-39,78-89,134-139`; `src-tauri/src/lib.rs:4408-4421`; `src-tauri/tauri.conf.json:29`
- **Durum:** Statik olarak doğrulandı; tam WebView runtime PoC'si yapılmadı

Ek MIME tipi yalnızca sözdizimi regex'iyle doğrulanıyor; `text/html` kabul ediliyor ve dosya içeriği/magic byte ile eşleştirilmiyor. `text/*` ve PDF blob URL'si `sandbox` özniteliği olmayan `iframe` içine veriliyor. CSP `frame-src 'self' blob:` izni sağlıyor. Ana pencere not ve ek komutlarının tamamını çağırabilen ayrıcalıklı WebView'dir.

**Saldırı senaryosu:** Kullanıcı kötü amaçlı HTML/SVG/PDF ekini içeri alıp önizler. WebView motorunun blob origin ve CSP uygulamasına göre script çalıştırma veya renderer açığı, kasa IPC erişimine dönüşebilir.

**Etki:** Kasa açıkken not/ek verisinin okunması veya değiştirilmesi; WebView açığı halinde kod çalıştırma. İstismar zincirinin son adımı hedef runtime'da ayrıca kanıtlanmalıdır, ancak mevcut sink güvenli kabul edilemez.

**Düzeltme:** `text/html`, SVG/XML ve çalıştırılabilir içerikleri inline açmayın. Düz metni escape edilmiş `<pre>` olarak render edin. MIME allowlist + magic-byte sniffing uygulayın. PDF/diğer aktif belgeleri `sandbox=""` olan, `allow-scripts` ve `allow-same-origin` verilmeyen ayrı bir önizleme bağlamına veya işletim sistemi görüntüleyicisine taşıyın. Kötü amaçlı HTML/SVG fixture ile “script çalışmadı ve IPC yok” entegrasyon testi ekleyin.

### SEC-04 — MCP grant politikası yokken bütün kasa fail-open

- **Önem:** Yüksek
- **Tür:** CWE-862 — Missing Authorization
- **Etkilenen yerler:** `src/grants.ts:133-137,239-247`; `src/mcp-server.ts:122`; `README.md:44,51-54,90`; `docs/PRODUCT.md:86`
- **Durum:** Doğrulandı; davranış README'de eski uyumluluk olarak belgelenmiş

Grant dosyası bulunmazsa karar doğrudan `allowed: true` döndürüyor ve “every unlocked key is reachable” diyor. `SBRAIN_AGENT` kimliği istemci tarafından seçilebilen ortam etiketidir; kimlik doğrulama değildir. Bu, ürün sözleşmesindeki “her ayrıcalıklı AI/plugin işlemi varsayılan reddedilir” maddesiyle ve “standing whole-vault access yok” ifadesiyle çelişir.

**Saldırı senaryosu:** MCP süreci parolayla başlatılır ama owner grant politikasını henüz oluşturmamıştır. MCP'ye bağlanan istemci katalogdaki her anahtarı tek tek çözebilir. Agent adı değiştirilerek farklı politika kimliği iddia etmek de mümkündür.

**Etki:** Yanlış yapılandırma halinde tüm kasa sırlarının istemciye açıklanması; least-privilege beklentisinin sessizce bozulması.

**Düzeltme:** Yeni ve mevcut kasalarda grant dosyası yoksa fail-closed yapın. Eski davranış gerekiyorsa açıkça adlandırılmış, süreli `--unsafe-legacy-open-access` geçiş bayrağı ve güçlü uyarı kullanın. Agent kimliğini owner kontrollü konfigürasyon/kimlik bilgisine bağlayın; istemcinin serbest ortam etiketi olmasın. İlk kullanımda politika kurulmadan MCP sunucusunu başlatmayın.

### SEC-05 — Faz 6 sync, düşman relay ve cihaz ele geçirilmesine hazır değil

- **Önem:** Yüksek / yayın engelleyici mimari eksik
- **Tür:** Kimlik doğrulama, iptal, replay/rollback ve freshness güvencesi eksikliği
- **Etkilenen yerler:** `src/sync.ts:235-280,492-552`; `docs/ROADMAP.md:71-81`; `README.md:517-553`
- **Durum:** Yol haritasında açıkça tamamlanmamış

Change ID ve şifreleme aynı kasa anahtarından türetiliyor; `deviceId` biçim doğrulamasından geçen bir UUID. Cihaza özgü asimetrik kimlik, owner-signed enrollment, cihaz iptal listesi ve anahtar rotasyonu yok. Relay'in en son bilinen head/checkpoint'i göstermesini zorlayan güvenilir freshness mekanizması da yok.

**Saldırı senaryoları:**

- Kasa anahtarını ele geçiren cihaz başka cihaz kimliğiyle geçerli change üretebilir.
- İptal edilmesi gereken cihaz yazmaya devam eder; rotasyon olmadığı için eski anahtar geçerlidir.
- Kötü relay geçerli geçmişin eski bir prefix'ini döndürüp yeni değişiklikleri saklar. HMAC bütünlüğü bozulmadığından istemci rollback/withholding'i kesin algılayamaz.
- Çok büyük fakat biçimsel olarak geçerli change kümesi DAG/ancestor doğrulamasında yüksek CPU/bellek tüketir.

**Düzeltme:** Per-device imza anahtarları, owner-signed enrollment sertifikaları, epoch tabanlı key rotation ve iptal; güvenilir/signed checkpoint veya şeffaflık günlüğü; change sayısı/toplam byte/derinlik sınırları; relay withholding/rollback testleri ekleyin. Bunlar tamamlanana kadar özelliği “experimental, trusted-device/local transport only” olarak kapılı tutun.

### SEC-06 — Audit zinciri tam silme, eşzamanlı append ve cache yaşam döngüsüne dayanıklı değil

- **Önem:** Orta
- **Tür:** CWE-778 / CWE-362 — Insufficient Logging; Race Condition
- **Etkilenen yerler:** `src/audit.ts:33,80-87,119-131,139-190`
- **Durum:** Doğrulandı

Hiç imzalı kayıt yoksa `verifyAudit` geçerli sonuç döndürüyor. Saldırgan audit dosyasını tamamen siler/truncate eder ve metadata'yı kaldırırsa zincir bozulması kanıtlanamaz. `appendAudit`, son hash'i okuyup `appendFileSync` yaparken kasa kilidi almıyor; paralel süreçler aynı `prevHash` ile kardeş kayıt yazabilir. Türetilmiş HMAC anahtarı process-global `Map` içinde süresiz tutuluyor.

**Etki:** Olayların silinmesi fark edilmeyebilir, normal eşzamanlı kullanım zinciri bozabilir ve audit anahtarı gereğinden uzun süre bellekte kalır.

**Düzeltme:** Append'i aynı kasa kilidi/tek-writer üzerinden seri hale getirin. Baş hash + monoton sayaç için şifreli ve kimlik doğrulamalı checkpoint tutun; silme tespiti gerekiyorsa owner'ın başka ortamında veya OS event log'unda sealed head saklayın. Başlatılmış kasada eksik audit'i uyarı/hata sayın. Cache'i lock/session yaşam döngüsüne bağlayıp zeroize edin. Dosya boyutunu okumadan önce sınırlayın.

### SEC-07 — `schema.json` hassas metadata'yı düz metin bırakıyor

- **Önem:** Orta
- **Tür:** CWE-312 — Cleartext Storage of Sensitive Information
- **Etkilenen yerler:** `src/schema.ts:16-44`; `src/mcp-server.ts:99,144,169,218`; `src/safety.ts:47-52`
- **Durum:** Doğrulandı; tasarım istisnası

Anahtar değerleri şifreli olsa da anahtar adları ve açıklamaları `schema.json` içinde düz metindir. “Açıklama non-sensitive olmalı” yalnızca prompt/metin sözleşmesidir; doğrulama uzunluk ve satır kontrolü yapar, sır veya hassas kategori tespit etmez. `health`, `finance`, IBAN, müşteri veya hesap anlamı taşıyan adlar disk hırsızına değerli profil çıkarımı sunabilir; kullanıcı açıklamaya yanlışlıkla gerçek sırrı da yazabilir.

**Düzeltme:** Şemayı varsayılan şifreli tutun. MCP discovery gerekiyorsa owner tarafından tek tek onaylanmış, minimize edilmiş exposure catalog üretin. Açıklama için secret scanner/redaction ve hassas kategori uyarısı ekleyin. Düz metin anahtar adlarını opsiyonel hale getirin.

### SEC-08 — Parola politikası zayıf; KDF maliyeti sabit ve düşük kalabilir

- **Önem:** Orta
- **Tür:** CWE-521 — Weak Password Requirements
- **Etkilenen yerler:** `src/document-crypto.ts:30-42,63-73`; `src-tauri/src/lib.rs:732-735,1400-1440`
- **Durum:** Doğrulandı

Uygulama yalnızca boş olmayan parola ister. scrypt `N=32768, r=8, p=1` yaklaşık 32 MiB bellek maliyetindedir ve manifest sürümünde sabittir. Güçsüz insan parolası kullanan kasanın kopyasını alan saldırgan, verifier veya AEAD doğrulamasıyla çevrimdışı sözlük saldırısı yapabilir.

**Düzeltme:** Hedef donanımlarda Argon2id veya daha güçlü/versioned scrypt parametrelerini benchmark edin; unlock bütçesine göre adaptif maliyet seçin. Parola gücü ölçümü, minimum uzunluk ve bilinen-parola kontrolü ekleyin. Eski manifestleri yeniden sarmalayan migrasyon ve opsiyonel keyfile/OS-keystore/hardware-backed ikinci faktör tasarlayın.

### SEC-09 — Şifreli dosya okumalarında genel boyut sınırı yok

- **Önem:** Orta
- **Tür:** CWE-400 — Uncontrolled Resource Consumption
- **Etkilenen yerler:** `src/documents.ts:551,567,748,759,814,828,1348,1372,1595,2043`; `src/store.ts:44,61`; `src/grants.ts:137`; `src/audit.ts:139`; `src-tauri/src/lib.rs:918-955,1611,1771,2269,2450,2658,2703,3904,4429,4513`
- **Durum:** Doğrulandı

Sync envelope'ları için 12 MiB ön-kontrol vardır; pek çok not/index/history/plugin/grant/audit dosyası ise `readFileSync` veya `fs::read` ile boyut kontrolü yapılmadan tamamen belleğe alınır. Yerel saldırgan veya bozuk yedek küçük bir şifreli dosyanın yerine çok büyük dosya koyarak AEAD doğrulaması başlamadan OOM/crash yaratabilir. 250 MiB ek okuması ayrıca Rust → base64 → JS string → `Uint8Array` → Blob boyunca birden fazla kopya oluşturur.

**Düzeltme:** Artifact türü başına ciphertext boyutu, kayıt sayısı ve toplam kasa limitleri koyun; okumadan önce metadata/stat kontrolü yapın. Ekleri stream edin, IPC response boyutunu sınırlayın ve backpressure kullanın. Oversized/corrupt corpus ile fuzz ve regresyon testleri ekleyin.

### SEC-10 — Eklenti runtime'ında in-flight, byte ve CPU bütçesi yok

- **Önem:** Orta
- **Tür:** CWE-770 — Allocation of Resources Without Limits
- **Etkilenen yerler:** `desktop/src/plugins/host.ts:83-280`; `desktop/src/App.tsx:220-268`
- **Durum:** Doğrulandı

Dakikada 600 çağrı limiti vardır, ancak aynı anda çalışan istek sayısı, response byte bütçesi, çağrı timeout/cancellation veya worker heartbeat'i yoktur. Her `message` bağımsız async handler başlatır. `attachments.read` tek çağrıda 250 MiB döndürebilir. Eklenti ready olduktan sonra sonsuz CPU döngüsü de startup timeout'una yakalanmaz.

**Etki:** İmzalı fakat kötü niyetli/bozuk eklenti UI'ı dondurabilir, belleği tüketebilir veya büyük sayıda ayrıcalıklı işi kuyruğa alabilir.

**Düzeltme:** Eklenti başına 1–4 in-flight sınırı, request/response byte kotası, deadline/cancellation, worker heartbeat ve büyük veri için streaming handle ekleyin. Kota aşımında tüm bekleyen işleri iptal edin; 250 MiB x paralel istek stres testi çalıştırın.

### SEC-11 — CI/release tedarik zinciri sertleştirmesi eksik

- **Önem:** Orta
- **Tür:** CWE-1104 — Use of Unmaintained Third Party Components
- **Etkilenen yerler:** `.github/workflows/ci.yml`; `.github/workflows/release.yml`; `src-tauri/Cargo.lock`
- **Durum:** Doğrulandı

`npm audit` ve `cargo audit` CI kapısı değildir. GitHub Actions sürüm etiketleri (`@v4`, `@stable`, `@v2`) immutable commit SHA'larına pinlenmemiştir. Release workflow MSI/NSIS üretir; Authenticode imzası, checksum, SBOM ve provenance/attestation adımı görünmüyor.

RustSec sonucu doğrudan vulnerability göstermedi; ancak `glib 0.18.5` için `RUSTSEC-2024-0429` unsound uyarısı ve GTK3/proc-macro/rust-unic ailesinde 16 unmaintained uyarısı verdi. `glib 0.18.5` mevcut Windows hedef grafiğine girmiyor; Linux/GTK hedefi için dikkate alınmalı.

**Düzeltme:** Actions'ı tam SHA'lara pinleyip Renovate/Dependabot ile güncelleyin. `npm audit --audit-level=high`, `cargo audit`/`cargo deny`, secret scan ve CodeQL/SAST'ı CI'ya ekleyin. SBOM, SHA-256 checksum, SLSA provenance ve Windows Authenticode imzası üretin. Tauri/GTK zincirini desteklenen sürümlere yükseltin.

## 6. Düşük önem / sertleştirme bulguları

### SEC-12 — Rust symlink kontrolü yalnızca son bileşeni kontrol ediyor

- **Önem:** Düşük–Orta
- **Etkilenen yer:** `src-tauri/src/lib.rs` içindeki `reject_symlink` kullanımları

Node tarafı yolun tüm bileşenlerini kontrol ederken Rust tarafında çoğu çağrı yalnızca son path'i kontrol ediyor. Aynı kullanıcı yetkisindeki saldırgan parent dizini symlink/junction ile değiştirerek veya kontrol ile kullanım arasında TOCTOU yaratarak şifreli okuma/yazmayı başka konuma yöneltebilir. Parent component doğrulaması, canonical root containment ve mümkünse handle-relative/no-follow açma kullanın.

### SEC-13 — macOS keychain secret'ı komut satırı argümanına geçiyor

- **Önem:** Düşük
- **Etkilenen yer:** `src/keychain.ts`

macOS `security` çağrısında secret argv içinde taşınıyor. Bazı ortamlarda aynı kullanıcıya ait process inspection/crash telemetry bunu açığa çıkarabilir. Native keychain binding veya stdin/IPC üzerinden secret kabul eden yöntem kullanın.

### SEC-14 — Oturum metadata'sı ve anahtar kopyaları bellek/yerel storage'da kalıyor

- **Önem:** Düşük / kabul edilmiş tehdit modeli
- **Etkilenen yerler:** `desktop/src/App.tsx`; `src/audit.ts`; Node/Rust oturum dizgileri

Son kasa yolu ve idle tercihi `localStorage` içindedir. Parola JS/Rust `String` kopyalarında ve türetilmiş audit key cache'inde beklenenden uzun kalabilir. Ana kasa anahtarı için Rust `Zeroizing` kullanılması olumlu olsa da dil/runtime kopyalarının tamamı silinemez. Kasa yolunu opsiyonel/minimize edin, cache'leri oturum kilidinde temizleyin ve crash dump/swap politikasını belgeleyin.

## 7. Saldırı sınıfı matrisi

| Saldırı | Mevcut kontrol | Kalan risk | Sonuç |
|---|---|---|---|
| Path traversal | Normalize/containment ve girdi doğrulama | Rust parent symlink/TOCTOU | Kısmen dayanıklı |
| Symlink/junction kaçışı | Node bileşen bazlı kontrol | Rust son-bileşen kontrolü | Sertleştirme gerekli |
| Ciphertext değiştirme | AES-GCM + AAD; HMAC change ID | Büyük dosyayla pre-auth DoS | Bütünlük güçlü, availability orta |
| Çevrimdışı parola kırma | scrypt + salt | Boş-olmayan dışında politika yok | Orta risk |
| Eşzamanlı yazım | Lock + journal + atomic rename | Canlı lock 30 sn sonra alınabiliyor | **Yüksek risk** |
| XSS/aktif belge | React escaping + CSP | Sandbox'sız blob iframe | **Yüksek koşullu risk** |
| Kötü eklenti | Worker, capability manifest, imza/revocation | Yetki Rust'ta değil; revocation gecikiyor; kota eksik | **Yüksek risk** |
| MCP yetki aşımı | Grant/expiry/confirmation/redaction | Grant yokken fail-open; agent adı self-asserted | **Yüksek risk** |
| Audit kurcalama | HMAC hash chain | Tam silme algılanmıyor; append race | Orta risk |
| Sync replay/fork | Canonical JSON, HMAC, device chain, DAG | Enrollment/revocation/rotation/freshness yok | **Üretime hazır değil** |
| Kaynak tüketimi | Ek ve sync envelope limitleri | Genel dosya/in-flight/CPU limitleri eksik | Orta risk |
| Tedarik zinciri | Lockfile, Dependabot, testler | Mutable Actions, audit gate/signing/SBOM yok | Orta risk |
| Sır sızıntısı | Secret desen taraması temiz | Düz metin schema metadata, argv/bellek | Düşük–Orta |

## 8. Öncelikli düzeltme planı

### P0 — Her türlü güvenlik iddialı sürümden önce

1. SEC-01: Kilit sahipliği/heartbeat/PID doğrulamasını düzeltin ve çapraz süreç testi ekleyin.
2. SEC-02: Eklenti çağrılarını Rust'ta kimlikli, capability kontrollü tek IPC sınırına taşıyın; revocation'ı anında uygulayın.
3. SEC-03: Aktif ek önizlemesini kapatın veya ayrı sandbox bağlamına alın.
4. SEC-04: MCP'yi grant yokken fail-closed yapın; legacy modu açık ve geçici hale getirin.
5. Faz 6'yı güvenilmeyen relay/multi-device için etkinleştirmeyin; SEC-05 tasarımını tamamlayın.

### P1 — 1.0 release adayı öncesi

1. Audit append ve silme tespitini güçlendirin.
2. Dosya, IPC ve eklenti kaynak limitlerini uygulayın.
3. KDF/parola politikasını versioned migrasyonla güçlendirin.
4. `schema.json` exposure modelini owner-controlled ve şifreli hale getirin.
5. CI dependency/SAST/secret kapıları, SHA pinleme, imzalı installer, SBOM ve provenance ekleyin.
6. Faz 6 cihaz enrollment/revocation/key rotation ile kurtarma tatbikatını tamamlayın.

### P2 — Sürekli sertleştirme

1. Parent symlink ve TOCTOU dayanıklılığını handle-relative I/O ile yükseltin.
2. macOS keychain argv kullanımını kaldırın.
3. Oturum cache'lerini kilitte temizleyip bellek/crash dump politikasını belgeleyin.
4. Kötü/bozuk kasa corpus'u için property-based test, fuzzing ve WebView runtime güvenlik testleri ekleyin.

## 9. Önerilen yayın kapıları

1. P0 bulgularının tümü kapanmadan “secure plugin runtime”, “least-privilege MCP” veya “untrusted sync” iddiasıyla sürüm çıkarılmamalı.
2. Her güvenlik düzeltmesi Node + Rust + desktop entegrasyon testine sahip olmalı.
3. `npm audit`, `cargo audit/deny`, secret scan ve SAST temiz olmadan release job başlamamalı.
4. Faz 6 için iki kötü relay testi zorunlu olmalı: geçerli prefix rollback ve seçici change withholding.
5. İptal edilmiş cihaz/eklenti, iptal anından sonraki ilk ayrıcalıklı çağrıda reddedilmeli.
6. 30 saniyeden uzun yazım sırasında ikinci süreç hiçbir zaman kritik bölgeye girememeli.
7. Kötü amaçlı HTML/SVG/PDF önizlemesi script çalıştıramamalı ve Tauri IPC'ye erişememeli.
8. Harici penetrasyon testi ve kurtarma tatbikatı tamamlanmadan stabil 1.0 formatı ilan edilmemeli.

## 10. Güçlü kontroller

- AES-256-GCM, rastgele 12-byte IV ve type/id/revision'a bağlı AAD.
- scrypt tabanlı anahtar türetme ve Rust ana anahtarında `Zeroizing`.
- Atomik temp-write + fsync + rename ve write journal/kurtarma akışı.
- Node tarafında traversal ve symlink bileşen kontrolleri.
- Dar CSP; shell, doğrudan filesystem ve network Tauri plugin'lerinin yokluğu.
- React Markdown'ın raw HTML'yi varsayılan çalıştırmaması ve canvas URL'lerinin HTTP(S) ile sınırlanması.
- İmzalı eklenti paketleri, TOFU signer pinning, restricted mode ve worker izolasyonu.
- Sync change'lerde canonical JSON, HMAC tabanlı content ID, device-chain ve causal DAG doğrulaması.
- Güncel bağımlılık taramasında bilinen vulnerability bulunmaması ve çalışma ağacı/git geçmişi secret taramasının temiz olması.
- 214 otomatik test ve başarılı 100 bin not performans kapısı.

## 11. Sınırlamalar

Bu denetim kaynak kodu, test, paket, dependency ve kontrollü yerel PoC incelemesidir. Aşağıdakiler yapılmadı:

- İmzalı MSI/NSIS kurulumu üzerinde bağımsız Windows sandbox dinamik analizi.
- WebView2 sürüm matrisi üzerinde gerçek HTML/SVG/PDF exploit PoC'si.
- Henüz uygulanmamış relay'e karşı ağ penetrasyon testi.
- macOS/Linux runtime testi ve mobil istemci testi.
- Uzun süreli coverage-guided fuzzing veya üçüncü taraf profesyonel pentest.
- Ortamda bulunmadıkları için Semgrep, Gitleaks, Trivy ve OSV-Scanner çalıştırılamadı. Bu boşluk regex/history secret taraması, manuel data-flow incelemesi, `npm audit` ve güncel RustSec ile kısmen telafi edildi.

Dolayısıyla “bulgu yok” sonucu verilmiyor; bu rapor doğrulanmış kusurları ve koddan güçlü biçimde çıkarılan riskleri önceliklendirir. Özellikle SEC-03'ün tam istismar edilebilirliği hedef WebView runtime'ında ayrıca doğrulanmalıdır.

## 12. Son karar

Mevcut sürüm güçlü bir şifreli yerel kasa temeline sahiptir ve ana testleri geçmektedir. Ancak **bütün fazlar tamamlanmış değildir**. Faz 6 açık durumdadır; Faz 5 güvenlik sınırlarında da iki yüksek önem bulgu vardır. P0 maddeleri kapanmadan ürünün güvenilmeyen eklenti, varsayılan least-privilege MCP veya güvenilmeyen relay senaryolarında güvenli olduğu ilan edilmemelidir.
