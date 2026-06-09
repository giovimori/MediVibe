# MediVibe - Secure Design & Threat Model

Questo documento mappa e tiene traccia dei requisiti di sicurezza, del modello delle minacce (Threat Model) e delle decisioni architetturali prese per mettere in sicurezza il prototipo di telemedicina **MediVibe**, passando dal branch insicuro (`initial-vulnerable-version`) al branch hardened (`main`).

---

## 1. Security Threat Model

### 1.1 Component Overview
* **Descrizione**: MediVibe è un'applicazione web MVC basata su Node.js, Express e SQLite3 per la gestione delle cartelle cliniche (sintomi, referti, assegnazione dei medici).
* **Consumatori**: Pazienti (utenti esterni), Medici (utenti interni privilegiati) ed Amministratori (utenti interni altamente privilegiati).
* **Contesto di Distribuzione**: Esposta sul web (HTTP/HTTPS) con accesso pubblico alle pagine di login e registrazione, e accesso autenticato alle dashboard di gestione.

### 1.2 Entry Points e Input non Fidati
| Entry Point | Tipo | Fidato? | Validazione / Gestione delle Minacce |
|---|---|---|---|
| `/login` (POST) | Form Data | No | Sanitizzazione e query parametrizzata per prevenire SQLi. Messaggio generico d'errore. |
| `/register` (POST) | Form Data | No | Prepared statements e cifratura asincrona con Bcrypt. |
| `/dashboard/symptoms` (POST) | Form Data | No | Validazione della sessione utente corrente prima dell'aggiornamento. |
| `/report` (GET) | Query Param (`id`) | No | Validazione dell'ownership: solo il proprietario del referto, il medico assegnato o l'amministratore possono vederlo. |
| `/upload` (POST) | Multipart Form | No | Filtro sulle estensioni dei file (solo PDF/PNG/JPG), ridenominazione tramite hash casuale (UUID) per prevenire Path Traversal e upload di Webshell. |

### 1.3 Confini di Fiducia (Trust Boundaries)
* **Autenticazione**: Gestita server-side tramite `express-session` firmata con chiave segreta. La sessione è protetta tramite fingerprinting del client (IP e User-Agent) e controllo di concorrenza degli accessi simultanei. I cookie non contengono dati sensibili in chiaro o modificabili.
* **Autorizzazione**: Controllo degli accessi basato sui ruoli (RBAC) con controlli strict basati sui dati di sessione salvati sul server (`req.session.role !== 'admin'/'doctor'/'patient'`).
* **Boundary Crossing**: Il passaggio dall'area pubblica (non autenticata) all'area privata richiede la creazione della sessione sul server. Il passaggio ad azioni amministrative richiede la verifica del ruolo `admin` salvato in sessione.

### 1.4 Sentieri dei Dati Sensibili (Sensitive Data Paths)
* **Password**: Ricevute via POST su HTTPS, cifrate immediatamente tramite Bcrypt (cost factor 10) prima della memorizzazione in SQLite3.
* **Referti Clinici**: I file fisici sono archiviati in `/public/uploads` con nomi casualizzati non prevedibili. L'accesso al record del referto `/report?id=X` è protetto da controlli di appartenenza utente-medico.

---

## 2. Requisiti di Sicurezza & Hardening Architetturale

Questo capitolo descrive come sono stati risolti i 6 problemi architetturali identificati inizialmente.

### 2.1 A03:2025 - Injection (SQL Injection)
* **Vulnerabilità Baseline**: Concatenazione diretta di stringhe non validate provenienti dall'input utente nelle query SQL.
* **Decisione Architetturale**: Adozione sistematica di Prepared Statements e Placeholders (`?`) per tutte le query SQLite3.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js) e [db.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/db.js).

### 2.2 A01:2025 - Broken Access Control & Session Management
* **Vulnerabilità Baseline**: Autorizzazione basata sui cookie del client (`isAdmin`, `user_id`) facilmente modificabili tramite Developer Tools.
* **Decisione Architetturale**: Implementazione di `express-session` con memorizzazione dello stato della sessione e dei privilegi sul server. Configurazione di cookie sicuri (`httpOnly: true`, `sameSite: 'lax'`, `secure: false` in ambiente locale).
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js).

### 2.3 A02:2025 - Cryptographic Failures
* **Vulnerabilità Baseline**: Password archiviate utilizzando l'algoritmo obsoleto MD5 senza sale (*salt*).
* **Decisione Architetturale**: Adozione della libreria `bcrypt` per calcolare un hash forte con salt generato automaticamente e cost factor impostato a 10.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js) e [db.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/db.js).

### 2.4 A05:2025 - Security Misconfiguration (Segreti Hardcoded)
* **Vulnerabilità Baseline**: Chiavi API fittizie e password di seeding scritte in chiaro nel codice sorgente.
* **Decisione Architetturale**: Esternalizzazione di tutte le configurazioni e delle credenziali sensibili nel file d'ambiente non tracciato `.env` tramite l'uso del modulo `dotenv`.
* **File Coinvolti**: [.env](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/.env) e [db.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/db.js).

### 2.5 A04:2025 - Insecure File Upload & Path Traversal
* **Vulnerabilità Baseline**: Salvataggio dei file sul server mantenendo il nome originale del client (`file.originalname`), permettendo l'upload di webshell (`.html`, `.js`) o la sovrascrittura di file di sistema tramite path traversal.
* **Decisione Architetturale**:
  1. Configurazione di un `fileFilter` su Multer che accetta esclusivamente estensioni whitelisted (`.pdf`, `.png`, `.jpg`, `.jpeg`).
  2. Generazione di un nome file univoco tramite hash casuale (`crypto.randomBytes(16)`) per impedire attacchi di sovrascrittura e path traversal.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js).

### 2.6 A01:2025 - IDOR (Insecure Direct Object Reference)
* **Vulnerabilità Baseline**: Visualizzazione del referto tramite `id` senza verificare se l'utente loggato fosse il proprietario o il medico associato a quel referto.
* **Decisione Architetturale**: Controllo autorizzativo server-side prima di renderizzare la risorsa. Il server verifica che `req.session.role === 'admin' || report.user_id == userId || report.doctor_id == userId`, altrimenti restituisce un codice di errore `403 Forbidden`.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js).

### 2.7 Session Concurrency Control (Controllo Concorrenza Sessioni)
* **Vulnerabilità Baseline**: Un utente (es. medico o amministratore) può effettuare l'accesso contemporaneamente da molteplici dispositivi o browser utilizzando le stesse credenziali, senza che le sessioni precedenti vengano terminate o controllate.
* **Decisione Architetturale**: Implementazione di un controllo di concorrenza che traccia l'identificativo di sessione attivo (`active_session_id`) nella tabella `users` del database. All'accesso di un nuovo client, la sessione precedente associata allo stesso utente viene terminata lato server ed invalidata.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js) e [db.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/db.js).

### 2.8 Session Fingerprint Binding (Prevenzione Session Hijacking)
* **Vulnerabilità Baseline**: Se un utente malintenzionato ruba il cookie di sessione valido (`connect.sid`), può riutilizzarlo da qualsiasi host o browser per impersonare la vittima, in quanto il server non verifica l'identità del client che effettua la richiesta rispetto a chi ha originato la sessione.
* **Decisione Architetturale**: Associazione della sessione dell'utente ad un fingerprint composto dal client IP (`X-Forwarded-For` o `socket.remoteAddress`) e dall'User-Agent. Il middleware `sessionFingerprintCheck` verifica ogni richiesta rispetto ai dati legati all'atto del login. Qualsiasi discrepanza comporta la distruzione immediata della sessione in memoria e nel DB, e la rimozione del cookie di sessione.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js).

### 2.9 Session Encryption At-Rest (Cifratura della sessione a riposo)
* **Vulnerabilità Baseline**: Se un attaccante ottiene accesso in lettura allo store delle sessioni (in memoria o su database/Redis), può leggere tutte le informazioni sensibili in chiaro (ID utente, ruolo, fingerprint IP/User-Agent).
* **Decisione Architetturale**: Implementazione di un wrapper per lo store di `express-session` che effettua in modo trasparente l'override dei metodi `get` e `set`. I dati di sessione vengono serializzati in JSON e cifrati simmetricamente tramite algoritmo `AES-256-CBC` con una chiave sicura derivata da `SESSION_ENCRYPTION_KEY`. Lo store archivia esclusivamente l'oggetto cifrato `{ encryptedPayload: iv + ":" + ciphertext }`.
* **File Coinvolti**: [server.js](file:///Users/giovannimorelli/Desktop/privacy/MediVibe/MediVibe/server.js).

---

## 3. Difesa in Profondità (Defense-in-Depth)

Sul branch sicuro (`main`) è stato aggiunto il modulo **Helmet** che configura automaticamente header di sicurezza HTTP raccomandati per mitigare minacce a livello di protocollo e browser:
* **HSTS (Strict-Transport-Security)**: Forza la connessione su canale cifrato.
* **X-Frame-Options (DENY)**: Previene attacchi di Clickjacking impedendo che l'app venga integrata all'interno di iframe non autorizzati.
* **Content-Security-Policy (CSP)**: Impedisce l'esecuzione di script iniettati riducendo drasticamente il rischio di attacchi XSS.
* **X-Content-Type-Options (nosniff)**: Impedisce al browser di interpretare i file scaricati come tipi diversi da quelli dichiarati dal server.

---

## 4. Validazione & Test di Sicurezza

I test automatici implementati nella cartella `/tests` forniscono un meccanismo di regressione continua per garantire che le mitigazioni non vengano rimosse.

Per avviare i test su qualsiasi branch:
```bash
npm test
```
Ogni test stamperà in console dettagli preziosi (payload inviati, cookie rilevati, risposte del server, valori attesi vs valori effettivi) per un'attività semplificata di debug e verifica della sicurezza.
