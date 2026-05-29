# MediVibe - Secure Telemedicine Platform

**MediVibe** è un prototipo di piattaforma web per la telemedicina, sviluppato come progetto per il corso di **Laboratorio di Sicurezza dei Sistemi e Privacy**. 

L'obiettivo del progetto è dimostrare l'applicazione pratica dei principi di **Secure Coding**. Partendo da una *baseline* software vulnerabile generata tramite IA (*Vibe Coding*), il codice è stato sottoposto a *Threat Modeling* e *Hardening* per mitigare le principali vulnerabilità della OWASP Top 10 (SQL Injection, Broken Access Control, Cryptographic Failures, Insecure File Upload).

---

## Funzionalità

- **RBAC (Role-Based Access Control):** Gestione rigorosa dei privilegi lato server per Pazienti, Medici e Amministratori.
- **Cartella Clinica:** Inserimento e consultazione di sintomi e referti.
- **Upload Sicuro dei Referti:** Caricamento di documenti (PDF/Immagini) con validazione MIME type, whitelisting delle estensioni e ridenominazione sicura dei file.
- **Database Sicuro:** Query parametrizzate (no SQLi) e password protette con hash crittografico forte e salt automatico.

---

## Stack Tecnologico

- **Backend:** Node.js, Express.js
- **Database:** SQLite3
- **Sicurezza:** Bcrypt, Express-Session, Dotenv, Multer (Secure Config)
- **Frontend:** EJS (Embedded JavaScript templates), CSS3 HTML5

---

## Istruzioni per l'Avvio

Segui questi passaggi per configurare e avviare il progetto in ambiente locale.

### 1. Prerequisiti
Assicurati di avere installato sul tuo sistema:
- [Node.js](https://nodejs.org/) (versione 18.x o superiore)
- npm (incluso con Node.js)

### 2. Clonazione e Installazione
Clona la repository e installa le dipendenze definite nel `package.json`:

```bash
git clone [https://github.com/giovimori/MediVibe.git](https://github.com/giovimori/MediVibe.git)
cd MediVibe
npm install
```

### 3. Configurazione delle Variabili d'Ambiente (.env)
Per motivi di sicurezza, i segreti non sono tracciati nel codice sorgente. **Devi creare manualmente un file chiamato `.env`** nella cartella principale del progetto e inserirvi i seguenti parametri:

```env
# Chiave segreta per la firma dei cookie di sessione
SESSION_SECRET=ScriviQuiUnaChiaveMoltoLungaESicura123!

# Chiave API (mock) per il servizio email
SENDGRID_API_KEY=sg_mock_key_98765

# Password di default per il caricamento iniziale del database (Seeding)
DEFAULT_ADMIN_PASSWORD=AdminPassword2026!
DEFAULT_DOCTOR_PASSWORD=DoctorPassword2026!
```

### 4. Avvio del Server e Inizializzazione DB
Avvia l'applicazione. Al primo avvio, il file `db.js` creerà automaticamente il file `database.sqlite`, configurerà le tabelle ed eseguirà il *seeding* degli account di default:

```bash
npm start
```
*(In alternativa, puoi usare il comando `node server.js`)*

Il server sarà in ascolto all'indirizzo: **`http://localhost:3000`**

---

## Account di Test (Seeding)

Una volta avviato il server, puoi effettuare il login con i seguenti account pre-generati:

| Ruolo | Email | Password |
| :--- | :--- | :--- |
| **Amministratore** | `admin@medivibe.com` | *Il valore assegnato a DEFAULT_ADMIN_PASSWORD nel file .env* |
| **Medico** | `bianchi@medivibe.com` | *Il valore assegnato a DEFAULT_DOCTOR_PASSWORD nel file .env* |
| **Paziente** | *Registrabile via UI* | *Scelta dall'utente in fase di registrazione* |

---

## Dettaglio delle Mitigazioni di Sicurezza (Hardening)

Questo ramo della repository contiene la versione messa in sicurezza. Le principali mitigazioni implementate includono:

1. **Injection:** Adozione esclusiva di Prepared Statements nel driver SQLite per prevenire manipolazioni SQL (Separazione dei Domini).
2. **Broken Access Control & Session Management:** Transizione da cookie in chiaro a `express-session` lato server, con hardening dei cookie (`HttpOnly`, `SameSite=lax`), distruzione sicura della sessione al logout e controlli RBAC.
3. **Cryptographic Failures:** Sostituzione dell'algoritmo obsoleto MD5 con Bcrypt (cost factor 10 e salt automatico).
4. **Security Misconfiguration (Segreti Hardcoded):** Isolamento di chiavi API e credenziali di default tramite la libreria `dotenv`.
5. **Insecure File Upload & Path Traversal:** Configurazione rigida di `multer` con generazione di identificativi univoci casuali per i nomi dei file e filtro rigoroso basato su whitelist di estensioni (`.pdf`, `.png`, `.jpg`, `.jpeg`).
6. **IDOR (Insecure Direct Object Reference):** Implementazione di rigorosi controlli autorizzativi lato server per verificare l'identità e la proprietà delle risorse (referti) prima dell'accesso, impedendo la manipolazione diretta degli identificativi (ID) nelle richieste HTTP.

---
**Autori:** Giovanni Morelli, Rei Mici
