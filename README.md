# MediVibe - Telemedicine Platform (Vulnerable Baseline)

⚠️ **ATTENZIONE: Questa è la versione di base insicura generata tramite IA (Vibe Coding). Contiene gravi vulnerabilità architetturali e NON deve essere utilizzata in ambienti di produzione.** ⚠️

**MediVibe** è un prototipo di piattaforma web per la telemedicina, sviluppato come progetto per il corso di **Laboratorio di Sicurezza dei Sistemi e Privacy**. 

Questo specifico branch (`initial-vulnerable-version`) rappresenta il punto di partenza del progetto: un'applicazione funzionale dal punto di vista dell'utente finale, ma strutturalmente fragile dal punto di vista della sicurezza. Questo codice è stato utilizzato come caso di studio per eseguire le successive attività di *Threat Modeling* e *Hardening* documentate nella relazione di progetto (disponibili nel branch `main`).

---

## Funzionalità (Implementazione Insicura)

- **RBAC (Role-Based Access Control):** Gestione dei privilegi per Pazienti, Medici e Amministratori (basata su cookie manipolabili lato client).
- **Cartella Clinica:** Inserimento e consultazione di sintomi e referti.
- **Upload dei Referti:** Caricamento di documenti tramite `multer` (privo di validazione e filtri di sicurezza).
- **Database:** Salvataggio dei dati su SQLite3 (vulnerabile a injection).

---

## Stack Tecnologico

- **Backend:** Node.js, Express.js
- **Database:** SQLite3
- **Librerie accessorie:** Multer, Crypto (modulo nativo Node.js)
- **Frontend:** EJS (Embedded JavaScript templates), CSS3 HTML5

---

## Istruzioni per l'Avvio

Segui questi passaggi per configurare e avviare la baseline vulnerabile in ambiente locale.

### 1. Prerequisiti
Assicurati di avere installato sul tuo sistema:
- [Node.js](https://nodejs.org/) (versione 18.x o superiore)
- npm (incluso con Node.js)

### 2. Clonazione e Installazione
Clona la repository, assicurati di posizionarti su questo specifico branch e installa le dipendenze:

```bash
git clone [https://github.com/giovimori/MediVibe.git](https://github.com/giovimori/MediVibe.git)
cd MediVibe
git checkout initial-vulnerable-version
npm install
```

### 3. Configurazione
In questa versione **non è necessario creare alcun file `.env`**. Come dimostrazione di una cattiva pratica di programmazione (*Security Misconfiguration*), le chiavi API e le credenziali di default sono hardcoded direttamente nei file sorgente (`server.js` e `db.js`).

### 4. Avvio del Server e Inizializzazione DB
Avvia l'applicazione. Al primo avvio, il file `db.js` creerà automaticamente il file `database.sqlite` e inserirà gli account di default:

```bash
node server.js
```

Il server sarà in ascolto all'indirizzo: **`http://localhost:3000`**

---

## Account di Test (Seeding)

Una volta avviato il server, puoi effettuare il login con i seguenti account pre-generati (le password sono hardcoded nel file `db.js`):

| Ruolo | Email | Password |
| :--- | :--- | :--- |
| **Amministratore** | `admin@medivibe.com` | `admin123` |
| **Medico** | `bianchi@medivibe.com` | `doc123` |
| **Paziente** | *Registrabile via UI* | *Scelta dall'utente* |

---

## Vulnerabilità Note (OWASP Top 10 2025)

Il codice presente in questo branch è affetto dalle seguenti criticità, discusse ampiamente nella Relazione di Progetto:

1. **A03:2025 - Injection:** Il driver SQLite concatena direttamente l'input utente nelle query SQL, permettendo la manipolazione delle istruzioni (SQL Injection).
2. **A01:2025 - Broken Access Control & Session Management:** L'autorizzazione si basa sulla fiducia cieca in cookie gestiti dal client (`isAdmin`, `user_id`), permettendo la *Privilege Escalation* tramite manipolazione locale.
3. **A02:2025 - Cryptographic Failures:** Le password sono protette utilizzando l'algoritmo obsoleto MD5 senza *salt*, rendendole vulnerabili agli attacchi tramite *Rainbow Tables*.
4. **A05:2025 - Security Misconfiguration (Segreti Hardcoded):** Le chiavi API per i servizi di terze parti (es. SendGrid) e le password di *seeding* sono scritte in chiaro nel codice.
5. **A04:2025 - Insecure File Upload & Path Traversal:** L'assenza di *Whitelisting* su `multer` e l'accettazione diretta di `file.originalname` consentono il caricamento di Webshell o payload malevoli.
6. **A01:2025 - IDOR (Insecure Direct Object Reference):** L'endpoint per la visualizzazione dei referti non verifica la proprietà della risorsa, permettendo l'accesso non autorizzato ai dati di altri pazienti manipolando l'ID nella richiesta `GET`.

---
**Autori:** Giovanni Morelli, Rei Mici
