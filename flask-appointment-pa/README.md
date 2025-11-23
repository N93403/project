# Sistema di Prenotazione Appuntamenti per Pubblica Amministrazione

## 📌 Descrizione
Applicazione web sviluppata in **Python Flask** per la gestione di prenotazioni presso uffici della Pubblica Amministrazione.  
Il progetto segue gli standard **ISO/IEC/IEEE 29148:2018 (Requirements Engineering)** e **ISO/IEC 12207 (Software Life Cycle Processes)**, con documentazione completa e tracciabilità dei requisiti.

## 🚀 Funzionalità
- Registrazione e login sicuro (bcrypt, Flask-Login).
- Prenotazione appuntamenti con validazione orari e prevenzione doppie prenotazioni.
- Modifica e cancellazione prenotazioni.
- Back-office per operatori (gestione slot e reportistica).
- Notifiche email/SMS (estendibile).
- Documentazione tecnica (SRS, piano test, matrice tracciabilità).

## 🛠 Tecnologie
- Python 3, Flask, SQLAlchemy, Flask-WTF
- PostgreSQL / SQLite
- Alembic per migrazioni
- Docker e docker-compose
- Pytest per test automatici

## 📑 Documentazione
- [docs/SRS.md](docs/SRS.md) → Specifica requisiti software (ISO 29148).
- [docs/Architecture.md](docs/Architecture.md) → Architettura e decisioni.
- [docs/TestPlan.md](docs/TestPlan.md) → Piano di test (ISO 12207).
- [docs/TraceabilityMatrix.csv](docs/TraceabilityMatrix.csv) → Matrice requisiti ↔ test.

## ⚙️ Installazione
```bash
git clone https://github.com/tuo-username/flask-appointment-pa.git
cd flask-appointment-pa
pip install -r requirements.txt
flask run
