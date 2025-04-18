# VirusScanBot

🦠 A simple Telegram bot that scans uploaded files with [VirusTotal](https://www.virustotal.com) and returns an interactive threat report with clickable buttons.

## 🔑 Requirements
You will need two (free) API tokens:

1. **VirusTotal API key** – Get yours at: https://www.virustotal.com/gui/my-apikey
2. **Telegram Bot Token** – Create one via [@BotFather](https://t.me/BotFather)

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/your-username/virusscanbot.git
cd virusscanbot
```

### 2. Install dependencies
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Create `.env`
Create a file called `.env` in the root folder:
```
API_ID = your_telegram_api_id
API_HASH = your_telegram_api_hash
BOT_TOKEN = your_telegram_bot_token
VT_API_KEY = your_virustotal_api_key
```

> Don't have `API_ID`/`API_HASH`? Get them here: https://www.virustotal.com/gui/my-apikey

### 4. Run the bot
```bash
python run.py
```

---

## 🛠 Features
- Accepts any file through Telegram
- Computes SHA256 and queries VirusTotal
- If not found — uploads it for analysis
- Shows detection count, signatures, metadata
- Clean inline buttons for navigation

---

## 📦 Optional
Run it with Docker:
```bash
docker build -t virusscanbot .
docker run --env-file .env virusscanbot
```

---

## 📄 License
MIT — use it, fork it, break it, improve it 😎

---

## 💡 Tip
Use a private group or channel with the bot added to keep your scans organized.