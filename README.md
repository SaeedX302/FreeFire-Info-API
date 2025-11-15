
<h1 align="center">🔥 FreeFire Info API 🔥</h1>

<p align="center">
  <b>A lightweight, fast & secure API for fetching Free Fire player profiles</b><br>
  <sub>Built with Flask • Powered by AES-CBC Encryption • Backed by Protobuf Serialization</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-Async-green?logo=flask" />
  <img src="https://img.shields.io/badge/License-MIT-orange" />
  <img src="https://img.shields.io/github/stars/TSun-FreeFire/TSun-FF-Info-API?style=social" />
  <img src="https://img.shields.io/github/forks/TSun-FreeFire/TSun-FF-Info-API?style=social" />
</p>

---

## ⚡ Overview

This project exposes a **Free Fire Player Info API** that:
- Retrieves player profiles by UID  
- Handles token refresh automatically  
- Uses **AES-CBC encryption** & **Protobuf serialization**  
- Runs asynchronously via Flask for maximum performance  

---

## 🧠 Core Features

✅ **Encrypted Communication** — AES-CBC protocol for secure request handling  
✅ **Protobuf Serialization** — Lightweight, binary-efficient data exchange  
✅ **In-Memory Token Cache** — Fast performance with lifecycle management  
✅ **Async Flask Server** — Works with Gunicorn, Uvicorn, or any WSGI server  
✅ **Auto Refresh** — Periodic background token renewal  

---

## 🔗 API Endpoints

| Endpoint | Method | Description |
|-----------|--------|-------------|
| `/get?uid=<PLAYER_UID>` | GET | Fetch player profile data |
| `/refresh` | GET | Manually refresh all region tokens |

**Example Usage**
```bash
GET /get?uid=123456789
````

**Response**

```json
{
  "AccountInfo": {
    "AccountName": "LegendX",
    "AccountLevel": 65,
    "AccountRegion": "AS",
    "AccountLikes": 2400
  },
  "BanStatus": {
    "isBanned": false,
    "reason": null
  }
}
```

---

## 🧩 Architecture

```
├── app.py              # Flask async app
├── core/
│   ├── encryption.py   # AES-CBC encrypt/decrypt
│   ├── protobuf.py     # Protobuf serializer/deserializer
│   └── token_cache.py  # Token cache + lifecycle
├── static/
│   └── logo.png
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/TSun-FreeFire/TSun-FF-Info-API.git
cd TSun-FF-Info-API
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Server

```bash
python app.py
```

---

## 🧠 Contributing

Contributions are **welcome & appreciated**!
Follow these steps:

1. **Fork** this repository
2. **Create a new branch** (`feature/new-feature`)
3. **Commit your changes**
4. **Push to your fork** and open a **Pull Request**

> ⚠️ Do not commit credentials or tokens.
> ✅ Add tests where possible.

---

## 🧾 License & Author

* **Author:** [@Saeedxdie](https://github.com/Saeedxdie)
* **License:** MIT *(recommended)*
* **Made with 💀 by TSun Studio*

---

## 🧰 Tech Stack

| Component            | Description                        |
| -------------------- | ---------------------------------- |
| **Python**           | Core language                      |
| **Flask**            | Backend framework                  |
| **Protobuf**         | Data serialization                 |
| **AES-CBC**          | Encryption algorithm               |
| **Gunicorn/Uvicorn** | Deployment-ready ASGI/WGSI servers |

---

## 💬 Support & Community

💌 **Discord:** Coming soon

🐞 **Report Bug:** [Issues](https://github.com/Saeedxdie/FreeFire-Info-API/issues)

⭐ **Star this repo** if you like it — it keeps the project alive!

---

<h3 align="center">🚀 — FreeFire Info API</h3>
