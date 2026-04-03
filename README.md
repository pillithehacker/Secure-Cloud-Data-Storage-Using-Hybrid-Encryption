# Secure Cloud Data Storage Using Hybrid Encryption

A full-stack Flask web application for secure file storage with role-based dashboards, hybrid cryptography (AES + RSA), and a modern cyber-security themed UI.

## Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite (SQLAlchemy ORM)
- **Auth:** Flask-Login, Flask-Bcrypt
- **Crypto:** `cryptography` (AES-GCM + RSA OAEP)
- **Frontend:** HTML, CSS, JavaScript, Bootstrap 5
- **Charts/Tables:** Chart.js, DataTables
- **UI Libraries:** Font Awesome, AOS, GSAP, SweetAlert2, Toastify, Typed.js, Particles.js, Lottie

## Project Structure

```text
.
├── app.py
├── config.py
├── models.py
├── seed.py
├── requirements.txt
├── services/
│   ├── access_control.py
│   ├── encryption_service.py
│   ├── file_service.py
│   ├── hash_service.py
│   └── rsa_key_manager.py
├── static/
│   ├── css/style.css
│   ├── js/app.js
│   ├── uploads/
│   ├── encrypted/
│   └── images/
└── templates/
    ├── layout.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── developers.html
    ├── dashboard/
    ├── files/
    └── errors/
```

## Core Features

- User registration and login
- Role-based access control (**Admin / User / Auditor**)
- Hybrid file encryption and decryption:
  - AES-256 (GCM) for file contents
  - RSA public/private keys for AES key wrapping
- File upload, download, share, delete
- Activity logging and security/audit visibility
- Admin/User/Auditor dashboards
- Profile management
- Modern responsive cyber-themed UI

## Roles and Permissions

### Admin
- Access admin dashboard
- View all users and files
- Block/unblock users
- Delete users/files
- View full logs and statistics

### User
- Access user dashboard
- Upload files
- Encrypt/decrypt/download own files
- Share files with other users
- View own logs

### Auditor
- Access auditor dashboard
- View logs and security reports
- Cannot download protected files

## Encryption Workflow

1. User uploads a file.
2. Server generates random AES-256 key.
3. File is encrypted using AES-GCM.
4. AES key is encrypted using user's RSA public key.
5. Encrypted file path, encrypted AES key, nonce, and SHA-256 hash are stored.
6. For decryption:
   - AES key is recovered with RSA private key.
   - Encrypted file is decrypted with AES-GCM.
   - Integrity hash is regenerated.

## Main Routes

- `/` - Home
- `/developers`
- `/register`
- `/login`
- `/logout`
- `/admin/dashboard`
- `/user/dashboard`
- `/auditor/dashboard`
- `/files`
- `/upload`
- `/encrypt/<file_id>`
- `/decrypt/<file_id>`
- `/download/<file_id>`
- `/delete/<file_id>`
- `/share/<file_id>`
- `/logs`
- `/profile`

## Database Models

### User
- `id`, `username`, `email`, `password_hash`
- `role`, `public_key`, `private_key`
- `created_at`, `is_active`

### File
- `id`, `filename`, `original_filename`
- `file_size`, `file_type`
- `encrypted_path`, `decrypted_path`
- `encrypted_aes_key`, `iv_or_nonce`
- `file_hash`, `owner_id`, `shared_with`
- `encryption_status`, `uploaded_at`

### ActivityLog
- `id`, `user_id`, `action`, `file_id`
- `ip_address`, `timestamp`, `status`

## Setup Instructions

1. **Create and activate virtual environment** (recommended)
2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Initialize DB and seed demo users**

```bash
python seed.py
```

4. **Run app**

```bash
python app.py
```

5. Open in browser:
   - `http://127.0.0.1:5000`

## Demo Credentials

- **Admin:** `admin@securecloud.com` / `Admin@123`
- **User:** `user@securecloud.com` / `User@123`
- **Auditor:** `auditor@securecloud.com` / `Auditor@123`

## UI/UX Notes

- Premium dark cyber-security theme
- Neon gradients, glassmorphism cards, hover glow effects
- Responsive layout across pages
- Compact and styled DataTables controls
- Page transitions and staggered section animations

## Security Notes

- Passwords are hashed with Flask-Bcrypt.
- RSA private keys are currently stored in DB for demo/project scope.
- For production:
  - Use secure key management (KMS/HSM or encrypted vault)
  - Enforce HTTPS
  - Rotate keys and secrets
  - Add CSRF, rate limiting, and stronger audit hardening

## Troubleshooting

- If images/CSS do not update, clear browser cache (`Ctrl+F5`).
- If DB errors occur, delete local DB and rerun `seed.py` (development only).
- Ensure Python package versions are compatible with your local Python version.

## Deploy on Render

This project is configured for Render via `render.yaml`.

### Option A (recommended): Blueprint deploy

1. Push this repo to GitHub.
2. In Render: **New +** -> **Blueprint**.
3. Select your repo. Render detects `render.yaml`.
4. Click **Apply** to create the service and disk.
5. Wait for deploy to complete.

### Option B: Manual Web Service setup

Use these settings in Render:

- **Runtime:** Python
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn app:app`

Environment variables:

- `SECRET_KEY` = any strong random value
- `DATABASE_URL` = `sqlite:////var/data/secure_cloud.db`
- `UPLOAD_FOLDER` = `/var/data/uploads`
- `ENCRYPTED_FOLDER` = `/var/data/encrypted`

Also attach a persistent disk:

- **Mount path:** `/var/data`

### Seed demo users on Render shell

After first deploy, open Render Shell and run:

```bash
python seed.py
```

Then login with demo credentials from this README.

## License

Academic / project use.
