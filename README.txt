TECHPULSE INNOVATIONS — COMPLETE WEBSITE + BACKEND
====================================================

This package is a complete working Node.js website system:
- Public website pages
- Login + sign up
- Client dashboard
- Client profile + password change
- Project requests and project progress tracking
- File upload/download/delete (15 MB per file)
- Contact/message inbox
- Admin-only dashboard
- User suspend/activate/delete
- Admin password reset
- Login rate limiting
- Persistent JSON data storage
- Persistent uploaded files
- Health-check endpoint
- No external database and no npm dependencies

PROJECT STRUCTURE
-----------------
server.js     Node.js backend and API
index.html    Main website, login, signup, dashboard and client pages
admin.html    Admin dashboard
package.json  npm start configuration
README.txt    This guide
.env.example  Environment variable examples
.gitignore    Protects local data/uploads from Git

RUN LOCALLY
-----------
Requirements: Node.js 16 or newer.

1. Extract the ZIP.
2. Open a terminal in the extracted folder.
3. Run:
       npm start
   or:
       node server.js
4. Open:
       http://localhost:3000

The first page is the login screen. Users can create an account from Sign Up.

DEFAULT ADMIN
-------------
Email:
    admin@techpulse.dev

Default password:
    Admin@123

IMPORTANT: Change the admin password immediately after the first login.

The admin dashboard is:
    /admin

It is protected by the server. A visitor or normal client cannot open the admin page.

PRODUCTION / ONLINE HOSTING
---------------------------
Use a Node.js host such as Render, Railway, a VPS, or another service that can run Node.js.

Build command:
    (none)

Start command:
    npm start

Environment variables:
    PORT            Usually supplied automatically by the host.
    ADMIN_EMAIL     Admin email. Default: admin@techpulse.dev
    ADMIN_PASSWORD  Your own admin password.
    DATA_DIR        Persistent folder/disk for db.json and uploads.

RECOMMENDED:
    ADMIN_PASSWORD = a strong password you create
    DATA_DIR       = a persistent disk/folder

Do NOT use a temporary filesystem for DATA_DIR in production. If the host
restarts and its disk is temporary, users, projects, messages and uploaded
files can be erased.

HEALTH CHECK
------------
The server provides:
    /health

Example:
    https://your-domain.example/health

A healthy server returns JSON similar to:
    {"ok":true,"service":"techpulse","uptime":123}

DATA STORAGE
------------
No database server is required.

The backend automatically creates:
    DATA_DIR/db.json
    DATA_DIR/uploads/

Passwords are never stored as plain text. They use Node's scrypt password
hashing with a unique salt.

Sessions use an HttpOnly cookie. Failed login attempts are rate-limited.

PASSWORD RESET
--------------
There is no email provider connected in this package.

If a client uses Forgot Password:
1. A reset request is added to Admin > Messages.
2. The admin opens Admin > Users.
3. The admin presses Reset beside that user.
4. The admin creates a new password.
5. The admin gives that temporary/new password to the client privately.
6. The client can then use Edit Profile to change it.

The admin cannot read an existing client password.

FILES
-----
Clients can upload files up to 15 MB each.
Clients can see and remove their own files.
Admins can open a client's Files list and download the files.

DEPLOYMENT CHECKLIST
--------------------
[ ] Set ADMIN_PASSWORD
[ ] Set DATA_DIR to persistent storage
[ ] Enable HTTPS on the host
[ ] Confirm /health returns ok
[ ] Log in as admin
[ ] Change/check the admin profile
[ ] Create a test client account
[ ] Test project request
[ ] Test file upload/download
[ ] Test contact message
[ ] Test suspend/activate
[ ] Test password reset
[ ] Remove any demo/test accounts before real use

SECURITY NOTES
--------------
- Never commit DATA_DIR/db.json or DATA_DIR/uploads to Git.
- Never publish your real ADMIN_PASSWORD.
- Use HTTPS in production.
- Keep Node.js updated.
- The application intentionally has no third-party npm dependencies.

This package is ready to run as one Node.js service.
