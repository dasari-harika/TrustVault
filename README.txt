TrustVault Front-End Prototype
==============================

Files
- index.html: standalone responsive front-end; no build tools required.

Run
1. Extract the ZIP.
2. Double-click index.html, or open it in Chrome/Edge.
3. Explore the sidebar, document actions, filters, upload modal, share modal, audit export, team roles, and settings.

Important limitations
- This is a front-end prototype with browser-local demo data (localStorage).
- Upload adds file names/metadata to the demo list; it does not upload/store the original file on a server.
- Preview shows placeholder content; Download creates a demo text file, not the original document.
- Sharing, invitations, roles, and settings are local demo interactions, not real access control.
- Do not use real confidential documents or credentials in this prototype.
- For a secure submission, connect the UI to backend APIs and enforce authentication, tenant isolation, role checks, file validation/storage, and audit logging server-side.
