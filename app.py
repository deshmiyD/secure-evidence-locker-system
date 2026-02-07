import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_mail import Mail, Message

from config import Config
from crypto_utils import (
    decrypt_evidence,
    encrypt_evidence,
    get_fernet_from_key,
    sha256_bytes,
)
from models import AuditLog, Evidence, User, db
from io import BytesIO


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    # Extensions
    db.init_app(app)
    bcrypt = Bcrypt(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    mail = Mail(app)

    # Create encryption helper (key persists in encryption_key.key file)
    key_file_path = os.path.join(app.config["EVIDENCE_FOLDER"], "..", "encryption_key.key")
    fernet = get_fernet_from_key(app.config.get("EVIDENCE_ENC_KEY"), key_file_path)

    @login_manager.user_loader
    def load_user(user_id: str):
        return db.session.get(User, int(user_id))

    # ---------- Utility: role-based decorators ----------

    def roles_required(*roles):
        def decorator(fn):
            @wraps(fn)
            @login_required
            def wrapper(*args, **kwargs):
                if current_user.role not in roles:
                    flash("You do not have permission to access this resource.", "danger")
                    return redirect(url_for("index"))
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    # ---------- Utility: audit logging ----------

    def log_action(action: str, details: str | None = None, user: User | None = None):
        entry = AuditLog(
            user_id=user.id if user else None,
            action=action,
            details=details,
        )
        db.session.add(entry)
        db.session.commit()

    # ---------- Utility: email alerts ----------

    def send_alert_email(subject: str, body: str) -> bool:
        """Send an alert email. Returns True on success, False on failure."""
        alert_to = app.config.get("ALERT_EMAIL_TO")
        if not alert_to:
            return False
        try:
            msg = Message(subject=subject, recipients=[alert_to], body=body)
            mail.send(msg)
            return True
        except Exception:
            return False

    def count_recent_failed_logins(username: str) -> int:
        """Count failed login attempts for username within the configured time window."""
        window_minutes = app.config.get("FAILED_LOGIN_WINDOW_MINUTES", 15)
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        return AuditLog.query.filter(
            AuditLog.action == "login_failure",
            AuditLog.details.like(f"%'{username}'%"),
            AuditLog.timestamp >= cutoff,
        ).count()

    # ---------- Utility: simple helper ----------

    def no_users_exist() -> bool:
        """Return True if the system has no registered users yet."""
        return User.query.count() == 0

    # ---------- Routes ----------

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            if current_user.is_admin():
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("investigator_dashboard"))
        # If no users exist yet, guide to initial admin registration
        first_setup = no_users_exist()
        return render_template("index.html", first_setup=first_setup)

    # ----- Initial admin registration (first-time setup only) -----

    @app.route("/register_admin", methods=["GET", "POST"])
    def register_admin():
        # If at least one user exists, do not allow hitting this page
        if not no_users_exist():
            flash("An admin already exists. Please log in.", "info")
            return redirect(url_for("login"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                flash("Username and password are required.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
            else:
                pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
                admin = User(username=username, password_hash=pw_hash, role="admin")
                db.session.add(admin)
                db.session.commit()
                # Log the creation; user is None because this is first-time setup
                log_action(
                    "initial_admin_created",
                    f"Initial admin '{username}' registered via setup page.",
                    user=None,
                )
                # Optionally, log in the new admin automatically
                login_user(admin)
                flash(
                    f"Admin account '{username}' created successfully. "
                    "You can now use this username and password to log in.",
                    "success",
                )
                return redirect(url_for("admin_dashboard"))

        return render_template("register_admin.html")

    # ----- Authentication -----

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()

            if user and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user)
                log_action("login_success", f"User {username} logged in.")
                flash("Logged in successfully.", "success")
                return redirect(url_for("index"))
            else:
                client_ip = request.remote_addr or "unknown"
                log_action(
                    "login_failure",
                    f"Failed login attempt for username '{username}' from IP {client_ip}.",
                )
                # Check if we've exceeded failed login threshold and send alert (only when first crossing threshold)
                threshold = app.config.get("FAILED_LOGIN_THRESHOLD", 3)
                recent_failures = count_recent_failed_logins(username)
                if recent_failures == threshold:
                    log_action(
                        "suspicious_activity",
                        f"ALERT: {recent_failures} failed login attempts for '{username}' within threshold. IP: {client_ip}",
                    )
                    send_alert_email(
                        subject=f"[SELS] Security Alert: Multiple Failed Logins for '{username}'",
                        body=(
                            f"SECURITY ALERT: Multiple failed login attempts detected.\n\n"
                            f"Username: {username}\n"
                            f"Failed attempts (in window): {recent_failures}\n"
                            f"Client IP: {client_ip}\n"
                            f"Timestamp (UTC): {datetime.utcnow()}\n\n"
                            f"This may indicate a brute-force or credential stuffing attack."
                        ),
                    )
                flash("Invalid username or password.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        log_action("logout", f"User {current_user.username} logged out.", user=current_user)
        logout_user()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    # ----- Admin: user management & overview -----

    @app.route("/admin")
    @roles_required("admin")
    def admin_dashboard():
        users = User.query.all()
        evidence_items = Evidence.query.order_by(Evidence.uploaded_at.desc()).all()
        return render_template(
            "admin_dashboard.html", users=users, evidence_items=evidence_items
        )

    @app.route("/admin/create_user", methods=["GET", "POST"])
    @roles_required("admin")
    def create_user():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "investigator").strip().lower()

            if not username or not password:
                flash("Username and password are required.", "danger")
            elif role not in ("admin", "investigator"):
                flash("Invalid role.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
            else:
                pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
                user = User(username=username, password_hash=pw_hash, role=role)
                db.session.add(user)
                db.session.commit()
                log_action(
                    "user_created",
                    f"Admin {current_user.username} created user {username} with role {role}.",
                    user=current_user,
                )
                flash("User created successfully.", "success")
                return redirect(url_for("admin_dashboard"))

        return render_template("create_user.html")

    @app.route("/admin/audit_logs")
    @roles_required("admin")
    def view_audit_logs():
        all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        
        # Categorize logs
        user_actions = [
            "login_success", "login_failure", "logout", "user_created", "initial_admin_created",
            "suspicious_activity",
        ]
        evidence_actions = [
            "evidence_upload", "evidence_access", "evidence_integrity_check",
            "unauthorized_evidence_access", "evidence_integrity_compromised",
        ]
        
        user_logs = [log for log in all_logs if log.action in user_actions]
        evidence_logs = [log for log in all_logs if log.action in evidence_actions]
        
        return render_template(
            "audit_logs.html",
            all_logs=all_logs,
            user_logs=user_logs,
            evidence_logs=evidence_logs,
        )

    # ----- Investigator: dashboard & evidence upload -----

    @app.route("/investigator")
    @roles_required("investigator", "admin")
    def investigator_dashboard():
        if current_user.is_admin():
            items = Evidence.query.order_by(Evidence.uploaded_at.desc()).all()
        else:
            items = (
                Evidence.query.filter_by(uploader_id=current_user.id)
                .order_by(Evidence.uploaded_at.desc())
                .all()
            )
        return render_template("investigator_dashboard.html", evidence_items=items)

    @app.route("/evidence/upload", methods=["GET", "POST"])
    @roles_required("investigator", "admin")
    def upload_evidence():
        if request.method == "POST":
            file = request.files.get("file")
            if not file or file.filename == "":
                flash("No file selected.", "danger")
                return redirect(request.url)

            original_filename = file.filename
            file_bytes = file.read()

            # Compute hash before encryption
            hash_hex = sha256_bytes(file_bytes)

            # Encrypt file
            encrypted_bytes = encrypt_evidence(file_bytes, fernet)

            # Store encrypted file on disk
            stored_name = f"{datetime.utcnow().timestamp()}_{current_user.id}.bin"
            stored_path = os.path.join(app.config["EVIDENCE_FOLDER"], stored_name)
            with open(stored_path, "wb") as f:
                f.write(encrypted_bytes)

            # Save metadata to DB
            ev = Evidence(
                original_filename=original_filename,
                stored_filename=stored_name,
                sha256_hash=hash_hex,
                uploader_id=current_user.id,
            )
            db.session.add(ev)
            db.session.commit()

            # Audit log
            log_action(
                "evidence_upload",
                f"User {current_user.username} uploaded evidence {original_filename} (id={ev.id}).",
                user=current_user,
            )

            # Email alert
            alert_to = app.config.get("ALERT_EMAIL_TO")
            if alert_to:
                try:
                    msg = Message(
                        subject="New Evidence Uploaded",
                        recipients=[alert_to],
                        body=(
                            f"New evidence uploaded by {current_user.username}.\n"
                            f"Original filename: {original_filename}\n"
                            f"Evidence ID: {ev.id}\n"
                            f"Uploaded at (UTC): {ev.uploaded_at}"
                        ),
                    )
                    mail.send(msg)
                except Exception as e:
                    # For academic purposes we only flash a message; in production we'd log this.
                    flash(f"Evidence uploaded, but email alert failed: {e}", "warning")

            flash("Evidence uploaded and encrypted successfully.", "success")
            return redirect(url_for("investigator_dashboard"))

        return render_template("upload_evidence.html")

    # ----- Evidence access & integrity verification -----

    @app.route("/evidence/<int:evidence_id>/view")
    @login_required
    def view_evidence(evidence_id: int):
        ev = Evidence.query.get_or_404(evidence_id)

        # Enforce that investigators can only see their own evidence
        if not current_user.is_admin() and ev.uploader_id != current_user.id:
            client_ip = request.remote_addr or "unknown"
            log_action(
                "unauthorized_evidence_access",
                f"User {current_user.username} (investigator) attempted to access evidence id={ev.id} "
                f"owned by user_id={ev.uploader_id}. IP: {client_ip}",
                user=current_user,
            )
            send_alert_email(
                subject=f"[SELS] Security Alert: Unauthorized Evidence Access Attempt",
                body=(
                    f"SECURITY ALERT: Unauthorized evidence access attempt detected.\n\n"
                    f"User: {current_user.username} (Investigator)\n"
                    f"Attempted to access: Evidence ID {ev.id} ({ev.original_filename})\n"
                    f"Evidence owner: user_id {ev.uploader_id}\n"
                    f"Client IP: {client_ip}\n"
                    f"Timestamp (UTC): {datetime.utcnow()}\n\n"
                    f"This may indicate an attempt to access restricted evidence."
                ),
            )
            flash("You do not have permission to access this evidence.", "danger")
            return redirect(url_for("investigator_dashboard"))

        stored_path = os.path.join(app.config["EVIDENCE_FOLDER"], ev.stored_filename)
        integrity_ok = False
        decrypted_bytes = b""
        
        if not os.path.exists(stored_path):
            flash("Encrypted evidence file missing. Integrity cannot be verified.", "danger")
            log_action(
                "evidence_access",
                f"User {current_user.username} attempted to access evidence id={ev.id}. "
                f"File missing. Integrity_ok=False",
                user=current_user,
            )
            return redirect(url_for("evidence_details", evidence_id=evidence_id))
        
        try:
            with open(stored_path, "rb") as f:
                encrypted_bytes = f.read()
            decrypted_bytes = decrypt_evidence(encrypted_bytes, fernet)

            # Re-compute hash for integrity verification
            recomputed_hash = sha256_bytes(decrypted_bytes)
            integrity_ok = recomputed_hash == ev.sha256_hash

            if not integrity_ok:
                log_action(
                    "evidence_integrity_compromised",
                    f"User {current_user.username} downloaded evidence id={ev.id}. "
                    f"INTEGRITY COMPROMISED - hash mismatch. Possible tampering.",
                    user=current_user,
                )
                send_alert_email(
                    subject=f"[SELS] Security Alert: Evidence Integrity Compromised (ID {ev.id})",
                    body=(
                        f"SECURITY ALERT: Evidence integrity verification FAILED.\n\n"
                        f"Evidence ID: {ev.id}\n"
                        f"Filename: {ev.original_filename}\n"
                        f"Accessed by: {current_user.username}\n"
                        f"Timestamp (UTC): {datetime.utcnow()}\n\n"
                        f"The recomputed SHA-256 hash does not match the stored hash. "
                        f"This may indicate file tampering or corruption."
                    ),
                )
                flash(
                    "WARNING: Integrity verification failed. The file hash does not match the stored hash. "
                    "Possible tampering detected. File download proceeding, but integrity is compromised.",
                    "warning"
                )
        except Exception as e:
            flash(f"Error decrypting file: {str(e)}", "danger")
            log_action(
                "evidence_access",
                f"User {current_user.username} attempted to access evidence id={ev.id}. "
                f"Decryption error: {str(e)}. Integrity_ok=False",
                user=current_user,
            )
            return redirect(url_for("evidence_details", evidence_id=evidence_id))

        # Log access with integrity status
        log_action(
            "evidence_access",
            f"User {current_user.username} downloaded evidence id={ev.id} (filename: {ev.original_filename}). "
            f"Integrity_ok={integrity_ok}",
            user=current_user,
        )

        # Present file to user
        file_stream = BytesIO(decrypted_bytes)
        return send_file(
            file_stream,
            as_attachment=True,
            download_name=ev.original_filename,
        )

    @app.route("/evidence/<int:evidence_id>/details")
    @login_required
    def evidence_details(evidence_id: int):
        ev = Evidence.query.get_or_404(evidence_id)
        if not current_user.is_admin() and ev.uploader_id != current_user.id:
            client_ip = request.remote_addr or "unknown"
            log_action(
                "unauthorized_evidence_access",
                f"User {current_user.username} (investigator) attempted to view details of evidence id={ev.id} "
                f"owned by user_id={ev.uploader_id}. IP: {client_ip}",
                user=current_user,
            )
            send_alert_email(
                subject=f"[SELS] Security Alert: Unauthorized Evidence Access Attempt",
                body=(
                    f"SECURITY ALERT: Unauthorized evidence access attempt detected.\n\n"
                    f"User: {current_user.username} (Investigator)\n"
                    f"Attempted to view: Evidence ID {ev.id} ({ev.original_filename})\n"
                    f"Evidence owner: user_id {ev.uploader_id}\n"
                    f"Client IP: {client_ip}\n"
                    f"Timestamp (UTC): {datetime.utcnow()}\n\n"
                    f"This may indicate an attempt to access restricted evidence."
                ),
            )
            flash("You do not have permission to access this evidence.", "danger")
            return redirect(url_for("investigator_dashboard"))

        # Verify integrity without returning the file content
        stored_path = os.path.join(app.config["EVIDENCE_FOLDER"], ev.stored_filename)
        integrity_ok = False
        recomputed_hash = None
        verification_timestamp = datetime.utcnow()
        file_exists = os.path.exists(stored_path)
        
        if file_exists:
            try:
                with open(stored_path, "rb") as f:
                    enc = f.read()
                dec = decrypt_evidence(enc, fernet)
                recomputed_hash = sha256_bytes(dec)
                integrity_ok = recomputed_hash == ev.sha256_hash
            except Exception as e:
                # Decryption or hash computation failed
                integrity_ok = False
                recomputed_hash = None
        else:
            integrity_ok = False

        # Log the integrity verification
        log_action(
            "evidence_integrity_check",
            f"User {current_user.username} verified integrity of evidence id={ev.id}. "
            f"Result: {'VERIFIED' if integrity_ok else 'COMPROMISED'}",
            user=current_user,
        )

        # Send alert if integrity is compromised (when viewing details page)
        if not integrity_ok:
            log_action(
                "evidence_integrity_compromised",
                f"User {current_user.username} viewed integrity of evidence id={ev.id}. "
                f"INTEGRITY COMPROMISED - hash mismatch. Possible tampering.",
                user=current_user,
            )
            send_alert_email(
                subject=f"[SELS] Security Alert: Evidence Integrity Compromised (ID {ev.id})",
                body=(
                    f"SECURITY ALERT: Evidence integrity verification FAILED.\n\n"
                    f"Evidence ID: {ev.id}\n"
                    f"Filename: {ev.original_filename}\n"
                    f"Verified by: {current_user.username}\n"
                    f"Timestamp (UTC): {datetime.utcnow()}\n\n"
                    f"The recomputed SHA-256 hash does not match the stored hash. "
                    f"This may indicate file tampering or corruption."
                ),
            )

        return render_template(
            "evidence_details.html",
            evidence=ev,
            integrity_ok=integrity_ok,
            recomputed_hash=recomputed_hash,
            verification_timestamp=verification_timestamp,
            file_exists=file_exists,
        )

    # ---------- CLI helper for first run ----------

    @app.cli.command("init-db")
    def init_db_command():
        """Initialize the database and create default admin user."""
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            password = "admin123"
            pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            admin = User(username="admin", password_hash=pw_hash, role="admin")
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user: username='admin', password='admin123'")
        else:
            print("Admin user already exists.")

    return app


if __name__ == "__main__":
    flask_app = create_app()
    with flask_app.app_context():
        db.create_all()
    flask_app.run(debug=True)
