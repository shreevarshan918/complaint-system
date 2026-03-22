from flask import Flask, render_template, request, redirect, session, url_for
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import bcrypt
import os
import datetime
import random
import string

app = Flask(__name__)
app.secret_key = "bgscet_complaint_system_2024"

# Upload config
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "mp4", "mov"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Email config
app.config["MAIL_SERVER"]   = "smtp.gmail.com"
app.config["MAIL_PORT"]     = 587
app.config["MAIL_USE_TLS"]  = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")

mail = Mail(app)

# MongoDB
client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))
db = client["complaint_system"]

students_col   = db["students"]
complaints_col = db["complaints"]
admins_col     = db["admins"]
dept_col       = db["departments"]
otp_col        = db["otps"]

COLLEGE_DOMAIN = "@bgscet.ac.in"

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    try:
        msg = Message(
            "BGSCET Complaint System - Email Verification",
            recipients=[email]
        )
        msg.body = f"""
Dear Student,

Your OTP for BGSCET Complaint System registration is:

{otp}

This OTP is valid for 10 minutes.

Do not share this OTP with anyone.

Regards,
BGSCET Complaint System
        """
        mail.send(msg)
        return True
    except:
        return False

def send_resolution_email(student_email, complaint_title, dept, remarks):
    try:
        msg = Message(
            "BGSCET Complaint System - Complaint Resolved",
            recipients=[student_email]
        )
        msg.body = f"""
Dear Student,

Your complaint has been resolved!

Complaint: {complaint_title}
Resolved by: {dept} Department
Remarks: {remarks}

Thank you for using BGSCET Complaint System.

Regards,
BGSCET Complaint Management Team
        """
        mail.send(msg)
        return True
    except:
        return False

@app.route("/")
def home():
    return redirect("/login")

# ─── REGISTER ───────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name       = request.form["name"]
        email      = request.form["email"]
        password   = request.form["password"]
        roll_no    = request.form["roll_no"]
        year       = request.form["year"]
        department = request.form["department"]

        # College email check
        if not email.endswith(COLLEGE_DOMAIN):
            return render_template("register.html",
                error=f"Only {COLLEGE_DOMAIN} email addresses are allowed!")

        existing = students_col.find_one({"email": email})
        if existing:
            return render_template("register.html",
                error="Email already registered!")

        # Generate and send OTP
        otp = generate_otp()
        otp_col.delete_many({"email": email})
        otp_col.insert_one({
            "email":      email,
            "otp":        otp,
            "name":       name,
            "password":   password,
            "roll_no":    roll_no,
            "year":       year,
            "department": department,
            "created_at": datetime.datetime.now()
        })

        send_otp_email(email, otp)

        session["pending_email"] = email
        return redirect("/verify_otp")

    return render_template("register.html")

# ─── VERIFY OTP ─────────────────────────────────────
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if "pending_email" not in session:
        return redirect("/register")

    if request.method == "POST":
        otp_entered = request.form["otp"]
        email       = session["pending_email"]

        otp_record = otp_col.find_one({"email": email})

        if not otp_record:
            return render_template("verify_otp.html",
                error="OTP expired! Please register again.")

        # Check OTP expiry (10 minutes)
        time_diff = datetime.datetime.now() - otp_record["created_at"]
        if time_diff.seconds > 600:
            otp_col.delete_many({"email": email})
            return render_template("verify_otp.html",
                error="OTP expired! Please register again.")

        if otp_record["otp"] != otp_entered:
            return render_template("verify_otp.html",
                error="Wrong OTP! Please try again.")

        # Save student
        hashed = bcrypt.hashpw(
            otp_record["password"].encode("utf-8"), bcrypt.gensalt())
        students_col.insert_one({
            "name":       otp_record["name"],
            "email":      email,
            "password":   hashed,
            "roll_no":    otp_record["roll_no"],
            "year":       otp_record["year"],
            "department": otp_record["department"],
            "phone":      "",
            "bio":        ""
        })
        otp_col.delete_many({"email": email})
        session.pop("pending_email", None)
        return redirect("/login")

    return render_template("verify_otp.html")

# ─── LOGIN ──────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form["email"]
        password = request.form["password"]

        admin = admins_col.find_one({"email": email})
        if admin and bcrypt.checkpw(password.encode("utf-8"), admin["password"]):
            session["user"] = email
            session["role"] = "admin"
            return redirect("/admin_dashboard")

        dept_user = dept_col.find_one({"email": email})
        if dept_user and bcrypt.checkpw(password.encode("utf-8"), dept_user["password"]):
            session["user"] = email
            session["role"] = "department"
            session["name"] = dept_user["name"]
            session["dept"] = dept_user["dept"]
            return redirect("/dept_dashboard")

        student = students_col.find_one({"email": email})
        if student and bcrypt.checkpw(password.encode("utf-8"), student["password"]):
            session["user"] = email
            session["role"] = "student"
            session["name"] = student["name"]
            return redirect("/student_dashboard")

        return render_template("login.html",
            error="Wrong email or password!")
    return render_template("login.html")

# ─── FORGOT PASSWORD ────────────────────────────────
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        if not email.endswith(COLLEGE_DOMAIN):
            return render_template("forgot_password.html",
                error=f"Only {COLLEGE_DOMAIN} emails allowed!")

        student = students_col.find_one({"email": email})
        if not student:
            return render_template("forgot_password.html",
                error="Email not registered!")

        otp = generate_otp()
        otp_col.delete_many({"email": email})
        otp_col.insert_one({
            "email":      email,
            "otp":        otp,
            "type":       "reset",
            "created_at": datetime.datetime.now()
        })
        send_otp_email(email, otp)
        session["reset_email"] = email
        return redirect("/reset_password")

    return render_template("forgot_password.html")

# ─── RESET PASSWORD ─────────────────────────────────
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if "reset_email" not in session:
        return redirect("/forgot_password")

    if request.method == "POST":
        otp_entered  = request.form["otp"]
        new_password = request.form["new_password"]
        email        = session["reset_email"]

        otp_record = otp_col.find_one({"email": email, "type": "reset"})
        if not otp_record:
            return render_template("reset_password.html",
                error="OTP expired!")

        time_diff = datetime.datetime.now() - otp_record["created_at"]
        if time_diff.seconds > 600:
            return render_template("reset_password.html",
                error="OTP expired! Try again.")

        if otp_record["otp"] != otp_entered:
            return render_template("reset_password.html",
                error="Wrong OTP!")

        hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
        students_col.update_one(
            {"email": email},
            {"$set": {"password": hashed}}
        )
        otp_col.delete_many({"email": email})
        session.pop("reset_email", None)
        return redirect("/login")

    return render_template("reset_password.html")

# ─── STUDENT DASHBOARD ──────────────────────────────
@app.route("/student_dashboard")
def student_dashboard():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")
    student = students_col.find_one({"email": session["user"]})
    complaints = list(complaints_col.find({"student_email": session["user"]}))
    total    = len(complaints)
    pending  = len([c for c in complaints if c["status"] == "Pending"])
    resolved = len([c for c in complaints if c["status"] == "Resolved"])
    return render_template("student_dashboard.html",
        name=session["name"],
        student=student,
        total=total,
        pending=pending,
        resolved=resolved)

# ─── PROFILE ────────────────────────────────────────
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")

    student = students_col.find_one({"email": session["user"]})

    if request.method == "POST":
        phone = request.form["phone"]
        bio   = request.form["bio"]
        students_col.update_one(
            {"email": session["user"]},
            {"$set": {"phone": phone, "bio": bio}}
        )
        return redirect("/profile")

    return render_template("profile.html",
        name=session["name"], student=student)

# ─── RAISE COMPLAINT ────────────────────────────────
@app.route("/raise_complaint", methods=["GET", "POST"])
def raise_complaint():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")

    if request.method == "POST":
        title       = request.form["title"]
        description = request.form["description"]
        priority    = request.form["priority"]
        anonymous   = "anonymous" in request.form

        dept = "Administration"
        keywords = {
            "Hostel":         ["room","hostel","warden","water","electricity","bed","mess"],
            "Academic":       ["marks","attendance","teacher","class","exam","results","faculty"],
            "Sports":         ["gym","ground","sports","cricket","football","equipment"],
            "Canteen":        ["food","canteen","lunch","dinner","breakfast","quality"],
            "IT":             ["wifi","internet","computer","lab","network","system"],
            "Administration": ["fee","certificate","id card","library","bus","admin"]
        }
        for department, words in keywords.items():
            if any(word in description.lower() for word in words):
                dept = department
                break

        proof_filename = None
        if "proof" in request.files:
            file = request.files["proof"]
            if file and file.filename != "":
                proof_filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], proof_filename))

        complaint_id = "CMP" + str(random.randint(10000, 99999))
        complaints_col.insert_one({
            "complaint_id":  complaint_id,
            "student_email": session["user"],
            "student_name":  "Anonymous" if anonymous else session["name"],
            "title":         title,
            "description":   description,
            "priority":      priority,
            "department":    dept,
            "status":        "Pending",
            "proof":         proof_filename,
            "anonymous":     anonymous,
            "remarks":       "",
            "created_at":    datetime.datetime.now()
        })
        return redirect("/my_complaints")
    return render_template("raise_complaint.html")

# ─── MY COMPLAINTS ───────────────────────────────────
@app.route("/my_complaints")
def my_complaints():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")
    complaints = list(complaints_col.find(
        {"student_email": session["user"]}))
    return render_template("my_complaints.html",
        complaints=complaints, name=session["name"])

# ─── DEPT DASHBOARD ─────────────────────────────────
@app.route("/dept_dashboard")
def dept_dashboard():
    if "user" not in session or session["role"] != "department":
        return redirect("/login")
    dept_complaints = list(complaints_col.find(
        {"department": session["dept"]}))
    return render_template("dept_dashboard.html",
        name=session["name"],
        dept=session["dept"],
        complaints=dept_complaints)

# ─── DEPT UPDATE STATUS ─────────────────────────────
@app.route("/dept_update_status", methods=["POST"])
def dept_update_status():
    if "user" not in session or session["role"] != "department":
        return redirect("/login")

    complaint_id = request.form["complaint_id"]
    new_status   = request.form["status"]
    remarks      = request.form["remarks"]

    complaint = complaints_col.find_one({"complaint_id": complaint_id})
    complaints_col.update_one(
        {"complaint_id": complaint_id},
        {"$set": {"status": new_status, "remarks": remarks}}
    )

    if new_status == "Resolved" and complaint and not complaint.get("anonymous"):
        send_resolution_email(
            complaint["student_email"],
            complaint["title"],
            session["dept"],
            remarks
        )
    return redirect("/dept_dashboard")

# ─── ADMIN DASHBOARD ────────────────────────────────
@app.route("/admin_dashboard")
def admin_dashboard():
    if "user" not in session or session["role"] != "admin":
        return redirect("/login")
    all_complaints = list(complaints_col.find())
    total    = len(all_complaints)
    pending  = len([c for c in all_complaints if c["status"] == "Pending"])
    progress = len([c for c in all_complaints if c["status"] == "In Progress"])
    resolved = len([c for c in all_complaints if c["status"] == "Resolved"])

    dept_stats = {}
    for c in all_complaints:
        d = c.get("department", "Other")
        dept_stats[d] = dept_stats.get(d, 0) + 1

    return render_template("admin_dashboard.html",
        complaints=all_complaints,
        total=total,
        pending=pending,
        progress=progress,
        resolved=resolved,
        dept_stats=dept_stats)

# ─── ADMIN UPDATE STATUS ────────────────────────────
@app.route("/update_status", methods=["POST"])
def update_status():
    if "user" not in session or session["role"] != "admin":
        return redirect("/login")
    complaint_id = request.form["complaint_id"]
    new_status   = request.form["status"]
    complaints_col.update_one(
        {"complaint_id": complaint_id},
        {"$set": {"status": new_status}}
    )
    return redirect("/admin_dashboard")

# ─── LOGOUT ─────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    import os
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)