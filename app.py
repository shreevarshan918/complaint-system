from flask import Flask, render_template, request, redirect, session
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import bcrypt
import os
import datetime
import random

app = Flask(__name__)
app.secret_key = "complaintsystem123"

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "mp4", "mov"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

import os
client = MongoClient(os.environ.get("MONGO_URI"))


db = client["complaint_system"]

students_col    = db["students"]
complaints_col  = db["complaints"]
admins_col      = db["admins"]
dept_col        = db["departments"]

@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name       = request.form["name"]
        email      = request.form["email"]
        password   = request.form["password"]
        roll_no    = request.form["roll_no"]
        year       = request.form["year"]
        department = request.form["department"]

        existing = students_col.find_one({"email": email})
        if existing:
            return render_template("register.html", error="Email already registered!")

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        students_col.insert_one({
            "name":       name,
            "email":      email,
            "password":   hashed,
            "roll_no":    roll_no,
            "year":       year,
            "department": department
        })
        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form["email"]
        password = request.form["password"]

        # Check admin
        admin = admins_col.find_one({"email": email})
        if admin and bcrypt.checkpw(password.encode("utf-8"), admin["password"]):
            session["user"] = email
            session["role"] = "admin"
            return redirect("/admin_dashboard")

        # Check department
        dept_user = dept_col.find_one({"email": email})
        if dept_user and bcrypt.checkpw(password.encode("utf-8"), dept_user["password"]):
            session["user"] = email
            session["role"] = "department"
            session["name"] = dept_user["name"]
            session["dept"] = dept_user["dept"]
            return redirect("/dept_dashboard")

        # Check student
        student = students_col.find_one({"email": email})
        if student and bcrypt.checkpw(password.encode("utf-8"), student["password"]):
            session["user"] = email
            session["role"] = "student"
            session["name"] = student["name"]
            return redirect("/student_dashboard")

        return render_template("login.html", error="Wrong email or password!")
    return render_template("login.html")

@app.route("/student_dashboard")
def student_dashboard():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")
    return render_template("student_dashboard.html", name=session["name"])

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
            "created_at":    datetime.datetime.now()
        })
        return redirect("/my_complaints")
    return render_template("raise_complaint.html")

@app.route("/my_complaints")
def my_complaints():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")
    complaints = list(complaints_col.find({"student_email": session["user"]}))
    return render_template("my_complaints.html", complaints=complaints)

@app.route("/dept_dashboard")
def dept_dashboard():
    if "user" not in session or session["role"] != "department":
        return redirect("/login")
    dept_complaints = list(complaints_col.find({"department": session["dept"]}))
    return render_template("dept_dashboard.html",
                           name=session["name"],
                           dept=session["dept"],
                           complaints=dept_complaints)

@app.route("/dept_update_status", methods=["POST"])
def dept_update_status():
    if "user" not in session or session["role"] != "department":
        return redirect("/login")
    complaint_id = request.form["complaint_id"]
    new_status   = request.form["status"]
    remarks      = request.form["remarks"]
    complaints_col.update_one(
        {"complaint_id": complaint_id},
        {"$set": {"status": new_status, "remarks": remarks}}
    )
    return redirect("/dept_dashboard")

@app.route("/admin_dashboard")
def admin_dashboard():
    if "user" not in session or session["role"] != "admin":
        return redirect("/login")
    all_complaints = list(complaints_col.find())
    return render_template("admin_dashboard.html", complaints=all_complaints)

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

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)