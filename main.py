from flask import Flask, render_template, request, session, logging, url_for, redirect, flash
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from werkzeug.utils import secure_filename

engine = create_engine("mysql+pymysql://root:pass123@localhost:3306/signupusers")
# mysql+pymysql://username:password@localhost/database_name
db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'C:\\Users\\Asus\\Desktop'


@app.route("/")
def home():
    return render_template('home.html', navbar='home')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_pass = request.form.get("confirm")
        secure_pass = sha256_crypt.encrypt(str(password))
        # check if someone already register with the email
        length = 0
        with engine.connect() as connection:
            result = connection.execute(text("select email from users where email='{}'".format(email)))
            for row in result:
                length += len(row)
        if length > 0:  # we can't sign this users! already registered with this email!
            flash("User has Already Registered with This Email! Kindly Login In...", "warning")
            return redirect(url_for('login', navbar='login'))
        else:
            if password == confirm_pass:
                db.execute("INSERT INTO users(name,email,password) VALUES(:name,:email,:password)",
                           {"name": name, "email": email, "password": secure_pass})
                db.commit()
                flash("You are successfully Registered! Kindly Login...", "success")
                return redirect(url_for('login', navbar='login'))
            else:
                flash("Password doesn't Match!", "danger")
                return redirect(url_for('register', navbar='reg'))
    return render_template('register.html', navbar='reg')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        email_data = db.execute("SELECT email FROM users WHERE email=:email",
                                {"email": email}).fetchone()
        pwd_data = db.execute("SELECT password FROM users WHERE email=:email",
                              {"email": email}).fetchone()

        user_data = db.execute("SELECT name FROM users WHERE email=:email",
                               {"email": email}).fetchone()
        # print(user_data[0])
        if email_data is None:
            flash("No Account is Registered from this EMAIL! Kindly Register First!", "danger")
            return redirect(url_for('register', navbar='reg'))
        else:
            for password_data in pwd_data:
                if sha256_crypt.verify(password, password_data):
                    session["log"] = True
                    session["user"] = str(user_data[0])
                    flash("Great! Login Successfully!", "success")
                    return redirect(url_for('crypto', navbar='cryp'))
                else:
                    flash("Invalid Email/Password! Try Again...", "danger")
                    return redirect(url_for('login', navbar='login'))
    return render_template('login.html', navbar='login')


@app.route("/crypto", methods=["GET", "POST"])
def crypto():
    if request.method == "POST":
        msg = request.form.get("data")
        key = request.form.get("key")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        message = msg.encode()
        k = base64.urlsafe_b64encode(kdf.derive(b'key__'))  # encode in bytes!
        f = Fernet(k)
        enc_msg = f.encrypt(message)
        dec_message = f.decrypt(enc_msg).decode()
        # session["encrypt"] = enc_msg
        session["dec"] = enc_msg.decode('UTF-8')  # byte array to string !
        session["decrypt"] = dec_message
        session["matcher"] = key
        flash("Message Encrypted! Cipher Text is in White Box. Please Check!", "success")
        return redirect(url_for('decrypt', navbar="cryp"))
    else:
        return render_template("crypto.html", navbar='cryp')


@app.route("/logout")
def logout():
    session.clear()
    flash("Successfully Logout!", "success")
    return redirect(url_for('login'))


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    # print(session["matcher"])
    if request.method == "POST":
        key = request.form.get("key")
        if str(key) != session["matcher"]:
            flash("Wrong Key!", "danger")
            return render_template('decrypt.html')
        flash("Message Decrypted! Your Message is in White Box. Please Check!", "success")
        return redirect(url_for('crypto', navbar="cryp"))
    else:
        return render_template("decrypt.html", navbar="cryp")


@app.route("/crypto_file", methods=["GET", "POST"])
def crypto_file():
    if request.method == "POST":
        key = request.form.get("key")
        file = request.files.get("file")
        if not key.isdigit():
            flash("Invalid Key!", "danger")
            return redirect(url_for('crypto_file', navbar='decy'))
        k = int(str(key))
        if k < 1 or k > 255:
            flash("Invalid Key!", "danger")
            return redirect(url_for('crypto_file', navbar='decy'))
        else:
            session["file_key"] = key
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Then save the file
            flash("File has been Uploaded and Encrypted!", "success")
            f = open(app.config['UPLOAD_FOLDER'] + "//" + filename, "rb")
            data = f.read()
            f.close()
            data = bytearray(data)
            for index, value in enumerate(data):
                data[index] = value ^ k
            fo = open(app.config['UPLOAD_FOLDER'] + "//" + "ENC-" + filename, "wb")
            fo.write(data)
            fo.close()
            return redirect(url_for('decrypt_file', navbar="decy"))

    else:
        return render_template("crypto_file.html", navbar="decy")


@app.route("/decrypt_file", methods=["GET", "POST"])
def decrypt_file():
    if request.method == "POST":
        key = request.form.get("key")
        file = request.files.get("file")
        if not key.isdigit():
            flash("Invalid Key!", "danger")
            return redirect(url_for('decrypt_file', navbar='decy'))
        k = int(str(key))
        if (k < 1 or k > 255) or int(session["file_key"]) != k:
            flash("Invalid Key!", "danger")
            return redirect(url_for('decrypt_file', navbar='decy'))
        else:
            filename = secure_filename(file.filename)
            if filename.startswith("ENC") :
                flash("File has been uploaded and Decrypted!", "success")
                f = open(app.config['UPLOAD_FOLDER'] + "//" + filename, "rb")
                data = f.read()
                f.close()
                data = bytearray(data)
                for index, value in enumerate(data):
                    data[index] = value ^ k
                fo = open(app.config['UPLOAD_FOLDER'] + "//" + "DEC-" + filename, "wb")
                fo.write(data)
                fo.close()
                return redirect(url_for('crypto_file', navbar="decy"))
            else:
                flash("Choose the Encrypted File !", "warning")
                return redirect(url_for('decrypt_file', navbar='decy'))
    else:
        return render_template("decrypt_file.html", navbar="decy")


if __name__ == '__main__':
    app.secret_key = "exposysInternship1234SoftwareDeveloper"
    app.run(debug=True)
