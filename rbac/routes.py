from flask import render_template, flash, redirect, url_for
from rbac import app, db

@app.route("/")
def home():
    return render_template('home.html')