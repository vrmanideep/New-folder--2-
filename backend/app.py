import os
from flask import Flask, request, jsonify, send_from_directory, render_template, session, redirect, url_for
from functools import wraps
from firebase_admin import auth, storage, exceptions

# Relative import for auth_service.py
from .auth_service import (
    check_username_uniqueness_backend,
    register_user_backend,
    login_user_backend,
    delete_user_data_backend,
    get_login_tips_backend,
    get_user_profile_backend,
    update_user_address_backend,
    handle_google_auth_backend,
    save_feedback_backend
)

# Relative import for firebase_config.py
from . import firebase_config

import asyncio

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_FOLDER = os.path.join(BASE_DIR, 'frontend')
STATIC_FOLDER = os.path.join(BASE_DIR, 'frontend')

# Define the Flask app instance
app = Flask(__name__,
            template_folder=TEMPLATE_FOLDER,
            static_folder=STATIC_FOLDER)

# Session secret key
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')

@app.route('/')
def index():
    if 'user' in session:
        return redirect('/home')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        data = request.json or request.form
        email = data.get('email')
        password = data.get('password')
        login_result = login_user_backend(email, password)
        if login_result.get("success"):
            session['user'] = email
            return redirect('/home')
        else:
            return render_template('login.html', error=login_result.get("message"))
    return render_template('login.html')

@app.route('/home')
def home_route():
    if 'user' not in session:
        return redirect('/login')
    return render_template('home.html', user=session.get('user'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')
