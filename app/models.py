from flask_login import UserMixin
from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app
from werkzeug.security import generate_password_hash
from . import login_manager
import secrets
import datetime
from user_agents import parse

def get_device_info(user_agent):
    ua = parse(user_agent)
    device = f'{ua.device.family} {ua.device.brand} {ua.device.model}'
    return device



def save_user_cookies(user_id):

    cookies = request.cookies
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    device = get_device_info(user_agent)
    country = 'ХЗ'
    with current_app.conn.cursor() as cur:
        for cookie_name, cookie_value in cookies.items():
            cur.execute("""
                INSERT INTO user_cookies (user_id, cookie_name, cookie_value, ip_address, user_agent, device, country, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, cookie_name, cookie_value, ip_address, user_agent, device, country, datetime.datetime.now()))
        current_app.conn.commit()

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, confirmed, confirmation_token):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.confirmed = confirmed
        self.confirmation_token = confirmation_token

    @staticmethod
    def get(user_id, cur):
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        data = cur.fetchone()
        if data:
            return User(*data)
        return None

    @staticmethod
    def get_by_email(email, cur):
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        data = cur.fetchone()
        if data:
            return User(*data)
        return None

    @staticmethod
    def create(username, email, password, cur, conn):
        password_hash = generate_password_hash(password)
        confirmation_token = secrets.token_urlsafe(16)
        cur.execute(
            "INSERT INTO users (username, email, password_hash, confirmation_token) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, email, password_hash, confirmation_token)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        return User(user_id, username, email, password_hash, False, confirmation_token)

@login_manager.user_loader
def load_user(user_id):
    with current_app.conn.cursor() as cur:
        return User.get(user_id, cur)
