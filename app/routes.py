from flask import Blueprint, request, redirect, url_for, render_template, flash, current_app, g, render_template_string
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import secrets
import base64
from PIL import Image
import io
from .models import User, save_user_cookies
from .email import send_email
import psycopg2
import uuid



main = Blueprint('main', __name__)

@main.before_request
def before_request():
    if 'user_id' in g:
        save_user_cookies(g.user_id)

@main.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            password_hash = generate_password_hash(password)
            token = str(uuid.uuid1())
            with current_app.conn.cursor() as cur:
                cur.execute("CALL register_user_procedure (%s,%s,%s,%s);",
                            (username, password_hash, email, token))
                current_app.conn.commit()
               # user = User.create(username, email, password, cur, current_app.conn)
                #token = token
                confirm_url = url_for('main.confirm_email', token=token, _external=True)
                html = render_template('confirm_email.html', confirm_url=confirm_url)
                send_email('Подтверждение регистрации', email, html)
                flash('Письмо с подтверждением отправлено на вашу почту.', 'success')
                return redirect(url_for('main.login'))
        return render_template('register.html')
    except Exception as e:
        # Если произошла ошибка, откатить транзакцию
        print(f"An error occurred: {e}")
        if current_app.conn:
            current_app.conn.rollback()
            return render_template_string('Что-то пошло не так')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with current_app.conn.cursor() as cur:
            user = User.get_by_email(email, cur)
            if user and check_password_hash(user.password_hash, password):
                if user.confirmed:
                    login_user(user)
                    return redirect(url_for('main.index'))
                else:
                    flash('Пожалуйста, подтвердите свой email.', 'warning')
            else:
                flash('Неправильный логин или пароль.', 'danger')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/confirm/<token>')
def confirm_email(token):
    try:
        with current_app.conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE confirmation_token = %s", (token,))
            user_data = cur.fetchone()
            if user_data:
                user = User(*user_data)
                user.confirmed = True
                user.confirmation_token = None
                cur.execute("UPDATE users SET confirmed = %s, confirmation_token = %s WHERE id = %s",
                            (user.confirmed, user.confirmation_token, user.id))
                current_app.conn.commit()
                flash('Вы успешно подтвердили свой email!', 'success')
                return redirect(url_for('main.login'))
            else:
                flash('Недействительная или истекшая ссылка подтверждения.', 'danger')
        return redirect(url_for('main.index'))

    except Exception as e:
        # Если произошла ошибка, откатить транзакцию
        print(f"An error occurred: {e}")
        if current_app.conn:
            current_app.conn.rollback()


@main.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        with current_app.conn.cursor() as cur:
            user = User.get_by_email(email, cur)
            if user:
                token = secrets.token_urlsafe(16)
                cur.execute("UPDATE users SET confirmation_token = %s WHERE id = %s", (token, user.id))
                current_app.conn.commit()
                reset_url = url_for('main.reset_password', token=token, _external=True)
                html = render_template('reset_password_mail.html', reset_url=reset_url)

                # Добавление отладочного сообщения
                print(f"Отправка письма на адрес {user.email} с ссылкой {reset_url}")

                send_email('Восстановление пароля', user.email, html)
                flash('Письмо с инструкциями по восстановлению пароля отправлено на вашу почту.', 'info')
            else:
                flash('Пользователь с таким email не найден.', 'warning')
        return redirect(url_for('main.login'))
    return render_template('reset_password_request.html')

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with current_app.conn.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE confirmation_token = %s", (token,))
        user_data = cur.fetchone()
        if not user_data:
            flash('Недействительная или истекшая ссылка.', 'danger')
            return redirect(url_for('main.index'))

        if request.method == 'POST':
            new_password = request.form['password']
            new_password_hash = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password_hash = %s, confirmation_token = NULL WHERE id = %s",
                        (new_password_hash, user_data[0]))
            current_app.conn.commit()
            flash('Ваш пароль был успешно изменен.', 'success')
            return redirect(url_for('main.login'))
    return render_template('reset_password.html')

@main.route('/')
@login_required
def index():
    with current_app.conn.cursor() as cur:
        user_id = current_user.id
        save_user_cookies(user_id)
        cur.execute("""
            SELECT instruments.id, instruments.name, instruments.description, instruments.photo, storage_locations.name
            FROM instruments
            LEFT JOIN storage_locations ON instruments.storage_location_id = storage_locations.id
            WHERE user_id = %s""", (user_id,))
        instruments = cur.fetchall()
        instruments = [
            {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "photo": base64.b64encode(row[3]).decode('utf-8') if row[3] else None,
                "storage_location": row[4]
            } for row in instruments
        ]
    return render_template('index.html', instruments=instruments)



@main.route('/admin', methods=['GET', 'POST'])
@login_required
def get_admin():
    if User.roles == 1:
        query_result = ''
        columns = []
        rows = []
        error_message = ''
        reports = []

        try:
            cur = current_app.conn.cursor()
            cur.execute("SELECT id_report, ReportName FROM Reports")
            reports = cur.fetchall()
            cur.close()
        except Exception as e:
            error_message = f'Error fetching reports: {str(e)}'
            if current_app.conn:
                current_app.conn.rollback()
        # finally:
        #     close_db()

        if request.method == 'POST':
            query = ''
            selected_report = request.form.get('report')
            if selected_report:
                try:
                    cur = current_app.conn.cursor()
                    cur.execute("SELECT SQLtext FROM Reports WHERE id_report = %s", (selected_report,))
                    query = cur.fetchone()[0]
                    cur.close()
                except Exception as e:
                    error_message = f'Error fetching report query: {str(e)}'
                    if current_app.conn:
                        current_app.conn.rollback()
                # finally:
                #     close_db()
            else:
                query = request.form.get('query', '')

            if query:
                try:
                    cur = current_app.conn.cursor()
                    cur.execute(query)

                    if cur.description:
                        columns = [desc[0] for desc in cur.description]
                        rows = cur.fetchall()

                    cur.close()
                except Exception as e:
                    error_message = f'Error executing query: {str(e)}'
                    if current_app.conn:
                        current_app.conn.rollback()
                # finally:
                #     close_db()

        return render_template('admin.html', columns=columns, rows=rows, error_message=error_message, reports=reports)
    else:
        return redirect(url_for('main.index'))

@main.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        storage_location_id = request.form['storage_location']
        photo = request.files['photo']
        user = current_user.id
        #user = User.get_id('self')

        if photo:
            image = Image.open(photo)
            # Уменьшаем разрешение изображения
            max_sum = 600
            width, height = image.size
            if width + height > max_sum:
                ratio = max_sum / (width + height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                image = image.resize((new_width, new_height), Image.LANCZOS)

            img_io = io.BytesIO()
            image.save(img_io, 'JPEG', quality=85)
            img_size = img_io.tell()

            quality = 85
            while img_size > 50 * 1024 and quality > 10:
                img_io = io.BytesIO()
                image.save(img_io, 'JPEG', quality=quality)
                img_size = img_io.tell()
                quality -= 5

            photo = img_io.getvalue()
        else:
            photo = None

        with current_app.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO instruments (name, description, photo, storage_location_id, user_id) VALUES (%s, %s, %s, %s, %s)",
                (name, description, psycopg2.Binary(photo), storage_location_id, user)
            )
            current_app.conn.commit()
        return redirect(url_for('main.index'))

    with current_app.conn.cursor() as cur:
        cur.execute("SELECT id, name FROM storage_locations")
        storage_locations = cur.fetchall()
        storage_locations = [{"id": row[0], "name": row[1]} for row in storage_locations]

    return render_template('upload.html', storage_locations=storage_locations)

@main.route('/edit/<int:instrument_id>', methods=['GET', 'POST'])
def edit(instrument_id):
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        storage_location_id = request.form['storage_location']
        photo = request.files['photo']

        if photo:
            image = Image.open(photo)
            # Уменьшаем разрешение изображения
            max_sum = 600
            width, height = image.size
            if width + height > max_sum:
                ratio = max_sum / (width + height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                image = image.resize((new_width, new_height), Image.LANCZOS)

            img_io = io.BytesIO()
            image.save(img_io, 'JPEG', quality=85)
            img_size = img_io.tell()

            quality = 85
            while img_size > 50 * 1024 and quality > 10:
                img_io = io.BytesIO()
                image.save(img_io, 'JPEG', quality=quality)
                img_size = img_io.tell()
                quality -= 5

            photo = img_io.getvalue()
        else:
            with current_app.conn.cursor() as cur:
                cur.execute("SELECT photo FROM instruments WHERE id = %s", (instrument_id,))
                photo = cur.fetchone()[0]

        with current_app.conn.cursor() as cur:
            cur.execute(
                "UPDATE instruments SET name = %s, description = %s, photo = %s, storage_location_id = %s WHERE id = %s",
                (name, description, psycopg2.Binary(photo), storage_location_id, instrument_id)
            )
            current_app.conn.commit()
        return redirect(url_for('main.index'))

    with current_app.conn.cursor() as cur:
        cur.execute("""
            SELECT instruments.id, instruments.name, instruments.description, instruments.photo, instruments.storage_location_id
            FROM instruments
            WHERE instruments.id = %s
        """, (instrument_id,))
        instrument = cur.fetchone()
        if instrument:
            instrument = {
                "id": instrument[0],
                "name": instrument[1],
                "description": instrument[2],
                "photo": base64.b64encode(instrument[3]).decode('utf-8') if instrument[3] else None,
                "storage_location_id": instrument[4]
            }
        else:
            return "Инструмент не найден", 404

        cur.execute("SELECT id, name FROM storage_locations")
        storage_locations = cur.fetchall()
        storage_locations = [{"id": row[0], "name": row[1]} for row in storage_locations]

    return render_template('edit.html', instrument=instrument, storage_locations=storage_locations)


@main.route('/edit_storage_locations', methods=['GET', 'POST'])
def edit_storage_locations():
    #with current_app.conn.cursor() as cur:
    cur = current_app.conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        cur.execute('INSERT INTO storage_locations (name) VALUES (%s)', (name,))
        current_app.conn.commit()
        #cur.close()
        #current_app.conn.close()
        return redirect(url_for('main.edit_storage_locations'))

    cur.execute('SELECT id, name FROM storage_locations')
    storage_locations = cur.fetchall()
    return render_template('edit_storage_locations.html', storage_locations=storage_locations)

@main.route('/edit_storage_location/<int:location_id>', methods=['POST'])
def edit_storage_location2(location_id):
    name = request.form['name']
    cur = current_app.conn.cursor()
    cur.execute('UPDATE storage_locations SET name = %s WHERE id = %s', (name, location_id))
    current_app.conn.commit()

    return redirect(url_for('main.edit_storage_locations'))

@main.route('/delete_storage_location/<int:location_id>', methods=['POST'])
def delete_storage_location(location_id):
    with current_app.conn.cursor() as cur:
        cur.execute('DELETE FROM storage_locations WHERE id = %s', (location_id,))
        current_app.conn.commit()
        return redirect(url_for('main.edit_storage_locations'))




@main.route('/delete/<int:instrument_id>', methods=['POST'])
def delete(instrument_id):
    with current_app.conn.cursor() as cur:
        cur.execute("DELETE FROM instruments WHERE id = %s", (instrument_id,))
        current_app.conn.commit()
    return redirect(url_for('main.index'))
