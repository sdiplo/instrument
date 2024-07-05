from flask_mail import Message
from . import mail


def send_email(subject, to, html, sender='sdiplo@yandex.ru'):
    msg = Message(subject, recipients=[to], html=html, sender=sender)
    mail.send(msg)