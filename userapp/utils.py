
from django.core.mail import send_mail
from django.conf import settings
from django.core import mail
import os
from dotenv import load_dotenv
from pathlib import Path

def send_email(email,token,emailsettings):
    try:
        path = Path("./config.env")
        load_dotenv(dotenv_path=path)
        SITE_URL = os.getenv('SITE_URL')
        subject ='Verify Your account'
        message=f'Click on this link to verify {SITE_URL}/verify/{token}'
        email_from=emailsettings.user
        recipt_lst=[email,]
        print('hello')

        connection = mail.get_connection()

        connection.open()
        print(subject, message, email_from, recipt_lst)
        email1 = mail.EmailMessage(
            subject,
            message,
            email_from,
            recipt_lst,
            connection=connection,)

        email1.send()
        print("Email sent successfully")

    except:
        return False
    return True
def send_otp(email,url,emailsettings):
    try:
        subject='Verify Your Account'
        message=url
        print(message)
        email_from=emailsettings.user
        recipt_lst=[email]
        connection = mail.get_connection()

        connection.open()
        print(subject, message, email_from, recipt_lst)
        email1 = mail.EmailMessage(
            subject,
            message,
            email_from,
            recipt_lst,
            connection=connection, )
        email1.send()
        print("Email Sent Successfully")
    except:
        return False
    return True



