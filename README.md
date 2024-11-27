Here’s an updated version of your README with all the features you mentioned, as well as some extra details to guide anyone using or contributing to the project:

---

# Project Name: User Authentication System

## Description
This Django-based authentication system allows users to sign up, log in, verify their email, reset their passwords, and manage their accounts. It supports essential features for secure authentication, including OTP-based email verification, password reset functionality, and password validation. 

### Key Features:
1. **User Registration**: Users can sign up by providing their first name, last name, username, email, and password.
2. **Email Verification (OTP-based)**: An OTP is sent to the user's email to verify their account during registration.
3. **User Login**: Registered users can log in using their username and password.
4. **Password Reset**: Users can reset their passwords by receiving a password reset link via email.
5. **Password Strength Validation**: Passwords must meet strength requirements (e.g., minimum length, use of numbers, special characters).
6. **Email Configuration**: Uses SMTP to send OTPs and password reset emails to users.
7. **Password Reset Token Expiration**: The password reset token expires after a set time to ensure security.

## Features in Detail:
- **User Registration**: On registration, users are required to enter a valid email, and an OTP is sent to that email for account verification.
- **Email Verification**: The user must enter the OTP sent to their email to complete the registration process.
- **User Login**: After registration and email verification, users can log in to the system using their username and password.
- **Password Reset**: Forgotten passwords can be reset by clicking the password reset link. A new password is set by entering the new password on a reset page.
- **Password Validation**: Password strength is validated to ensure strong passwords are used. This includes checks for minimum length, use of numbers, lowercase and uppercase letters, and special characters.
- **Email Service**: The system sends emails through your personal email account. It uses SMTP for email communication, and you must provide your email credentials in the `.env` file.
- **Customizable OTP Timeout**: OTP sent for email verification expires after a predefined duration.

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```

2. **Set up a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   Create a `.env` file in the root directory and add your email credentials:
   ```plaintext
   EMAIL_HOST_USER=<your_email>
   EMAIL_HOST_PASSWORD=<your_email_password>
   ```

   **Important**: Replace `<your_email>` and `<your_email_password>` with your email credentials. You should use an email service like SendGrid or Mailgun for production environments.

5. **Set up the database**:
   ```bash
   python manage.py migrate
   ```

6. **Create a superuser**:
   ```bash
   python manage.py createsuperuser
   ```

7. **Run the development server**:
   ```bash
   python manage.py runserver
   ```

   Your application will be available at `http://127.0.0.1:8000/`.

## Email Configuration

- **Email Sending**: The application uses SMTP to send verification OTPs and password reset emails. During development, you can use your personal email address (like Gmail), but for production, use a third-party service like SendGrid or Mailgun.
  
- **Email OTP**: During registration, users will receive an OTP on their email to verify their account. After successful verification, they can log in.
  
- **Password Reset**: When a user requests a password reset, they will receive a reset link at their registered email address. The reset link expires after a specified duration for security.

## Usage

1. **User Registration**: To sign up, navigate to `/register/` and fill out the registration form with your details. You will receive an OTP on your email for verification.
   
2. **User Login**: After verifying your email, you can log in at `/login/` using your username and password.

3. **Password Reset**: If you forget your password, navigate to `/password_reset/` to reset it. You will receive an email with a link to reset your password.

4. **Password Strength**: Passwords must meet the following criteria:
   - Minimum length of 8 characters.
   - Must include at least one lowercase letter.
   - Must include at least one uppercase letter.
   - Must include at least one special character (e.g., `@`, `#`, `!`).
   - Must include at least one number.

## Development Notes

- **Email Configuration**: Modify the email settings in the `.env` file for email sending configuration.
- **Email OTP**: The OTP expires after a short time (configurable). You can change the expiration time in the Django settings.
- **Security**: Always use a production-ready email service (like SendGrid or Mailgun) for email communication in production environments. Avoid using personal email accounts for live applications.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### Additional Notes:
1. **Password Validation**: If you need to modify password validation rules (e.g., change length or character requirements), you can edit the logic inside the `validators.py` file and adjust Django's built-in password validators in the `settings.py` file.
   
2. **Email Service**: The application is configured to work with SMTP servers (like Gmail, Yahoo, etc.) during development. For production, it's highly recommended to use a professional email service (like SendGrid or Mailgun).

3. **Security**: Do not push sensitive information, like email credentials, to the repository. Always use `.env` files to store such data and ensure they are added to `.gitignore`.

---
