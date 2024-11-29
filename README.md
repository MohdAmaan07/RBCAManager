# RBCAManager

A Django-based web application that implements role-based authentication and authorization. It includes user registration, login, password reset, and email verification with OTP. The project supports different user roles (Admin, Moderator, User) with specific permissions to access and manage resources such as logs, sessions, and user profiles.

## Features

- **User Registration**: Users can register with email verification (OTP).
- **Login & Logout**: Secure login and logout functionality.
- **Role-Based Access Control (RBAC)**: Admin, Moderator, and User roles with specific permissions.
- **Moderator Dashboard**: Moderators can view logs, sessions, and perform some administrative tasks based on their assigned permissions.
- **Password Reset**: Users can reset their password via OTP.
- **Email Verification**: OTP verification for user registration and password reset.

## Technologies Used

- **Django**: Web framework for backend development.
- **Python**: Programming language.
- **HTML/CSS**: Frontend for user interface.
- **Email Backend**: For OTP sending functionality.
- **SQLite/PostgreSQL**: Database (based on your configuration).

## Installation

### Prerequisites

Ensure you have Python and Django installed. This project also requires an email backend for OTP functionality.

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/moderator-dashboard.git
   cd moderator-dashboard
   ```

2. **Install Dependencies**:

   Install the required Python packages using pip:

   ```bash
   pip install -r requirements.txt
   ```

3. **Database Setup**:

   Run the following command to apply migrations and set up the database:

   ```bash
   python manage.py migrate
   ```

4. **Create a Superuser** (for Admin access):

   Create a superuser account to access the Django Admin panel:

   ```bash
   python manage.py createsuperuser
   ```

5. **Run the Development Server**:

   Start the Django development server:

   ```bash
   python manage.py runserver
   ```

6. **Access the Application**:

   Open your browser and go to `http://127.0.0.1:8000/` to start using the application.

## Usage

### User Roles and Permissions

- **Admin**: Full access to all resources, including user management and log viewing.
- **Moderator**: Can view logs, sessions, and some resources depending on permissions.
- **User**: Basic access to their profile and the ability to update personal details.

### Accessing the Moderator Dashboard

- Moderators with the appropriate permissions can access the dashboard by navigating to the `/moderator-dashboard/` route. If the user does not have the necessary permissions, they will see a `403 Forbidden` page.

### Registration and Email Verification

- **Step 1**: During registration, users will provide their email, and an OTP will be sent to verify the email address.
- **Step 2**: Once the OTP is verified, users can log in.

### Password Reset

- **Step 1**: Users can request a password reset by entering their email address.
- **Step 2**: An OTP will be sent to the user’s email for verification.
- **Step 3**: Upon successful verification, users can set a new password.

### Logout

- Users can log out anytime, and they will be redirected to the login page.


## Assigning Permissions

To assign permissions to both the **Admin** and **Moderator** groups in Django, you can do this through the Django shell or in your Django admin panel.

### Step-by-Step Guide

1. Open the Django shell by running the following command:

   ```bash
   python manage.py shell
   ```

2. Run the following commands to assign permissions to the **Admin** and **Moderator** groups.

### Permissions for the Admin Group
Admins generally have full access to all permissions, so we'll assign all relevant permissions to the Admin group:

```python
from django.contrib.auth.models import Group, Permission

admin_group = Group.objects.get(name='admin')

permissions = Permission.objects.all()

admin_group.permissions.set(permissions)
admin_group.save()

print("Permissions for Admin group assigned.")
```

### Permissions for the Moderator Group

```python
from django.contrib.auth.models import Group, Permission

moderator_group = Group.objects.get(name='moderator')

moderator_permissions = Permission.objects.filter(codename__in=[
    'view_logentry', 'view_group', 'view_permission', 'view_user',
    'view_roles', 'add_accessattempt', 'change_accessattempt', 'delete_accessattempt', 
    'view_accessattempt', 'add_accessfailure', 'change_accessfailure', 'delete_accessfailure', 
    'view_accessfailure', 'add_accesslog', 'change_accesslog', 'delete_accesslog', 
    'view_accesslog', 'add_session', 'change_session', 'delete_session', 'view_session'
])

moderator_group.permissions.set(moderator_permissions)
moderator_group.save()

print("Permissions for Moderator group assigned.")
```

## API Endpoints  Documentation:

### Endpoints

- **`/home/`**: Displays the home page for logged-in users with role-based content.
- **`/register/`**: Allows new users to register with email verification via OTP.
- **`/verify-otp/`**: Verifies the OTP sent to the user's email during registration or login.
- **`/login/`**: Authenticates the user and logs them into the system.
- **`/logout/`**: Logs the user out of the system.
- **`/password-reset/`**: Initiates the password reset process by sending an OTP to the user's email.
- **`/password-reset/verify/`**: Verifies the OTP and allows the user to reset their password.
- **`/profile/`**: Displays and allows updating of the user’s profile.
- **`/login-admin/`**: Auto-login for admin users to access the admin dashboard.
- **`/moderator/dashboard/`**: Provides access to the moderator dashboard for managing logs and sessions.

### Notes:

- **Admin Permissions**: Admin users should have full access to all model permissions in the system (e.g., view, add, change, delete).
- **Moderator Permissions**: Moderators have more restricted access, typically including the ability to view logs, sessions, and perform specific operations based on your requirements.

### Alternative: Assigning Permissions via Admin Panel
You can also assign permissions to the groups manually via Django's admin panel:

1. Log in to the Django admin panel (`/admin`).
2. Under **Authentication and Authorization**, go to **Groups**.
3. Edit the **Admin** or **Moderator** group.
4. Assign permissions as needed by checking the permissions available in the list.

After assigning permissions, you can test them by logging in as a user belonging to the respective group and verifying that they can access the appropriate resources.

