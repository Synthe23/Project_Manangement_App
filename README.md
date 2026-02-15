# Project_Manangement_App

About the project:
✍🏼
  Project Camp Backend is a fully-featured RESTful API built to power a collaborative project management system. It enables teams to create projects, manage tasks and subtasks, collaborate through notes, and control access with a secure role-based permission system.
  This backend focuses on structured teamwork, clean authorization logic, and secure authentication, making it a solid foundation for any project management application.


// Implementation:
🔐 Secure Authentication & Role-Based Access
  The system implements JWT-based authentication with refresh tokens, email verification, password reset, and secure session handling.
  It follows a three-tier role model:
  	•	Admin – Full control over projects, members, tasks, and notes
  	•	Project Admin – Manages tasks and subtasks within assigned projects
  	•	Member – Contributes by updating task and subtask progress
  Access to every route is protected through middleware-driven authorization logic.


📁 Project & Team Management
	•	Create and manage projects
	•	Invite members via email
	•	Assign and update roles within projects
	•	View project details and member lists
	•	Admin-controlled project lifecycle (create, update, delete)


🛡 Security
	•	JWT Authentication with refresh token mechanism
	•	Email verification & secure password reset
	•	Role-based authorization middleware
	•	Input validation across all endpoints
	•	Secure file uploads using Multer
	•	CORS configuration
	•	Dedicated health-check endpoint


⚡️ Authentication Routes** (`/api/v1/auth/`)

- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /logout` - User logout (secured)
- `GET /current-user` - Get current user info (secured)
- `POST /change-password` - Change user password (secured)
- `POST /refresh-token` - Refresh access token
- `GET /verify-email/:verificationToken` - Email verification
- `POST /forgot-password` - Request password reset
- `POST /reset-password/:resetToken` - Reset forgotten password
- `POST /resend-email-verification` - Resend verification email (secured)


  
