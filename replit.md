# FamilyGame

## Overview

FamilyGame is a multiplayer social gaming platform built with Flask and Socket.IO. The application supports user authentication, real-time messaging between friends, a friend system, leaderboards, and an admin dashboard. The interface is designed in Arabic (RTL) with a modern, glassmorphism-style UI.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Real-time Communication**: Flask-SocketIO for WebSocket-based features like live chat
- **Authentication**: Flask-Login for session management with UserMixin pattern
- **Password Security**: Werkzeug security utilities for password hashing

### Database Design
- **ORM**: Flask-SQLAlchemy
- **Database**: SQLite (file-based at `familygame_vFinal.db`)
- **Key Models**:
  - `User`: Stores player data including username, password hash, level, points, online status, bio, and avatar
  - `Friend`: Manages friend relationships between users (sender/receiver pattern)

### Frontend Architecture
- **Templating**: Jinja2 templates
- **Styling**: Custom CSS with CSS variables, Cairo font (Arabic support), glassmorphism effects
- **Icons**: Font Awesome 6.0
- **Layout**: RTL (Right-to-Left) for Arabic language support

### Key Features
1. **Authentication System**: Login/signup with CAPTCHA verification and password hashing
2. **Friend System**: Search users, add friends, view friend profiles
3. **Real-time Chat**: Socket.IO-powered messaging with message editing/deletion
4. **Leaderboard**: Points and level-based ranking system
5. **Admin Panel**: User management with block/delete capabilities (admin: gatapro901)
6. **User Profiles**: Online status tracking, bio, avatar support
7. **Lobby System**: Create game rooms, invite friends, kick players, real-time player updates

### Recent Changes (January 2026)
- Added password hashing using werkzeug.security (generate_password_hash, check_password_hash)
- Implemented lobby system with host/guest roles and kick player functionality
- Redesigned dashboard with modern card-based layout and notification dropdown
- Fixed Socket.IO room management for lobbies and personal notifications
- Added join_lobby route for accepting game invitations

### Design Patterns
- Session-based authentication with Flask-Login
- MVC-like structure with Flask routes and Jinja2 templates
- Real-time updates via WebSocket connections

## External Dependencies

### Python Packages
- `flask`: Web framework
- `flask-sqlalchemy`: Database ORM
- `flask-socketio`: WebSocket support
- `flask-login`: User session management
- `werkzeug`: Password hashing utilities

### Frontend CDN Resources
- Google Fonts (Cairo font family)
- Font Awesome 6.0 (icon library)

### Database
- SQLite (local file storage, no external database server required)

### Configuration
- Secret key configured for session management
- CORS enabled for Socket.IO connections
- SQLAlchemy track modifications disabled for performance