# 💕 Kink N Tease - Dating Platform

A full-featured dating and social networking platform with advanced features for adult connections.

## 🌟 Features

### Core Features
- ✅ User registration & email verification
- ✅ Profile management with photos
- ✅ Real-time messaging (DM & chat rooms)
- ✅ Member browsing with filters
- ✅ Winks & favorites system
- ✅ Virtual gifts
- ✅ Voice messages
- ✅ Admin dashboard

### Premium Features
- ⭐ Photo rating system (1-5 stars)
- 🔒 Lockable photos (premium-only viewing)
- 🚫 Block/ignore users
- 👁️ Read receipts (double check marks)
- 🔔 Notification sounds
- 💎 Premium membership tiers

### Recent Updates (v3 - Dec 2, 2025)
- 🔒 Photo locking for premium content
- 🚫 User blocking system
- 👁️ Read receipts with timestamps
- ⭐ Yellow/gold star effects with glow
- 🔔 Pleasant notification sounds

## 📁 Project Structure

```
kinkntease/
├── backend/
│   └── index.php          # Complete API (2,471 lines)
├── frontend/
│   └── kinkntease-v4-CLEAR-LOGIN.html  # Main application (5,895 lines)
├── database/
│   └── setup-three-features.sql  # Latest database schema
└── docs/
    ├── INSTALLATION.md
    └── CHANGELOG.md
```

## 🚀 Installation

### Prerequisites
- PHP 8.0+
- MySQL 8.0+
- Apache/Nginx web server
- SSL certificate (required for production)

### Database Setup
1. Create MySQL database: `db9hmsktz1ntus`
2. Import schema: `database/setup-three-features.sql`
3. Update credentials in `backend/index.php`

### Backend Setup
1. Upload `backend/index.php` to `/api/index.php`
2. Set permissions: `chmod 644 /api/index.php`
3. Configure database credentials:
   ```php
   define('DB_HOST', 'localhost');
   define('DB_NAME', 'your_database');
   define('DB_USER', 'your_username');
   define('DB_PASS', 'your_password');
   ```

### Frontend Setup
1. Upload `frontend/kinkntease-v4-CLEAR-LOGIN.html` to `/public_html/`
2. Update API endpoint if needed (default: `/api/index.php`)
3. Configure in HTML or create `config.js`

### SSL & Security
- Force HTTPS in production
- Update API_KEY in backend
- Configure CORS if needed
- Set up email SMTP settings

## 🔐 Security Features

- SQL injection protection (prepared statements)
- XSS prevention (sanitization)
- CSRF token validation
- Password hashing (bcrypt)
- Email verification required
- API key authentication
- Session management
- File upload validation

## 📊 Database Tables

- `users` - User accounts
- `profiles` - User profiles with details
- `user_photos` - Photo gallery with ratings & locking
- `messages` - Direct messages with read receipts
- `chat_rooms` - Public chat rooms
- `chat_messages` - Room messages
- `notifications` - User notifications
- `winks` - Wink interactions
- `favorites` - Favorite users
- `blocked_users` - User blocking system
- `photo_ratings` - Photo rating system
- `promo_codes` - Promotional codes
- And more...

## 🛠️ Tech Stack

**Backend:**
- PHP 8.0+ (pure PHP, no frameworks)
- MySQL 8.0+
- RESTful API architecture

**Frontend:**
- Vanilla JavaScript (ES6+)
- CSS3 with custom properties
- Web Audio API (notification sounds)
- Responsive design (mobile-first)

**APIs & Services:**
- Email notifications (SMTP)
- PayPal integration (subscriptions)
- File upload handling
- Real-time polling (30s intervals)

## 📈 Roadmap

- [ ] WebSocket for real-time messaging
- [ ] Video chat integration
- [ ] Mobile app (React Native)
- [ ] Advanced search filters
- [ ] Story/feed feature
- [ ] Location-based matching
- [ ] Push notifications

## 🐛 Known Issues

- None currently reported

## 📝 Changelog

### v3.0 (2025-12-02)
- Added photo locking system
- Implemented user blocking
- Added read receipts with timestamps
- Yellow/gold star effects
- Notification sounds

### v2.0 (2025-12-02)
- Photo rating system (1-5 stars)
- Clickable interactive stars
- Average rating calculation
- Rating count display

### v1.0 (2025-12-01)
- Initial release
- Core dating platform features
- User authentication
- Messaging system
- Profile management

## 👨‍💻 Developer

**Peet van Niekerk**
- Role: Full Stack Developer & Designer
- Company: SKAO / Abuntu Digital
- Location: Perth, Western Australia

## 📄 License

Proprietary - All rights reserved

## 🤝 Support

For support or questions:
- Check documentation in `/docs`
- Review changelog for recent updates
- Contact: peet.vanniekerk@skao.int

## ⚠️ Important Notes

- This is a production application handling real user data
- Always test changes in development before deploying
- Keep regular backups (automated rollbacks every 5 changes)
- Follow security best practices
- Keep dependencies updated

---

**Last Updated:** December 2, 2025  
**Version:** 3.0  
**Status:** Production Ready ✅
