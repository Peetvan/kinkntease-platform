# Changelog

All notable changes to Kink N Tease will be documented in this file.

## [3.0.0] - 2025-12-02

### Added
- **Photo Locking System**: Users can lock photos, making them visible only to premium members
  - Lock/unlock button on own photos (🔒/🔓)
  - Locked photos show placeholder for non-premium viewers
  - Backend validation and premium check
- **User Blocking**: Complete block/ignore functionality
  - Block button on all profiles
  - Bidirectional message blocking
  - `blocked_users` database table
  - Unblock functionality
- **Read Receipts**: Message delivery and read status
  - Single check (✓) for sent messages
  - Double check (✓✓) in green for read messages
  - Timestamp tracking with `read_at` field
  - Hover to see exact read time

### Changed
- Messages table now includes `read_at TIMESTAMP` field
- Profile display logic handles locked photos
- Message sending checks block status before delivery

### Database Changes
```sql
ALTER TABLE user_photos ADD COLUMN is_locked TINYINT(1) DEFAULT 0;
ALTER TABLE messages ADD COLUMN read_at TIMESTAMP NULL;
CREATE TABLE blocked_users (...)
```

## [2.0.0] - 2025-12-02

### Added
- **Photo Rating System**: 5-star rating for user photos
  - Interactive clickable stars
  - Average rating calculation
  - Rating count display
  - Yellow/gold glow effects on stars
  - Hover animations (scale 1.3x)
  - `photo_ratings` table
  - `rating` and `rating_count` columns in `user_photos`

### Changed
- Stars display with gold drop-shadow
- Rating text in gold color (#ffd700)
- Smooth transitions (0.2s) on hover

### Database Changes
```sql
CREATE TABLE photo_ratings (...)
ALTER TABLE user_photos ADD COLUMN rating DECIMAL(2,1) DEFAULT 0;
ALTER TABLE user_photos ADD COLUMN rating_count INT DEFAULT 0;
```

## [1.5.0] - 2025-12-02

### Added
- **Notification Sounds**: Pleasant "ding-dong" sound on new notifications
  - Two-tone system (800Hz + 1000Hz)
  - 30% volume (non-intrusive)
  - Web Audio API implementation
  - Plays only when count increases

### Changed
- Notification polling tracks previous count
- `lastNotifCount` variable tracks state
- Sound plays on count increase only

## [1.0.0] - 2025-12-01

### Initial Release

#### Core Features
- User registration with email verification
- Login/logout system with sessions
- Profile management (bio, photos, interests)
- Photo upload (up to 12 photos)
- Direct messaging between users
- Chat rooms (public group chat)
- Member browsing with filters
- Wink system
- Favorites system
- Virtual gifts
- Voice messages
- Notification system
- Admin dashboard

#### Premium Features
- Premium membership tiers
- Promo code system
- PayPal integration

#### Database Tables
- users, profiles, user_photos
- messages, chat_rooms, chat_messages
- notifications, winks, favorites
- gifts, voice_messages
- promo_codes, subscriptions

#### Security
- SQL injection protection
- XSS prevention
- Password hashing (bcrypt)
- Email verification required
- API key authentication

---

## Version Naming Convention

- **Major.Minor.Patch** (e.g., 3.0.0)
- **Major**: Breaking changes or major feature additions
- **Minor**: New features, backwards compatible
- **Patch**: Bug fixes and minor improvements

## Rollback System

- Automatic rollbacks created every 5 changes
- Timestamped format: `YYYYMMDD-HHMMSS`
- Stored in: `/mnt/user-data/outputs/rollbacks/`
- Last 10 versions kept

## Next Planned Features

- WebSocket real-time messaging
- Video chat integration
- Mobile app (React Native)
- Advanced search filters
- Story/feed feature
- Location-based matching
- Push notifications

---

**Maintained by:** Peet van Niekerk  
**Last Updated:** 2025-12-02
