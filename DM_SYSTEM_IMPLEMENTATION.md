# Divine Dynamic - Direct Messages System Implementation

## Overview
This implementation adds a complete Direct Messages (DM) system to Divine Dynamic with WebSocket realtime updates, DM-specific bans with appeal flow, and comprehensive owner panel controls.

## Architecture

### Database Schema
Six new tables were added to support the DM system:

1. **dm_bans** - DM-specific bans separate from site-wide bans
   - user_id (PRIMARY KEY)
   - banned_until (indexed)
   - ban_reason
   - created_at

2. **dm_threads** - 1:1 conversation threads
   - id (PRIMARY KEY) - format: `{userId1}___{userId2}` (sorted)
   - user_a, user_b (indexed)
   - created_at
   - last_message_at (indexed)

3. **dm_requests** - DM invitation requests
   - id (AUTOINCREMENT PRIMARY KEY)
   - from_user_id, to_user_id (indexed)
   - invite_message
   - status (pending/accepted/declined)
   - created_at (indexed)
   - responded_at

4. **dm_messages** - Message storage
   - id (AUTOINCREMENT PRIMARY KEY)
   - thread_id (indexed with created_at)
   - from_user_id (indexed)
   - message
   - created_at

5. **dm_reads** - Unread message tracking
   - thread_id, user_id (composite PRIMARY KEY)
   - last_read_message_id
   - last_read_at
   - Indexed by user_id

6. **dm_appeals** - DM ban appeals
   - id (AUTOINCREMENT PRIMARY KEY)
   - user_id
   - username
   - appeal_text
   - created_at
   - status (open/dismissed) (indexed)

### Backend API Routes

#### User DM Routes
- `GET /api/dm/search-users?q={query}` - Search users for DM invites
- `POST /api/dm/request` - Send a DM invite with optional message
- `GET /api/dm/pending-requests` - Get pending incoming requests with count
- `POST /api/dm/request/:id/accept` - Accept a DM request (creates thread)
- `POST /api/dm/request/:id/decline` - Decline a DM request (3-day cooldown)
- `GET /api/dm/threads` - List user's active DM threads with unread counts
- `GET /api/dm/threads/:threadId/messages` - Get messages in a thread
- `POST /api/dm/threads/:threadId/messages` - Send a message
- `POST /api/dm/threads/:threadId/read` - Mark thread as read
- `GET /api/dm/unread-count` - Get total unread message count
- `POST /api/dm/appeal` - Submit a DM ban appeal (24h cooldown)
- `GET /api/dm/ban-info` - Get current user's DM ban details

#### Owner DM Management Routes
- `GET /api/owner/dm-bans` - List active DM bans
- `POST /api/owner/dm-ban` - Ban a user from DMs
- `POST /api/owner/dm-unban` - Remove a DM ban
- `GET /api/owner/dm-appeals` - List open DM ban appeals
- `POST /api/owner/dm-appeals/:id/dismiss` - Dismiss an appeal

### WebSocket Server
- **Endpoint**: `ws://HOST:PORT/ws` or `wss://HOST:PORT/ws`
- **Authentication**: JWT cookie-based (same as HTTP)
- **Events**:
  - `connected` - Initial connection confirmation
  - `new_request` - New DM invite received
  - `request_accepted` - DM request was accepted
  - `request_declined` - DM request was declined
  - `new_message` - New message in a thread
  - `unread_update` - Unread count changed

### Middleware & Security
- `/divine/dm/*` routes are gated by DM ban check
- DM-banned users are redirected to `/divine/dm/ban.html`
- Site-wide bans take precedence over DM access
- WebSocket connections validate JWT and check site-wide bans
- All API routes require authentication
- Owner routes require owner PIN cookie

## Frontend Implementation

### DM Interface (`/divine/dm/`)
- **index.html** - Main DM interface
  - Left sidebar: Thread list with unread badges
  - Pending requests section (collapsible)
  - Right panel: Active chat view
  - New DM button with user search modal

- **styles.css** - Modern dark theme with gold/purple accents
  - Responsive design (mobile-friendly)
  - Smooth animations
  - Consistent with site theme

- **script.js** - Full DM functionality
  - WebSocket integration for realtime updates
  - Request management (send, accept, decline)
  - Message sending and receiving
  - Unread tracking
  - User search
  - Auto-scroll to latest messages

### DM Ban Page (`/divine/dm/ban.html`)
- Displays ban reason and duration
- Shows time remaining in human-readable format
- Appeal form with text input
- Submit appeal with 24h cooldown
- Links back to home page

### Home Page Updates (`/divine/`)
- Red unread badge on envelope icon
- Shows count (capped at "9+")
- Blue dot for pending requests
- Realtime updates via WebSocket
- Fetches initial counts on page load

### Owner Panel Updates (`/owner/`)
- **Bans Section**: Added tabs for "Site Bans" and "DM Bans"
  - Separate tables for each ban type
  - DM Ban modal for creating DM-specific bans
  - Unban buttons for both types

- **Reports Section**: Added tabs for "User Reports" and "DM Appeals"
  - DM Appeals list with dismiss functionality
  - Shows appeal text and user details
  - Separate from regular user reports

- **Tab Navigation**: Styled tabs for switching between views
  - Active tab highlighting
  - Smooth transitions

## Key Features

### 1. DM Request Flow
1. User searches for another user
2. Sends invite with optional message
3. Recipient sees pending request
4. Accept → Creates thread, both can message
5. Decline → 3-day cooldown before sender can try again

### 2. Unread Count System
- Tracks last read message per thread per user
- Calculates unread count across all threads
- Updates in realtime via WebSocket
- Displays badge on home page

### 3. DM Ban System
- **Separate from site-wide bans**
- Restricts only DM access (user can still use site)
- Displays ban page with reason and duration
- Appeal flow with owner review
- Owner can see all DM bans and appeals in panel

### 4. Realtime Updates
- WebSocket connection per logged-in user
- Automatic reconnection on disconnect
- Events trigger UI updates instantly
- Badge updates on home page
- Message delivery notifications

## Configuration

### Environment Variables
Existing environment variables from the Node server are used:
- `PORT` - Server port (default: 3000)
- `JWT_SECRET` - Required for JWT authentication
- `AUTH_PIN` - User access PIN
- `OWNER_PIN` - Owner panel PIN
- `DB_PATH` - SQLite database path
- `ACCESS_EXPIRES_DAYS` - JWT expiry in days (default: 7)

### Dependencies
New dependency added:
- `ws@8.18.0` - WebSocket server

## Testing Checklist

### Backend
- [ ] Database tables created on init
- [ ] All DM API routes respond correctly
- [ ] DM ban middleware redirects banned users
- [ ] WebSocket connects and authenticates
- [ ] Realtime events are sent correctly
- [ ] Owner API routes work with PIN auth

### Frontend
- [ ] DM interface loads and displays threads
- [ ] Can send/receive messages in realtime
- [ ] Request flow (send, accept, decline) works
- [ ] Unread counts update correctly
- [ ] Badge shows on home page
- [ ] WebSocket reconnects after disconnect

### Security
- [ ] Site-wide bans still work (redirects to /)
- [ ] DM bans gate `/divine/dm/*` properly
- [ ] Cannot bypass bans via API or WebSocket
- [ ] Owner routes require PIN
- [ ] User routes require login

### Owner Panel
- [ ] Can create/remove DM bans
- [ ] DM bans list loads correctly
- [ ] DM appeals appear and can be dismissed
- [ ] Tabs switch correctly
- [ ] Modals open and submit properly

## Deployment Notes

1. **Database Migration**: The database schema will auto-create on first run
2. **WebSocket Support**: Ensure reverse proxy (if any) supports WebSocket upgrades
3. **Node Version**: Requires Node.js 18+ for native fetch support
4. **Dependencies**: Run `npm install` in `/server` directory
5. **Environment**: Set all required environment variables

## File Changes Summary

### New Files
- `/divine/dm/index.html` - DM interface
- `/divine/dm/styles.css` - DM styles
- `/divine/dm/script.js` - DM client logic
- `/divine/dm/ban.html` - DM ban page
- `/divine/dm/ban.js` - Ban page logic
- `/.gitignore` - Ignore node_modules and SQLite files

### Modified Files
- `/server/index.js` - Added DM routes, WebSocket server, DB schema
- `/server/package.json` - Added `ws` dependency
- `/divine/index.html` - Updated badge HTML
- `/divine/styles.css` - Updated badge styles
- `/divine/script.js` - Added badge update logic
- `/owner/index.html` - Added tabs and DM ban modal
- `/owner/styles.css` - Added tab styles
- `/owner/script.js` - Added DM ban management code

## Future Enhancements
- Group DMs (3+ participants)
- Message reactions
- Message search
- Message deletion/editing
- File/image sharing
- Read receipts per message
- Typing indicators
- Block user functionality
- Message notifications (browser/email)
- DM settings (mute, archive)

## Support
For issues or questions, refer to the main repository documentation or contact the site owner.
