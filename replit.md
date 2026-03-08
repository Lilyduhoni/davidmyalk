# DAVID MYALIK | Sideways Always - Merch Store

## Overview
Full-featured e-commerce merch store for David Myalik ("Sideways Always") with user authentication, order management, admin panel, and stock tracking.

## Architecture
- **Frontend**: Multi-page HTML/CSS/JS served from `public/` directory
- **Backend**: Express.js server with PostgreSQL database
- **Auth**: Session-based authentication with bcrypt password hashing
- **Database**: PostgreSQL (Replit built-in) with `pg` driver

## Project Structure
```
server.js              - Express server with all API routes
db.js                  - PostgreSQL connection pool
public/
  index.html           - Main storefront (products from DB, cart, checkout)
  login.html           - Login page
  signup.html          - Registration page
  forgot-password.html - Password reset flow
  dashboard.html       - User dashboard (orders, settings, addresses)
  admin.html           - Admin panel (products, orders, users management)
  help-center.html     - Help Center / FAQ page
  shipping-info.html   - Shipping information page
  returns.html         - Returns & exchanges policy page
  css/styles.css       - Shared stylesheet
api/checkout.js        - Original Netlify function (reference only)
```

## Database Tables
- `users` - User accounts (email, password_hash, role: owner/admin/customer)
- `products` - Product catalog (name, price, stock, image_url, category, is_active)
- `orders` - Customer orders with shipping info and status tracking
- `order_items` - Individual items in each order
- `addresses` - Saved shipping addresses
- `password_reset_tokens` - Password reset tokens
- `session` - Express session store

## Key Features
- First registered user becomes the owner (admin)
- Owner can promote users to admin or demote back to customer
- Products managed via admin panel with stock tracking
- Stock auto-decrements on purchase, shows "ONLY X LEFT" when stock <= 10
- Shows "SOLD OUT" when stock reaches 0
- Order status tracking (pending, processing, shipped, delivered, cancelled)
- Tracking number support on orders
- Cart starts empty each page load (no localStorage persistence)
- Cart badge hidden when empty, shown with count when items added
- Auth pages (login, signup, forgot-password) have "Back to Store" navigation
- Category filter tabs in shop section (filter by hats, keychains, stickers, etc.)
- Multi-column footer with Company and Support columns (YouTube, Instagram social icons)
- Dedicated pages: Help Center (FAQ), Shipping Info, Returns & Exchanges
- Server-side price validation on orders (prevents price tampering)

## API Endpoints
### Auth
- `POST /api/auth/signup` - Register (first user = owner)
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Current user
- `POST /api/auth/forgot-password` - Generate reset token
- `POST /api/auth/reset-password` - Reset password with token

### Store
- `GET /api/products` - List active products
- `GET /api/products/:id` - Get single product
- `POST /api/orders` - Place order (auth required, decrements stock)
- `GET /api/orders` - User's orders
- `GET /api/orders/:id` - Single order detail

### User
- `PUT /api/user/profile` - Update profile
- `PUT /api/user/password` - Change password
- `GET /api/user/addresses` - List addresses
- `POST /api/user/addresses` - Add address

### Admin
- `GET /api/admin/stats` - Dashboard stats
- `GET /api/admin/users` - List all users
- `PUT /api/admin/users/:id/role` - Change user role
- `GET /api/admin/users/:id` - User detail with orders/addresses
- `GET /api/admin/products` - All products (inc. inactive)
- `POST /api/admin/products` - Create product
- `PUT /api/admin/products/:id` - Update product
- `DELETE /api/admin/products/:id` - Deactivate product
- `GET /api/admin/orders` - All orders
- `PUT /api/admin/orders/:id/status` - Update order status/tracking

## Environment Variables (for Vercel/Neon deployment)
- `DATABASE_URL` - PostgreSQL connection string (Neon)
- `SESSION_SECRET` - Secret for session encryption
- `STRIPE_SECRET_KEY` - Stripe secret key for checkout

## Running the App
```
node server.js
```
Runs on port 5000 at `http://0.0.0.0:5000`

## Deployment
- Configured for autoscale deployment
- Run command: `node server.js`
