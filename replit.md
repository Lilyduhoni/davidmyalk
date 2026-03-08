# DAVID MYALIK | Sideways Always - Merch Store

## Overview
A static merch store for artist David Myalik ("Sideways Always"). Features a product catalog with a Stripe-powered checkout flow.

## Architecture
- **Frontend**: Single-page HTML (`index.html`) with Tailwind CSS (CDN), custom fonts via Google Fonts
- **Backend**: Express.js server (`server.js`) serving static files and the Stripe checkout API
- **Stripe**: Checkout sessions created server-side, redirects user to Stripe-hosted payment page

## Project Structure
```
index.html      - Main storefront (all HTML/CSS/JS in one file)
server.js       - Express server (static file server + Stripe API endpoint)
api/checkout.js - Original Netlify function (kept for reference)
package.json    - Node.js dependencies
```

## Running the App
```
node server.js
```
Runs on port 5000 at `http://0.0.0.0:5000`

## API Endpoint
- `POST /.netlify/functions/checkout` — accepts `{ cart: [...] }`, creates Stripe checkout session, returns `{ url }`

## Stripe Configuration
- The Stripe secret key is hardcoded in `server.js` as a fallback (test key)
- Set `STRIPE_SECRET_KEY` environment variable to override

## Deployment
- Configured for autoscale deployment
- Run command: `node server.js`
