
# WHERE IS MY RIDE - Backend

Secure backend API for the WHERE IS MY RIDE project.

## Current Features

- Express.js server
- Firebase Admin SDK initialization
- Firebase ID token verification
- API rate limiting
- Security headers
- CORS configuration
- Health check endpoint

## Requirements

- Node.js 22
- npm
- Firebase project: myridebhilwala-45652

## Installation

From the backend directory:

```bash
npm install
```

## Environment Configuration

Set these environment variables in your hosting provider:

- PORT
- NODE_ENV
- GOOGLE_CLOUD_PROJECT
- ALLOWED_ORIGINS

Use a secure hosting identity with Firebase Admin permissions.
Never upload service-account keys or secrets to GitHub.

## Start Server

```bash
npm start
```

## API Endpoints

### Health Check

GET /api/health

### Authenticated User

GET /api/me

Requires:

Authorization: Bearer FIREBASE_ID_TOKEN

## Important

This is an initial backend foundation.

Booking APIs, driver APIs, admin APIs, payment processing,
Razorpay integration and frontend connection are not implemented yet.

Do not use for production rides or real payments until
authorization, database validation and end-to-end testing are complete.
