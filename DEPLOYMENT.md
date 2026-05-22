# VulnForge Production Deployment Guide

This guide walks you through deploying the VulnForge full-stack application (Frontend + Backend + PostgreSQL + Redis) to modern cloud infrastructure.

## Architecture Stack
- **Database**: Neon (PostgreSQL)
- **Queue/Cache**: Upstash (Serverless Redis)
- **Backend**: Render (via Docker)
- **Frontend**: Vercel (Static SPA)

---

## 1. Environment Preparation
Ensure you have the following services provisioned and credentials ready:
1. **Neon Postgres**: Get the standard connection string.
2. **Upstash Redis**: Get the `rediss://...` connection string.
3. **Gemini API Key**: For the AI Orchestration layer.

---

## 2. Backend Deployment (Render)

Because VulnForge requires Playwright and headless browser OS dependencies, you **must** deploy the backend using the provided `Dockerfile`.

1. In Render, create a new **Web Service**.
2. Connect your VulnForge GitHub repository.
3. **Environment**: Select `Docker`.
4. Render will automatically detect the `Dockerfile`.
5. Add the following **Environment Variables**:
   - `PORT` = `4000`
   - `NODE_ENV` = `production`
   - `DATABASE_URL` = `postgresql://... (Your Neon URL)`
   - `REDIS_URL` = `rediss://... (Your Upstash URL)`
   - `USE_DISTRIBUTED_QUEUE` = `true`
   - `VULNFORGE_API_KEY` = `(Generate a secure random string)`
   - `JWT_SECRET` = `(Generate a secure random string)`
   - `GEMINI_API_KEY` = `(Your Gemini Key)`
   - `FRONTEND_ORIGIN` = `https://your-frontend-domain.vercel.app` (You can update this after Vercel deployment)
6. Deploy the service.

*Note: The Dockerfile runs `npx prisma generate` and `npm run build` automatically.*

---

## 3. Database Migration
To apply the database schema to your production database, run the following command from your local machine (or Render's Shell):

```bash
DATABASE_URL="your-neon-url" npx prisma migrate deploy
```
*(Do NOT use `migrate dev` against the production database).*

---

## 4. Frontend Deployment (Vercel)

The frontend is a static React Single Page Application (SPA) built with Vite.

1. Create a new project in Vercel and link your GitHub repository.
2. Set the **Framework Preset** to `Vite`.
3. Set the **Root Directory** to `frontend`.
4. Add the following **Environment Variables**:
   - `VITE_API_BASE_URL` = `https://your-backend-app.onrender.com`
   - `VITE_VULNFORGE_API_KEY` = `(Must exactly match the backend VULNFORGE_API_KEY)`
5. Deploy.

*Note: The `vercel.json` file inside the `frontend` directory automatically handles SPA fallback routing.*

---

## 5. Final Verification
1. Open the Vercel frontend URL.
2. Register an initial user (this creates your root Tenant/Organization).
3. Kick off a scan against a test target.
4. Verify in Upstash that BullMQ jobs are populating and executing.
5. Verify in Neon that `TargetProfile`, `Scan`, and `Finding` records are being created.
