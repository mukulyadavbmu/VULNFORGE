# Use the Playwright base image that matches the installed package version.
# @playwright/test is pinned to 1.48.2 in package.json — this image ships the
# exact Chromium headless-shell binary that version expects.
FROM mcr.microsoft.com/playwright:v1.48.2-jammy

# Set working directory
WORKDIR /app

# Copy package.json and optionally any lockfiles first to leverage Docker cache
COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./

# Install dependencies based on what lockfile exists
RUN \
  if [ -f package-lock.json ]; then npm ci; \
  elif [ -f yarn.lock ]; then npm install -g yarn && yarn install --frozen-lockfile; \
  elif [ -f pnpm-lock.yaml ]; then npm install -g pnpm && pnpm install --frozen-lockfile; \
  else npm install; \
  fi

# Copy the rest of the application code
COPY . .

# Generate Prisma Client
RUN npx prisma generate

# Install the exact Playwright browsers that match the installed package.
# The base image ships its own chromium, but running this ensures the binary
# path matches whatever version npm resolved — prevents version drift crashes.
RUN npx playwright install chromium --with-deps

# Build the TypeScript backend
RUN npm run build

# Expose the application port
EXPOSE 4000

# Start the application
CMD ["npm", "start"]
