
# Dockerfile:

FROM --platform=linux/amd64 node:18.19.1-slim AS base
# Create app directory
WORKDIR /app

# Copy artifacts over
COPY pnpm-lock.yaml package.json ./

# Install pnpm
RUN npm install -g pnpm

# Copy over .env file
COPY ./.env ./.env

# Install dependencies
RUN pnpm i

# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY . .
RUN apt-get update -y && apt-get install -y openssl

# Expose the app
EXPOSE 8080

# Generate and push prisma file
RUN pnpm run db:generate-staging
RUN pnpm run db:push-staging

# Build the project
RUN pnpm run build

# Start the application
CMD ["pnpm", "start"]
