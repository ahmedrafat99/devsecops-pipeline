# Stage 1 - build
FROM node:20-alpine AS build

WORKDIR /app

# Install dependencies first (better caching)
COPY package.json package-lock.json* ./
RUN npm install

# Copy the rest of the app
COPY next.config.mjs ./next.config.mjs
COPY app ./app

# Build the Next.js app
RUN npm run build

# Stage 2 - runtime image
FROM node:20-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production

# Copy only what is needed to run
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY package.json ./package.json
COPY next.config.mjs ./next.config.mjs

EXPOSE 3000

# Start the vulnerable Next.js app
CMD ["npm", "run", "start"]
