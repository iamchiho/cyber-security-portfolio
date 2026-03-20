#!/bin/bash
# 🔹 Cyber Security Portfolio - Full Safe Deploy Script
# Usage: ./deploy.sh "Your commit message"

COMMIT_MSG=${1:-"Update portfolio"}
BUILD_DIR="build"
WEBSITE_URL="https://iamchiho.github.io/cyber-security-portfolio/"

echo "---------------------------------------------"
echo "✅ Cyber Security Portfolio Deployment Script"
echo "Commit message: $COMMIT_MSG"
echo "---------------------------------------------"

# Step 1: Check for changes
echo "🔎 Checking for local changes..."
if git diff-index --quiet HEAD --; then
    echo "⚠️ No changes detected. Skipping commit, push, build, and deploy."
    exit 0
fi

# Step 2: Check node_modules
if [ ! -d "node_modules" ]; then
    echo "❌ Error: node_modules not found. Please run 'npm install' first."
    exit 1
fi

# Step 3: Stage and commit changes
echo "📂 Staging changes..."
git add .

echo "📝 Committing changes..."
git commit -m "$COMMIT_MSG"

# Step 4: Push to GitHub main
echo "🚀 Pushing to main branch..."
git push origin main
if [ $? -ne 0 ]; then
    echo "❌ Error: Git push failed."
    exit 1
fi

# Step 5: Clean old build folder
if [ -d "$BUILD_DIR" ]; then
    echo "🧹 Cleaning old build folder..."
    rm -rf $BUILD_DIR
fi

# Step 6: Build website
echo "🏗 Building website..."
npm run build
if [ $? -ne 0 ]; then
    echo "❌ Error: Build failed. Deployment aborted."
    exit 1
fi

# Step 7: Deploy to GitHub Pages
echo "🌐 Deploying to GitHub Pages..."
GIT_USER=iamchiho USE_SSH=true npx docusaurus deploy
if [ $? -ne 0 ]; then
    echo "❌ Error: Deployment failed."
    exit 1
fi

echo "---------------------------------------------"
echo "✅ Deployment complete! Website updated at:"
echo "   $WEBSITE_URL"
echo "---------------------------------------------"