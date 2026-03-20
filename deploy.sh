#!/bin/bash
# 一鍵更新 + 部署 Cyber Security Portfolio
# 使用方式: ./deploy.sh "Your commit message"

# 讀取 commit message 參數，沒有就用預設
COMMIT_MSG=${1:-"Update portfolio"}

echo "Checking for changes..."
if git diff-index --quiet HEAD --; then
    echo "No changes detected. Skipping commit, push, build, and deploy."
    exit 0
fi

echo "Staging changes..."
git add .

echo "Committing changes..."
git commit -m "$COMMIT_MSG"

echo "Pushing to main branch..."
git push origin main

echo "Building website..."
npm run build

echo "Deploying to GitHub Pages..."
GIT_USER=iamchiho USE_SSH=true npx docusaurus deploy

echo "Done! Your website should be updated at https://iamchiho.github.io/cyber-security-portfolio/"