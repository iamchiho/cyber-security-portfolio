#!/bin/bash
# 一鍵更新 + 部署 Cyber Security Portfolio

echo "Staging changes..."
git add .

echo "Committing changes..."
git commit -m "Update portfolio"

echo "Pushing to main branch..."
git push origin main

echo "Building website..."
npm run build

echo "Deploying to GitHub Pages..."
GIT_USER=iamchiho USE_SSH=true npx docusaurus deploy

echo "Done! Your website should be updated at https://iamchiho.github.io/cyber-security-portfolio/"