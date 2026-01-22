# DE-MainFrame V11.15

Detection Engineering MainFrame - A web-based platform for managing Splunk Enterprise Security detection rules.

## Features

- Create, edit, and manage Splunk detection rules
- GitHub integration for version control
- Revalidation workflows
- History tracking
- Reports and analytics

## Deployment

This application is deployed via GitHub Pages from the `/docs` folder.

## Setup

1. Configure GitHub settings in `docs/app.js`
2. Enable GitHub Pages (Settings → Pages → Source: main branch, /docs folder)
3. Access at: https://threadlinqs-cmd.github.io/DE-Mainframe/docs/

## Configuration

Update `GITHUB_CONFIG` in `docs/app.js` with your:
- GitHub URL
- Repository name
- Branch
- Personal Access Token
