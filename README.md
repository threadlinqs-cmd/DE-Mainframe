# DE-MainFrame V11.15

## What's New in V11.15

### 1. Editor - Collapsible Form Sections
All form sections in the Editor tab are now collapsible:
- Click on any section header to collapse/expand
- **Collapsed by default:** 5. Notable Event, 6. Classification & Scheduling, 8. Proposed Test Plan
- Sections 5 & 6 show **"- Splunk"** label in green to indicate Splunk-specific fields

### 2. Editor - Data Sources Field Enabled
The Required Data Sources field is now fully editable:
- Analysts can manually add data sources
- Auto-populated sources from Search String are appended (no duplicates)
- Case-insensitive duplicate detection
- All tags have remove buttons

### 3. Revalidation Tab - Detection Names Clickable
Detection names in the revalidation results are now clickable links:
- Click a detection name to navigate to the Library tab
- Automatically opens the detection detail view

### 4. Revalidation Tab - UC Health Dashboard Button
- Added "UC Health Dashboard" button with dedicated link
- Configure the link in `SPLUNK_CONFIG.healthDashboardPath`
- Default placeholder: `'Health_dashboard'`

### 5. Resources Tab - Bug Fixes
- Added null-safety for resource properties
- Added console logging for debugging
- Fixed potential issues with missing category/name/id fields

### 6. Library Tab - Datasources Filter
- Filter is already labeled "All Datasources" (confirmed)
- Aggregates: indexes, sourcetypes, categories, and Required_Data_Sources

## Configuration

### UC Health Dashboard Link
In `app.js`, update the `SPLUNK_CONFIG` object:

```javascript
const SPLUNK_CONFIG = {
    baseUrl: 'https://your-splunk.com',
    // ... other settings ...
    healthDashboardPath: '/en-US/app/YourApp/your_health_dashboard',  // UPDATE THIS
};
```

## File Structure
```
v11.15/
├── app.js
├── index.html
├── styles.css
├── compile_detections.py
├── migrate_detections.py
├── reparse_detections.py
├── README.md
├── assets/
│   ├── DE-Mainframe-logo.png
│   ├── DE-Mainframe-favicon.png
│   └── splunk-icon.svg
└── dist/
    └── resources.json
```

## Collapsible Sections

| Section | Default State | Splunk Label |
|---------|--------------|--------------|
| 1. Roles & Ownership | Expanded | No |
| 2. Basic Information | Expanded | No |
| 3. Search Configuration | Expanded | No |
| 4. Analyst Response | Expanded | No |
| 5. Notable Event | **Collapsed** | **Yes** |
| 6. Classification & Scheduling | **Collapsed** | **Yes** |
| 7. Drilldowns | Expanded | No |
| 8. Proposed Test Plan | **Collapsed** | No |

## Features Summary

| Feature | Status |
|---------|--------|
| Collapsible form sections | ✅ NEW |
| Editable data sources | ✅ NEW |
| Clickable detection names (Revalidation) | ✅ NEW |
| UC Health Dashboard button | ✅ NEW |
| Resources tab bug fixes | ✅ FIXED |
| Absolute timestamps | ✅ |
| MITRE sub-techniques | ✅ |
| SPL parsing improvements | ✅ |
| Auto-populate Data Sources | ✅ |
| Proposed Test Plan field | ✅ |

## Previous Features (V11.14)

- Absolute timestamps (DD/MM/YYYY HH:MM)
- MITRE sub-techniques support
- Improved SPL parsing (index==, parentheses, categories)
- Auto-populated data sources from Search String
- Proposed Test Plan field
- Python re-parser script

## Deployment

1. Copy entire `v11.15/` folder to your repository's `docs/` directory
2. Update configuration in `app.js`:

```javascript
const GITHUB_CONFIG = {
    baseUrl: 'https://mygithub.myenterprise',
    repo: 'Security/Splunk',
    branch: 'DE-MainFrame-Branch',
    token: 'YOUR_PAT_HERE',
    // ...
};

const SPLUNK_CONFIG = {
    baseUrl: 'https://your-splunk.com',
    dashboardPath: '/en-US/app/...',
    healthDashboardPath: 'Health_dashboard',  // UPDATE THIS
    // ...
};
```

3. Commit and push all changes
