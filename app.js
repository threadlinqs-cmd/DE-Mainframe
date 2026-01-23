// =============================================================================
// DE-MAINFRAME V11.15 - Detection Engineering MainFrame
// =============================================================================
// 
// CONFIGURATION INSTRUCTIONS:
// ==========================
// Update the values in GITHUB_CONFIG and SPLUNK_CONFIG below with your 
// environment settings. These are the ONLY values you need to change.
//
// EXAMPLE for your setup:
//   GitHub URL: https://mygithub.myenterprise/Security/Splunk/blob/DE-MainFrame-Branch/docs/app.js
//   Splunk URL: https://myorg.splunkcloud.com/en-US/app/SplunkEnterpriseSecuritySuite/my_dashboard
//
// =============================================================================

// =============================================================================
// ⚙️ GITHUB CONFIGURATION - UPDATE THESE VALUES
// =============================================================================

const GITHUB_CONFIG = {
    // Your GitHub URL (no trailing slash, no /api/v3)
    // For github.com use: 'https://github.com'
    // For Enterprise use: 'https://github.yourcompany.com'
    baseUrl: 'https://github.com',

    // Repository in format 'owner/repo' or 'org/repo'
    // Example: 'Security/Splunk' or 'myusername/my-detections'
    repo: 'YOUR_USERNAME/YOUR_REPO',

    // Branch name
    // Example: 'main' or 'DE-MainFrame-Branch'
    branch: 'main',

    // Personal Access Token with repo read/write permissions
    // Generate at: https://github.com/settings/tokens
    // Required scopes: repo (full control of private repositories)
    token: 'YOUR_GITHUB_PAT',
    
    // Base path where all DE-MainFrame files live (leave empty if at repo root)
    // Example: 'docs' if your files are in /docs/ folder
    // Example: '' if your files are at repo root
    basePath: 'docs',
    
    // Subfolder names (relative to basePath)
    detectionsFolder: 'detections',
    metadataFolder: 'metadata',
    distFolder: 'dist'
};

// =============================================================================
// ⚙️ SPLUNK CONFIGURATION - UPDATE THESE VALUES
// =============================================================================

const SPLUNK_CONFIG = {
    // Your Splunk Cloud base URL (no trailing slash)
    // Example: 'https://myorg.splunkcloud.com'
    baseUrl: 'https://myorg.splunkcloud.com',
    
    // The full path to your revalidation dashboard
    // Example: '/en-US/app/SplunkEnterpriseSecuritySuite/enhanced_use_case_revalidation_dashboard_copy'
    dashboardPath: '/en-US/app/SplunkEnterpriseSecuritySuite/enhanced_use_case_revalidation_dashboard_copy',
    
    // The path to UC Health Dashboard (placeholder - update with your actual path)
    healthDashboardPath: 'Health_dashboard',
    
    // The path to correlation search editor
    correlationSearchPath: '/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit',
    
    // Default time range for the dashboard
    // Format: earliest and latest values
    defaultTimeEarliest: '-90d@d',
    defaultTimeLatest: 'now',
    
    // The form field name for the detection/use case input
    // This matches form.usecase in your dashboard URL
    useCaseFieldName: 'usecase',
    
    // Popup window dimensions
    popupWidth: 1400,
    popupHeight: 900
};

// =============================================================================
// ⚙️ ACCESS PASSWORD - UPDATE THIS VALUE
// =============================================================================

const ACCESS_PASSWORD = 'secmon2026';

// =============================================================================
// COMPUTED PATHS AND HELPER FUNCTIONS
// =============================================================================

// Computed paths (don't edit these)
const PATHS = {
    detections: GITHUB_CONFIG.basePath ? GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.detectionsFolder : GITHUB_CONFIG.detectionsFolder,
    metadata: GITHUB_CONFIG.basePath ? GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.metadataFolder : GITHUB_CONFIG.metadataFolder,
    dist: GITHUB_CONFIG.basePath ? GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.distFolder : GITHUB_CONFIG.distFolder
};

// Security domains that may be prepended to detection names
const SECURITY_DOMAINS = ['Access', 'Endpoint', 'Network', 'Threat', 'Identity', 'Audit'];

/**
 * Strip Security Domain prefix and "-Rule" suffix from detection name
 * Example: "Access - LNX-T1040 - Network Sniffing Using Promiscuous Mode - Rule"
 *       → "LNX-T1040 - Network Sniffing Using Promiscuous Mode"
 */
function stripForRevalidation(detectionName) {
    if (!detectionName) return '';
    var name = detectionName;
    
    // Strip Security Domain prefix (e.g., "Access - ", "Endpoint - ")
    for (var i = 0; i < SECURITY_DOMAINS.length; i++) {
        var prefix = SECURITY_DOMAINS[i] + ' - ';
        if (name.startsWith(prefix)) {
            name = name.substring(prefix.length);
            break;
        }
    }
    
    // Strip " - Rule" suffix
    if (name.endsWith(' - Rule')) {
        name = name.substring(0, name.length - 7);
    }
    
    return name;
}

/**
 * Normalize detection name to ensure proper spacing around separators
 * Fixes cases like "Access -LNX" → "Access - LNX"
 */
function normalizeDetectionName(detectionName) {
    if (!detectionName) return '';
    // Ensure " - " has spaces on both sides (fix "- " or " -" patterns)
    return detectionName
        .replace(/ -([^ ])/g, ' - $1')  // " -X" → " - X"
        .replace(/([^ ])- /g, '$1 - ')  // "X- " → "X - "
        .replace(/  +/g, ' ');          // collapse multiple spaces
}

/**
 * Return full detection name for correlation search (no stripping, with normalization)
 * Example: "Access - LNX-T1040 - Network Sniffing Using Promiscuous Mode - Rule"
 *       → "Access - LNX-T1040 - Network Sniffing Using Promiscuous Mode - Rule"
 */
function stripForCorrelationSearch(detectionName) {
    return normalizeDetectionName(detectionName);
}

// Build Splunk Revalidation Dashboard URL (strips domain and "-Rule")
function buildSplunkDashboardUrl(detectionName) {
    var strippedName = stripForRevalidation(detectionName);
    var url = SPLUNK_CONFIG.baseUrl + SPLUNK_CONFIG.dashboardPath;
    url += '?form.timerange.earliest=' + encodeURIComponent(SPLUNK_CONFIG.defaultTimeEarliest);
    url += '&form.timerange.latest=' + encodeURIComponent(SPLUNK_CONFIG.defaultTimeLatest);
    url += '&form.' + SPLUNK_CONFIG.useCaseFieldName + '=' + encodeURIComponent(strippedName);
    return url;
}

// Build Correlation Search Editor URL (full detection name, properly encoded)
function buildCorrelationSearchUrl(detectionName) {
    var fullName = stripForCorrelationSearch(detectionName);
    var url = SPLUNK_CONFIG.baseUrl + SPLUNK_CONFIG.correlationSearchPath;
    url += '?search=' + encodeURIComponent(fullName);
    return url;
}

// Open URL in popup window
function openSplunkPopup(url, title) {
    var width = SPLUNK_CONFIG.popupWidth;
    var height = SPLUNK_CONFIG.popupHeight;
    var left = (screen.width - width) / 2;
    var top = (screen.height - height) / 2;
    var features = 'width=' + width + ',height=' + height + ',left=' + left + ',top=' + top;
    features += ',menubar=no,toolbar=no,location=yes,status=yes,resizable=yes,scrollbars=yes';
    window.open(url, title || 'SplunkDashboard', features);
}

// =============================================================================
// END OF CONFIGURATION
// =============================================================================

// =============================================================================
// STATE MANAGEMENT
// =============================================================================

let detections = [];
let filteredDetections = [];
let currentDetection = null;
let selectedLibraryDetection = null;
let selectedHistoryDetection = null;
let detectionMetadata = {};
let resources = []; // Resources for the Resources tab
let resourceCategories = ['Dashboard', 'external url', 'internal url'];
let loadedMacros = []; // Loaded macros for validation
let parsingRules = [];
let hasUnsavedChanges = false;
let darkMode = true;
let editMode = null; // null, 'tune', or 'retrofit'
let isLoading = false;

// Legacy config object for compatibility with existing code
let githubConfig = {
    baseUrl: GITHUB_CONFIG.baseUrl,
    repo: GITHUB_CONFIG.repo,
    branch: GITHUB_CONFIG.branch,
    token: GITHUB_CONFIG.token,
    detectionsPath: PATHS.detections,
    metadataPath: PATHS.metadata,
    connected: false,
    lastSyncHash: null
};

const DEFAULT_PARSING_RULES = [
    { field: 'index', value: 'azure_cloud|O365', category: 'datasource', tag: 'Microsoft Defender' },
    { field: 'index', value: 'netskope', category: 'datasource', tag: 'Netskope' },
    { field: 'index', value: 'windows', category: 'datasource', tag: 'Windows Events' },
    { field: 'index', value: 'rsa', category: 'datasource', tag: 'RSA SecurID' },
    { field: 'sourcetype', value: 'XmlWinEventLog.*Sysmon', category: 'datasource', tag: 'Sysmon' },
    { field: 'sourcetype', value: 'rsa:securid', category: 'datasource', tag: 'RSA SecurID' },
    { field: 'EventCode', value: '1|3|7|10|11|22', category: 'technology', tag: 'Sysmon Events' }
];

const DETECTION_TEMPLATE = {
    "schema_version": "1.2", "file_name": "",
    "Roles": [
        { "Role": "Requestor", "Name": "", "Title": "" },
        { "Role": "Business Owner", "Name": "", "Title": "" },
        { "Role": "Technical Owner", "Name": "", "Title": "" }
    ],
    "Description": "", "Assumptions": "", "origin": "custom",
    "Detection Name": "", "Objective": "", "Severity/Priority": "",
    "Analyst Next Steps": "", "Blind_Spots_False_Positives": "",
    "Required_Data_Sources": "", "First Created": null, "Last Modified": null,
    "Search String": "", "Splunk_App_Context": "", "Search_Duration": "",
    "Cron Schedule": "", "Schedule Window": "", "Schedule Priority": "",
    "Trigger Condition": "", 
    "Throttling": { "enabled": 0, "fields": "", "period": "" },
    "Risk": [{ "risk_object_field": "", "risk_object_type": "user", "risk_score": 0 }],
    "Notable Title": "", "Notable Description": "", "Security Domain": "",
    "Drilldown Name (Legacy)": "", "Drilldown Search (Legacy)": "",
    "Drilldown Earliest Offset (Legacy)": null, "Drilldown Latest Offset (Legacy)": null,
    "Mitre ID": []
};

for (let i = 1; i <= 15; i++) {
    DETECTION_TEMPLATE["Drilldown Name " + i] = "";
    DETECTION_TEMPLATE["Drilldown Search " + i] = "";
    DETECTION_TEMPLATE["Drilldown Earliest " + i] = null;
    DETECTION_TEMPLATE["Drilldown Latest " + i] = null;
}

// Add Proposed Test Plan at the end
DETECTION_TEMPLATE["Proposed Test Plan"] = "";

const MANDATORY_FIELDS = [
    'Detection Name', 'Objective', 'Severity/Priority', 'Analyst Next Steps',
    'Blind_Spots_False_Positives', 'Required_Data_Sources', 'Search String',
    'Risk', 'Notable Title'
];

const KEY_FIELDS = [
    'Description', 'Assumptions', 'Security Domain', 'Cron Schedule',
    'Trigger Condition', 'Notable Description', 'Mitre ID', 'Drilldowns', 
    'Throttling', 'Roles'
];

const FIELD_LABELS = {
    'Detection Name': 'Detection Name', 'Objective': 'Objective',
    'Severity/Priority': 'Severity', 'Analyst Next Steps': 'Analyst Next Steps',
    'Blind_Spots_False_Positives': 'Blind Spots', 'Required_Data_Sources': 'Data Sources',
    'Search String': 'Search String', 'Risk': 'Risk',
    'Notable Title': 'Notable Title', 'Description': 'Description',
    'Assumptions': 'Assumptions', 'Security Domain': 'Domain',
    'Cron Schedule': 'Cron Schedule', 'Mitre ID': 'MITRE IDs',
    'Drilldowns': 'Drilldowns', 'Throttling': 'Throttling', 'Roles': 'Roles',
    'Trigger Condition': 'Trigger', 'Notable Description': 'Notable Desc'
};

// =============================================================================
// V11.15 RISK & THROTTLING HELPERS (backward compatible)
// =============================================================================

/**
 * Get risk score from detection - supports both old and new formats
 * Old format: d['Risk Score'] = 50
 * New format: d['Risk'] = [{ risk_score: 50, ... }]
 */
function getRiskScore(d) {
    if (!d) return 0;
    // New format (array)
    if (Array.isArray(d['Risk']) && d['Risk'].length > 0) {
        return parseInt(d['Risk'][0].risk_score) || 0;
    }
    // Old format (flat)
    if (d['Risk Score'] !== undefined) {
        return parseInt(d['Risk Score']) || 0;
    }
    return 0;
}

/**
 * Get risk object field - supports both old and new formats
 */
function getRiskObjectField(d) {
    if (!d) return '';
    if (Array.isArray(d['Risk']) && d['Risk'].length > 0) {
        return d['Risk'][0].risk_object_field || '';
    }
    return d['Risk Object Field'] || '';
}

/**
 * Get risk object type - supports both old and new formats
 */
function getRiskObjectType(d) {
    if (!d) return '';
    if (Array.isArray(d['Risk']) && d['Risk'].length > 0) {
        return d['Risk'][0].risk_object_type || '';
    }
    return d['Risk Object Type'] || '';
}

/**
 * Get all risk entries (for multiple risk objects)
 */
function getRiskEntries(d) {
    if (!d) return [];
    if (Array.isArray(d['Risk'])) {
        return d['Risk'].filter(function(r) { return r && (r.risk_score || r.risk_object_field); });
    }
    // Convert old format to new
    if (d['Risk Score'] || d['Risk Object Field']) {
        return [{
            risk_object_field: d['Risk Object Field'] || '',
            risk_object_type: d['Risk Object Type'] || 'user',
            risk_score: parseInt(d['Risk Score']) || 0
        }];
    }
    return [];
}

/**
 * Get throttling config - supports both old and new formats
 */
function getThrottling(d) {
    if (!d) return { enabled: 0, fields: '', period: '' };
    if (typeof d['Throttling'] === 'object' && d['Throttling'] !== null) {
        return {
            enabled: d['Throttling'].enabled || 0,
            fields: d['Throttling'].fields || '',
            period: d['Throttling'].period || ''
        };
    }
    // Old string format
    if (typeof d['Throttling'] === 'string') {
        return { enabled: d['Throttling'] ? 1 : 0, fields: '', period: '' };
    }
    return { enabled: 0, fields: '', period: '' };
}

/**
 * Check if risk is valid (has at least one risk entry with score)
 */
function hasValidRisk(d) {
    var entries = getRiskEntries(d);
    return entries.length > 0 && entries.some(function(r) { return r.risk_score > 0; });
}

// =============================================================================
// V10 TTL UTILITIES (pure helper functions, no side effects)
// =============================================================================

const TTL_DAYS = 365;

function calculateTTL(lastModified) {
    if (!lastModified) return { days: TTL_DAYS, expired: false };
    var modified = new Date(lastModified);
    var expiry = new Date(modified);
    expiry.setDate(expiry.getDate() + TTL_DAYS);
    var days = Math.ceil((expiry - new Date()) / (1000 * 60 * 60 * 24));
    return { days: Math.max(0, days), expired: days <= 0 };
}

function getTTLClass(days) {
    if (days <= 0) return 'ttl-expired';
    if (days <= 30) return 'ttl-critical';
    if (days <= 90) return 'ttl-warning';
    return 'ttl-ok';
}

// =============================================================================
// GITHUB API CLIENT
// =============================================================================

class GitHubAPI {
    constructor(config) {
        this.config = config;
    }
    
    getApiUrl() {
        let base = this.config.baseUrl.replace(/\/+$/, '');
        if (!base || base === 'https://github.com' || base === 'http://github.com') {
            return 'https://api.github.com';
        }
        base = base.replace(/\/api\/v3\/?$/, '');
        if (!base.includes('api.github.com')) {
            return base + '/api/v3';
        }
        return base;
    }
    
    sanitizePath(path) {
        if (!path) return '';
        const urlMatch = path.match(/\/tree\/[^\/]+\/(.+)$/);
        if (urlMatch) path = urlMatch[1];
        const blobMatch = path.match(/\/blob\/[^\/]+\/(.+)$/);
        if (blobMatch) path = blobMatch[1];
        path = path.replace(/^https?:\/\/[^\/]+\//, '');
        return path.replace(/^\/+|\/+$/g, '');
    }
    
    async request(endpoint, options, suppressErrorLog) {
        options = options || {};
        const apiUrl = this.getApiUrl();
        const url = apiUrl + '/repos/' + this.config.repo + endpoint;

        console.log('GitHub API Request:', options.method || 'GET', url);

        // Build headers - only include Authorization if we have a valid token
        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        };

        const token = this.config.token;
        if (token && token !== 'YOUR_GITHUB_PAT' && token.length > 10) {
            headers['Authorization'] = 'token ' + token;
        } else {
            console.warn('GitHubAPI: No valid token configured for request to', endpoint);
        }

        const response = await fetch(url, Object.assign({}, options, { headers: headers }));
        
        if (!response.ok) {
            const error = await response.json().catch(function() { return {}; });
            // Only log error if not suppressed (used for expected 404s on new file checks)
            if (!suppressErrorLog) {
                console.error('GitHub API Error:', response.status, error);
            }
            // Include status code in error message for better handling
            throw new Error((error.message || 'GitHub API error') + ' (HTTP ' + response.status + ')');
        }
        
        return response.json();
    }
    
    async testConnection() {
        try {
            await this.request('');
            return { success: true, message: 'Connected successfully!' };
        } catch (error) {
            return { success: false, message: error.message };
        }
    }
    
    async listFiles(path) {
        try {
            const cleanPath = this.sanitizePath(path);
            const data = await this.request('/contents/' + cleanPath + '?ref=' + this.config.branch);
            return Array.isArray(data) ? data : [];
        } catch (error) {
            if (error.message.includes('404')) return [];
            throw error;
        }
    }
    
    async getFile(path) {
        try {
            const cleanPath = this.sanitizePath(path);
            const data = await this.request('/contents/' + cleanPath + '?ref=' + this.config.branch);
            const content = atob(data.content.replace(/\n/g, ''));
            return { content: JSON.parse(content), sha: data.sha };
        } catch (error) {
            if (error.message.includes('404')) return null;
            throw error;
        }
    }
    
    async getTreeHash(path) {
        try {
            const cleanPath = this.sanitizePath(path);
            const data = await this.request('/contents/' + cleanPath + '?ref=' + this.config.branch);
            if (Array.isArray(data)) {
                // Create hash from file shas
                return data.map(function(f) { return f.sha; }).sort().join('');
            }
            return data.sha;
        } catch (error) {
            return null;
        }
    }
    
    async getFileSha(path) {
        const cleanPath = this.sanitizePath(path);
        console.log('getFileSha: Checking path:', cleanPath);
        
        try {
            // Pass true to suppress error logging for expected 404s
            const data = await this.request('/contents/' + cleanPath + '?ref=' + this.config.branch, {}, true);
            
            if (data && data.sha) {
                console.log('getFileSha: Found SHA:', data.sha.substring(0, 8) + '...');
                return data.sha;
            } else {
                console.log('getFileSha: Response has no SHA property:', Object.keys(data || {}));
                return null;
            }
        } catch (error) {
            // Check if it's a 404 (file doesn't exist) - that's OK
            if (error.message && (error.message.includes('404') || error.message.includes('Not Found'))) {
                console.log('getFileSha: File not found (404), will create new');
                return null;
            }
            // Any other error should be reported
            console.error('getFileSha: Error:', error.message);
            throw error;
        }
    }
    
    async createOrUpdateFile(path, content, message, sha) {
        const cleanPath = this.sanitizePath(path);
        const body = {
            message: message,
            content: btoa(unescape(encodeURIComponent(JSON.stringify(content, null, 2)))),
            branch: this.config.branch
        };
        
        // SHA is REQUIRED when updating an existing file
        if (sha) {
            body.sha = sha;
            console.log('Updating existing file:', cleanPath, 'with SHA:', sha.substring(0, 8) + '...');
        } else {
            console.log('Creating new file:', cleanPath);
        }
        
        return this.request('/contents/' + cleanPath, {
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }
    
    async deleteFile(path, message, sha) {
        const cleanPath = this.sanitizePath(path);
        return this.request('/contents/' + cleanPath, {
            method: 'DELETE',
            body: JSON.stringify({
                message: message,
                sha: sha,
                branch: this.config.branch
            })
        });
    }
}

let github = null;

// =============================================================================
// INITIALIZATION - NO AUTO-SYNC
// =============================================================================

document.addEventListener('DOMContentLoaded', function() {
    // Check for password authentication
    checkPasswordAccess();
});

function checkPasswordAccess() {
    // Check if already authenticated this session
    var authenticated = sessionStorage.getItem('dmf_authenticated');
    if (authenticated === 'true') {
        initializeApp();
        return;
    }
    
    // Show password modal
    showPasswordModal();
}

function showPasswordModal() {
    var modal = document.getElementById('modal-password');
    if (modal) {
        modal.classList.remove('hidden');
        var input = document.getElementById('password-input');
        if (input) {
            input.focus();
            input.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    validatePassword();
                }
            });
        }
    }
}

function validatePassword() {
    var input = document.getElementById('password-input');
    var error = document.getElementById('password-error');
    var enteredPassword = input ? input.value : '';
    
    if (enteredPassword === ACCESS_PASSWORD) {
        // Store authentication in session
        sessionStorage.setItem('dmf_authenticated', 'true');
        
        // Hide modal and start app
        var modal = document.getElementById('modal-password');
        if (modal) modal.classList.add('hidden');
        
        initializeApp();
    } else {
        // Show error
        if (error) {
            error.textContent = 'Incorrect password. Please try again.';
            error.classList.remove('hidden');
        }
        if (input) {
            input.value = '';
            input.focus();
        }
    }
}

function initializeApp() {
    initBootScreen();
    loadTheme();
    loadParsingRules();
    loadGitHubConfig();  // Load saved GitHub config from localStorage before API calls
    autoLoadFromStaticFiles();
}

function initBootScreen() {
    const bootScreen = document.getElementById('boot-screen');
    const bootStatus = document.getElementById('boot-status');
    
    if (bootStatus) bootStatus.textContent = 'Connecting to repository...';
}

function loadParsingRules() {
    const savedRules = localStorage.getItem('dmf_parsing_rules');
    if (savedRules) {
        try { parsingRules = JSON.parse(savedRules); }
        catch (e) { parsingRules = DEFAULT_PARSING_RULES.slice(); }
    } else {
        parsingRules = DEFAULT_PARSING_RULES.slice();
    }
}

function loadTheme() {
    const savedTheme = localStorage.getItem('dmf_dark_mode');
    darkMode = savedTheme !== 'false';
    applyTheme();
}

function applyTheme() {
    document.body.classList.toggle('light-mode', !darkMode);
    const themeBtn = document.getElementById('btn-theme');
    if (themeBtn) {
        themeBtn.innerHTML = darkMode ? '☀️' : '🌙';
        themeBtn.title = darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode';
    }
}

function toggleTheme() {
    darkMode = !darkMode;
    localStorage.setItem('dmf_dark_mode', darkMode);
    applyTheme();
    showToast(darkMode ? 'Dark mode enabled' : 'Light mode enabled', 'info');
}

// =============================================================================
// V11.15 GITHUB ENTERPRISE API HELPERS
// =============================================================================

/**
 * Build the GitHub API URL for fetching file contents
 * Handles both github.com and GitHub Enterprise
 * Format: https://api.github.com/repos/<owner>/<repo>/contents/<path>?ref=<branch>
 * Or: https://<enterprise>/api/v3/repos/<owner>/<repo>/contents/<path>?ref=<branch>
 */
function buildApiUrl(filePath) {
    // Use dynamic config (from Settings/localStorage) with fallback to hardcoded
    var baseUrl = (githubConfig.baseUrl || GITHUB_CONFIG.baseUrl).replace(/\/+$/, '');
    var repo = githubConfig.repo || GITHUB_CONFIG.repo;
    var branch = githubConfig.branch || GITHUB_CONFIG.branch;

    var apiUrl;
    if (!baseUrl || baseUrl === 'https://github.com' || baseUrl === 'http://github.com') {
        apiUrl = 'https://api.github.com';
    } else {
        apiUrl = baseUrl + '/api/v3';
    }
    return apiUrl + '/repos/' + repo + '/contents/' + filePath + '?ref=' + branch;
}

/**
 * Fetch a JSON file from GitHub Enterprise using the Contents API
 * Uses Accept header to get raw content directly
 */
function fetchGitHubFile(filePath) {
    var url = buildApiUrl(filePath);
    console.log('Fetching:', url);

    // Use dynamic config (from Settings/localStorage) with fallback to hardcoded
    var token = githubConfig.token || GITHUB_CONFIG.token;

    // Build headers - only include Authorization if we have a valid token
    // Sending invalid/placeholder tokens causes 401 errors even for public repos
    var headers = {
        'Accept': 'application/vnd.github.v3.raw'  // Get raw content, not base64
    };

    if (token && token !== 'YOUR_GITHUB_PAT' && token.length > 10) {
        headers['Authorization'] = 'token ' + token;
        console.log('  Using token authentication');
    } else {
        console.warn('%c⚠️ No valid token - attempting unauthenticated access (public repos only)', 'color: #f1fa8c');
    }

    return fetch(url, {
        method: 'GET',
        headers: headers,
        cache: 'no-store'
    })
    .then(function(response) {
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ' fetching ' + filePath);
        }
        return response.text().then(function(text) {
            if (!text || text.trim() === '') {
                console.warn('Empty file received:', filePath);
                return null;
            }
            try {
                return JSON.parse(text);
            } catch (e) {
                console.warn('Invalid JSON in file:', filePath, e.message);
                return null;
            }
        });
    });
}

// =============================================================================
// V11.15 AUTO-LOAD FROM COMPILED FILES
// =============================================================================

function autoLoadFromStaticFiles() {
    const bootStatus = document.getElementById('boot-status');
    const bootScreen = document.getElementById('boot-screen');
    const app = document.getElementById('app');
    
    isLoading = true;
    if (bootStatus) bootStatus.textContent = 'Loading detections...';
    
    // Initialize GitHub API for writes - use dynamic githubConfig (from localStorage) with fallbacks
    github = new GitHubAPI({
        baseUrl: githubConfig.baseUrl || GITHUB_CONFIG.baseUrl,
        repo: githubConfig.repo || GITHUB_CONFIG.repo,
        branch: githubConfig.branch || GITHUB_CONFIG.branch,
        token: githubConfig.token || GITHUB_CONFIG.token,
        detectionsPath: PATHS.detections,
        metadataPath: PATHS.metadata
    });
    githubConfig.connected = true;
    
    // Build file paths
    var detectionsFile = PATHS.dist + '/all-detections.json';
    var metadataFile = PATHS.dist + '/all-metadata.json';
    var resourcesFile = PATHS.dist + '/resources.json';
    var macrosFile = PATHS.dist + '/macros.json';

    console.log('Loading from:', detectionsFile, metadataFile, resourcesFile, macrosFile);

    // Fetch all files in parallel
    Promise.all([
        fetchGitHubFile(detectionsFile),
        fetchGitHubFile(metadataFile),
        fetchGitHubFile(resourcesFile).catch(function() { return []; }), // Resources optional
        fetchGitHubFile(macrosFile).catch(function() { return []; }) // Macros optional
    ])
    .then(function(results) {
        var detectionsData = results[0];
        var metadataData = results[1];
        var resourcesData = results[2];
        var macrosData = results[3];

        if (bootStatus) bootStatus.textContent = 'Processing data...';
        
        // Load detections
        if (Array.isArray(detectionsData) && detectionsData.length > 0) {
            detections = detectionsData;
            filteredDetections = detections.slice();
            console.log('✓ Loaded ' + detections.length + ' detections');
        } else {
            if (detectionsData === null) {
                console.warn('No detections data (empty or invalid file), falling back to cache');
            } else if (Array.isArray(detectionsData) && detectionsData.length === 0) {
                console.warn('Detections file is empty array');
            } else {
                console.warn('Invalid detections data format');
            }
            detections = [];
            filteredDetections = [];
        }

        // Load metadata
        if (metadataData && typeof metadataData === 'object' && Object.keys(metadataData).length > 0) {
            detectionMetadata = metadataData;
            console.log('✓ Loaded metadata for ' + Object.keys(metadataData).length + ' detections');
        } else {
            if (metadataData === null) {
                console.warn('No metadata data (empty or invalid file), falling back to cache');
            } else {
                console.warn('Invalid or empty metadata data');
            }
            detectionMetadata = {};
        }
        
        // Load resources
        if (Array.isArray(resourcesData)) {
            resources = resourcesData;
            console.log('✓ Loaded ' + resources.length + ' resources');
        } else {
            console.warn('No resources found, using defaults');
            resources = getDefaultResources();
        }

        // Load macros for validation
        if (Array.isArray(macrosData)) {
            loadedMacros = macrosData;
            console.log('✓ Loaded ' + loadedMacros.length + ' macros for validation');
        } else {
            console.warn('No macros found, macro validation will flag all macros as missing');
            loadedMacros = [];
        }

        // Cache locally for offline access
        saveToLocalStorage();
        
        if (bootStatus) bootStatus.textContent = 'Initializing interface...';
        
        // Complete boot sequence
        setTimeout(function() {
            bootScreen.style.opacity = '0';
            bootScreen.style.transition = 'opacity 0.5s';
            setTimeout(function() {
                bootScreen.classList.add('hidden');
                app.classList.remove('hidden');
                isLoading = false;
                initUI();
                updateSyncStatus('synced', 'Loaded');
                showToast('Loaded ' + detections.length + ' detections', 'success');
            }, 500);
        }, 300);
    })
    .catch(function(error) {
        console.error('Failed to load from repository:', error);
        if (bootStatus) bootStatus.textContent = 'Loading from cache...';
        
        // Fallback to localStorage cache
        loadFromLocalStorage();
        
        setTimeout(function() {
            bootScreen.style.opacity = '0';
            bootScreen.style.transition = 'opacity 0.5s';
            setTimeout(function() {
                bootScreen.classList.add('hidden');
                app.classList.remove('hidden');
                isLoading = false;
                initUI();
                updateSyncStatus('error', 'Offline Mode');
                
                if (detections.length > 0) {
                    showToast('Using cached data (' + detections.length + ' detections)', 'warning');
                } else {
                    showToast('Could not load data. Check configuration and run compile_detections.py first.', 'error');
                }
            }, 500);
        }, 300);
    });
}

function sanitizePathInput(path) {
    if (!path) return '';
    const urlMatch = path.match(/\/tree\/[^\/]+\/(.+)$/);
    if (urlMatch) return urlMatch[1];
    const blobMatch = path.match(/\/blob\/[^\/]+\/(.+)$/);
    if (blobMatch) return blobMatch[1];
    path = path.replace(/^https?:\/\/[^\/]+\//, '');
    return path.replace(/^\/+|\/+$/g, '');
}

// Check if remote has changes (non-blocking)
async function checkForRemoteChanges() {
    if (!github) return;
    
    try {
        const detectionsPath = sanitizePathInput(githubConfig.detectionsPath) || 'detections';
        const currentHash = await github.getTreeHash(detectionsPath);
        
        if (currentHash && githubConfig.lastSyncHash && currentHash !== githubConfig.lastSyncHash) {
            updateSyncStatus('warning', 'Changes Available');
            showToast('Remote changes detected. Click Sync to update.', 'info');
        }
    } catch (e) {
        console.log('Could not check for remote changes:', e.message);
    }
}

function loadFromLocalStorage() {
    const storedDetections = localStorage.getItem('dmf_detections');
    if (storedDetections) {
        try { detections = JSON.parse(storedDetections); } catch (e) { detections = []; }
    }

    const storedMetadata = localStorage.getItem('dmf_metadata');
    if (storedMetadata) {
        try { detectionMetadata = JSON.parse(storedMetadata); } catch (e) { detectionMetadata = {}; }
    }

    const storedMacros = localStorage.getItem('dmf_macros');
    if (storedMacros) {
        try { loadedMacros = JSON.parse(storedMacros); } catch (e) { loadedMacros = []; }
    }

    filteredDetections = detections.slice();
    console.log('%c⚡ Loaded ' + detections.length + ' detections from cache', 'color: #50fa7b');
}

function loadGitHubConfig() {
    const savedConfig = localStorage.getItem('dmf_github_config');
    if (savedConfig) {
        try {
            const parsed = JSON.parse(savedConfig);
            // Merge saved config into githubConfig (preserving any new fields from GITHUB_CONFIG)
            githubConfig = Object.assign({}, githubConfig, parsed);
            console.log('%c⚡ Loaded GitHub config from localStorage', 'color: #50fa7b');
            console.log('  Config loaded - repo:', githubConfig.repo, 'branch:', githubConfig.branch, 'token present:', !!githubConfig.token && githubConfig.token !== 'YOUR_GITHUB_PAT');
        } catch (e) {
            console.warn('Could not parse saved GitHub config:', e);
        }
    } else {
        console.log('%c⚠️ No saved GitHub config found in localStorage', 'color: #f1fa8c');
    }
}

function saveToLocalStorage() {
    localStorage.setItem('dmf_detections', JSON.stringify(detections));
    localStorage.setItem('dmf_metadata', JSON.stringify(detectionMetadata));
    localStorage.setItem('dmf_parsing_rules', JSON.stringify(parsingRules));
    localStorage.setItem('dmf_github_config', JSON.stringify(githubConfig));
    localStorage.setItem('dmf_macros', JSON.stringify(loadedMacros));
}

function initUI() {
    initNavigation();
    initEditor();
    initLibrary();
    initConfig();
    initRevalidation();
    initHistory();
    initResources();
    initMacros();
    initReportsTabs();
    initModals();
    initSettings();
    initKeyboardShortcuts();
    
    renderDashboard();
    renderLibrary();
}

function updateSyncStatus(status, text) {
    const el = document.getElementById('sync-status');
    el.className = 'sync-status ' + status;
    el.querySelector('.sync-text').textContent = text;
}

// =============================================================================
// GITHUB OPERATIONS - MANUAL SYNC ONLY
// =============================================================================

async function syncWithGitHub() {
    if (!github) {
        openSettingsModal();
        return;
    }
    
    try {
        updateSyncStatus('syncing', 'Syncing...');
        showToast('Syncing with GitHub...', 'info');
        
        const detectionsPath = sanitizePathInput(githubConfig.detectionsPath) || 'detections';
        const metadataPath = sanitizePathInput(githubConfig.metadataPath) || 'metadata';
        
        // Get current tree hash for change detection
        const newHash = await github.getTreeHash(detectionsPath);
        
        const detectionFiles = await github.listFiles(detectionsPath);
        const jsonFiles = detectionFiles.filter(function(f) { return f.name.endsWith('.json'); });
        
        console.log('Found ' + jsonFiles.length + ' detection files');
        
        detections = [];
        for (let i = 0; i < jsonFiles.length; i++) {
            const file = jsonFiles[i];
            try {
                const result = await github.getFile(detectionsPath + '/' + file.name);
                if (result && result.content) {
                    result.content._sha = result.sha;
                    result.content._path = detectionsPath + '/' + file.name;
                    result.content.file_name = file.name;
                    detections.push(result.content);
                }
            } catch (e) {
                console.warn('Failed to load ' + file.name + ':', e);
            }
        }
        
        // Load metadata
        detectionMetadata = {};
        const metadataFiles = await github.listFiles(metadataPath);
        const metaJsonFiles = metadataFiles.filter(function(f) { return f.name.endsWith('.json'); });
        
        for (let i = 0; i < metaJsonFiles.length; i++) {
            const file = metaJsonFiles[i];
            try {
                const result = await github.getFile(metadataPath + '/' + file.name);
                if (result && result.content && result.content.detectionName) {
                    result.content._sha = result.sha;
                    result.content._path = metadataPath + '/' + file.name;
                    detectionMetadata[result.content.detectionName] = result.content;
                }
            } catch (e) {}
        }
        
        // Auto-create metadata for detections without it
        let metadataCreated = 0;
        for (let i = 0; i < detections.length; i++) {
            const detection = detections[i];
            const name = detection['Detection Name'];
            if (name && !detectionMetadata[name]) {
                const newMeta = createMetadataForDetection(detection);
                detectionMetadata[name] = newMeta;
                
                try {
                    const filename = generateMetaFileName(name, detection.file_name);
                    const path = metadataPath + '/' + filename;

                    // Check if file already exists and get its SHA
                    const existingSha = await github.getFileSha(path);

                    const result = await github.createOrUpdateFile(path, newMeta, 'Auto-generate metadata: ' + name, existingSha);
                    newMeta._sha = result.content.sha;
                    newMeta._path = path;
                    metadataCreated++;
                } catch (e) {
                    console.warn('Failed to create metadata for ' + name + ':', e);
                }
            }
        }
        
        // Save sync state
        githubConfig.lastSyncHash = newHash;
        githubConfig.connected = true;
        saveToLocalStorage();
        
        filteredDetections = detections.slice();
        buildDynamicFilters();
        renderDashboard();
        renderLibrary();

        // Update compiled files so other users see the synced data
        try {
            await updateCompiledFiles();
        } catch (compileError) {
            console.warn('Could not update compiled files:', compileError.message);
        }

        updateSyncStatus('connected', 'Synced');
        showToast('Synced ' + detections.length + ' detections' + (metadataCreated ? ', created ' + metadataCreated + ' metadata files' : ''), 'success');
        
    } catch (error) {
        console.error('Sync error:', error);
        updateSyncStatus('error', 'Sync Error');
        showToast('Sync failed: ' + error.message, 'error');
    }
}

function createMetadataForDetection(detection) {
    return {
        detectionName: detection['Detection Name'],
        history: [{ id: Date.now(), type: 'version', description: 'Initial import', timestamp: new Date().toISOString() }],
        parsed: parseSPL(detection['Search String']),
        drilldownVars: parseDrilldownVariables(detection),
        lastParsed: new Date().toISOString(),
        needsTune: false,
        needsRetrofit: false
    };
}

async function saveDetectionToGitHub(detection) {
    if (!github) {
        showToast('Not connected to GitHub. Configure in Settings.', 'warning');
        return false;
    }
    
    try {
        updateSyncStatus('syncing', 'Saving...');
        
        const detectionsPath = sanitizePathInput(githubConfig.detectionsPath) || 'detections';
        const filename = detection.file_name || generateFileName(detection['Detection Name'], detection['Security Domain']);
        const path = detectionsPath + '/' + filename;
        const message = 'Update detection: ' + detection['Detection Name'];
        
        let sha = null;
        for (let i = 0; i < detections.length; i++) {
            if (detections[i]['Detection Name'] === detection['Detection Name']) {
                sha = detections[i]._sha;
                break;
            }
        }
        
        // If no SHA cached, check if file exists on GitHub
        if (!sha) {
            sha = await github.getFileSha(path);
        }
        
        const result = await github.createOrUpdateFile(path, detection, message, sha);
        
        detection._sha = result.content.sha;
        detection._path = path;
        detection.file_name = filename;
        
        updateSyncStatus('connected', 'Synced');
        return true;
    } catch (error) {
        updateSyncStatus('error', 'Save Error');
        showToast('Failed to save to GitHub: ' + error.message, 'error');
        return false;
    }
}

async function saveMetadataToGitHub(name, metadata, detectionFileName) {
    if (!github) return false;

    try {
        const metadataPath = sanitizePathInput(githubConfig.metadataPath) || 'metadata';
        const filename = generateMetaFileName(name, detectionFileName);
        const path = metadataPath + '/' + filename;
        const message = 'Update metadata: ' + name;
        
        const existing = detectionMetadata[name];
        let sha = existing ? existing._sha : null;
        
        // If no SHA cached, check if file exists on GitHub
        if (!sha) {
            sha = await github.getFileSha(path);
        }
        
        const result = await github.createOrUpdateFile(path, Object.assign({ detectionName: name }, metadata), message, sha);
        
        metadata._sha = result.content.sha;
        metadata._path = path;
        
        return true;
    } catch (error) {
        console.error('Failed to save metadata:', error);
        return false;
    }
}

async function deleteDetectionFromGitHub(detection) {
    if (!github || !detection._sha || !detection._path) return false;
    
    try {
        updateSyncStatus('syncing', 'Deleting...');
        await github.deleteFile(detection._path, 'Delete detection: ' + detection['Detection Name'], detection._sha);
        
        const meta = detectionMetadata[detection['Detection Name']];
        if (meta && meta._sha && meta._path) {
            await github.deleteFile(meta._path, 'Delete metadata: ' + detection['Detection Name'], meta._sha);
        }
        
        updateSyncStatus('connected', 'Synced');
        return true;
    } catch (error) {
        updateSyncStatus('error', 'Delete Error');
        showToast('Failed to delete from GitHub: ' + error.message, 'error');
        return false;
    }
}

/**
 * Migrate existing files to new naming convention: <domain>_<name>_rule.json
 * This renames files that don't follow the convention and updates compiled files
 */
async function migrateFileNamesToNewConvention() {
    if (!github) {
        showToast('Not connected to GitHub', 'error');
        return { migrated: 0, errors: 0 };
    }

    console.log('Starting file name migration...');
    showToast('Migrating file names...', 'info');
    updateSyncStatus('syncing', 'Migrating...');

    let migrated = 0;
    let errors = 0;
    const detectionsPath = sanitizePathInput(githubConfig.detectionsPath) || PATHS.detections;
    const metadataPath = sanitizePathInput(githubConfig.metadataPath) || PATHS.metadata;

    for (let i = 0; i < detections.length; i++) {
        const detection = detections[i];
        const name = detection['Detection Name'];
        const domain = detection['Security Domain'] || '';
        const currentFileName = detection.file_name;

        // Generate correct filename
        const correctFileName = generateFileName(name, domain);

        // Skip if already correct
        if (currentFileName === correctFileName) {
            console.log('✓ Already correct:', name);
            continue;
        }

        console.log('Migrating:', name, 'from', currentFileName, 'to', correctFileName);

        try {
            // 1. Delete old detection file if it exists
            if (detection._sha && detection._path) {
                await github.deleteFile(detection._path, 'Migrate: remove old file ' + currentFileName, detection._sha);
            }

            // 2. Delete old metadata file if it exists
            const meta = detectionMetadata[name];
            if (meta && meta._sha && meta._path) {
                await github.deleteFile(meta._path, 'Migrate: remove old metadata', meta._sha);
            }

            // 3. Update detection with new filename
            detection.file_name = correctFileName;
            delete detection._sha;
            delete detection._path;

            // 4. Save detection with new filename
            const detPath = detectionsPath + '/' + correctFileName;
            const detResult = await github.createOrUpdateFile(detPath, detection, 'Migrate: ' + name + ' to new naming convention', null);
            detection._sha = detResult.content.sha;
            detection._path = detPath;

            // 5. Save metadata with new filename
            const metaFileName = generateMetaFileName(name, correctFileName);
            const metaPath = metadataPath + '/' + metaFileName;
            if (meta) {
                delete meta._sha;
                delete meta._path;
                const metaResult = await github.createOrUpdateFile(metaPath, Object.assign({ detectionName: name }, meta), 'Migrate metadata: ' + name, null);
                meta._sha = metaResult.content.sha;
                meta._path = metaPath;
            }

            migrated++;
            console.log('✓ Migrated:', name);
        } catch (e) {
            console.error('Failed to migrate:', name, e);
            errors++;
        }
    }

    // Update compiled files
    if (migrated > 0) {
        try {
            await updateCompiledFiles();
            saveToLocalStorage();
        } catch (e) {
            console.error('Failed to update compiled files after migration:', e);
        }
    }

    updateSyncStatus('synced', 'Migration Complete');
    const message = 'Migration complete: ' + migrated + ' files renamed' + (errors > 0 ? ', ' + errors + ' errors' : '');
    showToast(message, errors > 0 ? 'warning' : 'success');
    console.log(message);

    return { migrated, errors };
}

function generateFileName(name, domain) {
    if (!name) return 'unnamed_rule.json';
    const baseName = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
    const domainPrefix = domain ? domain.toLowerCase() + '_' : '';
    return domainPrefix + baseName + '_rule.json';
}

function generateMetaFileName(name, detectionFileName) {
    // If we have the detection's file_name, derive metadata filename from it
    if (detectionFileName && detectionFileName.endsWith('_rule.json')) {
        return detectionFileName.replace(/_rule\.json$/, '_rule_meta.json');
    }
    // Handle legacy files without _rule suffix
    if (detectionFileName && detectionFileName.endsWith('.json')) {
        return detectionFileName.replace(/\.json$/, '_meta.json');
    }
    // Fallback: generate from name
    if (!name) return 'unnamed_rule_meta.json';
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') + '_rule_meta.json';
}

// =============================================================================
// SPL PARSING - WITH COMMENT FIX
// =============================================================================

function parseSPL(spl) {
    const parsed = {
        indexes: [], sources: [], sourcetypes: [], eventCodes: [],
        actionTypes: [], macros: [], lookups: [], fields: [], 
        customTags: [], comments: [], evalFields: [], categories: [],
        mainSearchFields: [], mainSearchFunctions: [], byFields: []
    };
    if (!spl) return parsed;
    
    // Extract comments FIRST (``` comment ```) - NOT macros!
    const commentMatches = spl.match(/```[^`]*```/g);
    if (commentMatches) {
        commentMatches.forEach(function(m) {
            const comment = m.replace(/```/g, '').trim();
            if (comment && parsed.comments.indexOf(comment) === -1) {
                parsed.comments.push(comment);
            }
        });
    }
    
    // Remove comments from SPL before parsing other elements
    var cleanSpl = spl.replace(/```[^`]*```/g, '');
    
    // Split into phases - ONLY on pipes at beginning of lines (after newline or at start)
    // This regex looks for: start of string OR newline, followed by optional whitespace, then pipe
    var phases = cleanSpl.split(/(?:^|\n)\s*\|\s*/);
    var searchPhase = phases[0] || '';
    
    // === MAIN SEARCH FIELDS ===
    // Extract fields that have =, !=, IN, or like after them in the search phase
    
    // Pattern: field = value or field != value
    var eqMatches = searchPhase.match(/\b([a-zA-Z_][a-zA-Z0-9_\.]*)\s*[!=]=\s*/gi);
    if (eqMatches) {
        eqMatches.forEach(function(m) {
            var field = m.replace(/\s*[!=]=.*/, '').trim();
            // Exclude reserved words and time-related fields
            var reserved = ['index', 'source', 'sourcetype', 'host', '_time', '_raw', '_indextime', 'earliest', 'latest', '_index_earliest', '_index_latest'];
            if (field && reserved.indexOf(field.toLowerCase()) === -1 && parsed.mainSearchFields.indexOf(field) === -1) {
                parsed.mainSearchFields.push(field);
            }
        });
    }
    
    // Pattern: field IN (values)
    var inMatches = searchPhase.match(/\b([a-zA-Z_][a-zA-Z0-9_\.]*)\s+IN\s*\(/gi);
    if (inMatches) {
        inMatches.forEach(function(m) {
            var field = m.replace(/\s+IN\s*\(.*/i, '').trim();
            var reserved = ['index', 'source', 'sourcetype', 'host'];
            if (field && reserved.indexOf(field.toLowerCase()) === -1 && parsed.mainSearchFields.indexOf(field) === -1) {
                parsed.mainSearchFields.push(field);
            }
        });
    }
    
    // Pattern: field like pattern
    var likeMatches = searchPhase.match(/\b([a-zA-Z_][a-zA-Z0-9_\.]*)\s+like\s+/gi);
    if (likeMatches) {
        likeMatches.forEach(function(m) {
            var field = m.replace(/\s+like\s+.*/i, '').trim();
            if (field && parsed.mainSearchFields.indexOf(field) === -1) {
                parsed.mainSearchFields.push(field);
            }
        });
    }
    
    // === MAIN SEARCH FUNCTIONS ===
    // Extract function names that follow pipes (only from phases after the first)
    for (var i = 1; i < phases.length; i++) {
        var phase = phases[i].trim();
        // Get the first word (function name)
        var funcMatch = phase.match(/^([a-zA-Z_][a-zA-Z0-9_]*)/);
        if (funcMatch) {
            var funcName = funcMatch[1].toLowerCase();
            if (parsed.mainSearchFunctions.indexOf(funcName) === -1) {
                parsed.mainSearchFunctions.push(funcName);
            }
        }
    }
    
    // Indexes - handle various formats:
    // index=value, index==value, (index=value), ((index=value)
    var indexMatches = cleanSpl.match(/index\s*={1,2}\s*"?([^"\s|()]+)"?/gi);
    if (indexMatches) {
        indexMatches.forEach(function(m) {
            var val = m.replace(/index\s*={1,2}\s*"?/i, '').replace(/"$/, '').replace(/[()]/g, '').trim();
            if (val && parsed.indexes.indexOf(val) === -1) parsed.indexes.push(val);
        });
    }
    
    // Also match index IN (val1, val2) patterns
    var indexInMatches = cleanSpl.match(/index\s+IN\s*\(([^)]+)\)/gi);
    if (indexInMatches) {
        indexInMatches.forEach(function(m) {
            var valsPart = m.replace(/index\s+IN\s*\(/i, '').replace(/\)$/, '');
            var vals = valsPart.split(',');
            vals.forEach(function(v) {
                v = v.trim().replace(/["']/g, '');
                if (v && parsed.indexes.indexOf(v) === -1) parsed.indexes.push(v);
            });
        });
    }
    
    // Sourcetypes - handle various formats including parentheses
    var stMatches = cleanSpl.match(/sourcetype\s*={1,2}\s*"?([^"\s|()]+)"?/gi);
    if (stMatches) {
        stMatches.forEach(function(m) {
            var val = m.replace(/sourcetype\s*={1,2}\s*"?/i, '').replace(/"$/, '').replace(/[()]/g, '').trim();
            if (val && parsed.sourcetypes.indexOf(val) === -1) parsed.sourcetypes.push(val);
        });
    }
    
    // Categories (e.g., category="AdvancedHunting-DeviceNetworkEvents")
    if (!parsed.categories) parsed.categories = [];
    var categoryMatches = cleanSpl.match(/category\s*={1,2}\s*"([^"]+)"/gi);
    if (categoryMatches) {
        categoryMatches.forEach(function(m) {
            var val = m.replace(/category\s*={1,2}\s*"/i, '').replace(/"$/, '').trim();
            if (val && parsed.categories.indexOf(val) === -1) parsed.categories.push(val);
        });
    }
    // Also handle unquoted category values
    var categoryUnquotedMatches = cleanSpl.match(/category\s*={1,2}\s*([^\s|()]+)/gi);
    if (categoryUnquotedMatches) {
        categoryUnquotedMatches.forEach(function(m) {
            var val = m.replace(/category\s*={1,2}\s*/i, '').replace(/[()]/g, '').trim();
            // Skip if it starts with a quote (already handled above)
            if (val && !val.startsWith('"') && parsed.categories.indexOf(val) === -1) parsed.categories.push(val);
        });
    }
    
    // EventCodes
    var ecMatches = cleanSpl.match(/EventCode\s*[=!<>]+\s*"?(\d+)"?/gi);
    if (ecMatches) {
        ecMatches.forEach(function(m) {
            var val = m.match(/\d+/);
            if (val && parsed.eventCodes.indexOf(val[0]) === -1) parsed.eventCodes.push(val[0]);
        });
    }
    
    // Macros (single backtick only, not triple)
    var macroMatches = cleanSpl.match(/(?<![`])`([^`]+)`(?![`])/g);
    if (macroMatches) {
        macroMatches.forEach(function(m) {
            var val = m.replace(/`/g, '');
            if (val && parsed.macros.indexOf(val) === -1) parsed.macros.push(val);
        });
    }
    
    // Lookups
    var lookupMatches = cleanSpl.match(/\b(lookup|inputlookup)\s+(\w+)/gi);
    if (lookupMatches) {
        lookupMatches.forEach(function(m) {
            var parts = m.split(/\s+/);
            if (parts[1] && parsed.lookups.indexOf(parts[1]) === -1) parsed.lookups.push(parts[1]);
        });
    }
    
    // Eval fields
    var evalMatches = cleanSpl.match(/\beval\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=/gi);
    if (evalMatches) {
        evalMatches.forEach(function(m) {
            var field = m.replace(/\beval\s+/i, '').replace(/\s*=.*/, '').trim();
            if (field && parsed.evalFields.indexOf(field) === -1) parsed.evalFields.push(field);
        });
    }
    
    // Fields from table command
    var tableMatch = cleanSpl.match(/\|\s*table\s+([^\|]+)/i);
    if (tableMatch) {
        var tableFields = tableMatch[1].split(/[,\s]+/).filter(function(f) { return f && f.length > 1; });
        tableFields.forEach(function(f) {
            if (parsed.fields.indexOf(f) === -1) parsed.fields.push(f);
        });
    }
    
    // Fields from stats/by - capture separately in byFields
    var byMatches = cleanSpl.match(/\bby\s+([a-zA-Z_][a-zA-Z0-9_,\s]*)/gi);
    if (byMatches) {
        byMatches.forEach(function(m) {
            var fields = m.replace(/\bby\s+/i, '').split(/[,\s]+/);
            fields.forEach(function(f) {
                f = f.trim();
                if (f && f.length > 1) {
                    if (parsed.fields.indexOf(f) === -1) parsed.fields.push(f);
                    if (parsed.byFields.indexOf(f) === -1) parsed.byFields.push(f);
                }
            });
        });
    }
    
    // Custom tags from parsing rules
    parsingRules.forEach(function(rule) {
        try {
            var regex = new RegExp(rule.field + '\\s*=\\s*"?(' + rule.value + ')"?', 'gi');
            if (regex.test(cleanSpl)) {
                var exists = parsed.customTags.some(function(t) {
                    return t.category === rule.category && t.tag === rule.tag;
                });
                if (!exists) {
                    parsed.customTags.push({ category: rule.category, tag: rule.tag });
                }
            }
        } catch (e) {}
    });
    
    return parsed;
}

// =============================================================================
// DRILLDOWN VARIABLE PARSING
// =============================================================================

function parseDrilldownVariables(detection) {
    var vars = {
        mainSearchFields: [],
        mainSearchFunctions: [],
        drilldownVars: {},
        allDrilldownVars: []
    };
    
    var mainSearch = detection['Search String'] || '';
    
    // Parse the main search for fields and functions
    var parsed = parseSPL(mainSearch);
    vars.mainSearchFields = parsed.mainSearchFields || [];
    vars.mainSearchFunctions = parsed.mainSearchFunctions || [];
    
    // Parse each drilldown for $variable$ usage
    function parseVarsFromSearch(search) {
        var found = [];
        var varMatches = search.match(/\$([a-zA-Z_][a-zA-Z0-9_]*)\$/g);
        if (varMatches) {
            varMatches.forEach(function(v) {
                var varName = v.replace(/\$/g, '');
                if (found.indexOf(varName) === -1) found.push(varName);
                if (vars.allDrilldownVars.indexOf(varName) === -1) vars.allDrilldownVars.push(varName);
            });
        }
        return found;
    }
    
    // Legacy drilldown
    if (detection['Drilldown Search (Legacy)']) {
        vars.drilldownVars['legacy'] = parseVarsFromSearch(detection['Drilldown Search (Legacy)']);
    }
    
    // Numbered drilldowns
    for (var i = 1; i <= 15; i++) {
        var search = detection['Drilldown Search ' + i];
        if (search) {
            vars.drilldownVars['drilldown_' + i] = parseVarsFromSearch(search);
        }
    }
    
    return vars;
}

// =============================================================================
// ANALYST NEXT STEPS PARSING
// =============================================================================

function parseAnalystNextSteps(text) {
    if (!text) return '';
    
    // Check if it's JSON format
    if (text.trim().startsWith('{')) {
        try {
            var parsed = JSON.parse(text);
            if (parsed.data) text = parsed.data;
        } catch (e) {}
    }
    
    // Replace \n with actual newlines
    text = text.replace(/\\n/g, '\n');
    
    return text;
}

// =============================================================================
// NAVIGATION & VIEWS
// =============================================================================

function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(function(btn) {
        btn.addEventListener('click', function() { switchView(btn.dataset.view); });
    });
    document.getElementById('btn-refresh').addEventListener('click', syncWithGitHub);
    document.getElementById('btn-import').addEventListener('click', openImportModal);
    document.getElementById('btn-export').addEventListener('click', exportAllDetections);
    document.getElementById('btn-new').addEventListener('click', createNewDetection);
    document.getElementById('btn-theme').addEventListener('click', toggleTheme);
    
    // Config button handler - opens Settings modal
    var configBtn = document.getElementById('btn-config');
    if (configBtn) {
        configBtn.addEventListener('click', function() {
            openSettingsModal();
        });
    }
    
    // Splunk Search button handler
    var splunkSearchBtn = document.getElementById('btn-splunk-search');
    if (splunkSearchBtn) {
        splunkSearchBtn.addEventListener('click', function() {
            var splunkUrl = SPLUNK_CONFIG.baseUrl + '/en-US/app/search/search';
            window.open(splunkUrl, '_blank');
        });
    }
}

function refreshFromRepository() {
    if (isLoading) {
        showToast('Already loading...', 'info');
        return;
    }
    
    showToast('Refreshing from repository...', 'info');
    updateSyncStatus('syncing', 'Refreshing...');
    isLoading = true;
    
    var detectionsFile = PATHS.dist + '/all-detections.json';
    var metadataFile = PATHS.dist + '/all-metadata.json';
    var resourcesFile = PATHS.dist + '/resources.json';
    
    Promise.all([
        fetchGitHubFile(detectionsFile),
        fetchGitHubFile(metadataFile),
        fetchGitHubFile(resourcesFile).catch(function() { return []; })
    ])
    .then(function(results) {
        var detectionsData = results[0];
        var metadataData = results[1];
        var resourcesData = results[2];
        
        if (Array.isArray(detectionsData) && detectionsData.length > 0) {
            detections = detectionsData;
            filteredDetections = detections.slice();
            console.log('✓ Refreshed ' + detections.length + ' detections');
        } else {
            if (detectionsData === null) {
                console.warn('Detections file empty or invalid, keeping existing data');
            } else if (Array.isArray(detectionsData) && detectionsData.length === 0) {
                console.warn('Detections file is empty array, keeping existing data');
            }
            // Keep existing detections if refresh returns empty/invalid
        }

        if (metadataData && typeof metadataData === 'object' && Object.keys(metadataData).length > 0) {
            detectionMetadata = metadataData;
            console.log('✓ Refreshed metadata for ' + Object.keys(metadataData).length + ' detections');
        } else {
            if (metadataData === null) {
                console.warn('Metadata file empty or invalid, keeping existing data');
            }
            // Keep existing metadata if refresh returns empty/invalid
        }

        if (Array.isArray(resourcesData) && resourcesData.length > 0) {
            resources = resourcesData;
            console.log('✓ Refreshed ' + resources.length + ' resources');
        } else {
            if (resourcesData === null) {
                console.warn('Resources file empty or invalid, keeping existing data');
            }
            // Keep existing resources if refresh returns empty/invalid
        }
        
        saveToLocalStorage();
        buildDynamicFilters();
        renderDashboard();
        renderLibrary();
        renderResources();
        
        isLoading = false;
        updateSyncStatus('synced', 'Refreshed');
        showToast('Loaded ' + detections.length + ' detections', 'success');

        // Validate and repair any missing metadata
        validateAndRepairMetadata().then(function(repaired) {
            if (repaired > 0) {
                showToast('Auto-generated metadata for ' + repaired + ' detection(s)', 'info');
                saveToLocalStorage(); // Update cache with new metadata
            }
        }).catch(function(e) {
            console.warn('Metadata validation failed:', e);
        });
    })
    .catch(function(error) {
        console.error('Refresh failed:', error);
        isLoading = false;
        updateSyncStatus('error', 'Refresh Failed');
        showToast('Could not refresh: ' + error.message, 'error');
    });
}

// =============================================================================
// V11.16 - METADATA INTEGRITY CHECKING
// =============================================================================

async function validateAndRepairMetadata() {
    let repaired = 0;

    for (let i = 0; i < detections.length; i++) {
        const detection = detections[i];
        const name = detection['Detection Name'];

        if (name && !detectionMetadata[name]) {
            console.log('Auto-creating metadata for:', name);

            // Create metadata using existing function
            const newMeta = createMetadataForDetection(detection);
            detectionMetadata[name] = newMeta;

            // Save to GitHub if connected
            if (github) {
                const filename = generateMetaFileName(name, detection.file_name);
                const metadataPath = sanitizePathInput(githubConfig.metadataPath) || PATHS.metadata;
                const path = metadataPath + '/' + filename;

                try {
                    const existingSha = await github.getFileSha(path);
                    const result = await github.createOrUpdateFile(
                        path,
                        Object.assign({ detectionName: name }, newMeta),
                        'Auto-generate metadata: ' + name,
                        existingSha
                    );
                    newMeta._sha = result.content.sha;
                    newMeta._path = path;
                    repaired++;
                } catch (e) {
                    console.warn('Failed to save metadata for:', name, e);
                }
            } else {
                // No GitHub connection, just count as repaired in memory
                repaired++;
            }
        }
    }

    // Update compiled files if any repairs were made and GitHub is connected
    if (repaired > 0 && github) {
        console.log('Repaired metadata for', repaired, 'detection(s)');
        try {
            await updateCompiledFiles();
        } catch (e) {
            console.warn('Failed to update compiled files after metadata repair:', e);
        }
    }

    return repaired;
}

function switchView(viewName) {
    document.querySelectorAll('.nav-btn').forEach(function(btn) {
        btn.classList.toggle('active', btn.dataset.view === viewName);
    });
    document.querySelectorAll('.view').forEach(function(view) {
        view.classList.toggle('active', view.id === 'view-' + viewName);
    });
    if (viewName === 'library') renderLibrary();
    else if (viewName === 'revalidation') { renderRevalidationCheckboxes(); renderRevalidationResults(); }
    else if (viewName === 'history') { populateHistoryFilters(); renderHistoryDetectionList(); }
    else if (viewName === 'reports') { renderDashboard(); renderReports(); }
    else if (viewName === 'config') renderParsingRules();
    else if (viewName === 'resources') renderResources();
    else if (viewName === 'macros') renderMacros();
}

// =============================================================================
// DASHBOARD
// =============================================================================

function renderDashboard() {
    var severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    detections.forEach(function(d) {
        var sev = (d['Severity/Priority'] || '').toLowerCase();
        if (severityCounts.hasOwnProperty(sev)) severityCounts[sev]++;
    });
    
    document.getElementById('stat-total').textContent = detections.length;
    document.getElementById('stat-critical').textContent = severityCounts.critical;
    document.getElementById('stat-high').textContent = severityCounts.high;
    document.getElementById('stat-medium').textContent = severityCounts.medium;
    document.getElementById('stat-low').textContent = severityCounts.low;
    document.getElementById('stat-info').textContent = severityCounts.informational;
    
    renderSeverityChart(severityCounts);
    renderRiskChart();
    renderDomainChart();
    renderDataSourcesChart();
    renderMitreChart();
    renderRecentList();
    renderRecentTunesList();
    renderRecentRetrofitsList();
}

function renderSeverityChart(counts) {
    var container = document.getElementById('chart-severity');
    var colors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', informational: 'var(--info)' };
    var max = Math.max(counts.critical, counts.high, counts.medium, counts.low, counts.informational, 1);
    var html = '';
    Object.keys(counts).forEach(function(sev) {
        var count = counts[sev];
        html += '<div class="labeled-bar-item"><span class="bar-label">' + sev + '</span><div class="bar-track"><div class="bar-fill" style="width: ' + (count/max)*100 + '%; background: ' + colors[sev] + ';"></div></div><span class="bar-value">' + count + '</span></div>';
    });
    container.innerHTML = html;
}

function renderRiskChart() {
    var container = document.getElementById('chart-risk');
    var buckets = [0,0,0,0,0,0,0,0,0,0];
    var labels = ['0-9', '10-19', '20-29', '30-39', '40-49', '50-59', '60-69', '70-79', '80-89', '90-100'];
    detections.forEach(function(d) {
        var bucket = Math.min(Math.floor(getRiskScore(d) / 10), 9);
        buckets[bucket]++;
    });
    var max = Math.max.apply(null, buckets.concat([1]));
    var html = '';
    buckets.forEach(function(count, i) {
        html += '<div class="labeled-bar-item"><span class="bar-label">' + labels[i] + '</span><div class="bar-track"><div class="bar-fill" style="width: ' + (count/max)*100 + '%; background: var(--tune-color);"></div></div><span class="bar-value">' + count + '</span></div>';
    });
    container.innerHTML = html;
}

function renderDomainChart() {
    var container = document.getElementById('chart-domain');
    var domains = {};
    detections.forEach(function(d) {
        var domain = d['Security Domain'] || 'unassigned';
        domains[domain] = (domains[domain] || 0) + 1;
    });
    var sorted = Object.keys(domains).map(function(k) { return [k, domains[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var max = sorted.length > 0 ? sorted[0][1] : 1;
    var html = '';
    sorted.forEach(function(item) {
        html += '<div class="labeled-bar-item"><span class="bar-label">' + item[0] + '</span><div class="bar-track"><div class="bar-fill" style="width: ' + (item[1]/max)*100 + '%; background: var(--retrofit-color);"></div></div><span class="bar-value">' + item[1] + '</span></div>';
    });
    container.innerHTML = html || '<div class="list-empty">No data</div>';
}

function renderDataSourcesChart() {
    var container = document.getElementById('chart-datasources');
    var sources = {};
    detections.forEach(function(d) {
        parseSPL(d['Search String']).indexes.forEach(function(idx) {
            sources[idx] = (sources[idx] || 0) + 1;
        });
    });
    var sorted = Object.keys(sources).map(function(k) { return [k, sources[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var max = sorted.length > 0 ? sorted[0][1] : 1;
    var html = '';
    sorted.slice(0, 8).forEach(function(item) {
        html += '<div class="chart-bar-horizontal"><span class="chart-bar-label" title="' + item[0] + '">' + item[0] + '</span><div class="chart-bar-fill" style="width: ' + (item[1]/max)*100 + '%;"></div><span class="chart-bar-value">' + item[1] + '</span></div>';
    });
    container.innerHTML = html || '<div class="list-empty">No data sources</div>';
}

function renderMitreChart() {
    var container = document.getElementById('chart-mitre');
    var techniques = {};
    detections.forEach(function(d) {
        (d['Mitre ID'] || []).forEach(function(id) {
            techniques[id] = (techniques[id] || 0) + 1;
        });
    });
    var sorted = Object.keys(techniques).map(function(k) { return [k, techniques[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var max = sorted.length > 0 ? sorted[0][1] : 1;
    var html = '';
    sorted.slice(0, 8).forEach(function(item) {
        html += '<div class="chart-bar-horizontal"><span class="chart-bar-label">' + item[0] + '</span><div class="chart-bar-fill" style="width: ' + (item[1]/max)*100 + '%; background: var(--retrofit-color);"></div><span class="chart-bar-value">' + item[1] + '</span></div>';
    });
    container.innerHTML = html || '<div class="list-empty">No MITRE techniques</div>';
}

function renderRecentList() {
    var container = document.getElementById('list-recent');
    var sorted = detections.filter(function(d) { return d['Last Modified']; }).sort(function(a, b) {
        return new Date(b['Last Modified']) - new Date(a['Last Modified']);
    }).slice(0, 5);
    
    if (sorted.length === 0) {
        container.innerHTML = '<div class="list-empty">No recent modifications</div>';
        return;
    }
    
    var html = '';
    sorted.forEach(function(d) {
        html += '<div class="list-item" onclick="selectLibraryDetection(\'' + escapeAttr(d['Detection Name']) + '\'); switchView(\'library\');"><span class="list-item-name">' + escapeHtml(d['Detection Name']) + '</span><span class="list-item-meta">' + formatDate(d['Last Modified']) + '</span></div>';
    });
    container.innerHTML = html;
}

function renderRecentTunesList() {
    var container = document.getElementById('list-recent-tunes');
    var tunes = [];
    Object.keys(detectionMetadata).forEach(function(name) {
        var meta = detectionMetadata[name];
        if (meta.history) {
            meta.history.filter(function(h) { return h.type === 'tune'; }).forEach(function(h) {
                tunes.push({ name: name, timestamp: h.timestamp });
            });
        }
    });
    tunes.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });
    
    if (tunes.length === 0) {
        container.innerHTML = '<div class="list-empty">No recent tunes</div>';
        return;
    }
    
    var html = '';
    tunes.slice(0, 5).forEach(function(t) {
        html += '<div class="list-item" onclick="selectLibraryDetection(\'' + escapeAttr(t.name) + '\'); switchView(\'library\');"><span class="list-item-name">' + escapeHtml(t.name) + '</span><span class="list-item-meta tune">' + formatDate(t.timestamp) + '</span></div>';
    });
    container.innerHTML = html;
}

function renderRecentRetrofitsList() {
    var container = document.getElementById('list-recent-retrofits');
    var retrofits = [];
    Object.keys(detectionMetadata).forEach(function(name) {
        var meta = detectionMetadata[name];
        if (meta.history) {
            meta.history.filter(function(h) { return h.type === 'retrofit'; }).forEach(function(h) {
                retrofits.push({ name: name, timestamp: h.timestamp });
            });
        }
    });
    retrofits.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });
    
    if (retrofits.length === 0) {
        container.innerHTML = '<div class="list-empty">No recent retrofits</div>';
        return;
    }
    
    var html = '';
    retrofits.slice(0, 5).forEach(function(r) {
        html += '<div class="list-item" onclick="selectLibraryDetection(\'' + escapeAttr(r.name) + '\'); switchView(\'library\');"><span class="list-item-name">' + escapeHtml(r.name) + '</span><span class="list-item-meta retrofit">' + formatDate(r.timestamp) + '</span></div>';
    });
    container.innerHTML = html;
}

// =============================================================================
// LIBRARY - WITH NEW VARIABLE FILTERS
// =============================================================================

var libraryFilters = {
    search: '',
    severity: '',
    domain: '',
    status: '',
    sort: 'name-asc',
    datasource: '',
    sourcetype: '',
    mitre: '',
    origin: '',
    mainSearchVar: '',
    drilldownVar: ''
};

// Cache for variable counts
var variableCache = {
    mainSearchFields: {},
    mainSearchFunctions: {},
    drilldownVars: {}
};

function initLibrary() {
    document.getElementById('search-input').addEventListener('input', debounce(function(e) {
        libraryFilters.search = e.target.value;
        applyFilters();
        renderLibrary();
    }, 300));
    
    ['filter-severity', 'filter-domain', 'filter-status', 'filter-sort'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', function(e) {
                var key = id.replace('filter-', '');
                libraryFilters[key] = e.target.value;
                applyFilters();
                renderLibrary();
            });
        }
    });
    
    buildDynamicFilters();
    
    document.getElementById('btn-detail-correlation').addEventListener('click', function() {
        if (selectedLibraryDetection) openCorrelationSearch(selectedLibraryDetection['Detection Name']);
    });
    document.getElementById('btn-detail-tune').addEventListener('click', function() {
        if (selectedLibraryDetection) openTuneModal(selectedLibraryDetection['Detection Name']);
    });
    document.getElementById('btn-detail-retrofit').addEventListener('click', function() {
        if (selectedLibraryDetection) openRetrofitModal(selectedLibraryDetection['Detection Name']);
    });
    document.getElementById('btn-detail-metadata').addEventListener('click', function() {
        if (selectedLibraryDetection) openMetadataModal(selectedLibraryDetection['Detection Name']);
    });
    document.getElementById('btn-detail-edit').addEventListener('click', function() {
        if (selectedLibraryDetection) loadDetectionIntoEditor(selectedLibraryDetection['Detection Name']);
    });
    document.getElementById('btn-detail-delete').addEventListener('click', function() {
        if (selectedLibraryDetection) confirmDeleteDetection(selectedLibraryDetection['Detection Name']);
    });
}

function buildDynamicFilters() {
    var datasources = {};
    var sourcetypes = {};
    var mitres = {};
    var origins = {};
    variableCache.mainSearchFields = {};
    variableCache.mainSearchFunctions = {};
    variableCache.drilldownVars = {};
    
    detections.forEach(function(d) {
        var parsed = parseSPL(d['Search String']);
        var drillVars = parseDrilldownVariables(d);
        
        // Collect all datasources (indexes, sourcetypes, categories, and from Required_Data_Sources)
        parsed.indexes.forEach(function(i) { datasources[i] = (datasources[i] || 0) + 1; });
        parsed.sourcetypes.forEach(function(s) { datasources[s] = (datasources[s] || 0) + 1; });
        if (parsed.categories) {
            parsed.categories.forEach(function(c) { datasources[c] = (datasources[c] || 0) + 1; });
        }
        
        // Also count from Required_Data_Sources field
        var reqDs = d['Required_Data_Sources'] || '';
        if (reqDs) {
            reqDs.split(',').forEach(function(ds) {
                ds = ds.trim();
                if (ds && !datasources[ds]) {
                    datasources[ds] = (datasources[ds] || 0) + 1;
                }
            });
        }
        
        // Still track sourcetypes separately for the sourcetype filter
        parsed.sourcetypes.forEach(function(s) { sourcetypes[s] = (sourcetypes[s] || 0) + 1; });
        (d['Mitre ID'] || []).forEach(function(m) { mitres[m] = (mitres[m] || 0) + 1; });
        if (d.origin) origins[d.origin] = (origins[d.origin] || 0) + 1;
        
        // Count main search fields
        drillVars.mainSearchFields.forEach(function(v) {
            variableCache.mainSearchFields[v] = (variableCache.mainSearchFields[v] || 0) + 1;
        });
        
        // Count main search functions
        drillVars.mainSearchFunctions.forEach(function(v) {
            variableCache.mainSearchFunctions[v] = (variableCache.mainSearchFunctions[v] || 0) + 1;
        });
        
        // Count drilldown variables
        drillVars.allDrilldownVars.forEach(function(v) {
            variableCache.drilldownVars[v] = (variableCache.drilldownVars[v] || 0) + 1;
        });
    });
    
    var filterBar = document.querySelector('.library-filters');
    
    // Populate existing filter select elements (instead of creating new ones)
    
    // Populate datasource filter (replaces index filter)
    var dsSelect = document.getElementById('filter-datasource');
    if (dsSelect) {
        var dsHtml = '<option value="">All Datasources</option>';
        Object.keys(datasources).sort().forEach(function(ds) {
            dsHtml += '<option value="' + escapeAttr(ds) + '">' + escapeHtml(ds) + ' (' + datasources[ds] + ')</option>';
        });
        dsSelect.innerHTML = dsHtml;
    }
    
    // Populate sourcetype filter  
    var stSelect = document.getElementById('filter-sourcetype');
    if (stSelect) {
        var stHtml = '<option value="">All Sourcetypes</option>';
        Object.keys(sourcetypes).sort().forEach(function(st) {
            stHtml += '<option value="' + escapeAttr(st) + '">' + escapeHtml(st) + ' (' + sourcetypes[st] + ')</option>';
        });
        stSelect.innerHTML = stHtml;
    }
    
    // Populate MITRE filter
    var mitreSelect = document.getElementById('filter-mitre');
    if (mitreSelect) {
        var mitreHtml = '<option value="">All MITRE</option>';
        Object.keys(mitres).sort().forEach(function(m) {
            mitreHtml += '<option value="' + escapeAttr(m) + '">' + m + ' (' + mitres[m] + ')</option>';
        });
        mitreSelect.innerHTML = mitreHtml;
    }
    
    // Populate origin filter
    var originSelect = document.getElementById('filter-origin');
    if (originSelect) {
        var originHtml = '<option value="">All Origins</option>';
        Object.keys(origins).sort().forEach(function(o) {
            originHtml += '<option value="' + escapeAttr(o) + '">' + o + ' (' + origins[o] + ')</option>';
        });
        originSelect.innerHTML = originHtml;
    }
    
    // Populate Main Search Fields filter
    var mainFieldSelect = document.getElementById('filter-main-search-field');
    if (mainFieldSelect) {
        var mainFieldHtml = '<option value="">Main Search Fields</option>';
        Object.keys(variableCache.mainSearchFields).sort().forEach(function(v) {
            mainFieldHtml += '<option value="' + escapeAttr(v) + '">' + escapeHtml(v) + ' (' + variableCache.mainSearchFields[v] + ')</option>';
        });
        mainFieldSelect.innerHTML = mainFieldHtml;
    }
    
    // Populate Search Functions filter
    var mainFuncSelect = document.getElementById('filter-search-function');
    if (mainFuncSelect) {
        var mainFuncHtml = '<option value="">Search Functions</option>';
        Object.keys(variableCache.mainSearchFunctions).sort().forEach(function(v) {
            mainFuncHtml += '<option value="' + escapeAttr(v) + '">' + escapeHtml(v) + ' (' + variableCache.mainSearchFunctions[v] + ')</option>';
        });
        mainFuncSelect.innerHTML = mainFuncHtml;
    }
    
    // Populate Drilldown Variables filter
    var ddVarSelect = document.getElementById('filter-drilldown-var');
    if (ddVarSelect) {
        var ddVarHtml = '<option value="">Drilldown Vars</option>';
        Object.keys(variableCache.drilldownVars).sort().forEach(function(v) {
            ddVarHtml += '<option value="' + escapeAttr(v) + '">$' + escapeHtml(v) + '$ (' + variableCache.drilldownVars[v] + ')</option>';
        });
        ddVarSelect.innerHTML = ddVarHtml;
    }
    
    // Add event listeners for dynamic filters (use updated IDs)
    ['filter-datasource', 'filter-sourcetype', 'filter-mitre', 'filter-origin', 'filter-main-search-field', 'filter-search-function', 'filter-drilldown-var'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el && !el.hasAttribute('data-listener-added')) {
            el.setAttribute('data-listener-added', 'true');
            el.addEventListener('change', function(e) {
                if (id === 'filter-main-search-field') libraryFilters.mainSearchField = e.target.value;
                else if (id === 'filter-search-function') libraryFilters.mainSearchFunc = e.target.value;
                else if (id === 'filter-drilldown-var') libraryFilters.drilldownVar = e.target.value;
                else if (id === 'filter-datasource') libraryFilters.datasource = e.target.value;
                else if (id === 'filter-sourcetype') libraryFilters.sourcetype = e.target.value;
                else if (id === 'filter-mitre') libraryFilters.mitre = e.target.value;
                else if (id === 'filter-origin') libraryFilters.origin = e.target.value;
                applyFilters();
                renderLibrary();
            });
        }
    });
}

function applyFilters() {
    var search = libraryFilters.search.toLowerCase();
    var severity = libraryFilters.severity.toLowerCase();
    var domain = libraryFilters.domain.toLowerCase();
    var status = libraryFilters.status;
    var sort = libraryFilters.sort;
    var dsFilter = libraryFilters.datasource;
    var stFilter = libraryFilters.sourcetype;
    var mitreFilter = libraryFilters.mitre;
    var originFilter = libraryFilters.origin;
    var mainFieldFilter = libraryFilters.mainSearchField;
    var mainFuncFilter = libraryFilters.mainSearchFunc;
    var ddVarFilter = libraryFilters.drilldownVar;
    
    filteredDetections = detections.filter(function(d) {
        if (search) {
            var searchText = [d['Detection Name'], d['Objective'], d['Search String']].concat(d['Mitre ID'] || []).join(' ').toLowerCase();
            if (searchText.indexOf(search) === -1) return false;
        }
        if (severity && (d['Severity/Priority'] || '').toLowerCase() !== severity) return false;
        if (domain && (d['Security Domain'] || '').toLowerCase() !== domain) return false;
        if (originFilter && d.origin !== originFilter) return false;
        
        if (dsFilter) {
            // Check all datasources: parsed indexes, sourcetypes, categories, and Required_Data_Sources
            var parsed = parseSPL(d['Search String']);
            var allDs = parsed.indexes.concat(parsed.sourcetypes).concat(parsed.categories || []);
            var reqDs = (d['Required_Data_Sources'] || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean);
            allDs = allDs.concat(reqDs);
            if (allDs.indexOf(dsFilter) === -1) return false;
        }
        
        if (stFilter) {
            var parsed2 = parseSPL(d['Search String']);
            if (parsed2.sourcetypes.indexOf(stFilter) === -1) return false;
        }
        
        if (mitreFilter) {
            if (!(d['Mitre ID'] || []).some(function(m) { return m === mitreFilter; })) return false;
        }
        
        // NEW: Main search field filter
        if (mainFieldFilter) {
            var drillVars = parseDrilldownVariables(d);
            if (drillVars.mainSearchFields.indexOf(mainFieldFilter) === -1) return false;
        }
        
        // NEW: Main search function filter
        if (mainFuncFilter) {
            var drillVars2 = parseDrilldownVariables(d);
            if (drillVars2.mainSearchFunctions.indexOf(mainFuncFilter) === -1) return false;
        }
        
        // NEW: Drilldown variable filter
        if (ddVarFilter) {
            var drillVars3 = parseDrilldownVariables(d);
            if (drillVars3.allDrilldownVars.indexOf(ddVarFilter) === -1) return false;
        }
        
        if (status) {
            var mandatoryCount = MANDATORY_FIELDS.filter(function(f) { return hasValue(d, f); }).length;
            var keyCount = KEY_FIELDS.filter(function(f) { return hasValue(d, f); }).length;
            var needsTune = mandatoryCount < 3 || keyCount < 3;
            var needsRetrofit = mandatoryCount > 3 && keyCount > 3;
            
            if (status === 'valid' && mandatoryCount < MANDATORY_FIELDS.length) return false;
            if (status === 'incomplete' && mandatoryCount >= MANDATORY_FIELDS.length) return false;
            if (status === 'needs-tune' && !needsTune) return false;
            if (status === 'needs-retrofit' && !needsRetrofit) return false;
        }
        return true;
    });
    
    if (sort === 'name-asc') {
        filteredDetections.sort(function(a, b) { return (a['Detection Name'] || '').localeCompare(b['Detection Name'] || ''); });
    } else if (sort === 'name-desc') {
        filteredDetections.sort(function(a, b) { return (b['Detection Name'] || '').localeCompare(a['Detection Name'] || ''); });
    } else if (sort === 'modified-desc') {
        filteredDetections.sort(function(a, b) { return new Date(b['Last Modified'] || 0) - new Date(a['Last Modified'] || 0); });
    } else if (sort === 'risk-desc') {
        filteredDetections.sort(function(a, b) { return getRiskScore(b) - getRiskScore(a); });
    }
}

function hasValue(d, field) {
    var val = d[field];
    if (field === 'Risk') return hasValidRisk(d);
    if (field === 'Mitre ID') return val && Array.isArray(val) && val.length > 0;
    if (field === 'Drilldowns') return d['Drilldown Name (Legacy)'] || d['Drilldown Name 1'];
    if (field === 'Throttling') {
        var throttle = getThrottling(d);
        return throttle.enabled || throttle.fields;
    }
    if (field === 'Roles') return d['Roles'] && d['Roles'].some(function(r) { return r.Name && r.Name.trim(); });
    return val && val !== '';
}

function renderLibrary() {
    var container = document.getElementById('library-list');
    
    // Update count display
    var countEl = document.getElementById('library-count');
    if (countEl) {
        countEl.textContent = filteredDetections.length + ' detection' + (filteredDetections.length !== 1 ? 's' : '');
    }
    
    if (filteredDetections.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="empty-icon">📭</span><p>No detections found</p></div>';
        return;
    }
    
    var html = '';
    filteredDetections.forEach(function(d) {
        var sev = (d['Severity/Priority'] || '').toLowerCase();
        var name = d['Detection Name'] || 'Unnamed';
        var domain = d['Security Domain'] || '';
        var mitreCount = (d['Mitre ID'] || []).length;
        var isSelected = selectedLibraryDetection && selectedLibraryDetection['Detection Name'] === name;
        var ttl = calculateTTL(d['Last Modified']);
        var ttlClass = getTTLClass(ttl.days);
        var ttlLabel = ttl.days <= 0 ? 'Exp' : ttl.days + 'd';
        
        html += '<div class="library-list-item ' + (isSelected ? 'selected' : '') + '" onclick="selectLibraryDetection(\'' + escapeAttr(name) + '\')">';
        html += '<div class="library-list-item-header">';
        html += '<span class="library-list-item-name">' + escapeHtml(name) + '</span>';
        html += '<span class="library-list-item-severity card-severity ' + sev + '">' + (sev || 'N/A') + '</span>';
        html += '</div>';
        html += '<div class="library-list-item-meta">';
        html += '<span>' + (domain || 'No domain') + '</span>';
        html += '<span>Risk: ' + getRiskScore(d) + '</span>';
        html += '<span>' + mitreCount + ' MITRE</span>';
        html += '<span class="ttl-badge ' + ttlClass + '" title="TTL: ' + ttl.days + ' days">' + ttlLabel + '</span>';
        html += '</div>';
        html += '</div>';
    });
    container.innerHTML = html;
}

function selectLibraryDetection(name) {
    var detection = detections.find(function(d) { return d['Detection Name'] === name; });
    if (!detection) return;
    
    selectedLibraryDetection = detection;
    renderLibrary();
    renderLibraryDetail(detection);
}

// =============================================================================
// LIBRARY DETAIL - DOCUMENT STYLE WITH COPY BUTTONS
// =============================================================================

// Store copyable content for reference
var copyableContent = [];

function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(function() {
        var original = btn.innerHTML;
        btn.innerHTML = '✓';
        btn.classList.add('copied');
        setTimeout(function() {
            btn.innerHTML = original;
            btn.classList.remove('copied');
        }, 1500);
    }).catch(function(err) {
        console.error('Failed to copy:', err);
    });
}

function copyById(id, btn) {
    var text = copyableContent[id] || '';
    copyToClipboard(text, btn);
}

function createCopyableField(label, value, isCode) {
    if (!value && value !== 0) return '';
    var escapedValue = escapeHtml(String(value));
    var copyId = copyableContent.length;
    copyableContent.push(String(value));
    
    var html = '<div class="doc-field">';
    html += '<div class="doc-field-header">';
    html += '<span class="doc-field-label">' + label + '</span>';
    html += '<button class="copy-btn" onclick="copyById(' + copyId + ', this)" title="Copy">📋</button>';
    html += '</div>';
    if (isCode) {
        html += '<div class="doc-field-value code-block">' + escapedValue + '</div>';
    } else {
        html += '<div class="doc-field-value">' + escapedValue + '</div>';
    }
    html += '</div>';
    return html;
}

function renderLibraryDetail(d) {
    // Reset copyable content array
    copyableContent = [];
    
    document.getElementById('detail-placeholder').classList.add('hidden');
    document.getElementById('library-detail-content').classList.remove('hidden');
    
    var html = '<div class="doc-container">';
    
    // V10: TTL Warning Banner
    var ttl = calculateTTL(d['Last Modified']);
    if (ttl.days <= 30) {
        var ttlClass = getTTLClass(ttl.days);
        var ttlMsg = ttl.days <= 0 ? '⚠️ TTL EXPIRED - Revalidation required' : '⏰ TTL: ' + ttl.days + ' days remaining';
        html += '<div class="ttl-banner ' + ttlClass + '">' + ttlMsg + '</div>';
    }
    
    // === HEADER SECTION: Key Info ===
    html += '<div class="doc-section doc-header-section">';
    
    // Detection Name
    html += '<h2 class="doc-detection-name">' + escapeHtml(d['Detection Name'] || 'Unnamed') + '</h2>';
    
    // Severity Badge
    if (d['Severity/Priority']) {
        var sev = (d['Severity/Priority'] || '').toLowerCase();
        html += '<div class="doc-severity"><span class="card-severity ' + sev + '">' + d['Severity/Priority'] + '</span></div>';
    }
    
    // Key metrics row
    html += '<div class="doc-metrics">';
    var riskScore = getRiskScore(d);
    if (riskScore > 0) html += '<div class="doc-metric"><span class="metric-label">Risk Score</span><span class="metric-value">' + riskScore + '</span></div>';
    if (d['Security Domain']) html += '<div class="doc-metric"><span class="metric-label">Domain</span><span class="metric-value">' + escapeHtml(d['Security Domain']) + '</span></div>';
    if (d['origin']) html += '<div class="doc-metric"><span class="metric-label">Origin</span><span class="metric-value">' + escapeHtml(d['origin']) + '</span></div>';
    html += '</div>';
    
    html += '</div>';
    
    // === ROLES SECTION ===
    if (d['Roles'] && d['Roles'].some(function(r) { return r.Name; })) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Roles & Ownership</h3>';
        html += '<div class="doc-roles">';
        d['Roles'].filter(function(r) { return r.Name; }).forEach(function(r) {
            html += '<div class="doc-role">';
            html += '<div class="doc-role-type">' + escapeHtml(r.Role) + '</div>';
            html += '<div class="doc-role-name">' + escapeHtml(r.Name) + '</div>';
            if (r.Title) html += '<div class="doc-role-title">' + escapeHtml(r.Title) + '</div>';
            html += '</div>';
        });
        html += '</div></div>';
    }
    
    // === OVERVIEW SECTION ===
    html += '<div class="doc-section">';
    html += '<h3 class="doc-section-title">Overview</h3>';
    html += createCopyableField('Objective', d['Objective'], false);
    if (d['Description'] && d['Description'].trim() && d['Description'] !== d['Objective']) {
        html += createCopyableField('Description', d['Description'], false);
    }
    html += createCopyableField('Assumptions', d['Assumptions'], false);
    html += createCopyableField('Blind Spots / False Positives', d['Blind_Spots_False_Positives'], false);
    html += createCopyableField('Required Data Sources', d['Required_Data_Sources'], false);
    html += '</div>';
    
    // === ANALYST GUIDANCE SECTION ===
    if (d['Analyst Next Steps']) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Analyst Guidance</h3>';
        var steps = parseAnalystNextSteps(d['Analyst Next Steps']);
        html += createCopyableField('Next Steps', steps, true);
        html += '</div>';
    }
    
    // === SEARCH LOGIC SECTION ===
    if (d['Search String']) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Search Logic</h3>';
        html += createCopyableField('SPL Query', d['Search String'], true);
        
        // Parsed metadata tags
        var parsed = parseSPL(d['Search String']);
        var drilldownVars = parseDrilldownVariables(d);
        var hasParsedData = parsed.indexes.length || parsed.sourcetypes.length || parsed.eventCodes.length || 
                            parsed.macros.length || parsed.lookups.length || 
                            (drilldownVars.mainSearchFields && drilldownVars.mainSearchFields.length) ||
                            (drilldownVars.mainSearchFunctions && drilldownVars.mainSearchFunctions.length);
        
        if (hasParsedData) {
            html += '<div class="doc-parsed-metadata">';
            html += '<div class="doc-parsed-title">Parsed from SPL</div>';
            html += '<div class="doc-tags-grid">';
            
            if (parsed.indexes.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Indexes</span><div class="tag-group-items">';
                parsed.indexes.forEach(function(i) { html += '<span class="card-tag datasource">' + escapeHtml(i) + '</span>'; });
                html += '</div></div>';
            }
            if (parsed.sourcetypes.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Sourcetypes</span><div class="tag-group-items">';
                parsed.sourcetypes.forEach(function(s) { html += '<span class="card-tag">' + escapeHtml(s) + '</span>'; });
                html += '</div></div>';
            }
            if (parsed.eventCodes.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Event Codes</span><div class="tag-group-items">';
                parsed.eventCodes.forEach(function(e) { html += '<span class="card-tag">' + escapeHtml(e) + '</span>'; });
                html += '</div></div>';
            }
            if (parsed.macros.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Macros</span><div class="tag-group-items">';
                parsed.macros.forEach(function(m) { html += '<span class="card-tag macro">`' + escapeHtml(m) + '`</span>'; });
                html += '</div></div>';
            }
            if (parsed.lookups.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Lookups</span><div class="tag-group-items">';
                parsed.lookups.forEach(function(l) { html += '<span class="card-tag">' + escapeHtml(l) + '</span>'; });
                html += '</div></div>';
            }
            if (drilldownVars.mainSearchFields && drilldownVars.mainSearchFields.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Fields</span><div class="tag-group-items">';
                drilldownVars.mainSearchFields.forEach(function(v) { html += '<span class="card-tag field">' + escapeHtml(v) + '</span>'; });
                html += '</div></div>';
            }
            if (drilldownVars.mainSearchFunctions && drilldownVars.mainSearchFunctions.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">Functions</span><div class="tag-group-items">';
                drilldownVars.mainSearchFunctions.forEach(function(v) { html += '<span class="card-tag function">' + escapeHtml(v) + '</span>'; });
                html += '</div></div>';
            }
            if (parsed.byFields && parsed.byFields.length) {
                html += '<div class="doc-tag-group"><span class="tag-group-label">by</span><div class="tag-group-items">';
                parsed.byFields.forEach(function(f) { html += '<span class="card-tag by-field">' + escapeHtml(f) + '</span>'; });
                html += '</div></div>';
            }
            
            html += '</div></div>';
        }
        html += '</div>';
    }
    
    // === MITRE SECTION ===
    if (d['Mitre ID'] && d['Mitre ID'].length > 0) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">MITRE ATT&CK</h3>';
        html += '<div class="doc-mitre-tags">';
        d['Mitre ID'].forEach(function(id) { html += '<span class="card-tag mitre">' + escapeHtml(id) + '</span>'; });
        html += '</div></div>';
    }
    
    // === NOTABLE EVENT SECTION ===
    var riskEntries = getRiskEntries(d);
    if (d['Notable Title'] || d['Notable Description'] || riskEntries.length > 0) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Notable Event Configuration</h3>';
        html += createCopyableField('Notable Title', d['Notable Title'], false);
        html += createCopyableField('Notable Description', d['Notable Description'], false);
        
        // Display Risk entries
        if (riskEntries.length > 0) {
            html += '<div class="doc-risk-entries">';
            html += '<div class="doc-risk-header">Risk Configuration</div>';
            riskEntries.forEach(function(risk, idx) {
                html += '<div class="doc-risk-entry">';
                html += '<span class="risk-field">Field: <code>' + escapeHtml(risk.risk_object_field || 'N/A') + '</code></span>';
                html += '<span class="risk-type">Type: <code>' + escapeHtml(risk.risk_object_type || 'N/A') + '</code></span>';
                html += '<span class="risk-score">Score: <strong>' + (risk.risk_score || 0) + '</strong></span>';
                html += '</div>';
            });
            html += '</div>';
        }
        html += '</div>';
    }
    
    // === SCHEDULING SECTION ===
    var throttle = getThrottling(d);
    if (d['Cron Schedule'] || d['Trigger Condition'] || throttle.enabled || throttle.fields) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Scheduling</h3>';
        html += '<div class="doc-schedule-grid">';
        if (d['Cron Schedule']) html += '<div class="doc-schedule-item"><span class="schedule-label">Cron</span><code>' + escapeHtml(d['Cron Schedule']) + '</code></div>';
        if (d['Schedule Window']) html += '<div class="doc-schedule-item"><span class="schedule-label">Window</span><span>' + escapeHtml(d['Schedule Window']) + '</span></div>';
        if (d['Schedule Priority']) html += '<div class="doc-schedule-item"><span class="schedule-label">Priority</span><span>' + escapeHtml(d['Schedule Priority']) + '</span></div>';
        if (d['Trigger Condition']) html += '<div class="doc-schedule-item full-width"><span class="schedule-label">Trigger</span><code>' + escapeHtml(d['Trigger Condition']) + '</code></div>';
        html += '</div>';
        
        if (throttle.enabled || throttle.fields) {
            html += '<div class="doc-throttle">Throttling: Fields: <code>' + escapeHtml(throttle.fields || 'N/A') + '</code>, Period: <code>' + escapeHtml(throttle.period || 'N/A') + '</code></div>';
        }
        html += '</div>';
    }
    
    // === DRILLDOWNS SECTION ===
    var drilldowns = [];
    if (d['Drilldown Name (Legacy)']) {
        drilldowns.push({
            name: d['Drilldown Name (Legacy)'],
            search: d['Drilldown Search (Legacy)'],
            earliest: d['Drilldown Earliest Offset (Legacy)'],
            latest: d['Drilldown Latest Offset (Legacy)'],
            vars: drilldownVars.drilldownVars['legacy'] || []
        });
    }
    for (var i = 1; i <= 15; i++) {
        if (d['Drilldown Name ' + i]) {
            drilldowns.push({
                name: d['Drilldown Name ' + i],
                search: d['Drilldown Search ' + i],
                earliest: d['Drilldown Earliest ' + i],
                latest: d['Drilldown Latest ' + i],
                vars: drilldownVars.drilldownVars['drilldown_' + i] || []
            });
        }
    }
    
    if (drilldowns.length > 0) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Drilldowns <span class="section-count">(' + drilldowns.length + ')</span></h3>';
        drilldowns.forEach(function(dd, idx) {
            html += '<div class="doc-drilldown">';
            html += '<div class="drilldown-header">';
            html += '<span class="drilldown-name">' + escapeHtml(dd.name) + '</span>';
            if (dd.earliest || dd.latest) html += '<span class="drilldown-time">' + (dd.earliest || 'earliest') + ' → ' + (dd.latest || 'latest') + '</span>';
            html += '</div>';
            if (dd.search) {
                var ddCopyId = copyableContent.length;
                copyableContent.push(dd.search);
                html += '<div class="drilldown-search-wrap">';
                html += '<button class="copy-btn" onclick="copyById(' + ddCopyId + ', this)" title="Copy">📋</button>';
                html += '<pre class="drilldown-search">' + escapeHtml(dd.search) + '</pre>';
                html += '</div>';
                
                // Parse drilldown search for SPL metadata
                var ddParsed = parseSPL(dd.search);
                var ddHasParsed = ddParsed.indexes.length || ddParsed.sourcetypes.length || ddParsed.eventCodes.length || 
                                  ddParsed.mainSearchFunctions.length || ddParsed.byFields.length;
                if (ddHasParsed) {
                    html += '<div class="doc-parsed-metadata drilldown-parsed">';
                    html += '<div class="doc-parsed-title">Parsed from SPL</div>';
                    html += '<div class="doc-tags-grid">';
                    if (ddParsed.indexes.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Indexes</span><div class="tag-group-items">';
                        ddParsed.indexes.forEach(function(i) { html += '<span class="card-tag datasource">' + escapeHtml(i) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (ddParsed.eventCodes.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Event Codes</span><div class="tag-group-items">';
                        ddParsed.eventCodes.forEach(function(e) { html += '<span class="card-tag">' + escapeHtml(e) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (ddParsed.mainSearchFunctions.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Functions</span><div class="tag-group-items">';
                        ddParsed.mainSearchFunctions.forEach(function(f) { html += '<span class="card-tag function">' + escapeHtml(f) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (ddParsed.byFields.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">by</span><div class="tag-group-items">';
                        ddParsed.byFields.forEach(function(f) { html += '<span class="card-tag by-field">' + escapeHtml(f) + '</span>'; });
                        html += '</div></div>';
                    }
                    html += '</div></div>';
                }
            }
            if (dd.vars.length) {
                html += '<div class="drilldown-vars">';
                dd.vars.forEach(function(v) { html += '<span class="card-tag variable">$' + escapeHtml(v) + '$</span>'; });
                html += '</div>';
            }
            html += '</div>';
        });
        html += '</div>';
    }
    
    // === PROPOSED TEST PLAN SECTION ===
    if (d['Proposed Test Plan'] && d['Proposed Test Plan'].trim()) {
        html += '<div class="doc-section">';
        html += '<h3 class="doc-section-title">Proposed Test Plan</h3>';
        html += createCopyableField('Test Plan', d['Proposed Test Plan'], true);
        html += '</div>';
    }
    
    // === METADATA SECTION ===
    html += '<div class="doc-section doc-footer">';
    html += '<h3 class="doc-section-title">File Information</h3>';
    html += '<div class="doc-file-info">';
    if (d['file_name']) {
        var githubFileUrl = GITHUB_CONFIG.baseUrl + '/' + GITHUB_CONFIG.repo + '/blob/' + GITHUB_CONFIG.branch + '/' + GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.detectionsFolder + '/' + d['file_name'];
        html += '<div class="file-info-item"><span class="file-label">File:</span> <a href="' + githubFileUrl + '" target="_blank" class="file-link"><code>' + escapeHtml(d['file_name']) + '</code> ↗</a></div>';
    }
    if (d['First Created']) html += '<div class="file-info-item"><span class="file-label">Created:</span> ' + formatDateTime(d['First Created']) + '</div>';
    if (d['Last Modified']) html += '<div class="file-info-item"><span class="file-label">Modified:</span> ' + formatDateTime(d['Last Modified']) + '</div>';
    html += '</div></div>';
    
    html += '</div>'; // End doc-container
    
    document.getElementById('library-detail-body').innerHTML = html;
}

// =============================================================================
// EDITOR - WITH TUNE/RETROFIT MODE
// =============================================================================

var drilldownCount = 0;
var mitreIds = [];
var dataSources = [];

function initEditor() {
    document.querySelectorAll('.editor-tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.editor-tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.editor-content').forEach(function(c) { c.classList.remove('active'); });
            tab.classList.add('active');
            document.getElementById('editor-' + tab.dataset.mode).classList.add('active');
            if (tab.dataset.mode === 'json') updateJSONView();
            if (tab.dataset.mode === 'metadata') updateMetadataView();
        });
    });
    
    // Metadata tab buttons
    var copyMetaBtn = document.getElementById('btn-copy-metadata');
    if (copyMetaBtn) {
        copyMetaBtn.addEventListener('click', function() {
            var meta = getMetadataForCopy();
            navigator.clipboard.writeText(JSON.stringify(meta, null, 2));
            showToast('Metadata copied', 'success');
        });
    }
    var refreshMetaBtn = document.getElementById('btn-refresh-metadata');
    if (refreshMetaBtn) {
        refreshMetaBtn.addEventListener('click', updateMetadataView);
    }
    
    document.querySelectorAll('.section-header').forEach(function(header) {
        header.addEventListener('click', function() { header.classList.toggle('collapsed'); });
    });
    
    var splInput = document.getElementById('field-search_string');
    if (splInput) {
        splInput.addEventListener('input', function() { 
            renderParsedMetadataSidebar(); 
            autoPopulateDataSources();
            validateForm(); 
        });
    }
    
    var mitreInput = document.getElementById('mitre-input');
    if (mitreInput) {
        mitreInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                addMitreTag(e.target.value);
                e.target.value = '';
            }
        });
    }
    
    // Data Sources tag input - allows manual additions alongside auto-populated
    var datasourceInput = document.getElementById('datasource-input');
    if (datasourceInput) {
        datasourceInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                addDataSourceTag(e.target.value);
                e.target.value = '';
            }
        });
    }
    
    var nameInput = document.getElementById('field-detection_name');
    if (nameInput) {
        nameInput.addEventListener('input', function() {
            updateAutoFileName();
            autoPopulateNotableFields();
        });
    }
    
    var domainSelect = document.getElementById('field-security_domain');
    if (domainSelect) domainSelect.addEventListener('change', updateAutoFileName);
    
    document.getElementById('btn-add-drilldown').addEventListener('click', addDrilldown);
    document.getElementById('btn-save').addEventListener('click', saveDetection);
    document.getElementById('btn-metadata-editor').addEventListener('click', function() {
        if (currentDetection && currentDetection['Detection Name']) {
            openMetadataModal(currentDetection['Detection Name']);
        } else {
            showToast('No detection loaded', 'warning');
        }
    });
    document.getElementById('btn-download').addEventListener('click', downloadCurrentDetection);
    document.getElementById('btn-clear').addEventListener('click', function() { showConfirm('Clear the form?', clearForm); });
    document.getElementById('btn-copy-json').addEventListener('click', function() {
        navigator.clipboard.writeText(JSON.stringify(getFormData(), null, 2));
        showToast('Copied', 'success');
    });
    document.getElementById('btn-format-json').addEventListener('click', updateJSONView);
    
    document.querySelectorAll('#detection-form input, #detection-form select, #detection-form textarea').forEach(function(el) {
        el.addEventListener('input', validateForm);
        el.addEventListener('change', validateForm);
    });
}

// Data Sources tag functions
function addDataSourceTag(value) {
    var trimmed = value.trim();
    if (trimmed && dataSources.indexOf(trimmed) === -1) {
        dataSources.push(trimmed);
        renderDataSourceTags();
        validateForm();
    }
}

function removeDataSourceTag(index) {
    dataSources.splice(index, 1);
    renderDataSourceTags();
    validateForm();
}

function renderDataSourceTags() {
    var container = document.getElementById('datasource-tags');
    if (!container) return;
    // Show remove button for all data sources (manual and auto-populated)
    container.innerHTML = dataSources.map(function(ds, i) {
        return '<span class="tag">' + escapeHtml(ds) + '<button type="button" onclick="removeDataSourceTag(' + i + ')">×</button></span>';
    }).join('');
}

/**
 * Auto-populate data sources from parsed Search String
 * Appends to existing datasources without duplicates
 */
function autoPopulateDataSources() {
    var spl = document.getElementById('field-search_string') ? document.getElementById('field-search_string').value : '';
    var parsed = parseSPL(spl);
    
    // Keep existing manual entries, append parsed ones (avoid duplicates)
    // Using case-insensitive comparison for duplicates
    var existingLower = dataSources.map(function(ds) { return ds.toLowerCase(); });
    
    // Add indexes
    parsed.indexes.forEach(function(idx) {
        if (idx && existingLower.indexOf(idx.toLowerCase()) === -1) {
            dataSources.push(idx);
            existingLower.push(idx.toLowerCase());
        }
    });
    
    // Add sourcetypes
    parsed.sourcetypes.forEach(function(st) {
        if (st && existingLower.indexOf(st.toLowerCase()) === -1) {
            dataSources.push(st);
            existingLower.push(st.toLowerCase());
        }
    });
    
    // Add categories (e.g., AdvancedHunting-DeviceNetworkEvents)
    if (parsed.categories) {
        parsed.categories.forEach(function(cat) {
            if (cat && existingLower.indexOf(cat.toLowerCase()) === -1) {
                dataSources.push(cat);
                existingLower.push(cat.toLowerCase());
            }
        });
    }
    
    renderDataSourceTags();
}

/**
 * Toggle collapsible form section
 */
function toggleSection(sectionNum) {
    var section = document.querySelector('.form-section[data-section="' + sectionNum + '"]');
    if (!section) return;
    
    var icon = section.querySelector('.collapse-icon');
    var content = section.querySelector('.section-content');
    
    if (section.classList.contains('collapsed')) {
        section.classList.remove('collapsed');
        if (icon) icon.textContent = '▼';
        if (content) content.style.display = 'block';
    } else {
        section.classList.add('collapsed');
        if (icon) icon.textContent = '▶';
        if (content) content.style.display = 'none';
    }
}

function updateAutoFileName() {
    var name = document.getElementById('field-detection_name').value;
    var domain = document.getElementById('field-security_domain').value;
    if (name) document.getElementById('field-file_name').value = generateFileName(name, domain);
}

function autoPopulateNotableFields() {
    var detectionName = document.getElementById('field-detection_name').value;
    var notableTitleEl = document.getElementById('field-notable_title');
    var notableDescEl = document.getElementById('field-notable_description');
    
    // Only auto-populate if fields are empty or contain auto-generated content
    if (notableTitleEl && (!notableTitleEl.value || notableTitleEl.dataset.autopopulated === 'true')) {
        notableTitleEl.value = detectionName;
        notableTitleEl.dataset.autopopulated = 'true';
    }
    
    if (notableDescEl && (!notableDescEl.value || notableDescEl.dataset.autopopulated === 'true')) {
        notableDescEl.value = detectionName + ' detected on ';
        notableDescEl.dataset.autopopulated = 'true';
    }
}

function createNewDetection() {
    editMode = null;
    currentDetection = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));
    currentDetection['First Created'] = new Date().toISOString();
    
    // Prepopulate Risk defaults (new array format)
    currentDetection['Risk'] = [{
        risk_object_field: '$src$',
        risk_object_type: 'user',
        risk_score: 0
    }];
    
    // Prepopulate Drilldown defaults
    currentDetection['Drilldown Name (Legacy)'] = 'View Events Associated to this Notable on ';
    currentDetection['Drilldown Earliest Offset (Legacy)'] = '2592000';
    currentDetection['Drilldown Latest Offset (Legacy)'] = '86400';
    
    // Prepopulate Assumptions & Potential Impact
    currentDetection['Assumptions'] = 'Assumptions:\n\nPotential Impact:';
    
    mitreIds = [];
    dataSources = [];
    drilldownCount = 0;
    document.getElementById('drilldowns-container').innerHTML = '';
    loadDetectionIntoForm(currentDetection);
    switchView('editor');
    updateEditorHeader('New Detection', null);
    
    // Set focus on detection name
    setTimeout(function() {
        document.getElementById('field-detection_name').focus();
    }, 100);
}

function loadDetectionIntoEditor(name, mode) {
    var detection = detections.find(function(d) { return d['Detection Name'] === name; });
    if (!detection) { showToast('Detection not found', 'error'); return; }
    
    editMode = mode || null;
    currentDetection = JSON.parse(JSON.stringify(detection));
    loadDetectionIntoForm(currentDetection);
    switchView('editor');
    updateEditorHeader(name, mode);
}

function updateEditorHeader(name, mode) {
    var headerEl = document.getElementById('editor-detection-name');
    var modeIndicator = document.getElementById('edit-mode-indicator');
    
    headerEl.textContent = name;
    
    if (!modeIndicator) {
        modeIndicator = document.createElement('span');
        modeIndicator.id = 'edit-mode-indicator';
        headerEl.parentNode.insertBefore(modeIndicator, headerEl.nextSibling);
    }
    
    if (mode === 'tune') {
        modeIndicator.className = 'mode-indicator tune';
        modeIndicator.textContent = '🔧 TUNE MODE';
    } else if (mode === 'retrofit') {
        modeIndicator.className = 'mode-indicator retrofit';
        modeIndicator.textContent = '⚡ RETROFIT MODE';
    } else {
        modeIndicator.className = '';
        modeIndicator.textContent = '';
    }
}

function loadDetectionIntoForm(d) {
    document.getElementById('field-file_name').value = d['file_name'] || '';
    document.getElementById('field-schema_version').value = d['schema_version'] || '1.2';
    document.getElementById('field-origin').value = d['origin'] || 'custom';
    document.getElementById('field-detection_name').value = d['Detection Name'] || '';
    document.getElementById('field-objective').value = d['Objective'] || '';
    
    // Description independent from Objective
    var desc = d['Description'] || '';
    var obj = d['Objective'] || '';
    document.getElementById('field-description').value = (desc && desc !== obj) ? desc : '';
    
    document.getElementById('field-assumptions').value = d['Assumptions'] || '';
    document.getElementById('field-severity').value = (d['Severity/Priority'] || '').toLowerCase();
    document.getElementById('field-risk_score').value = getRiskScore(d) || '';
    document.getElementById('field-security_domain').value = (d['Security Domain'] || '').toLowerCase();
    document.getElementById('field-first_created').value = d['First Created'] ? new Date(d['First Created']).toISOString().split('T')[0] : '';
    document.getElementById('field-last_modified').value = d['Last Modified'] ? formatDateTime(d['Last Modified']) : '';
    
    if (d['Roles'] && Array.isArray(d['Roles'])) {
        var r = d['Roles'].find(function(x) { return x.Role === 'Requestor'; }) || {};
        var b = d['Roles'].find(function(x) { return x.Role === 'Business Owner'; }) || {};
        var t = d['Roles'].find(function(x) { return x.Role === 'Technical Owner'; }) || {};
        document.getElementById('role-requestor-name').value = r.Name || '';
        document.getElementById('role-requestor-title').value = r.Title || '';
        document.getElementById('role-business-name').value = b.Name || '';
        document.getElementById('role-business-title').value = b.Title || '';
        document.getElementById('role-technical-name').value = t.Name || '';
        document.getElementById('role-technical-title').value = t.Title || '';
    }
    
    document.getElementById('field-search_string').value = d['Search String'] || '';
    
    // Handle Required Data Sources as array
    var dsValue = d['Required_Data_Sources'] || '';
    if (Array.isArray(dsValue)) {
        dataSources = dsValue.slice();
    } else if (typeof dsValue === 'string' && dsValue.trim()) {
        // Parse comma-separated or newline-separated
        dataSources = dsValue.split(/[,\n]/).map(function(s) { return s.trim(); }).filter(function(s) { return s; });
    } else {
        dataSources = [];
    }
    renderDataSourceTags();
    
    document.getElementById('field-splunk_app_context').value = d['Splunk_App_Context'] || '';
    document.getElementById('field-search_duration').value = d['Search_Duration'] || '';
    
    // Parse Analyst Next Steps if it's JSON
    var nextSteps = d['Analyst Next Steps'] || '';
    if (nextSteps.trim().startsWith('{')) {
        try {
            var parsed = JSON.parse(nextSteps);
            if (parsed.data) nextSteps = parsed.data;
        } catch (e) {}
    }
    nextSteps = nextSteps.replace(/\\n/g, '\n');
    document.getElementById('field-analyst_next_steps').value = nextSteps;
    
    document.getElementById('field-blind_spots').value = d['Blind_Spots_False_Positives'] || '';
    document.getElementById('field-notable_title').value = d['Notable Title'] || '';
    document.getElementById('field-notable_description').value = d['Notable Description'] || '';
    document.getElementById('field-risk_object_field').value = getRiskObjectField(d) || '';
    document.getElementById('field-risk_object_type').value = (getRiskObjectType(d) || '').toLowerCase();
    document.getElementById('field-cron_schedule').value = d['Cron Schedule'] || '';
    document.getElementById('field-schedule_window').value = d['Schedule Window'] || '';
    document.getElementById('field-schedule_priority').value = (d['Schedule Priority'] || 'default').toLowerCase();
    document.getElementById('field-trigger_condition').value = d['Trigger Condition'] || '';
    var throttle = getThrottling(d);
    document.getElementById('field-throttling_enabled').value = (throttle.enabled || 0).toString();
    document.getElementById('field-throttling_fields').value = throttle.fields || '';
    document.getElementById('field-throttling_period').value = throttle.period || '';
    
    mitreIds = d['Mitre ID'] ? d['Mitre ID'].slice() : [];
    renderMitreTags();
    
    document.getElementById('field-drilldown_legacy_name').value = d['Drilldown Name (Legacy)'] || '';
    document.getElementById('field-drilldown_legacy_search').value = d['Drilldown Search (Legacy)'] || '';
    document.getElementById('field-drilldown_legacy_earliest').value = d['Drilldown Earliest Offset (Legacy)'] || '';
    document.getElementById('field-drilldown_legacy_latest').value = d['Drilldown Latest Offset (Legacy)'] || '';
    
    document.getElementById('drilldowns-container').innerHTML = '';
    drilldownCount = 0;
    for (var i = 1; i <= 15; i++) {
        if (d['Drilldown Name ' + i]) {
            addDrilldown();
            document.getElementById('dd-name-' + drilldownCount).value = d['Drilldown Name ' + i] || '';
            document.getElementById('dd-search-' + drilldownCount).value = d['Drilldown Search ' + i] || '';
            document.getElementById('dd-earliest-' + drilldownCount).value = d['Drilldown Earliest ' + i] || '';
            document.getElementById('dd-latest-' + drilldownCount).value = d['Drilldown Latest ' + i] || '';
        }
    }
    
    // Proposed Test Plan
    var testPlanEl = document.getElementById('field-proposed_test_plan');
    if (testPlanEl) testPlanEl.value = d['Proposed Test Plan'] || '';
    
    // Auto-populate data sources from Search String
    autoPopulateDataSources();
    
    renderParsedMetadataSidebar();
    validateForm();
}

function renderParsedMetadataSidebar() {
    var container = document.getElementById('parsed-metadata');
    var spl = document.getElementById('field-search_string') ? document.getElementById('field-search_string').value : '';
    var parsed = parseSPL(spl);
    
    var formName = document.getElementById('field-detection_name') ? document.getElementById('field-detection_name').value : '';
    var formSeverity = document.getElementById('field-severity') ? document.getElementById('field-severity').value : '';
    var formDomain = document.getElementById('field-security_domain') ? document.getElementById('field-security_domain').value : '';
    var formRisk = document.getElementById('field-risk_score') ? document.getElementById('field-risk_score').value : '';
    
    var html = '';
    
    if (formName) html += '<div class="metadata-group"><div class="metadata-label">Detection</div><div class="metadata-values"><span class="metadata-tag">' + escapeHtml(formName) + '</span></div></div>';
    if (formSeverity) html += '<div class="metadata-group"><div class="metadata-label">Severity</div><div class="metadata-values"><span class="metadata-tag card-severity ' + formSeverity + '">' + formSeverity + '</span></div></div>';
    if (formDomain) html += '<div class="metadata-group"><div class="metadata-label">Domain</div><div class="metadata-values"><span class="metadata-tag">' + formDomain + '</span></div></div>';
    if (formRisk) html += '<div class="metadata-group"><div class="metadata-label">Risk Score</div><div class="metadata-values"><span class="metadata-tag">' + formRisk + '</span></div></div>';
    
    if (mitreIds.length) {
        html += '<div class="metadata-group"><div class="metadata-label">MITRE IDs</div><div class="metadata-values">';
        mitreIds.forEach(function(id) { html += '<span class="metadata-tag mitre">' + id + '</span>'; });
        html += '</div></div>';
    }
    
    if (parsed.indexes.length) {
        html += '<div class="metadata-group"><div class="metadata-label">Indexes</div><div class="metadata-values">';
        parsed.indexes.forEach(function(i) { html += '<span class="metadata-tag">' + escapeHtml(i) + '</span>'; });
        html += '</div></div>';
    }
    if (parsed.sourcetypes.length) {
        html += '<div class="metadata-group"><div class="metadata-label">Sourcetypes</div><div class="metadata-values">';
        parsed.sourcetypes.forEach(function(s) { html += '<span class="metadata-tag">' + escapeHtml(s) + '</span>'; });
        html += '</div></div>';
    }
    if (parsed.eventCodes.length) {
        html += '<div class="metadata-group"><div class="metadata-label">Event Codes</div><div class="metadata-values">';
        parsed.eventCodes.forEach(function(e) { html += '<span class="metadata-tag">' + e + '</span>'; });
        html += '</div></div>';
    }
    if (parsed.macros.length) {
        html += '<div class="metadata-group"><div class="metadata-label">Macros</div><div class="metadata-values">';
        parsed.macros.forEach(function(m) { html += '<span class="metadata-tag">' + escapeHtml(m) + '</span>'; });
        html += '</div></div>';
    }
    if (parsed.comments.length) {
        html += '<div class="metadata-group"><div class="metadata-label">Comments</div><div class="metadata-values">';
        parsed.comments.forEach(function(c) { html += '<span class="metadata-tag comment">' + escapeHtml(c) + '</span>'; });
        html += '</div></div>';
    }
    if (parsed.fields.length) {
        html += '<div class="metadata-group"><div class="metadata-label">Fields</div><div class="metadata-values">';
        parsed.fields.slice(0, 15).forEach(function(f) { html += '<span class="metadata-tag">' + escapeHtml(f) + '</span>'; });
        html += '</div></div>';
    }
    
    container.innerHTML = html || '<p class="no-data">No metadata parsed yet</p>';
}

// MITRE TAG - SUPPORTS SUB-TECHNIQUES (T1003.002)
function addMitreTag(value) {
    var cleaned = value.trim().toUpperCase();
    if (!cleaned) return;
    // Updated regex to support sub-techniques like T1003.002
    if (!/^T\d{4}(\.\d{3})?$/.test(cleaned)) { 
        showToast('Invalid MITRE format. Use T1234 or T1234.001', 'warning'); 
        return; 
    }
    if (mitreIds.indexOf(cleaned) === -1) {
        mitreIds.push(cleaned);
        renderMitreTags();
        renderParsedMetadataSidebar();
    }
}

function removeMitreTag(index) {
    mitreIds.splice(index, 1);
    renderMitreTags();
    renderParsedMetadataSidebar();
}

function renderMitreTags() {
    var html = '';
    mitreIds.forEach(function(id, i) {
        html += '<span class="tag">' + id + '<span class="tag-remove" onclick="removeMitreTag(' + i + ')">×</span></span>';
    });
    document.getElementById('mitre-tags').innerHTML = html;
}

function addDrilldown() {
    if (drilldownCount >= 15) { showToast('Max 15 drilldowns', 'warning'); return; }
    drilldownCount++;
    var html = '<div class="drilldown-card" id="drilldown-' + drilldownCount + '">' +
        '<div class="drilldown-header"><span>Drilldown ' + drilldownCount + '</span><span class="drilldown-remove" onclick="removeDrilldown(' + drilldownCount + ')">×</span></div>' +
        '<div class="form-row"><div class="form-group"><label>Name</label><input type="text" id="dd-name-' + drilldownCount + '"></div><div class="form-group"><label>Earliest</label><input type="text" id="dd-earliest-' + drilldownCount + '" placeholder="-24h"></div><div class="form-group"><label>Latest</label><input type="text" id="dd-latest-' + drilldownCount + '" placeholder="now"></div></div>' +
        '<div class="form-row"><div class="form-group full"><label>Search</label><textarea id="dd-search-' + drilldownCount + '" rows="3" placeholder="Use $variable$ for tokens from main search"></textarea></div></div>' +
        '</div>';
    document.getElementById('drilldowns-container').insertAdjacentHTML('beforeend', html);
}

function removeDrilldown(num) {
    showConfirm('Remove drilldown?', function() {
        var el = document.getElementById('drilldown-' + num);
        if (el) el.remove();
    });
}

function getFormData() {
    var d = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));
    d['schema_version'] = '1.2';
    d['file_name'] = document.getElementById('field-file_name').value || generateFileName(document.getElementById('field-detection_name').value, document.getElementById('field-security_domain').value);
    d['origin'] = document.getElementById('field-origin').value;
    d['Detection Name'] = document.getElementById('field-detection_name').value;
    d['Objective'] = document.getElementById('field-objective').value;
    d['Description'] = document.getElementById('field-description').value;
    d['Assumptions'] = document.getElementById('field-assumptions').value;
    d['Severity/Priority'] = document.getElementById('field-severity').value;
    
    // New Risk array format
    d['Risk'] = [{
        risk_object_field: document.getElementById('field-risk_object_field').value,
        risk_object_type: document.getElementById('field-risk_object_type').value,
        risk_score: parseInt(document.getElementById('field-risk_score').value) || 0
    }];
    // Remove old flat risk fields if they exist
    delete d['Risk Score'];
    delete d['Risk Object Field'];
    delete d['Risk Object Type'];
    
    d['Security Domain'] = document.getElementById('field-security_domain').value;
    var fc = document.getElementById('field-first_created').value;
    d['First Created'] = fc ? new Date(fc).toISOString() : (currentDetection ? currentDetection['First Created'] : null) || new Date().toISOString();
    d['Last Modified'] = new Date().toISOString();
    d['Roles'] = [
        { Role: 'Requestor', Name: document.getElementById('role-requestor-name').value, Title: document.getElementById('role-requestor-title').value },
        { Role: 'Business Owner', Name: document.getElementById('role-business-name').value, Title: document.getElementById('role-business-title').value },
        { Role: 'Technical Owner', Name: document.getElementById('role-technical-name').value, Title: document.getElementById('role-technical-title').value }
    ];
    d['Search String'] = document.getElementById('field-search_string').value;
    d['Required_Data_Sources'] = dataSources.length > 0 ? dataSources.join(', ') : '';
    d['Splunk_App_Context'] = document.getElementById('field-splunk_app_context').value;
    d['Search_Duration'] = document.getElementById('field-search_duration').value;
    d['Analyst Next Steps'] = document.getElementById('field-analyst_next_steps').value;
    d['Blind_Spots_False_Positives'] = document.getElementById('field-blind_spots').value;
    d['Notable Title'] = document.getElementById('field-notable_title').value;
    d['Notable Description'] = document.getElementById('field-notable_description').value;
    d['Cron Schedule'] = document.getElementById('field-cron_schedule').value;
    d['Schedule Window'] = document.getElementById('field-schedule_window').value;
    d['Schedule Priority'] = document.getElementById('field-schedule_priority').value;
    d['Trigger Condition'] = document.getElementById('field-trigger_condition').value;
    d['Throttling'] = { 
        enabled: parseInt(document.getElementById('field-throttling_enabled').value) || 0, 
        fields: document.getElementById('field-throttling_fields').value, 
        period: document.getElementById('field-throttling_period').value 
    };
    d['Mitre ID'] = mitreIds.slice();
    d['Drilldown Name (Legacy)'] = document.getElementById('field-drilldown_legacy_name').value;
    d['Drilldown Search (Legacy)'] = document.getElementById('field-drilldown_legacy_search').value;
    d['Drilldown Earliest Offset (Legacy)'] = document.getElementById('field-drilldown_legacy_earliest').value || null;
    d['Drilldown Latest Offset (Legacy)'] = document.getElementById('field-drilldown_legacy_latest').value || null;
    
    var ddNum = 0;
    document.querySelectorAll('#drilldowns-container .drilldown-card').forEach(function(card) {
        ddNum++;
        var id = card.id.split('-')[1];
        var nameEl = document.getElementById('dd-name-' + id);
        var searchEl = document.getElementById('dd-search-' + id);
        var earliestEl = document.getElementById('dd-earliest-' + id);
        var latestEl = document.getElementById('dd-latest-' + id);
        d['Drilldown Name ' + ddNum] = nameEl ? nameEl.value : '';
        d['Drilldown Search ' + ddNum] = searchEl ? searchEl.value : '';
        d['Drilldown Earliest ' + ddNum] = earliestEl ? earliestEl.value : null;
        d['Drilldown Latest ' + ddNum] = latestEl ? latestEl.value : null;
    });
    
    // Proposed Test Plan
    var testPlanEl = document.getElementById('field-proposed_test_plan');
    d['Proposed Test Plan'] = testPlanEl ? testPlanEl.value || '' : '';
    
    if (currentDetection && currentDetection._sha) d._sha = currentDetection._sha;
    if (currentDetection && currentDetection._path) d._path = currentDetection._path;
    
    return d;
}

function validateForm() {
    var errors = [];
    var d = getFormData();
    MANDATORY_FIELDS.forEach(function(field) {
        if (!hasValue(d, field)) errors.push((FIELD_LABELS[field] || field) + ' is required');
    });

    // Validate macros in Search String against loaded macros
    var spl = d['Search String'] || '';
    if (spl) {
        var parsed = parseSPL(spl);
        if (parsed.macros && parsed.macros.length > 0) {
            parsed.macros.forEach(function(macro) {
                if (loadedMacros.indexOf(macro) === -1) {
                    errors.push('Macro not found: `' + macro + '`');
                }
            });
        }
    }

    var statusContainer = document.getElementById('validation-status');
    var errorsContainer = document.getElementById('validation-errors');
    var saveBtn = document.getElementById('btn-save');

    if (errors.length === 0) {
        statusContainer.innerHTML = '<div class="validation-indicator valid">✓ Ready to Save</div>';
        errorsContainer.innerHTML = '';
        saveBtn.disabled = false;
    } else {
        statusContainer.innerHTML = '<div class="validation-indicator invalid">✗ ' + errors.length + ' Error(s)</div>';
        var errHtml = '';
        errors.slice(0, 5).forEach(function(e) {
            // Check if this is a macro not found error and make it clickable
            var macroMatch = e.match(/^Macro not found: `(.+)`$/);
            if (macroMatch) {
                var macroName = macroMatch[1];
                errHtml += '<div class="validation-error">• <a href="#" class="validation-error-link" onclick="navigateToMacrosWithName(\'' + escapeAttr(macroName) + '\'); return false;">Macro not found: `' + escapeHtml(macroName) + '`</a></div>';
            } else {
                errHtml += '<div class="validation-error">• ' + e + '</div>';
            }
        });
        errorsContainer.innerHTML = errHtml;
        saveBtn.disabled = true;
    }
    return errors.length === 0;
}

async function saveDetection() {
    if (!validateForm()) { showToast('Fix validation errors', 'error'); return; }
    
    var detection = getFormData();
    var existingIndex = -1;
    for (var i = 0; i < detections.length; i++) {
        if (detections[i]['Detection Name'] === detection['Detection Name']) {
            existingIndex = i;
            break;
        }
    }
    
    var name = detection['Detection Name'];
    var meta = detectionMetadata[name] || { history: [], parsed: {} };
    
    // Build history entry based on mode
    var historyEntry = null;
    if (editMode === 'tune' && meta.pendingTune) {
        historyEntry = {
            id: Date.now(),
            type: 'tune',
            description: meta.pendingTune.description,
            reason: meta.pendingTune.reason,
            jira: meta.pendingTune.jira,
            analyst: meta.pendingTune.analyst,
            fieldsModified: meta.pendingTune.fieldsModified,
            timestamp: new Date().toISOString()
        };
        delete meta.pendingTune;
    } else if (editMode === 'retrofit' && meta.pendingRetrofit) {
        historyEntry = {
            id: Date.now(),
            type: 'retrofit',
            subtype: meta.pendingRetrofit.subtype,
            description: meta.pendingRetrofit.description,
            jira: meta.pendingRetrofit.jira,
            analyst: meta.pendingRetrofit.analyst,
            fieldsModified: meta.pendingRetrofit.fieldsModified,
            timestamp: new Date().toISOString()
        };
        delete meta.pendingRetrofit;
    } else {
        historyEntry = {
            id: Date.now(),
            type: existingIndex >= 0 ? 'version' : 'version',
            description: existingIndex >= 0 ? 'Detection updated' : 'Detection created',
            timestamp: new Date().toISOString()
        };
    }
    
    // Add to history
    if (!meta.history) meta.history = [];
    meta.history.unshift(historyEntry);
    detectionMetadata[name] = meta;
    
    if (existingIndex >= 0) {
        var oldDetection = detections[existingIndex];
        if (oldDetection._sha) detection._sha = oldDetection._sha;
        if (oldDetection._path) detection._path = oldDetection._path;
        detections[existingIndex] = detection;
    } else {
        detections.push(detection);
    }
    
    parseAndSaveMetadata(detection);
    
    // Track tune/retrofit in metadata
    if (editMode) {
        if (editMode === 'tune') {
            meta.needsTune = false;
            meta.lastTuned = new Date().toISOString();
        } else if (editMode === 'retrofit') {
            meta.needsRetrofit = false;
            meta.lastRetrofitted = new Date().toISOString();
        }
    }
    
    currentDetection = detection;
    
    if (github) {
        updateSyncStatus('syncing', 'Saving...');
        
        try {
            // 1. Save individual detection file
            var success = await saveDetectionToGitHub(detection);

            if (success) {
                // 2. Save individual metadata file
                await saveMetadataToGitHub(detection['Detection Name'], detectionMetadata[detection['Detection Name']], detection.file_name);
                
                // 3. Update compiled files for other analysts
                await updateCompiledFiles();
                
                updateSyncStatus('synced', 'Saved');
                showToast('Saved and synced to repository', 'success');
            } else {
                updateSyncStatus('error', 'Save Failed');
                showToast('Failed to save to repository', 'error');
            }
        } catch (error) {
            console.error('Save error:', error);
            updateSyncStatus('error', 'Error');
            showToast('Error saving: ' + error.message, 'error');
        }
    } else {
        showToast('Saved locally (not connected)', 'warning');
    }
    
    saveToLocalStorage();
    updateEditorHeader(detection['Detection Name'], null);
    editMode = null;
    renderParsedMetadataSidebar();
    filteredDetections = detections.slice();
    buildDynamicFilters();
}

// =============================================================================
// V11.15 - UPDATE COMPILED FILES
// =============================================================================

async function updateCompiledFiles() {
    console.log('Updating compiled files...');
    
    try {
        // Build compiled detections array (remove internal fields)
        var compiledDetections = detections.map(function(d) {
            var clean = Object.assign({}, d);
            clean._sourceFile = clean.file_name || (generateFileName(d['Detection Name'], d['Security Domain']));
            delete clean._sha;
            delete clean._path;
            return clean;
        });
        
        // Build compiled metadata object
        var compiledMetadata = {};
        Object.keys(detectionMetadata).forEach(function(name) {
            compiledMetadata[name] = detectionMetadata[name];
        });
        
        // Build manifest
        var manifest = {
            lastCompiled: new Date().toISOString(),
            version: '11.1',
            counts: {
                detections: compiledDetections.length,
                metadata: Object.keys(compiledMetadata).length
            },
            files: {
                detections: compiledDetections.map(function(d) { return d._sourceFile; }),
                metadata: Object.keys(compiledMetadata).map(function(n) { return n.replace(/[^a-zA-Z0-9_-]/g, '_') + '.json'; })
            }
        };
        
        // Save all-detections.json (pass object, not string - createOrUpdateFile handles stringification)
        var detectionsPath = PATHS.dist + '/all-detections.json';
        await saveFileToGitHub(detectionsPath, compiledDetections, 'Update compiled detections');
        
        // Save all-metadata.json
        var metadataPath = PATHS.dist + '/all-metadata.json';
        await saveFileToGitHub(metadataPath, compiledMetadata, 'Update compiled metadata');
        
        // Save manifest.json
        var manifestPath = PATHS.dist + '/manifest.json';
        await saveFileToGitHub(manifestPath, manifest, 'Update manifest');
        
        console.log('Compiled files updated successfully');
    } catch (error) {
        console.error('Failed to update compiled files:', error);
        // Don't throw - individual file was saved, compiled files are secondary
    }
}

async function saveFileToGitHub(path, content, message) {
    if (!github) return false;
    
    console.log('saveFileToGitHub called for:', path);
    
    try {
        // Get current file SHA if it exists
        var sha = null;
        try {
            sha = await github.getFileSha(path);
            console.log('SHA result for ' + path + ':', sha ? sha.substring(0, 8) + '...' : 'null (new file)');
        } catch (shaError) {
            console.warn('Could not get SHA for ' + path + ':', shaError.message);
            // If we can't get SHA but file might exist, try without SHA first
            // GitHub will tell us if file exists and we need SHA
        }
        
        // Try to create or update file
        try {
            await github.createOrUpdateFile(path, content, message, sha);
            console.log('Successfully saved:', path);
            return true;
        } catch (saveError) {
            // If we got "sha wasn't supplied" error, the file exists but we couldn't get its SHA
            // This can happen with large files or API issues
            if (saveError.message.includes("sha") && saveError.message.includes("supplied") && !sha) {
                console.error('File exists but could not retrieve SHA. Manual intervention needed.');
                console.error('Try running compile_detections.py locally and pushing to refresh the files.');
            }
            throw saveError;
        }
    } catch (error) {
        console.error('Failed to save file:', path, error);
        throw error;
    }
}

function parseAndSaveMetadata(detection) {
    var name = detection['Detection Name'];
    if (!detectionMetadata[name]) detectionMetadata[name] = { history: [], parsed: {} };
    detectionMetadata[name].parsed = parseSPL(detection['Search String']);
    detectionMetadata[name].drilldownVars = parseDrilldownVariables(detection);
    detectionMetadata[name].lastParsed = new Date().toISOString();
    detectionMetadata[name].detectionName = name;
}

function syntaxHighlightJSON(json) {
    // Escape HTML first
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    // Apply syntax highlighting
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function(match) {
        var cls = 'json-number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'json-key';
            } else {
                cls = 'json-string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'json-boolean';
        } else if (/null/.test(match)) {
            cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

function updateJSONView() {
    var data = getFormData();
    var json = JSON.stringify(data, null, 2);
    
    // Apply syntax highlighting
    document.getElementById('json-display').innerHTML = syntaxHighlightJSON(json);
}

function updateMetadataView() {
    var detectionName = document.getElementById('field-detection_name').value;
    var meta = detectionMetadata[detectionName] || {};
    
    // If no stored metadata, generate from current form data
    if (Object.keys(meta).length === 0) {
        var formData = getFormData();
        var parsed = parseSPL(formData['Search String'] || '');
        var drilldownVars = parseDrilldownVariables(formData);
        meta = {
            parsed: parsed,
            drilldownVars: drilldownVars,
            ttl: calculateTTL(formData['Last Modified']),
            generated: true
        };
    }
    
    var json = JSON.stringify(meta, null, 2);
    
    // Apply syntax highlighting
    var displayEl = document.getElementById('metadata-display');
    if (displayEl) {
        displayEl.innerHTML = syntaxHighlightJSON(json);
    }
}

function getMetadataForCopy() {
    var detectionName = document.getElementById('field-detection_name').value;
    var meta = detectionMetadata[detectionName] || {};
    
    if (Object.keys(meta).length === 0) {
        var formData = getFormData();
        var parsed = parseSPL(formData['Search String'] || '');
        var drilldownVars = parseDrilldownVariables(formData);
        meta = {
            parsed: parsed,
            drilldownVars: drilldownVars,
            ttl: calculateTTL(formData['Last Modified']),
            generated: true
        };
    }
    return meta;
}

function clearForm() {
    editMode = null;
    currentDetection = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));
    currentDetection['First Created'] = new Date().toISOString();
    mitreIds = [];
    dataSources = [];
    drilldownCount = 0;
    document.getElementById('drilldowns-container').innerHTML = '';
    loadDetectionIntoForm(currentDetection);
    updateEditorHeader('New Detection', null);
}

function downloadCurrentDetection() {
    var d = getFormData();
    downloadFile(d['file_name'] || 'detection.json', JSON.stringify(d, null, 2));
}

// =============================================================================
// CONFIG
// =============================================================================

function initConfig() {
    document.getElementById('btn-add-rule').addEventListener('click', addParsingRule);
}

function renderParsingRules() {
    var container = document.getElementById('parsing-rules-list');
    if (parsingRules.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted); text-align: center; padding: 20px;">No custom rules</p>';
        return;
    }
    var html = '';
    parsingRules.forEach(function(rule, i) {
        html += '<div class="parsing-rule"><code>' + escapeHtml(rule.field) + '=' + escapeHtml(rule.value) + '</code><span class="tag-category">' + escapeHtml(rule.category) + '</span><span class="tag-value">' + escapeHtml(rule.tag) + '</span><div class="rule-actions"><span class="rule-delete" onclick="deleteParsingRule(' + i + ')">🗑</span></div></div>';
    });
    container.innerHTML = html;
}

function addParsingRule() {
    var field = document.getElementById('rule-field').value.trim();
    var value = document.getElementById('rule-value').value.trim();
    var category = document.getElementById('rule-category').value.trim();
    var tag = document.getElementById('rule-tag').value.trim();
    if (!field || !value || !category || !tag) { showToast('All fields required', 'warning'); return; }
    parsingRules.push({ field: field, value: value, category: category, tag: tag });
    saveToLocalStorage();
    renderParsingRules();
    document.getElementById('rule-field').value = '';
    document.getElementById('rule-value').value = '';
    document.getElementById('rule-category').value = '';
    document.getElementById('rule-tag').value = '';
    showToast('Rule added', 'success');
}

function deleteParsingRule(index) {
    showConfirm('Delete rule?', function() {
        parsingRules.splice(index, 1);
        saveToLocalStorage();
        renderParsingRules();
    });
}

// =============================================================================
// REVALIDATION
// =============================================================================

var selectedMandatoryFields = MANDATORY_FIELDS.slice();
var selectedKeyFields = [];
var revalStatusFilter = '';

function initRevalidation() {
    renderRevalidationCheckboxes();
    document.getElementById('btn-run-revalidation').addEventListener('click', runRevalidation);
    document.getElementById('btn-clear-filters').addEventListener('click', clearRevalFilters);
    
    // Search input
    var searchInput = document.getElementById('reval-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(renderRevalidationResults, 300));
    }
    
    // Sort dropdown
    var sortSelect = document.getElementById('reval-sort');
    if (sortSelect) {
        sortSelect.addEventListener('change', renderRevalidationResults);
    }
    
    // Click handlers for stats
    document.querySelectorAll('.reval-stat.clickable').forEach(function(stat) {
        stat.addEventListener('click', function() {
            var filter = this.dataset.filter;
            document.querySelectorAll('.reval-stat.clickable').forEach(function(s) { s.classList.remove('active'); });
            if (revalStatusFilter !== filter) {
                this.classList.add('active');
                revalStatusFilter = filter;
            } else {
                revalStatusFilter = '';
            }
            renderRevalidationResults();
        });
    });
}

function renderRevalidation() {
    renderRevalidationCheckboxes();
    renderRevalidationResults();
}

function renderRevalidationCheckboxes() {
    var mandatoryCounts = {};
    var keyCounts = {};
    
    MANDATORY_FIELDS.forEach(function(f) {
        mandatoryCounts[f] = detections.filter(function(d) { return !hasValue(d, f); }).length;
    });
    KEY_FIELDS.forEach(function(f) {
        keyCounts[f] = detections.filter(function(d) { return !hasValue(d, f); }).length;
    });
    
    var mandatoryHtml = '';
    MANDATORY_FIELDS.forEach(function(f) {
        var count = mandatoryCounts[f];
        if (count > 0) {
            mandatoryHtml += '<div class="field-check-item" data-field="' + escapeAttr(f) + '" data-type="mandatory"><input type="checkbox" value="' + escapeAttr(f) + '"><span class="field-check-label">' + (FIELD_LABELS[f] || f) + '</span><span class="field-check-count">' + count + '</span></div>';
        }
    });
    document.getElementById('mandatory-fields-checks').innerHTML = mandatoryHtml || '<span class="no-missing">All fields complete ✓</span>';
    
    var keyHtml = '';
    KEY_FIELDS.forEach(function(f) {
        var count = keyCounts[f];
        if (count > 0) {
            keyHtml += '<div class="field-check-item" data-field="' + escapeAttr(f) + '" data-type="key"><input type="checkbox" value="' + escapeAttr(f) + '"><span class="field-check-label">' + (FIELD_LABELS[f] || f) + '</span><span class="field-check-count">' + count + '</span></div>';
        }
    });
    document.getElementById('key-fields-checks').innerHTML = keyHtml || '<span class="no-missing">All fields complete ✓</span>';
    
    // Add click handlers for live filtering - use event delegation approach
    document.querySelectorAll('.field-check-item').forEach(function(item) {
        item.onclick = function(e) {
            e.preventDefault();
            e.stopPropagation();
            var checkbox = this.querySelector('input[type="checkbox"]');
            checkbox.checked = !checkbox.checked;
            this.classList.toggle('active', checkbox.checked);
            renderRevalidationResults();
        };
    });
}

function getSelectedRevalFields() {
    var fields = [];
    document.querySelectorAll('.field-check-item input:checked').forEach(function(cb) {
        fields.push(cb.value);
    });
    return fields;
}

function clearRevalFilters() {
    revalStatusFilter = '';
    document.querySelectorAll('.reval-stat.clickable').forEach(function(s) { s.classList.remove('active'); });
    document.querySelectorAll('.field-check-item').forEach(function(item) {
        item.classList.remove('active');
        var cb = item.querySelector('input');
        if (cb) cb.checked = false;
    });
    renderRevalidationResults();
}

function runRevalidation() {
    renderRevalidationCheckboxes();
    renderRevalidationResults();
    showToast('Revalidation refreshed', 'info');
}

function renderRevalidationResults() {
    var selectedFields = getSelectedRevalFields();
    var results = [];
    var needsTuneCount = 0;
    var needsRetrofitCount = 0;
    var validCount = 0;
    var incompleteCount = 0;
    
    // Get search filter value
    var searchEl = document.getElementById('reval-search');
    var searchTerm = searchEl ? searchEl.value.toLowerCase().trim() : '';
    
    detections.forEach(function(d) {
        var detName = d['Detection Name'] || 'Unnamed';
        
        // Apply search filter first
        if (searchTerm && detName.toLowerCase().indexOf(searchTerm) === -1) return;
        
        var allMissingMandatory = MANDATORY_FIELDS.filter(function(f) { return !hasValue(d, f); });
        var allMissingKey = KEY_FIELDS.filter(function(f) { return !hasValue(d, f); });
        var totalMissing = allMissingMandatory.length + allMissingKey.length;
        
        var needsTune = allMissingMandatory.length > 0 && allMissingMandatory.length <= 3;
        var needsRetrofit = allMissingMandatory.length > 3 || allMissingKey.length > 3;
        var isValid = allMissingMandatory.length === 0;
        var isIncomplete = !isValid;
        
        if (needsTune) needsTuneCount++;
        if (needsRetrofit) needsRetrofitCount++;
        if (isValid) validCount++;
        if (isIncomplete) incompleteCount++;
        
        // Status filter
        if (revalStatusFilter === 'valid' && !isValid) return;
        if (revalStatusFilter === 'incomplete' && !isIncomplete) return;
        if (revalStatusFilter === 'need-tune' && !needsTune) return;
        if (revalStatusFilter === 'need-retrofit' && !needsRetrofit) return;
        
        // Field filter - show detection if it's missing ANY of the selected fields
        if (selectedFields.length > 0) {
            var hasMissingSelectedField = selectedFields.some(function(f) {
                return allMissingMandatory.indexOf(f) >= 0 || allMissingKey.indexOf(f) >= 0;
            });
            if (!hasMissingSelectedField) return;
        }
        
        // Calculate TTL
        var ttl = calculateTTL(d['Last Modified']);
        
        results.push({
            name: d['Detection Name'] || 'Unnamed',
            severity: d['Severity/Priority'] || '',
            missingMandatory: allMissingMandatory,
            missingKey: allMissingKey,
            totalMissing: totalMissing,
            needsTune: needsTune,
            needsRetrofit: needsRetrofit,
            isValid: isValid,
            ttlDays: ttl.days,
            ttlClass: getTTLClass(ttl.days)
        });
    });
    
    // Update stats
    document.getElementById('reval-stat-total').textContent = detections.length;
    document.getElementById('reval-stat-valid').textContent = validCount;
    document.getElementById('reval-stat-incomplete').textContent = incompleteCount;
    document.getElementById('reval-stat-tune').textContent = needsTuneCount;
    document.getElementById('reval-stat-retrofit').textContent = needsRetrofitCount;
    
    // Update results count
    var resultsCountEl = document.getElementById('reval-results-count');
    if (resultsCountEl) {
        resultsCountEl.textContent = results.length + ' detection' + (results.length !== 1 ? 's' : '');
    }
    
    // Sort results
    var sortSelect = document.getElementById('reval-sort');
    var sortBy = sortSelect ? sortSelect.value : 'name';
    if (sortBy === 'missing') {
        results.sort(function(a, b) { return b.totalMissing - a.totalMissing; });
    } else if (sortBy === 'severity') {
        var sevOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, '': 5 };
        results.sort(function(a, b) { return (sevOrder[a.severity.toLowerCase()] || 5) - (sevOrder[b.severity.toLowerCase()] || 5); });
    } else if (sortBy === 'ttl') {
        results.sort(function(a, b) { return a.ttlDays - b.ttlDays; });
    } else {
        results.sort(function(a, b) { return a.name.localeCompare(b.name); });
    }
    
    var container = document.getElementById('revalidation-results');
    if (results.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="empty-icon">✓</span><p>' + (selectedFields.length > 0 || revalStatusFilter ? 'No detections match filters' : 'All detections valid!') + '</p></div>';
        return;
    }
    
    var html = '';
    results.forEach(function(r) {
        html += '<div class="reval-result-card">';
        html += '<div class="reval-result-info">';
        html += '<h4><a href="#" class="detection-link" onclick="goToLibraryDetection(\'' + escapeAttr(r.name) + '\'); return false;">' + escapeHtml(r.name) + '</a> <button class="btn-splunk btn-xs" onclick="openSplunkDashboard(\'' + escapeAttr(r.name) + '\')" title="View in Splunk Dashboard"><img src="assets/splunk-icon.svg" alt="" class="btn-icon-img-sm"></button></h4>';
        html += '<div class="reval-result-badges">';
        if (r.isValid) {
            html += '<span class="status-badge valid">✓ Valid</span>';
        } else if (r.needsRetrofit) {
            html += '<span class="status-badge need-retrofit">Need Retrofit</span>';
        } else if (r.needsTune) {
            html += '<span class="status-badge need-tune">Need Tune</span>';
        }
        // TTL Badge
        var ttlText = r.ttlDays <= 0 ? 'EXPIRED' : r.ttlDays + 'd';
        html += '<span class="ttl-badge ' + r.ttlClass + '" title="Time to Live">' + ttlText + '</span>';
        r.missingMandatory.forEach(function(f) { 
            html += '<span class="reval-missing-field">' + (FIELD_LABELS[f] || f) + '</span>'; 
        });
        r.missingKey.forEach(function(f) { 
            html += '<span class="reval-missing-field key">' + (FIELD_LABELS[f] || f) + '</span>'; 
        });
        html += '</div></div>';
        html += '<div class="reval-result-actions">';
        if (!r.isValid) {
            html += '<button class="btn-tune btn-sm" onclick="openTuneModal(\'' + escapeAttr(r.name) + '\')">🔧 Tune</button>';
            if (r.needsRetrofit) {
                html += '<button class="btn-retrofit btn-sm" onclick="openRetrofitModal(\'' + escapeAttr(r.name) + '\')">⚡ Retrofit</button>';
            }
        }
        html += '<button class="btn-secondary btn-sm" onclick="loadDetectionIntoEditor(\'' + escapeAttr(r.name) + '\')">Edit</button>';
        html += '</div></div>';
    });
    container.innerHTML = html;
}

// =============================================================================
// SPLUNK DASHBOARD INTEGRATION (V11.15 - New Tab Approach)
// =============================================================================

// Track recently opened detections in Splunk
var splunkRecentDetections = [];

function openSplunkDashboard(detectionName) {
    // Build URL with detection name pre-populated (stripped of domain and "-Rule")
    var url = buildSplunkDashboardUrl(detectionName);
    
    // Open in popup window
    openSplunkPopup(url, 'SplunkRevalidation');
    
    // Track in recent list (keep last 10)
    var existing = splunkRecentDetections.indexOf(detectionName);
    if (existing > -1) {
        splunkRecentDetections.splice(existing, 1);
    }
    splunkRecentDetections.unshift(detectionName);
    if (splunkRecentDetections.length > 10) {
        splunkRecentDetections.pop();
    }
    
    // Update the Splunk tab if visible
    renderSplunkLauncher();
    
    var strippedName = stripForRevalidation(detectionName);
    showToast('Opened Splunk dashboard for: ' + strippedName, 'success');
    console.log('Opened Splunk dashboard:', url);
}

function openCorrelationSearch(detectionName) {
    // Build correlation search URL (stripped of domain only, keeps "-Rule")
    var url = buildCorrelationSearchUrl(detectionName);
    
    // Open in popup window
    openSplunkPopup(url, 'CorrelationSearchEdit');
    
    var strippedName = stripForCorrelationSearch(detectionName);
    showToast('Opened Correlation Search: ' + strippedName, 'success');
    console.log('Opened Correlation Search:', url);
}

function switchRevalTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.reval-sub-tab').forEach(function(tab) {
        tab.classList.toggle('active', tab.dataset.revalTab === tabName);
    });
    
    // Update tab content
    document.getElementById('reval-tab-analysis').classList.toggle('hidden', tabName !== 'analysis');
    document.getElementById('reval-tab-splunk').classList.toggle('hidden', tabName !== 'splunk');
    
    // Render launcher if switching to splunk tab
    if (tabName === 'splunk') {
        renderSplunkLauncher();
    }
}

function renderSplunkLauncher() {
    var container = document.getElementById('splunk-recent-list');
    if (!container) return;
    
    if (splunkRecentDetections.length === 0) {
        container.innerHTML = '<p class="splunk-empty">No detections opened yet. Click a <span class="btn-splunk-demo">SPLK</span> button from the Analysis tab.</p>';
        return;
    }
    
    var html = '';
    splunkRecentDetections.forEach(function(name) {
        var strippedName = stripForRevalidation(name);
        html += '<div class="splunk-recent-item">';
        html += '<span class="splunk-recent-name">' + escapeHtml(strippedName) + '</span>';
        html += '<button class="btn-splunk btn-sm" onclick="openSplunkDashboard(\'' + escapeAttr(name) + '\')">Open in Splunk ↗</button>';
        html += '</div>';
    });
    container.innerHTML = html;
}

function openSplunkEmpty() {
    // Open dashboard without a detection pre-selected
    var url = buildSplunkDashboardUrl('');
    openSplunkPopup(url, 'SplunkRevalidation');
    showToast('Opened Splunk dashboard', 'info');
}

function openHealthDashboard() {
    // Open UC Health Dashboard (separate from Reval Dashboard)
    var url = SPLUNK_CONFIG.baseUrl + SPLUNK_CONFIG.healthDashboardPath;
    openSplunkPopup(url, 'UCHealthDashboard');
    showToast('Opened UC Health Dashboard', 'info');
}

/**
 * Navigate to Library tab and show a specific detection
 */
function goToLibraryDetection(detectionName) {
    // Switch to Library tab
    switchTab('library');
    
    // Find the detection
    var found = detections.find(function(d) {
        return d['Detection Name'] === detectionName;
    });
    
    if (found) {
        // Clear any existing filters
        document.getElementById('library-search').value = detectionName;
        filterLibrary();
        
        // Open the detection detail
        setTimeout(function() {
            showLibraryDetail(detectionName);
        }, 100);
    } else {
        showToast('Detection not found: ' + detectionName, 'error');
    }
}

// =============================================================================
// HISTORY
// =============================================================================

function initHistory() {
    document.getElementById('history-detection-search').addEventListener('input', debounce(renderHistoryDetectionList, 300));
    document.getElementById('history-domain-filter').addEventListener('change', renderHistoryDetectionList);
    document.getElementById('history-has-history-filter').addEventListener('change', renderHistoryDetectionList);
    
    var sortFilter = document.getElementById('history-sort-filter');
    if (sortFilter) sortFilter.addEventListener('change', renderHistoryDetectionList);
    
    var analystFilter = document.getElementById('history-analyst-filter');
    if (analystFilter) analystFilter.addEventListener('change', renderHistoryDetectionList);
    
    var reasonFilter = document.getElementById('history-reason-filter');
    if (reasonFilter) reasonFilter.addEventListener('change', renderHistoryDetectionList);
    
    var fieldFilter = document.getElementById('history-field-filter');
    if (fieldFilter) fieldFilter.addEventListener('change', renderHistoryDetectionList);
    
    document.querySelectorAll('.history-type-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.history-type-btn').forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
            if (selectedHistoryDetection) renderHistoryTimeline(selectedHistoryDetection);
        });
    });
}

function populateHistoryFilters() {
    var analysts = {}, reasons = {}, fields = {};
    var reasonLabels = { false_positives: 'False Positives', performance: 'Performance', coverage: 'Coverage', threshold: 'Threshold', data_source: 'Data Source', other: 'Other' };
    
    Object.keys(detectionMetadata).forEach(function(name) {
        var meta = detectionMetadata[name];
        if (meta.history) {
            meta.history.forEach(function(h) {
                if (h.analyst) analysts[h.analyst] = (analysts[h.analyst] || 0) + 1;
                if (h.reason) reasons[h.reason] = (reasons[h.reason] || 0) + 1;
                if (h.fieldsModified) {
                    h.fieldsModified.forEach(function(f) {
                        fields[f] = (fields[f] || 0) + 1;
                    });
                }
            });
        }
    });
    
    // Populate analyst filter
    var analystSelect = document.getElementById('history-analyst-filter');
    if (analystSelect) {
        var html = '<option value="">All Analysts</option>';
        Object.keys(analysts).sort().forEach(function(a) {
            html += '<option value="' + escapeAttr(a) + '">' + escapeHtml(a) + ' (' + analysts[a] + ')</option>';
        });
        analystSelect.innerHTML = html;
    }
    
    // Populate reason filter
    var reasonSelect = document.getElementById('history-reason-filter');
    if (reasonSelect) {
        var html = '<option value="">All Reasons</option>';
        Object.keys(reasons).forEach(function(r) {
            html += '<option value="' + escapeAttr(r) + '">' + (reasonLabels[r] || r) + ' (' + reasons[r] + ')</option>';
        });
        reasonSelect.innerHTML = html;
    }
    
    // Populate field filter
    var fieldSelect = document.getElementById('history-field-filter');
    if (fieldSelect) {
        var html = '<option value="">All Fields</option>';
        Object.keys(fields).sort(function(a, b) { return fields[b] - fields[a]; }).forEach(function(f) {
            html += '<option value="' + escapeAttr(f) + '">' + (FIELD_LABELS[f] || f) + ' (' + fields[f] + ')</option>';
        });
        fieldSelect.innerHTML = html;
    }
}

function addToHistory(name, type, description, oldData) {
    if (!detectionMetadata[name]) detectionMetadata[name] = { history: [], parsed: {} };
    detectionMetadata[name].history.unshift({
        id: Date.now(),
        type: type,
        description: description,
        timestamp: new Date().toISOString(),
        oldData: oldData ? JSON.stringify(oldData) : null
    });
    if (detectionMetadata[name].history.length > 50) {
        detectionMetadata[name].history = detectionMetadata[name].history.slice(0, 50);
    }
}

function getHistoryCounts(name) {
    var meta = detectionMetadata[name];
    var history = meta && meta.history ? meta.history : [];
    return {
        total: history.length,
        tunes: history.filter(function(h) { return h.type === 'tune'; }).length,
        retrofits: history.filter(function(h) { return h.type === 'retrofit'; }).length,
        revalidations: history.filter(function(h) { return h.type === 'revalidation' || h.subtype === 'revalidation'; }).length
    };
}

function renderHistoryDetectionList() {
    var search = document.getElementById('history-detection-search').value.toLowerCase();
    var domainFilter = document.getElementById('history-domain-filter').value.toLowerCase();
    var hasHistoryFilter = document.getElementById('history-has-history-filter').value;
    var sortFilter = document.getElementById('history-sort-filter');
    var sortBy = sortFilter ? sortFilter.value : 'name';
    
    var analystFilter = document.getElementById('history-analyst-filter');
    var reasonFilter = document.getElementById('history-reason-filter');
    var fieldFilter = document.getElementById('history-field-filter');
    var analystVal = analystFilter ? analystFilter.value : '';
    var reasonVal = reasonFilter ? reasonFilter.value : '';
    var fieldVal = fieldFilter ? fieldFilter.value : '';
    
    var filtered = detections.filter(function(d) {
        if (search && (d['Detection Name'] || '').toLowerCase().indexOf(search) === -1) return false;
        if (domainFilter && (d['Security Domain'] || '').toLowerCase() !== domainFilter) return false;
        
        var meta = detectionMetadata[d['Detection Name']];
        var hasHistory = meta && meta.history && meta.history.length > 0;
        if (hasHistoryFilter === 'yes' && !hasHistory) return false;
        if (hasHistoryFilter === 'no' && hasHistory) return false;
        
        // Analyst filter
        if (analystVal && meta && meta.history) {
            var hasAnalyst = meta.history.some(function(h) { return h.analyst === analystVal; });
            if (!hasAnalyst) return false;
        }
        
        // Reason filter
        if (reasonVal && meta && meta.history) {
            var hasReason = meta.history.some(function(h) { return h.reason === reasonVal; });
            if (!hasReason) return false;
        }
        
        // Field filter
        if (fieldVal && meta && meta.history) {
            var hasField = meta.history.some(function(h) { 
                return h.fieldsModified && h.fieldsModified.indexOf(fieldVal) >= 0;
            });
            if (!hasField) return false;
        }
        
        return true;
    });
    
    // Sort
    if (sortBy === 'history-count') {
        filtered.sort(function(a, b) {
            var countA = getHistoryCounts(a['Detection Name']).total;
            var countB = getHistoryCounts(b['Detection Name']).total;
            return countB - countA;
        });
    } else if (sortBy === 'recent') {
        filtered.sort(function(a, b) {
            var metaA = detectionMetadata[a['Detection Name']];
            var metaB = detectionMetadata[b['Detection Name']];
            var lastA = metaA && metaA.history && metaA.history[0] ? new Date(metaA.history[0].timestamp) : new Date(0);
            var lastB = metaB && metaB.history && metaB.history[0] ? new Date(metaB.history[0].timestamp) : new Date(0);
            return lastB - lastA;
        });
    } else {
        filtered.sort(function(a, b) { return (a['Detection Name'] || '').localeCompare(b['Detection Name'] || ''); });
    }
    
    var container = document.getElementById('history-detection-list');
    
    // Update count display
    var countEl = document.getElementById('history-list-count');
    if (countEl) {
        countEl.textContent = filtered.length + ' detection' + (filtered.length !== 1 ? 's' : '');
    }
    
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No detections found</p></div>';
        return;
    }
    
    var html = '';
    filtered.forEach(function(d) {
        var name = d['Detection Name'];
        var counts = getHistoryCounts(name);
        var isSelected = selectedHistoryDetection === name;
        
        html += '<div class="history-detection-item ' + (isSelected ? 'selected' : '') + '" onclick="selectHistoryDetection(\'' + escapeAttr(name) + '\')">';
        html += '<h4>' + escapeHtml(name) + '</h4>';
        html += '<div class="history-item-tags">';
        if (counts.revalidations > 0) {
            html += '<span class="history-tag revalidation">Revalidations (' + counts.revalidations + ')</span>';
        }
        if (counts.tunes > 0) {
            html += '<span class="history-tag tune">Tunes (' + counts.tunes + ')</span>';
        }
        if (counts.retrofits > 0) {
            html += '<span class="history-tag retrofit">Retrofits (' + counts.retrofits + ')</span>';
        }
        if (counts.total === 0) {
            html += '<span class="history-tag empty">No history</span>';
        }
        html += '</div>';
        html += '</div>';
    });
    container.innerHTML = html;
}

function selectHistoryDetection(name) {
    selectedHistoryDetection = name;
    renderHistoryDetectionList();
    renderHistoryTimeline(name);
}

function renderHistoryTimeline(name) {
    document.getElementById('history-detail-title').textContent = name;
    
    var meta = detectionMetadata[name];
    var history = meta && meta.history ? meta.history : [];
    
    var activeBtn = document.querySelector('.history-type-btn.active');
    var typeFilter = activeBtn ? activeBtn.dataset.type : 'all';
    var filtered = typeFilter === 'all' ? history : history.filter(function(h) { return h.type === typeFilter; });
    
    var counts = getHistoryCounts(name);
    document.getElementById('history-total-entries').textContent = counts.total;
    document.getElementById('history-tune-count').textContent = counts.tunes;
    document.getElementById('history-retrofit-count').textContent = counts.retrofits;
    
    var revalCountEl = document.getElementById('history-reval-count');
    if (revalCountEl) revalCountEl.textContent = counts.revalidations;
    
    var container = document.getElementById('history-timeline');
    var icons = { tune: '🔧', retrofit: '⚡', version: '📝', revalidation: '✓' };
    
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="empty-icon">📜</span><p>No history entries</p></div>';
        return;
    }
    
    var html = '';
    filtered.forEach(function(h) {
        var entryType = h.type || 'version';
        html += '<div class="history-entry ' + entryType + '">';
        html += '<div class="history-entry-marker">' + (icons[entryType] || '📝') + '</div>';
        html += '<div class="history-entry-content">';
        html += '<div class="history-entry-header">';
        html += '<span class="history-entry-type">' + entryType.charAt(0).toUpperCase() + entryType.slice(1) + '</span>';
        html += '<span class="history-entry-date">' + formatDate(h.timestamp) + '</span>';
        html += '</div>';
        html += '<div class="history-entry-desc">' + escapeHtml(h.description || 'No description') + '</div>';
        html += '<div class="history-entry-meta">';
        if (h.jira) {
            html += '<span class="history-entry-jira">' + escapeHtml(h.jira) + '</span>';
        }
        if (h.analyst) {
            html += '<span>By: ' + escapeHtml(h.analyst) + '</span>';
        }
        if (h.fieldsModified && h.fieldsModified.length > 0) {
            html += '<span>Fields: ' + h.fieldsModified.map(function(f) { return FIELD_LABELS[f] || f; }).join(', ') + '</span>';
        }
        if (h.reason) {
            html += '<span>Reason: ' + escapeHtml(h.reason) + '</span>';
        }
        html += '</div>';
        html += '</div></div>';
    });
    container.innerHTML = html;
}

// =============================================================================
// REPORTS
// =============================================================================

function renderReports() {
    var total = detections.length || 1;
    
    var withMitre = detections.filter(function(d) { return d['Mitre ID'] && d['Mitre ID'].length > 0; }).length;
    var withDrilldowns = detections.filter(function(d) { return d['Drilldown Name (Legacy)'] || d['Drilldown Name 1']; }).length;
    var complete = detections.filter(function(d) { return MANDATORY_FIELDS.every(function(f) { return hasValue(d, f); }); }).length;
    
    var riskSum = 0;
    var maxRisk = 0;
    var minRisk = 100;
    detections.forEach(function(d) {
        var risk = getRiskScore(d);
        riskSum += risk;
        if (risk > maxRisk) maxRisk = risk;
        if (risk < minRisk && risk > 0) minRisk = risk;
    });
    var avgRisk = detections.length ? Math.round(riskSum / detections.length) : 0;
    
    var uniqueMitre = {};
    detections.forEach(function(d) {
        (d['Mitre ID'] || []).forEach(function(id) { uniqueMitre[id] = true; });
    });
    var mitreCount = Object.keys(uniqueMitre).length;
    
    var uniqueIndexes = {};
    detections.forEach(function(d) {
        parseSPL(d['Search String']).indexes.forEach(function(idx) { uniqueIndexes[idx] = true; });
    });
    var indexCount = Object.keys(uniqueIndexes).length;
    
    var totalDrilldowns = 0;
    detections.forEach(function(d) {
        if (d['Drilldown Name (Legacy)']) totalDrilldowns++;
        for (var i = 1; i <= 15; i++) {
            if (d['Drilldown Name ' + i]) totalDrilldowns++;
        }
    });
    
    document.getElementById('report-coverage-mitre').textContent = Math.round(withMitre/total*100) + '%';
    document.getElementById('report-coverage-drilldowns').textContent = Math.round(withDrilldowns/total*100) + '%';
    document.getElementById('report-avg-risk').textContent = avgRisk;
    document.getElementById('report-total').textContent = detections.length;
    
    var extraStatsContainer = document.getElementById('report-extra-stats');
    if (extraStatsContainer) {
        extraStatsContainer.innerHTML = 
            '<div class="stat-card"><div class="stat-value">' + mitreCount + '</div><div class="stat-label">Unique MITRE</div></div>' +
            '<div class="stat-card"><div class="stat-value">' + indexCount + '</div><div class="stat-label">Data Sources</div></div>' +
            '<div class="stat-card"><div class="stat-value">' + totalDrilldowns + '</div><div class="stat-label">Total Drilldowns</div></div>' +
            '<div class="stat-card"><div class="stat-value">' + complete + '</div><div class="stat-label">Complete</div></div>' +
            '<div class="stat-card"><div class="stat-value">' + maxRisk + '</div><div class="stat-label">Max Risk</div></div>' +
            '<div class="stat-card"><div class="stat-value">' + (minRisk < 100 ? minRisk : 0) + '</div><div class="stat-label">Min Risk</div></div>';
    }
    
    // Data sources
    var sources = {};
    detections.forEach(function(d) {
        parseSPL(d['Search String']).indexes.forEach(function(idx) {
            sources[idx] = (sources[idx] || 0) + 1;
        });
    });
    var sortedSources = Object.keys(sources).map(function(k) { return [k, sources[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var maxSource = sortedSources.length > 0 ? sortedSources[0][1] : 1;
    var sourceHtml = '';
    sortedSources.slice(0, 10).forEach(function(item) {
        sourceHtml += '<div class="chart-bar-horizontal"><span class="chart-bar-label">' + escapeHtml(item[0]) + '</span><div class="chart-bar-fill" style="width: ' + (item[1]/maxSource)*100 + '%;"></div><span class="chart-bar-value">' + item[1] + '</span></div>';
    });
    document.getElementById('report-datasources').innerHTML = sourceHtml || '<div class="list-empty">No data</div>';
    
    // Platforms
    var platforms = {};
    detections.forEach(function(d) {
        parseSPL(d['Search String']).customTags.forEach(function(t) {
            platforms[t.tag] = (platforms[t.tag] || 0) + 1;
        });
    });
    var sortedPlatforms = Object.keys(platforms).map(function(k) { return [k, platforms[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var maxPlatform = sortedPlatforms.length > 0 ? sortedPlatforms[0][1] : 1;
    var platformHtml = '';
    sortedPlatforms.slice(0, 8).forEach(function(item) {
        platformHtml += '<div class="chart-bar-horizontal"><span class="chart-bar-label">' + escapeHtml(item[0]) + '</span><div class="chart-bar-fill" style="width: ' + (item[1]/maxPlatform)*100 + '%; background: var(--retrofit-color);"></div><span class="chart-bar-value">' + item[1] + '</span></div>';
    });
    document.getElementById('report-platforms').innerHTML = platformHtml || '<div class="list-empty">No data</div>';
    
    // MITRE Heatmap
    var tactics = {};
    detections.forEach(function(d) {
        (d['Mitre ID'] || []).forEach(function(id) {
            tactics[id] = (tactics[id] || 0) + 1;
        });
    });
    var sortedTactics = Object.keys(tactics).map(function(k) { return [k, tactics[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var maxTactic = sortedTactics.length > 0 ? sortedTactics[0][1] : 1;
    var tacticHtml = '';
    if (sortedTactics.length > 0) {
        sortedTactics.slice(0, 20).forEach(function(item) {
            var opacity = 0.2 + (item[1]/maxTactic) * 0.8;
            tacticHtml += '<div class="mitre-heatmap-cell" style="background: rgba(168, 85, 247, ' + opacity + ');">' + item[0] + '<span class="count">' + item[1] + '</span></div>';
        });
    } else {
        tacticHtml = '<div class="list-empty">No MITRE data</div>';
    }
    document.getElementById('report-mitre-heatmap').innerHTML = tacticHtml;
    
    // Severity
    var sevCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    detections.forEach(function(d) {
        var s = (d['Severity/Priority'] || '').toLowerCase();
        if (sevCounts.hasOwnProperty(s)) sevCounts[s]++;
    });
    var colors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', informational: 'var(--info)' };
    var sevHtml = '';
    Object.keys(sevCounts).forEach(function(s) {
        var c = sevCounts[s];
        sevHtml += '<div class="chart-bar-horizontal"><span class="chart-bar-label" style="text-transform: capitalize;">' + s + '</span><div class="chart-bar-fill" style="width: ' + Math.round(c/total*100) + '%; background: ' + colors[s] + ';"></div><span class="chart-bar-value">' + c + ' (' + Math.round(c/total*100) + '%)</span></div>';
    });
    document.getElementById('report-severity').innerHTML = sevHtml;
    
    // Quality
    var withDescription = detections.filter(function(d) { return d['Description'] && d['Description'].trim() && d['Description'] !== d['Objective']; }).length;
    var withRoles = detections.filter(function(d) { return d['Roles'] && d['Roles'].some(function(r) { return r.Name; }); }).length;
    var withAnalystSteps = detections.filter(function(d) { return d['Analyst Next Steps'] && d['Analyst Next Steps'].trim(); }).length;
    
    var metrics = {
        'Has MITRE Tags': withMitre,
        'Has Drilldowns': withDrilldowns,
        'Has Roles/Owners': withRoles,
        'Has Analyst Steps': withAnalystSteps,
        'Has Description': withDescription,
        'All Mandatory': complete
    };
    var qualityHtml = '';
    Object.keys(metrics).forEach(function(l) {
        var c = metrics[l];
        var pct = Math.round(c/total*100);
        var colorClass = pct >= 80 ? 'success' : pct >= 50 ? 'warning' : 'error';
        qualityHtml += '<div class="chart-bar-horizontal"><span class="chart-bar-label">' + l + '</span><div class="chart-bar-fill ' + colorClass + '" style="width: ' + pct + '%;"></div><span class="chart-bar-value">' + pct + '% (' + c + ')</span></div>';
    });
    document.getElementById('report-quality').innerHTML = qualityHtml;
    
    // Domains
    var domains = {};
    detections.forEach(function(d) {
        var domain = d['Security Domain'] || 'Unassigned';
        domains[domain] = (domains[domain] || 0) + 1;
    });
    var sortedDomains = Object.keys(domains).map(function(k) { return [k, domains[k]]; }).sort(function(a, b) { return b[1] - a[1]; });
    var maxDomain = sortedDomains.length > 0 ? sortedDomains[0][1] : 1;
    var domainHtml = '';
    sortedDomains.forEach(function(item) {
        domainHtml += '<div class="chart-bar-horizontal"><span class="chart-bar-label">' + escapeHtml(item[0]) + '</span><div class="chart-bar-fill" style="width: ' + (item[1]/maxDomain)*100 + '%; background: var(--tune-color);"></div><span class="chart-bar-value">' + item[1] + '</span></div>';
    });
    var domainContainer = document.getElementById('report-domains');
    if (domainContainer) domainContainer.innerHTML = domainHtml || '<div class="list-empty">No data</div>';
    
    // Origins
    var origins = {};
    detections.forEach(function(d) {
        var origin = d['origin'] || 'unknown';
        origins[origin] = (origins[origin] || 0) + 1;
    });
    var originHtml = '<div class="origin-breakdown">';
    Object.keys(origins).forEach(function(o) {
        originHtml += '<div class="origin-item"><span class="origin-label">' + o + '</span><span class="origin-count">' + origins[o] + '</span></div>';
    });
    originHtml += '</div>';
    var originContainer = document.getElementById('report-origins');
    if (originContainer) originContainer.innerHTML = originHtml;
}

// =============================================================================
// SETTINGS
// =============================================================================

function initSettings() {
    document.getElementById('btn-test-connection').addEventListener('click', testGitHubConnection);
    document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
    document.getElementById('btn-migrate-filenames').addEventListener('click', function() {
        if (confirm('This will rename all detection and metadata files to follow the naming convention:\\n\\n<domain>_<name>_rule.json\\n<domain>_<name>_rule_meta.json\\n\\nContinue?')) {
            migrateFileNamesToNewConvention();
        }
    });
    document.getElementById('btn-reparse-all').addEventListener('click', function() {
        if (confirm('This will re-parse all ' + detections.length + ' detections and update their metadata.\\n\\nContinue?')) {
            detections.forEach(function(d) { parseAndSaveMetadata(d); });
            saveToLocalStorage();
            buildDynamicFilters();
            showToast('Re-parsed ' + detections.length + ' detections', 'success');
        }
    });
    
    var pathInputs = ['setting-detections-path', 'setting-metadata-path'];
    pathInputs.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
            el.addEventListener('blur', function() {
                el.value = sanitizePathInput(el.value);
            });
        }
    });
    
    document.getElementById('setting-github-url').value = githubConfig.baseUrl || '';
    document.getElementById('setting-repo').value = githubConfig.repo || '';
    document.getElementById('setting-branch').value = githubConfig.branch || 'main';
    document.getElementById('setting-token').value = githubConfig.token || '';
    document.getElementById('setting-detections-path').value = githubConfig.detectionsPath || 'detections';
    document.getElementById('setting-metadata-path').value = githubConfig.metadataPath || 'metadata';
}

function openSettingsModal() {
    document.getElementById('modal-settings').classList.remove('hidden');
    document.getElementById('settings-status').innerHTML = '';
    
    document.getElementById('setting-github-url').value = githubConfig.baseUrl || '';
    document.getElementById('setting-repo').value = githubConfig.repo || '';
    document.getElementById('setting-branch').value = githubConfig.branch || 'main';
    document.getElementById('setting-token').value = githubConfig.token || '';
    document.getElementById('setting-detections-path').value = githubConfig.detectionsPath || 'detections';
    document.getElementById('setting-metadata-path').value = githubConfig.metadataPath || 'metadata';
}

async function testGitHubConnection() {
    var config = getSettingsFromForm();
    var statusEl = document.getElementById('settings-status');
    
    if (!config.repo || !config.token) {
        statusEl.className = 'settings-status error';
        statusEl.textContent = 'Repository and Token are required';
        return;
    }
    
    if (config.detectionsPath.includes('://') || config.metadataPath.includes('://')) {
        statusEl.className = 'settings-status error';
        statusEl.innerHTML = '✗ Paths should be folder names only. Auto-corrected.';
        document.getElementById('setting-detections-path').value = sanitizePathInput(config.detectionsPath);
        document.getElementById('setting-metadata-path').value = sanitizePathInput(config.metadataPath);
        return;
    }
    
    statusEl.className = 'settings-status info';
    statusEl.textContent = 'Testing connection...';
    
    var testApi = new GitHubAPI(config);
    var result = await testApi.testConnection();
    
    if (result.success) {
        try {
            await testApi.listFiles(config.detectionsPath);
            statusEl.className = 'settings-status success';
            statusEl.innerHTML = '✓ Connection successful! Repository and paths verified.';
        } catch (e) {
            statusEl.className = 'settings-status warning';
            statusEl.innerHTML = '✓ Connected to repository<br>⚠ Detections folder not found - will be created on first save.';
        }
    } else {
        statusEl.className = 'settings-status error';
        statusEl.textContent = '✗ Connection failed: ' + result.message;
    }
}

function getSettingsFromForm() {
    return {
        baseUrl: document.getElementById('setting-github-url').value.trim(),
        repo: document.getElementById('setting-repo').value.trim(),
        branch: document.getElementById('setting-branch').value.trim() || 'main',
        token: document.getElementById('setting-token').value.trim(),
        detectionsPath: sanitizePathInput(document.getElementById('setting-detections-path').value.trim()) || 'detections',
        metadataPath: sanitizePathInput(document.getElementById('setting-metadata-path').value.trim()) || 'metadata'
    };
}

async function saveSettings() {
    var config = getSettingsFromForm();
    
    if (!config.repo || !config.token) {
        showToast('Repository and Token are required', 'warning');
        return;
    }
    
    var testApi = new GitHubAPI(config);
    var result = await testApi.testConnection();
    
    if (!result.success) {
        showToast('Connection failed: ' + result.message, 'error');
        return;
    }
    
    githubConfig = Object.assign({}, config, { connected: true });
    localStorage.setItem('dmf_github_config', JSON.stringify(githubConfig));
    github = new GitHubAPI(githubConfig);
    
    closeAllModals();
    showToast('Settings saved! Click Sync to load data from GitHub.', 'success');
    updateSyncStatus('idle', 'Click Sync');
}

// =============================================================================
// MODALS - TUNE/RETROFIT OPENS EDITOR
// =============================================================================

function initModals() {
    document.querySelectorAll('.modal-overlay').forEach(function(o) {
        o.addEventListener('click', closeAllModals);
    });
    document.querySelectorAll('.modal-close').forEach(function(b) {
        b.addEventListener('click', closeAllModals);
    });
    initImportModal();
    document.getElementById('btn-submit-tune').addEventListener('click', submitTune);
    document.getElementById('btn-submit-retrofit').addEventListener('click', submitRetrofit);
    document.getElementById('btn-confirm-yes').addEventListener('click', executeConfirmAction);
    document.getElementById('btn-confirm-no').addEventListener('click', closeAllModals);
}

var pendingConfirmAction = null;
var pendingTuneName = null;
var pendingRetrofitName = null;

function showConfirm(message, onConfirm) {
    document.getElementById('confirm-message').textContent = message;
    pendingConfirmAction = onConfirm;
    document.getElementById('modal-confirm').classList.remove('hidden');
}

function executeConfirmAction() {
    if (pendingConfirmAction) {
        pendingConfirmAction();
        pendingConfirmAction = null;
    }
    closeAllModals();
}

function closeAllModals() {
    document.querySelectorAll('.modal').forEach(function(m) { m.classList.add('hidden'); });
}

function openImportModal() {
    document.getElementById('modal-import').classList.remove('hidden');
    document.getElementById('import-results').classList.add('hidden');
    document.getElementById('import-progress').classList.add('hidden');
}

function initImportModal() {
    var dropzone = document.getElementById('import-dropzone');
    var fileInput = document.getElementById('import-file-input');
    dropzone.addEventListener('click', function() { fileInput.click(); });
    dropzone.addEventListener('dragover', function(e) { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', function() { dropzone.classList.remove('dragover'); });
    dropzone.addEventListener('drop', function(e) { e.preventDefault(); dropzone.classList.remove('dragover'); handleFiles(e.dataTransfer.files); });
    fileInput.addEventListener('change', function() { handleFiles(fileInput.files); });
}

async function handleFiles(files) {
    var progress = document.getElementById('import-progress');
    var progressFill = document.getElementById('import-progress-fill');
    var progressText = document.getElementById('import-progress-text');
    var results = document.getElementById('import-results');
    progress.classList.remove('hidden');
    results.classList.add('hidden');
    var imported = 0, failed = 0;
    
    for (var i = 0; i < files.length; i++) {
        var file = files[i];
        progressText.textContent = 'Processing ' + file.name + '...';
        progressFill.style.width = ((i + 1) / files.length) * 100 + '%';
        try {
            var text = await file.text();
            var detection = JSON.parse(text);
            if (!detection['Detection Name'] && !detection['Search String']) throw new Error('Invalid format');
            // Always regenerate filename to follow naming convention (<domain>_<name>_rule.json)
            detection['file_name'] = generateFileName(
                detection['Detection Name'],
                detection['Security Domain']
            );
            
            var existingIndex = -1;
            for (var j = 0; j < detections.length; j++) {
                if (detections[j]['Detection Name'] === detection['Detection Name']) {
                    existingIndex = j;
                    break;
                }
            }
            if (existingIndex >= 0) {
                detections[existingIndex] = detection;
            } else {
                detections.push(detection);
            }
            parseAndSaveMetadata(detection);

            if (github) {
                var saved = await saveDetectionToGitHub(detection);
                if (saved) {
                    await saveMetadataToGitHub(detection['Detection Name'], detectionMetadata[detection['Detection Name']], detection.file_name);
                }
            }

            imported++;
        } catch (e) {
            console.error('Failed: ' + file.name, e);
            failed++;
        }
    }

    // Update compiled files after all imports complete
    if (github && imported > 0) {
        progressText.textContent = 'Updating aggregate files...';
        try {
            await updateCompiledFiles();
        } catch (compileError) {
            console.warn('Could not update compiled files:', compileError.message);
        }
    }

    saveToLocalStorage();
    filteredDetections = detections.slice();
    progressText.textContent = 'Complete!';
    results.classList.remove('hidden');
    results.innerHTML = '<p><strong>Import Complete</strong></p><p>✓ Imported: ' + imported + '</p>' + (failed > 0 ? '<p>✗ Failed: ' + failed + '</p>' : '');
    buildDynamicFilters();
    renderLibrary();
    renderDashboard();
    showToast('Imported ' + imported + ' detection(s)', 'success');
}

function exportAllDetections() {
    if (detections.length === 0) { showToast('No detections', 'warning'); return; }
    var exportData = {
        exportDate: new Date().toISOString(),
        version: '6.0',
        detectionsCount: detections.length,
        files: {},
        metadata: detectionMetadata,
        parsingRules: parsingRules
    };
    detections.forEach(function(d) {
        exportData.files[d['file_name'] || generateFileName(d['Detection Name'], d['Security Domain'])] = d;
    });
    downloadFile('de_mainframe_export.json', JSON.stringify(exportData, null, 2));
    showToast('Exported ' + detections.length + ' detections', 'success');
}

function downloadFile(filename, content) {
    var blob = new Blob([content], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// TUNE MODAL - OPENS EDITOR AFTER
function openTuneModal(name) {
    pendingTuneName = name;
    document.getElementById('modal-tune').classList.remove('hidden');
    document.getElementById('tune-detection-name').textContent = name;
    document.getElementById('tune-description').value = '';
    document.getElementById('tune-reason').value = '';
    document.getElementById('tune-jira').value = '';
    document.getElementById('tune-analyst').value = '';
    
    // Populate multi-select dropdown
    renderFieldsMultiSelect('tune-fields');
}

function renderFieldsMultiSelect(prefix) {
    var dropdown = document.getElementById(prefix + '-dropdown');
    var display = document.getElementById(prefix + '-display');
    var allFields = MANDATORY_FIELDS.concat(KEY_FIELDS);
    
    var html = '';
    allFields.forEach(function(field) {
        var label = FIELD_LABELS[field] || field;
        html += '<label class="multi-select-option"><input type="checkbox" value="' + escapeAttr(field) + '" onchange="updateMultiSelectDisplay(\'' + prefix + '\')"><span>' + escapeHtml(label) + '</span></label>';
    });
    dropdown.innerHTML = html;
    display.innerHTML = '<span class="placeholder">Select fields...</span>';
}

function toggleMultiSelect(prefix) {
    var dropdown = document.getElementById(prefix + '-dropdown');
    dropdown.classList.toggle('hidden');
}

function updateMultiSelectDisplay(prefix) {
    var dropdown = document.getElementById(prefix + '-dropdown');
    var display = document.getElementById(prefix + '-display');
    var selected = [];
    dropdown.querySelectorAll('input:checked').forEach(function(cb) {
        selected.push(FIELD_LABELS[cb.value] || cb.value);
    });
    
    if (selected.length === 0) {
        display.innerHTML = '<span class="placeholder">Select fields...</span>';
    } else if (selected.length <= 3) {
        display.innerHTML = selected.map(function(s) { return '<span class="multi-select-tag">' + escapeHtml(s) + '</span>'; }).join('');
    } else {
        display.innerHTML = '<span class="multi-select-tag">' + selected.length + ' fields selected</span>';
    }
}

function getSelectedFields(prefix) {
    var dropdown = document.getElementById(prefix + '-dropdown');
    var selected = [];
    dropdown.querySelectorAll('input:checked').forEach(function(cb) {
        selected.push(cb.value);
    });
    return selected;
}

function submitTune() {
    var name = pendingTuneName;
    var desc = document.getElementById('tune-description').value.trim();
    var reason = document.getElementById('tune-reason').value;
    var jira = document.getElementById('tune-jira').value.trim();
    var analyst = document.getElementById('tune-analyst').value.trim();
    var fieldsModified = getSelectedFields('tune-fields');
    
    if (!desc) { showToast('Description is required', 'warning'); return; }
    if (!jira || jira.length !== 4 || !/^\d{4}$/.test(jira)) { 
        showToast('JIRA Issue must be 4 digits (e.g., 1234)', 'warning'); 
        return; 
    }
    if (!analyst) { showToast('Analyst name is required', 'warning'); return; }
    
    // Store tune info for when detection is saved
    if (!detectionMetadata[name]) detectionMetadata[name] = { history: [], parsed: {} };
    detectionMetadata[name].pendingTune = {
        type: 'tune',
        description: desc,
        reason: reason,
        jira: 'MRDP-' + jira,
        analyst: analyst,
        fieldsModified: fieldsModified,
        timestamp: new Date().toISOString()
    };
    
    closeAllModals();
    
    // Open editor in tune mode
    loadDetectionIntoEditor(name, 'tune');
    showToast('Make your tuning changes and save to record the tune.', 'info');
}

// RETROFIT MODAL - OPENS EDITOR AFTER
function openRetrofitModal(name) {
    pendingRetrofitName = name;
    document.getElementById('modal-retrofit').classList.remove('hidden');
    document.getElementById('retrofit-detection-name').textContent = name;
    document.getElementById('retrofit-description').value = '';
    document.getElementById('retrofit-type').value = 'schema';
    document.getElementById('retrofit-jira').value = '';
    document.getElementById('retrofit-analyst').value = '';
    
    // Populate multi-select dropdown
    renderFieldsMultiSelect('retrofit-fields');
}

function submitRetrofit() {
    var name = pendingRetrofitName;
    var desc = document.getElementById('retrofit-description').value.trim();
    var type = document.getElementById('retrofit-type').value;
    var jira = document.getElementById('retrofit-jira').value.trim();
    var analyst = document.getElementById('retrofit-analyst').value.trim();
    var fieldsModified = getSelectedFields('retrofit-fields');
    
    if (!desc) { showToast('Description is required', 'warning'); return; }
    if (!jira || jira.length !== 4 || !/^\d{4}$/.test(jira)) { 
        showToast('JIRA Issue must be 4 digits (e.g., 1234)', 'warning'); 
        return; 
    }
    if (!analyst) { showToast('Analyst name is required', 'warning'); return; }
    
    // Store retrofit info for when detection is saved
    if (!detectionMetadata[name]) detectionMetadata[name] = { history: [], parsed: {} };
    detectionMetadata[name].pendingRetrofit = {
        type: 'retrofit',
        subtype: type,
        description: desc,
        jira: 'MRDP-' + jira,
        analyst: analyst,
        fieldsModified: fieldsModified,
        timestamp: new Date().toISOString()
    };
    
    closeAllModals();
    
    // Open editor in retrofit mode
    loadDetectionIntoEditor(name, 'retrofit');
    showToast('Make your retrofit changes and save to record the retrofit.', 'info');
}

function confirmDeleteDetection(name) {
    showConfirm('Delete "' + name + '"? This cannot be undone.', function() { deleteDetection(name); });
}

async function deleteDetection(name) {
    var detection = detections.find(function(d) { return d['Detection Name'] === name; });
    var index = -1;
    for (var i = 0; i < detections.length; i++) {
        if (detections[i]['Detection Name'] === name) {
            index = i;
            break;
        }
    }
    if (index > -1) {
        if (github && detection) await deleteDetectionFromGitHub(detection);
        detections.splice(index, 1);
        delete detectionMetadata[name];
        saveToLocalStorage();
        filteredDetections = detections.slice();
        selectedLibraryDetection = null;
        document.getElementById('detail-placeholder').classList.remove('hidden');
        document.getElementById('library-detail-content').classList.add('hidden');
        renderLibrary();
        renderDashboard();
        closeAllModals();
        showToast('Detection deleted', 'info');
    }
}

// =============================================================================
// UTILITIES
// =============================================================================

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeAttr(text) {
    if (!text) return '';
    return String(text)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');
}

function formatDate(dateStr) {
    if (!dateStr) return 'Never';
    var date = new Date(dateStr);
    // Use absolute timestamp format: DD/MM/YYYY HH:MM
    var day = String(date.getDate()).padStart(2, '0');
    var month = String(date.getMonth() + 1).padStart(2, '0');
    var year = date.getFullYear();
    var hours = String(date.getHours()).padStart(2, '0');
    var minutes = String(date.getMinutes()).padStart(2, '0');
    return day + '/' + month + '/' + year + ' ' + hours + ':' + minutes;
}

function formatDateTime(dateStr) {
    if (!dateStr) return 'N/A';
    var date = new Date(dateStr);
    // Use absolute timestamp format: DD/MM/YYYY HH:MM
    var day = String(date.getDate()).padStart(2, '0');
    var month = String(date.getMonth() + 1).padStart(2, '0');
    var year = date.getFullYear();
    var hours = String(date.getHours()).padStart(2, '0');
    var minutes = String(date.getMinutes()).padStart(2, '0');
    return day + '/' + month + '/' + year + ' ' + hours + ':' + minutes;
}

function debounce(func, wait) {
    var t;
    return function() {
        var args = arguments;
        var context = this;
        clearTimeout(t);
        t = setTimeout(function() { func.apply(context, args); }, wait);
    };
}

function showToast(message, type) {
    type = type || 'info';
    var container = document.getElementById('toast-container');
    var toast = document.createElement('div');
    toast.className = 'toast ' + type;
    var icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
    toast.innerHTML = '<span class="toast-icon">' + icons[type] + '</span><span class="toast-message">' + message + '</span><span class="toast-close" onclick="this.parentElement.remove()">×</span>';
    container.appendChild(toast);
    setTimeout(function() {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(function() { toast.remove(); }, 300);
    }, 4000);
}

function initKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeAllModals();
        if (e.ctrlKey || e.metaKey) {
            if (e.key === 's') {
                e.preventDefault();
                if (document.getElementById('view-editor').classList.contains('active')) saveDetection();
            } else if (e.key === 'n') {
                e.preventDefault();
                createNewDetection();
            } else if (e.key === 'i') {
                e.preventDefault();
                openImportModal();
            } else if (e.key === 'e') {
                e.preventDefault();
                exportAllDetections();
            } else if (e.key === 'f' && document.getElementById('view-library').classList.contains('active')) {
                e.preventDefault();
                document.getElementById('search-input').focus();
            }
        }
        if (!e.ctrlKey && !e.metaKey && !e.altKey && !e.target.matches('input, textarea, select')) {
            var views = ['dashboard', 'library', 'editor', 'config', 'revalidation', 'history', 'reports'];
            var num = parseInt(e.key);
            if (num >= 1 && num <= 7) switchView(views[num - 1]);
        }
    });
    
    // Close multi-select dropdowns when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.multi-select-wrapper')) {
            document.querySelectorAll('.multi-select-dropdown').forEach(function(dd) {
                dd.classList.add('hidden');
            });
        }
    });
}

// =============================================================================
// METADATA MODAL
// =============================================================================

function openMetadataModal(name) {
    var detection = detections.find(function(d) { return d['Detection Name'] === name; });
    var meta = detectionMetadata[name] || {};
    
    // Generate parsed data if not available
    if (!meta.parsed && detection) {
        meta.parsed = parseSPL(detection['Search String'] || '');
        meta.drilldownVars = parseDrilldownVariables(detection);
        meta.allDrilldownVars = meta.drilldownVars;
    }
    
    document.getElementById('modal-metadata').classList.remove('hidden');
    document.getElementById('metadata-detection-name').textContent = name;
    
    // Render formatted view
    renderFormattedMetadata(name, detection, meta);
    
    // Render JSON view with syntax highlighting
    var fullMeta = Object.assign({}, meta, { _detection: detection });
    var jsonContent = document.getElementById('metadata-json-content');
    jsonContent.innerHTML = syntaxHighlightJSON(JSON.stringify(fullMeta, null, 2));
    
    // Set up view toggle
    document.querySelectorAll('.metadata-view-toggle .toggle-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.metadata-view-toggle .toggle-btn').forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
            
            if (btn.dataset.view === 'json') {
                document.getElementById('metadata-formatted').classList.add('hidden');
                document.getElementById('metadata-json').classList.remove('hidden');
            } else {
                document.getElementById('metadata-formatted').classList.remove('hidden');
                document.getElementById('metadata-json').classList.add('hidden');
            }
        });
    });
}

function renderFormattedMetadata(name, detection, meta) {
    var html = '';
    
    // TTL Status
    var ttl = calculateTTL(detection['Last Modified']);
    var ttlClass = getTTLClass(ttl.days);
    html += '<div class="metadata-section">';
    html += '<h4>TTL Status</h4>';
    html += '<div class="metadata-ttl ' + ttlClass + '">';
    html += '<span class="ttl-days">' + ttl.days + ' days</span>';
    html += '<span class="ttl-label">' + (ttl.days <= 0 ? 'EXPIRED' : ttl.days <= 30 ? 'Critical' : ttl.days <= 90 ? 'Warning' : 'OK') + '</span>';
    html += '</div></div>';
    
    // Parsed SPL Data (metadata-only)
    var parsed = meta.parsed || {};
    var hasParsedData = parsed.indexes && parsed.indexes.length || 
                        parsed.sourcetypes && parsed.sourcetypes.length || 
                        parsed.eventCodes && parsed.eventCodes.length ||
                        parsed.macros && parsed.macros.length ||
                        parsed.lookups && parsed.lookups.length ||
                        parsed.evalFields && parsed.evalFields.length ||
                        parsed.mainSearchFields && parsed.mainSearchFields.length ||
                        parsed.mainSearchFunctions && parsed.mainSearchFunctions.length ||
                        parsed.byFields && parsed.byFields.length;
    
    if (hasParsedData) {
        html += '<div class="metadata-section">';
        html += '<h4>Parsed SPL Data</h4>';
        html += '<p class="metadata-note">These fields are parsed from the SPL search.</p>';
        html += '<div class="metadata-parsed">';
        if (parsed.indexes && parsed.indexes.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Indexes:</span><span class="parsed-tags">' + parsed.indexes.map(function(i) { return '<span class="tag datasource">' + escapeHtml(i) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.sourcetypes && parsed.sourcetypes.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Sourcetypes:</span><span class="parsed-tags">' + parsed.sourcetypes.map(function(s) { return '<span class="tag">' + escapeHtml(s) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.eventCodes && parsed.eventCodes.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Event Codes:</span><span class="parsed-tags">' + parsed.eventCodes.map(function(e) { return '<span class="tag">' + escapeHtml(e) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.macros && parsed.macros.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Macros:</span><span class="parsed-tags">' + parsed.macros.map(function(m) { return '<span class="tag macro">`' + escapeHtml(m) + '`</span>'; }).join('') + '</span></div>';
        }
        if (parsed.lookups && parsed.lookups.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Lookups:</span><span class="parsed-tags">' + parsed.lookups.map(function(l) { return '<span class="tag">' + escapeHtml(l) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.evalFields && parsed.evalFields.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Eval Fields:</span><span class="parsed-tags">' + parsed.evalFields.map(function(f) { return '<span class="tag">' + escapeHtml(f) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.mainSearchFields && parsed.mainSearchFields.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Main Search Fields:</span><span class="parsed-tags">' + parsed.mainSearchFields.map(function(f) { return '<span class="tag field">' + escapeHtml(f) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.mainSearchFunctions && parsed.mainSearchFunctions.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Search Functions:</span><span class="parsed-tags">' + parsed.mainSearchFunctions.map(function(f) { return '<span class="tag func">' + escapeHtml(f) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.byFields && parsed.byFields.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Stats By Fields:</span><span class="parsed-tags">' + parsed.byFields.map(function(f) { return '<span class="tag by-field">' + escapeHtml(f) + '</span>'; }).join('') + '</span></div>';
        }
        if (parsed.customTags && parsed.customTags.length) {
            html += '<div class="parsed-item"><span class="parsed-label">Custom Tags:</span><span class="parsed-tags">' + parsed.customTags.map(function(t) { return '<span class="tag custom">' + escapeHtml(t.category + ': ' + t.tag) + '</span>'; }).join('') + '</span></div>';
        }
        html += '</div></div>';
    }
    
    // Drilldown Variables (metadata-only)
    var drilldownVars = meta.drilldownVars || meta.allDrilldownVars || {};
    // Handle nested structure
    if (drilldownVars.drilldownVars) {
        drilldownVars = drilldownVars.drilldownVars;
    }
    var hasVars = false;
    var varHtml = '<div class="metadata-section">';
    varHtml += '<h4>Drilldown Variables</h4>';
    varHtml += '<div class="metadata-parsed">';
    Object.keys(drilldownVars).forEach(function(key) {
        var vars = drilldownVars[key];
        if (vars && vars.length > 0) {
            hasVars = true;
            varHtml += '<div class="parsed-item"><span class="parsed-label">' + escapeHtml(key) + ':</span><span class="parsed-tags">' + vars.map(function(v) { return '<span class="tag variable">$' + escapeHtml(v) + '$</span>'; }).join('') + '</span></div>';
        }
    });
    varHtml += '</div></div>';
    if (hasVars) html += varHtml;
    
    // Metadata-only fields
    var metadataFields = ['needsTune', 'needsRetrofit', 'lastTuned', 'lastRetrofitted', 'lastParsed'];
    var hasMetaFields = false;
    var metaFieldsHtml = '<div class="metadata-section"><h4>Metadata Status</h4><div class="metadata-parsed">';
    metadataFields.forEach(function(f) {
        if (meta[f] !== undefined && meta[f] !== null) {
            hasMetaFields = true;
            var val = meta[f];
            if (typeof val === 'boolean') val = val ? 'Yes' : 'No';
            if (f.indexOf('last') === 0 && val) val = new Date(val).toLocaleString();
            metaFieldsHtml += '<div class="parsed-item"><span class="parsed-label">' + f + ':</span><span class="parsed-value">' + escapeHtml(String(val)) + '</span></div>';
        }
    });
    metaFieldsHtml += '</div></div>';
    if (hasMetaFields) html += metaFieldsHtml;
    
    // History Summary
    var counts = getHistoryCounts(name);
    html += '<div class="metadata-section">';
    html += '<h4>History Summary</h4>';
    html += '<div class="metadata-history-summary">';
    html += '<span class="history-count total">' + counts.total + ' Total</span>';
    html += '<span class="history-count tune">' + counts.tunes + ' Tunes</span>';
    html += '<span class="history-count retrofit">' + counts.retrofits + ' Retrofits</span>';
    html += '<span class="history-count reval">' + counts.revalidations + ' Revalidations</span>';
    html += '</div></div>';
    
    // Recent History
    if (meta.history && meta.history.length > 0) {
        html += '<div class="metadata-section">';
        html += '<h4>Recent History (Last 5)</h4>';
        html += '<div class="metadata-history-list">';
        meta.history.slice(0, 5).forEach(function(h) {
            var icon = h.type === 'tune' ? '🔧' : h.type === 'retrofit' ? '⚡' : '📝';
            html += '<div class="metadata-history-item ' + h.type + '">';
            html += '<span class="history-icon">' + icon + '</span>';
            html += '<div class="history-details">';
            html += '<div class="history-desc">' + escapeHtml(h.description || 'No description') + '</div>';
            html += '<div class="history-meta">';
            if (h.jira) html += '<span class="jira">' + h.jira + '</span>';
            if (h.analyst) html += '<span>by ' + escapeHtml(h.analyst) + '</span>';
            html += '<span>' + new Date(h.timestamp).toLocaleDateString() + '</span>';
            html += '</div></div></div>';
        });
        html += '</div></div>';
    }
    
    document.getElementById('metadata-formatted').innerHTML = html;
}

function copyMetadataJson() {
    var json = document.getElementById('metadata-json-content').textContent;
    navigator.clipboard.writeText(json);
    showToast('Metadata JSON copied', 'success');
}

// =============================================================================
// REPORTS TABS
// =============================================================================

function initReportsTabs() {
    document.querySelectorAll('.reports-tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.reports-tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.reports-tab-content').forEach(function(c) { c.classList.add('hidden'); c.classList.remove('active'); });
            tab.classList.add('active');
            var content = document.getElementById('reports-' + tab.dataset.tab);
            if (content) {
                content.classList.remove('hidden');
                content.classList.add('active');
            }
            
            // Render specific report
            if (tab.dataset.tab === 'overview') renderDashboard();
            else if (tab.dataset.tab === 'revalidations') renderRevalidationReport();
            else if (tab.dataset.tab === 'metadata') renderMetadataReport();
        });
    });
}

function renderRevalidationReport() {
    var total = detections.length;
    var valid = 0, needTune = 0, needRetrofit = 0;
    var fieldMissing = {};
    var ttlExpired = 0, ttlCritical = 0, ttlWarning = 0, ttlOk = 0;
    
    MANDATORY_FIELDS.concat(KEY_FIELDS).forEach(function(f) { fieldMissing[f] = 0; });
    
    detections.forEach(function(d) {
        var mm = MANDATORY_FIELDS.filter(function(f) { return !hasValue(d, f); });
        var mk = KEY_FIELDS.filter(function(f) { return !hasValue(d, f); });
        mm.forEach(function(f) { fieldMissing[f]++; });
        mk.forEach(function(f) { fieldMissing[f]++; });
        
        if (mm.length === 0) valid++;
        else if (mm.length > 3) needRetrofit++;
        else needTune++;
        
        var ttl = calculateTTL(d['Last Modified']);
        if (ttl.days <= 0) ttlExpired++;
        else if (ttl.days <= 30) ttlCritical++;
        else if (ttl.days <= 90) ttlWarning++;
        else ttlOk++;
    });
    
    document.getElementById('reval-report-total').textContent = total;
    document.getElementById('reval-report-valid').textContent = valid;
    document.getElementById('reval-report-tune').textContent = needTune;
    document.getElementById('reval-report-retrofit').textContent = needRetrofit;
    
    // Field chart
    var fieldHtml = '<div class="field-missing-chart">';
    Object.keys(fieldMissing).sort(function(a, b) { return fieldMissing[b] - fieldMissing[a]; }).forEach(function(f) {
        if (fieldMissing[f] > 0) {
            var pct = (fieldMissing[f] / total * 100).toFixed(1);
            fieldHtml += '<div class="field-bar-row"><span class="field-name">' + (FIELD_LABELS[f] || f) + '</span><div class="field-bar"><div class="field-bar-fill" style="width:' + pct + '%"></div></div><span class="field-count">' + fieldMissing[f] + '</span></div>';
        }
    });
    fieldHtml += '</div>';
    document.getElementById('reval-report-fields').innerHTML = fieldHtml || '<div class="empty-state">All fields complete</div>';
    
    // TTL chart
    var ttlHtml = '<div class="ttl-summary-chart">';
    ttlHtml += '<div class="ttl-bar-item"><span class="ttl-label ttl-expired">Expired</span><span class="ttl-count">' + ttlExpired + '</span></div>';
    ttlHtml += '<div class="ttl-bar-item"><span class="ttl-label ttl-critical">Critical (≤30d)</span><span class="ttl-count">' + ttlCritical + '</span></div>';
    ttlHtml += '<div class="ttl-bar-item"><span class="ttl-label ttl-warning">Warning (≤90d)</span><span class="ttl-count">' + ttlWarning + '</span></div>';
    ttlHtml += '<div class="ttl-bar-item"><span class="ttl-label ttl-ok">OK</span><span class="ttl-count">' + ttlOk + '</span></div>';
    ttlHtml += '</div>';
    document.getElementById('reval-report-ttl').innerHTML = ttlHtml;
    
    // History stats (moved from metadata report)
    var totalEntries = 0, totalTunes = 0, totalRetrofits = 0;
    var analysts = {}, reasons = {};
    var recentActivity = [];
    
    Object.keys(detectionMetadata).forEach(function(name) {
        var meta = detectionMetadata[name];
        if (meta.history) {
            meta.history.forEach(function(h) {
                totalEntries++;
                if (h.type === 'tune') totalTunes++;
                if (h.type === 'retrofit') totalRetrofits++;
                if (h.analyst) analysts[h.analyst] = (analysts[h.analyst] || 0) + 1;
                if (h.reason) reasons[h.reason] = (reasons[h.reason] || 0) + 1;
                recentActivity.push({ name: name, entry: h });
            });
        }
    });
    
    document.getElementById('reval-report-history-total').textContent = totalEntries;
    document.getElementById('reval-report-tunes').textContent = totalTunes;
    document.getElementById('reval-report-retrofits').textContent = totalRetrofits;
    document.getElementById('reval-report-analysts').textContent = Object.keys(analysts).length;
    
    // Analyst chart
    var analystHtml = '<div class="meta-chart">';
    Object.keys(analysts).sort(function(a, b) { return analysts[b] - analysts[a]; }).slice(0, 10).forEach(function(a) {
        analystHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(a) + '</span><span class="meta-count">' + analysts[a] + '</span></div>';
    });
    analystHtml += '</div>';
    document.getElementById('reval-report-analyst-chart').innerHTML = analystHtml || '<div class="empty-state">No analyst data</div>';
    
    // Reason chart
    var reasonLabels = { false_positives: 'False Positives', performance: 'Performance', coverage: 'Coverage', threshold: 'Threshold', data_source: 'Data Source', other: 'Other' };
    var reasonHtml = '<div class="meta-chart">';
    Object.keys(reasons).sort(function(a, b) { return reasons[b] - reasons[a]; }).forEach(function(r) {
        reasonHtml += '<div class="meta-bar-row"><span class="meta-label">' + (reasonLabels[r] || r) + '</span><span class="meta-count">' + reasons[r] + '</span></div>';
    });
    reasonHtml += '</div>';
    document.getElementById('reval-report-reason-chart').innerHTML = reasonHtml || '<div class="empty-state">No reason data</div>';
    
    // Recent timeline
    recentActivity.sort(function(a, b) { return new Date(b.entry.timestamp) - new Date(a.entry.timestamp); });
    var timelineHtml = '<div class="activity-timeline">';
    recentActivity.slice(0, 20).forEach(function(item) {
        var h = item.entry;
        var icon = h.type === 'tune' ? '🔧' : h.type === 'retrofit' ? '⚡' : '📝';
        timelineHtml += '<div class="activity-item ' + h.type + '">';
        timelineHtml += '<span class="activity-icon">' + icon + '</span>';
        timelineHtml += '<div class="activity-content">';
        timelineHtml += '<span class="activity-detection">' + escapeHtml(item.name) + '</span>';
        timelineHtml += '<span class="activity-desc">' + escapeHtml(h.description || 'No description') + '</span>';
        timelineHtml += '</div>';
        timelineHtml += '<span class="activity-date">' + new Date(h.timestamp).toLocaleDateString() + '</span>';
        timelineHtml += '</div>';
    });
    timelineHtml += '</div>';
    document.getElementById('reval-report-timeline').innerHTML = timelineHtml || '<div class="empty-state">No activity</div>';
}

function renderMetadataReport() {
    // Aggregate parsed data from all metadata
    var indexes = {};
    var sourcetypes = {};
    var mainSearchFields = {};
    var mainSearchFunctions = {};
    var macros = {};
    var lookups = {};
    var detectionsWithMeta = 0;
    
    Object.keys(detectionMetadata).forEach(function(name) {
        var meta = detectionMetadata[name];
        if (meta.parsed) {
            detectionsWithMeta++;
            
            if (meta.parsed.indexes) {
                meta.parsed.indexes.forEach(function(i) {
                    indexes[i] = (indexes[i] || 0) + 1;
                });
            }
            if (meta.parsed.sourcetypes) {
                meta.parsed.sourcetypes.forEach(function(s) {
                    sourcetypes[s] = (sourcetypes[s] || 0) + 1;
                });
            }
            if (meta.parsed.mainSearchFields) {
                meta.parsed.mainSearchFields.forEach(function(f) {
                    mainSearchFields[f] = (mainSearchFields[f] || 0) + 1;
                });
            }
            if (meta.parsed.mainSearchFunctions) {
                meta.parsed.mainSearchFunctions.forEach(function(f) {
                    mainSearchFunctions[f] = (mainSearchFunctions[f] || 0) + 1;
                });
            }
            if (meta.parsed.macros) {
                meta.parsed.macros.forEach(function(m) {
                    macros[m] = (macros[m] || 0) + 1;
                });
            }
            if (meta.parsed.lookups) {
                meta.parsed.lookups.forEach(function(l) {
                    lookups[l] = (lookups[l] || 0) + 1;
                });
            }
        }
    });
    
    // Update summary stats
    document.getElementById('meta-report-detections').textContent = detectionsWithMeta;
    document.getElementById('meta-report-indexes').textContent = Object.keys(indexes).length;
    document.getElementById('meta-report-sourcetypes').textContent = Object.keys(sourcetypes).length;
    document.getElementById('meta-report-functions').textContent = Object.keys(mainSearchFunctions).length;
    
    // Indexes chart
    var indexHtml = '<div class="meta-chart">';
    Object.keys(indexes).sort(function(a, b) { return indexes[b] - indexes[a]; }).slice(0, 15).forEach(function(i) {
        indexHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(i) + '</span><span class="meta-count">' + indexes[i] + '</span></div>';
    });
    indexHtml += '</div>';
    document.getElementById('meta-report-index-chart').innerHTML = indexHtml || '<div class="empty-state">No index data</div>';
    
    // Sourcetypes chart
    var stHtml = '<div class="meta-chart">';
    Object.keys(sourcetypes).sort(function(a, b) { return sourcetypes[b] - sourcetypes[a]; }).slice(0, 15).forEach(function(s) {
        stHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(s) + '</span><span class="meta-count">' + sourcetypes[s] + '</span></div>';
    });
    stHtml += '</div>';
    document.getElementById('meta-report-sourcetype-chart').innerHTML = stHtml || '<div class="empty-state">No sourcetype data</div>';
    
    // Main Search Fields chart
    var fieldsHtml = '<div class="meta-chart">';
    Object.keys(mainSearchFields).sort(function(a, b) { return mainSearchFields[b] - mainSearchFields[a]; }).slice(0, 15).forEach(function(f) {
        fieldsHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(f) + '</span><span class="meta-count">' + mainSearchFields[f] + '</span></div>';
    });
    fieldsHtml += '</div>';
    document.getElementById('meta-report-fields-chart').innerHTML = fieldsHtml || '<div class="empty-state">No field data</div>';
    
    // Search Functions chart
    var funcHtml = '<div class="meta-chart">';
    Object.keys(mainSearchFunctions).sort(function(a, b) { return mainSearchFunctions[b] - mainSearchFunctions[a]; }).slice(0, 15).forEach(function(f) {
        funcHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(f) + '</span><span class="meta-count">' + mainSearchFunctions[f] + '</span></div>';
    });
    funcHtml += '</div>';
    document.getElementById('meta-report-func-chart').innerHTML = funcHtml || '<div class="empty-state">No function data</div>';
    
    // Macros chart
    var macroHtml = '<div class="meta-chart">';
    Object.keys(macros).sort(function(a, b) { return macros[b] - macros[a]; }).slice(0, 15).forEach(function(m) {
        macroHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(m) + '</span><span class="meta-count">' + macros[m] + '</span></div>';
    });
    macroHtml += '</div>';
    document.getElementById('meta-report-macros-chart').innerHTML = macroHtml || '<div class="empty-state">No macros used</div>';
    
    // Lookups chart
    var lookupHtml = '<div class="meta-chart">';
    Object.keys(lookups).sort(function(a, b) { return lookups[b] - lookups[a]; }).slice(0, 15).forEach(function(l) {
        lookupHtml += '<div class="meta-bar-row"><span class="meta-label">' + escapeHtml(l) + '</span><span class="meta-count">' + lookups[l] + '</span></div>';
    });
    lookupHtml += '</div>';
    document.getElementById('meta-report-lookups-chart').innerHTML = lookupHtml || '<div class="empty-state">No lookups used</div>';
}

// Global exports
window.openTuneModal = openTuneModal;
window.openRetrofitModal = openRetrofitModal;
window.loadDetectionIntoEditor = loadDetectionIntoEditor;
window.confirmDeleteDetection = confirmDeleteDetection;
window.removeMitreTag = removeMitreTag;
// =============================================================================
// RESOURCES TAB - V11.15 (GitHub API)
// =============================================================================

var editingResourceId = null;

function initResources() {
    renderResources();
    
    // Search input
    var searchInput = document.getElementById('resources-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(renderResources, 300));
    }
    
    // Category filter
    var categoryFilter = document.getElementById('resources-category-filter');
    if (categoryFilter) {
        categoryFilter.addEventListener('change', renderResources);
    }
    
    // Add Resource button
    var addBtn = document.getElementById('btn-add-resource');
    if (addBtn) {
        addBtn.addEventListener('click', function() {
            openResourceModal();
        });
    }
    
    // Save Resource button
    var saveBtn = document.getElementById('btn-save-resource');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveResource);
    }
    
    // Add Category button
    var addCatBtn = document.getElementById('btn-add-category');
    if (addCatBtn) {
        addCatBtn.addEventListener('click', addNewCategory);
    }
    
    // Modal close handlers
    document.querySelectorAll('#modal-resource .modal-close').forEach(function(btn) {
        btn.addEventListener('click', function() {
            closeResourceModal();
        });
    });
    
    // Update category dropdown
    updateCategoryDropdown();
}

function getDefaultResources() {
    return [
        {
            id: 'res_default_1',
            name: 'Use Case Throttling Status',
            description: 'Overview of Throttling status',
            url: 'https://es-myorg.splunkcloud.com/en-US/app/SplunkEnterpriseSecuritySuite/myorg_use_case_throttling_status?tab=layout_1&form.dd_5TFxjPlG=*',
            category: 'Dashboard',
            addedBy: 'TestUser1',
            addedAt: new Date().toISOString()
        }
    ];
}

function saveResourcesToGitHub() {
    if (!github) {
        return Promise.reject(new Error('Not connected to GitHub'));
    }
    
    var resourcesPath = PATHS.dist + '/resources.json';
    
    // Get SHA first (file may or may not exist)
    return github.getFileSha(resourcesPath)
        .then(function(sha) {
            return github.createOrUpdateFile(resourcesPath, resources, 'Update resources.json', sha);
        })
        .then(function() {
            console.log('✓ Resources saved to GitHub');
        })
        .catch(function(error) {
            console.error('Failed to save resources to GitHub:', error);
            throw error;
        });
}

function renderResources() {
    var container = document.getElementById('resources-grid');
    if (!container) return;
    
    console.log('renderResources called, resources count:', resources.length, resources);
    
    var searchTerm = (document.getElementById('resources-search-input')?.value || '').toLowerCase().trim();
    var categoryFilter = document.getElementById('resources-category-filter')?.value || '';
    
    var filtered = resources.filter(function(r) {
        var matchesSearch = !searchTerm || 
            (r.name && r.name.toLowerCase().indexOf(searchTerm) !== -1) ||
            (r.description && r.description.toLowerCase().indexOf(searchTerm) !== -1);
        var matchesCategory = !categoryFilter || r.category === categoryFilter;
        return matchesSearch && matchesCategory;
    });
    
    // Update count
    var countEl = document.getElementById('resources-count');
    if (countEl) {
        countEl.textContent = filtered.length + ' resource' + (filtered.length !== 1 ? 's' : '');
    }
    
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="empty-icon">📚</span><p>No resources found</p><p class="empty-hint">Click "Add Resource" to add your first resource</p></div>';
        return;
    }
    
    var html = '';
    filtered.forEach(function(r) {
        var categoryClass = (r.category || 'other').toLowerCase().replace(/\s+/g, '-');
        html += '<div class="resource-list-item" data-id="' + (r.id || '') + '">';
        html += '<div class="resource-list-info">';
        html += '<h4>' + escapeHtml(r.name || 'Unnamed') + '</h4>';
        html += '<div class="resource-list-badges">';
        html += '<span class="resource-category-badge ' + categoryClass + '">' + escapeHtml(r.category || 'Other') + '</span>';
        html += '<span class="resource-added-badge">Added by: ' + escapeHtml(r.addedBy || 'Unknown') + '</span>';
        html += '</div>';
        html += '<p class="resource-list-description">' + escapeHtml(r.description || '') + '</p>';
        html += '</div>';
        html += '<div class="resource-list-actions">';
        html += '<button class="btn-primary btn-sm" onclick="openResource(\'' + (r.id || '') + '\')">🔗 Open</button>';
        html += '<button class="btn-edit btn-sm" onclick="editResource(\'' + (r.id || '') + '\')">✏️ Edit</button>';
        html += '<button class="btn-danger btn-sm" onclick="confirmDeleteResource(\'' + (r.id || '') + '\')">🗑️</button>';
        html += '</div>';
        html += '</div>';
    });
    
    container.innerHTML = html;
}

function openResourceModal(resourceId) {
    editingResourceId = resourceId || null;
    var modal = document.getElementById('modal-resource');
    var title = document.getElementById('resource-modal-title');
    
    if (resourceId) {
        // Edit mode
        var resource = resources.find(function(r) { return r.id === resourceId; });
        if (resource) {
            title.textContent = '✏️ Edit Resource';
            document.getElementById('resource-name').value = resource.name;
            document.getElementById('resource-description').value = resource.description;
            document.getElementById('resource-url').value = resource.url;
            document.getElementById('resource-category').value = resource.category;
            document.getElementById('resource-added-by').value = resource.addedBy;
        }
    } else {
        // Add mode
        title.textContent = '➕ Add Resource';
        document.getElementById('resource-form').reset();
    }
    
    modal.classList.remove('hidden');
}

function closeResourceModal() {
    var modal = document.getElementById('modal-resource');
    modal.classList.add('hidden');
    editingResourceId = null;
    document.getElementById('resource-form').reset();
}

function saveResource() {
    var name = document.getElementById('resource-name').value.trim();
    var description = document.getElementById('resource-description').value.trim();
    var url = document.getElementById('resource-url').value.trim();
    var category = document.getElementById('resource-category').value;
    var addedBy = document.getElementById('resource-added-by').value.trim();
    
    if (!name || !description || !url || !category || !addedBy) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    var isEdit = !!editingResourceId;
    
    if (editingResourceId) {
        // Update existing
        var idx = resources.findIndex(function(r) { return r.id === editingResourceId; });
        if (idx !== -1) {
            resources[idx].name = name;
            resources[idx].description = description;
            resources[idx].url = url;
            resources[idx].category = category;
            resources[idx].addedBy = addedBy;
            resources[idx].updatedAt = new Date().toISOString();
        }
    } else {
        // Add new
        resources.push({
            id: 'res_' + Date.now(),
            name: name,
            description: description,
            url: url,
            category: category,
            addedBy: addedBy,
            addedAt: new Date().toISOString()
        });
    }
    
    // Save to GitHub
    showToast('Saving resource...', 'info');
    saveResourcesToGitHub()
        .then(function() {
            closeResourceModal();
            renderResources();
            showToast(isEdit ? 'Resource updated' : 'Resource added', 'success');
        })
        .catch(function(error) {
            showToast('Failed to save resource: ' + error.message, 'error');
        });
}

function editResource(id) {
    openResourceModal(id);
}

function confirmDeleteResource(id) {
    var resource = resources.find(function(r) { return r.id === id; });
    if (!resource) return;
    
    showConfirm('Are you sure you want to delete the resource "' + resource.name + '"?', function(confirmed) {
        if (confirmed) {
            deleteResource(id);
        }
    });
}

function deleteResource(id) {
    resources = resources.filter(function(r) { return r.id !== id; });
    
    // Save to GitHub
    showToast('Deleting resource...', 'info');
    saveResourcesToGitHub()
        .then(function() {
            renderResources();
            showToast('Resource deleted', 'success');
        })
        .catch(function(error) {
            showToast('Failed to delete resource: ' + error.message, 'error');
        });
}

function openResource(id) {
    var resource = resources.find(function(r) { return r.id === id; });
    if (resource && resource.url) {
        window.open(resource.url, '_blank');
    }
}

function addNewCategory() {
    var newCategory = prompt('Enter new category name:');
    if (newCategory && newCategory.trim()) {
        newCategory = newCategory.trim();
        if (resourceCategories.indexOf(newCategory) === -1) {
            resourceCategories.push(newCategory);
            updateCategoryDropdown();
            document.getElementById('resource-category').value = newCategory;
            showToast('Category added: ' + newCategory, 'success');
        } else {
            showToast('Category already exists', 'info');
        }
    }
}

function updateCategoryDropdown() {
    var select = document.getElementById('resource-category');
    var filter = document.getElementById('resources-category-filter');
    
    // Collect unique categories from resources
    var uniqueCats = {};
    resourceCategories.forEach(function(cat) { uniqueCats[cat] = true; });
    resources.forEach(function(r) {
        if (r.category) uniqueCats[r.category] = true;
    });
    var allCategories = Object.keys(uniqueCats).sort();
    
    if (select) {
        var currentValue = select.value;
        select.innerHTML = '<option value="">Select category...</option>';
        allCategories.forEach(function(cat) {
            select.innerHTML += '<option value="' + escapeHtml(cat) + '">' + escapeHtml(cat) + '</option>';
        });
        if (currentValue) select.value = currentValue;
    }
    
    if (filter) {
        var currentFilter = filter.value;
        filter.innerHTML = '<option value="">All Categories</option>';
        allCategories.forEach(function(cat) {
            filter.innerHTML += '<option value="' + escapeHtml(cat) + '">' + escapeHtml(cat) + '</option>';
        });
        if (currentFilter) filter.value = currentFilter;
    }
}

// Export Resources functions
window.editResource = editResource;
window.confirmDeleteResource = confirmDeleteResource;
window.deleteResource = deleteResource;
window.openResource = openResource;

// =============================================================================
// MACROS TAB
// =============================================================================

var pendingMacroName = null; // Used for pre-populating from validation errors

function initMacros() {
    renderMacros();

    // Search input
    var searchInput = document.getElementById('macros-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(renderMacros, 300));
    }

    // Add Macro button
    var addBtn = document.getElementById('btn-add-macro');
    if (addBtn) {
        addBtn.addEventListener('click', function() {
            openMacroModal();
        });
    }

    // Save Macro button
    var saveBtn = document.getElementById('btn-save-macro');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveMacro);
    }

    // Modal close handlers
    document.querySelectorAll('#modal-macro .modal-close').forEach(function(btn) {
        btn.addEventListener('click', function() {
            closeMacroModal();
        });
    });

    document.querySelector('#modal-macro .modal-overlay').addEventListener('click', closeMacroModal);
}

function renderMacros() {
    var container = document.getElementById('macros-grid');
    if (!container) return;

    var searchTerm = (document.getElementById('macros-search-input')?.value || '').toLowerCase().trim();

    var filtered = loadedMacros.filter(function(m) {
        return !searchTerm || m.toLowerCase().indexOf(searchTerm) !== -1;
    });

    // Sort alphabetically
    filtered.sort(function(a, b) {
        return a.toLowerCase().localeCompare(b.toLowerCase());
    });

    // Update count
    var countEl = document.getElementById('macros-count');
    if (countEl) {
        countEl.textContent = filtered.length + ' macro' + (filtered.length !== 1 ? 's' : '');
    }

    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="empty-icon">📐</span><p>No macros found</p><p class="empty-hint">Click "Add Macro" to register a macro for validation</p></div>';
        return;
    }

    var html = '<div class="macros-grid-items">';
    filtered.forEach(function(m) {
        html += '<div class="macro-list-item">';
        html += '<span class="macro-name">`' + escapeHtml(m) + '`</span>';
        html += '<button class="btn-icon-small btn-delete-macro" onclick="confirmDeleteMacro(\'' + escapeAttr(m) + '\')" title="Delete macro">🗑️</button>';
        html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
}

function openMacroModal(macroName) {
    var modal = document.getElementById('modal-macro');
    var titleEl = document.getElementById('macro-modal-title');
    var nameInput = document.getElementById('macro-name');

    // Clear form
    nameInput.value = '';

    // Check if we have a pending macro name from validation error click
    if (pendingMacroName) {
        nameInput.value = pendingMacroName;
        pendingMacroName = null;
        titleEl.textContent = '➕ Add Missing Macro';
    } else if (macroName) {
        nameInput.value = macroName;
        titleEl.textContent = '➕ Add Macro';
    } else {
        titleEl.textContent = '➕ Add Macro';
    }

    modal.classList.remove('hidden');
    nameInput.focus();
}

function closeMacroModal() {
    var modal = document.getElementById('modal-macro');
    modal.classList.add('hidden');
    pendingMacroName = null;
}

function saveMacro() {
    var nameInput = document.getElementById('macro-name');
    var macroName = nameInput.value.trim();

    // Remove backticks if user included them
    macroName = macroName.replace(/^`|`$/g, '');

    if (!macroName) {
        showToast('Please enter a macro name', 'error');
        return;
    }

    // Check for duplicates
    if (loadedMacros.indexOf(macroName) !== -1) {
        showToast('Macro already exists: ' + macroName, 'error');
        return;
    }

    // Add to loadedMacros
    loadedMacros.push(macroName);
    loadedMacros.sort(function(a, b) {
        return a.toLowerCase().localeCompare(b.toLowerCase());
    });

    // Save to GitHub
    showToast('Saving macro...', 'info');
    saveMacrosToGitHub()
        .then(function() {
            closeMacroModal();
            renderMacros();
            showToast('Macro added: ' + macroName, 'success');
            // Also trigger re-validation if in editor
            validateForm();
        })
        .catch(function(error) {
            showToast('Failed to save macro: ' + error.message, 'error');
        });
}

function confirmDeleteMacro(macroName) {
    showConfirm('Are you sure you want to delete the macro "`' + macroName + '`"?', function(confirmed) {
        if (confirmed) {
            deleteMacro(macroName);
        }
    });
}

function deleteMacro(macroName) {
    loadedMacros = loadedMacros.filter(function(m) { return m !== macroName; });

    // Save to GitHub
    showToast('Deleting macro...', 'info');
    saveMacrosToGitHub()
        .then(function() {
            renderMacros();
            showToast('Macro deleted', 'success');
        })
        .catch(function(error) {
            showToast('Failed to delete macro: ' + error.message, 'error');
        });
}

async function saveMacrosToGitHub() {
    if (!github) {
        saveToLocalStorage();
        return Promise.resolve();
    }

    const macrosPath = PATHS.dist + '/macros.json';
    const content = JSON.stringify(loadedMacros, null, 2);

    try {
        // Try to get current file SHA
        let sha = null;
        try {
            const response = await github.getContents({ path: macrosPath });
            sha = response.data.sha;
        } catch (e) {
            // File doesn't exist, will create new
        }

        await github.createOrUpdateFile({
            path: macrosPath,
            content: content,
            message: 'Update macros.json',
            sha: sha
        });

        saveToLocalStorage();
    } catch (error) {
        console.error('Failed to save macros to GitHub:', error);
        saveToLocalStorage(); // Still save locally
        throw error;
    }
}

function navigateToMacrosWithName(macroName) {
    // Set the pending macro name and switch to macros view
    pendingMacroName = macroName;
    switchView('macros');
    // Open the modal after a short delay to ensure view is rendered
    setTimeout(function() {
        openMacroModal();
    }, 100);
}

// Export Macros functions
window.confirmDeleteMacro = confirmDeleteMacro;
window.deleteMacro = deleteMacro;
window.navigateToMacrosWithName = navigateToMacrosWithName;

window.removeDrilldown = removeDrilldown;
window.closeAllModals = closeAllModals;
window.showConfirm = showConfirm;
window.escapeAttr = escapeAttr;
window.selectLibraryDetection = selectLibraryDetection;
window.selectHistoryDetection = selectHistoryDetection;
window.deleteParsingRule = deleteParsingRule;
window.toggleTheme = toggleTheme;
window.switchView = switchView;
window.openMetadataModal = openMetadataModal;
window.copyMetadataJson = copyMetadataJson;
window.toggleMultiSelect = toggleMultiSelect;
window.updateMultiSelectDisplay = updateMultiSelectDisplay;

console.log('%c⚡ DE-MainFrame V11.15', 'color: #50fa7b; font-size: 16px; font-weight: bold;');
console.log('%c  Auto-loads from GitHub Enterprise on page open', 'color: #8b949e; font-size: 12px;');
console.log('%c  Detection Engineering Platform', 'color: #8b949e; font-size: 12px;');