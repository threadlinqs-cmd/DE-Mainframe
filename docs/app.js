/**
 * DE-MainFrame New UI - Application Logic
 * Nancy-inspired flat, monochrome design
 *
 * Data sources available:
 * - localStorage: For user preferences and cached data
 * - GitHub API: For fetching detection content
 * - dist/ files: For accessing compiled detection data (via ../dist/)
 */

// Password for access (shared with Classic UI)
const ACCESS_PASSWORD = 'secmon2026';

// TTL Configuration
const TTL_DAYS = 365;

// Splunk Configuration (same as Classic UI)
const SPLUNK_CONFIG = {
    baseUrl: 'https://myorg.splunkcloud.com',
    correlationSearchPath: '/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit',
    dashboardPath: '/en-US/app/SplunkEnterpriseSecuritySuite/enhanced_use_case_revalidation_dashboard_copy',
    healthDashboardPath: 'Health_dashboard',
    useCaseFieldName: 'usecase',
    defaultTimeEarliest: '-90d@d',
    defaultTimeLatest: 'now',
    popupWidth: 1400,
    popupHeight: 900
};

// =============================================================================
// SPLUNK INTEGRATION FUNCTIONS
// =============================================================================

// Strip Security Domain prefix and "-Rule" suffix from detection name for dashboard URL
function stripForRevalidation(detectionName) {
    if (!detectionName) return '';
    var name = detectionName;

    // Strip Security Domain prefix (e.g., "Access - ", "Endpoint - ")
    var domains = ['Access', 'Endpoint', 'Network', 'Threat', 'Identity', 'Audit'];
    for (var i = 0; i < domains.length; i++) {
        var prefix = domains[i] + ' - ';
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

// Normalize detection name to ensure proper spacing around separators
function normalizeDetectionName(detectionName) {
    if (!detectionName) return '';
    return detectionName
        .replace(/ -([^ ])/g, ' - $1')  // " -X" → " - X"
        .replace(/([^ ])- /g, '$1 - ')  // "X- " → "X - "
        .replace(/  +/g, ' ');          // collapse multiple spaces
}

// Return full detection name for correlation search (no stripping, with normalization)
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

// Open URL in popup window centered on screen
function openSplunkPopup(url, title) {
    var width = SPLUNK_CONFIG.popupWidth;
    var height = SPLUNK_CONFIG.popupHeight;
    var left = (screen.width - width) / 2;
    var top = (screen.height - height) / 2;
    var features = 'width=' + width + ',height=' + height + ',left=' + left + ',top=' + top;
    features += ',menubar=no,toolbar=no,location=yes,status=yes,resizable=yes,scrollbars=yes';
    window.open(url, title || 'SplunkDashboard', features);
}

// Open Splunk Revalidation Dashboard for a specific detection
function openSplunkDashboard(detectionName) {
    var url = buildSplunkDashboardUrl(detectionName);
    openSplunkPopup(url, 'SplunkRevalidation');
    console.log('Opened Splunk dashboard:', url);
}

// Open Correlation Search Editor for a specific detection
function openCorrelationSearch(detectionName) {
    var url = buildCorrelationSearchUrl(detectionName);
    openSplunkPopup(url, 'CorrelationSearchEdit');
    console.log('Opened Correlation Search:', url);
}

// Open UC Health Dashboard
function openHealthDashboard() {
    var url = SPLUNK_CONFIG.baseUrl + '/' + SPLUNK_CONFIG.healthDashboardPath;
    openSplunkPopup(url, 'UCHealthDashboard');
}

// Open Splunk Dashboard without a pre-selected detection
function openSplunkEmpty() {
    var url = buildSplunkDashboardUrl('');
    openSplunkPopup(url, 'SplunkRevalidation');
}

// =============================================================================
// GITHUB CONFIGURATION - Update these values for your environment
// =============================================================================
const GITHUB_CONFIG = {
    // GitHub URL (github.com or Enterprise)
    baseUrl: 'https://github.com',
    // Repository in 'owner/repo' format
    repo: 'threadlinqs-cmd/DE-Mainframe',
    // Branch name
    branch: 'main',
    // Personal Access Token (for write operations)
    token: '',
    // Base path where all files live
    basePath: 'docs',
    // Subfolder names
    detectionsFolder: 'detections',
    metadataFolder: 'metadata',
    distFolder: 'dist'
};

// Computed paths
const PATHS = {
    detections: GITHUB_CONFIG.basePath ? GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.detectionsFolder : GITHUB_CONFIG.detectionsFolder,
    metadata: GITHUB_CONFIG.basePath ? GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.metadataFolder : GITHUB_CONFIG.metadataFolder,
    dist: GITHUB_CONFIG.basePath ? GITHUB_CONFIG.basePath + '/' + GITHUB_CONFIG.distFolder : GITHUB_CONFIG.distFolder
};

// Security domains for name processing
const SECURITY_DOMAINS = ['Access', 'Endpoint', 'Network', 'Threat', 'Identity', 'Audit'];

// =============================================================================
// GITHUB API CLASS
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

        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        };

        const token = this.config.token;
        if (token && token !== 'YOUR_GITHUB_PAT' && token.length > 10) {
            headers['Authorization'] = 'token ' + token;
        }

        const response = await fetch(url, Object.assign({}, options, { headers: headers }));

        if (!response.ok) {
            const error = await response.json().catch(function() { return {}; });
            if (!suppressErrorLog) {
                console.error('GitHub API Error:', response.status, error);
            }
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

    async getFileSha(path) {
        const cleanPath = this.sanitizePath(path);
        try {
            const data = await this.request('/contents/' + cleanPath + '?ref=' + this.config.branch, {}, true);
            return data && data.sha ? data.sha : null;
        } catch (error) {
            if (error.message && (error.message.includes('404') || error.message.includes('Not Found'))) {
                return null;
            }
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

        if (sha) {
            body.sha = sha;
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

// Global GitHub API instance
let github = null;

// Dynamic GitHub config (can be overridden by Settings)
let githubConfig = {
    baseUrl: GITHUB_CONFIG.baseUrl,
    repo: GITHUB_CONFIG.repo,
    branch: GITHUB_CONFIG.branch,
    token: GITHUB_CONFIG.token,
    detectionsPath: PATHS.detections,
    metadataPath: PATHS.metadata,
    connected: false
};

// Detection metadata storage
let detectionMetadata = {};

// Generate file name from detection name and domain (global version)
function generateFileName(name, domain) {
    if (!name) return '';
    var prefix = '';
    if (domain) {
        var domainMap = {
            'access': 'access', 'endpoint': 'endpoint', 'network': 'network',
            'threat': 'threat', 'identity': 'identity', 'audit': 'audit',
            'application': 'application', 'web': 'web'
        };
        prefix = domainMap[domain.toLowerCase()] || '';
    }
    var cleanName = name.replace(/[<>:"/\\|?*]/g, '').replace(/\s+/g, '_');
    var fileName = (prefix ? prefix + '_' : '') + cleanName;
    return fileName.substring(0, 100) + '.json';
}

// Parse SPL query to extract metadata (global version)
function parseSPL(spl) {
    var result = {
        indexes: [],
        sourcetypes: [],
        eventCodes: [],
        categories: [],
        macros: [],
        lookups: [],
        evalFields: [],
        mainSearchFields: [],
        mainSearchFunctions: [],
        byFields: [],
        functions: [],
        comments: [],
        customTags: []
    };

    if (!spl) return result;

    // Extract comments FIRST (``` comment ```) - NOT macros!
    var commentMatches = spl.match(/```[^`]*```/g);
    if (commentMatches) {
        commentMatches.forEach(function(m) {
            var comment = m.replace(/```/g, '').trim();
            if (comment && result.comments.indexOf(comment) === -1) {
                result.comments.push(comment);
            }
        });
    }

    // Remove comments from SPL for further parsing to avoid false positives
    var cleanSpl = spl.replace(/```[^`]*```/g, ' ');

    // Parse indexes (handles index=, index==, index IN ())
    var indexRegex = /index\s*={1,2}\s*["']?([^\s"'|()]+)["']?/gi;
    var match;
    while ((match = indexRegex.exec(cleanSpl)) !== null) {
        if (result.indexes.indexOf(match[1]) === -1) {
            result.indexes.push(match[1]);
        }
    }
    // Also handle index IN (...)
    var indexInRegex = /index\s+IN\s*\(([^)]+)\)/gi;
    while ((match = indexInRegex.exec(cleanSpl)) !== null) {
        var inValues = match[1].split(',');
        inValues.forEach(function(v) {
            var val = v.trim().replace(/["']/g, '');
            if (val && result.indexes.indexOf(val) === -1) {
                result.indexes.push(val);
            }
        });
    }

    // Parse sourcetypes
    var sourcetypeRegex = /sourcetype\s*={1,2}\s*["']?([^\s"'|()]+)["']?/gi;
    while ((match = sourcetypeRegex.exec(cleanSpl)) !== null) {
        if (result.sourcetypes.indexOf(match[1]) === -1) {
            result.sourcetypes.push(match[1]);
        }
    }

    // Parse Event Codes
    var eventCodeRegex = /EventCode\s*[=!<>]+\s*["']?(\d+)["']?/gi;
    while ((match = eventCodeRegex.exec(cleanSpl)) !== null) {
        if (result.eventCodes.indexOf(match[1]) === -1) {
            result.eventCodes.push(match[1]);
        }
    }

    // Parse categories (Azure/Defender) - quoted values
    var categoryRegex = /category\s*={1,2}\s*["']([^"']+)["']/gi;
    while ((match = categoryRegex.exec(cleanSpl)) !== null) {
        if (result.categories.indexOf(match[1]) === -1) {
            result.categories.push(match[1]);
        }
    }
    // Also handle unquoted category values
    var categoryUnquotedRegex = /category\s*={1,2}\s*([^\s"'|()]+)/gi;
    while ((match = categoryUnquotedRegex.exec(cleanSpl)) !== null) {
        var val = match[1].trim();
        // Skip if it starts with a quote (already handled above)
        if (val && !val.startsWith('"') && !val.startsWith("'") && result.categories.indexOf(val) === -1) {
            result.categories.push(val);
        }
    }

    // Parse macros (single backticks) - use cleanSpl to avoid matching triple backticks
    var macroRegex = /`([^`(]+)(?:\([^)]*\))?`/g;
    while ((match = macroRegex.exec(cleanSpl)) !== null) {
        if (result.macros.indexOf(match[1]) === -1) {
            result.macros.push(match[1]);
        }
    }

    // Parse lookups
    var lookupRegex = /\b(?:lookup|inputlookup|outputlookup)\s+([^\s|,]+)/gi;
    while ((match = lookupRegex.exec(cleanSpl)) !== null) {
        if (result.lookups.indexOf(match[1]) === -1) {
            result.lookups.push(match[1]);
        }
    }

    // Parse eval fields
    var evalRegex = /\beval\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=/gi;
    while ((match = evalRegex.exec(cleanSpl)) !== null) {
        if (result.evalFields.indexOf(match[1]) === -1) {
            result.evalFields.push(match[1]);
        }
    }

    // Parse by fields
    var byRegex = /\bby\s+([a-zA-Z_][a-zA-Z0-9_,\s]*)/gi;
    while ((match = byRegex.exec(cleanSpl)) !== null) {
        var fields = match[1].split(/[,\s]+/);
        fields.forEach(function(f) {
            f = f.trim();
            if (f && result.byFields.indexOf(f) === -1 && f !== 'as' && f !== 'where') {
                result.byFields.push(f);
            }
        });
    }

    // Parse functions (commands after pipes)
    var funcRegex = /\|\s*([a-z_][a-z0-9_]*)/gi;
    while ((match = funcRegex.exec(cleanSpl)) !== null) {
        var fn = match[1].toLowerCase();
        if (result.functions.indexOf(fn) === -1 && fn !== 'lookup' && fn !== 'inputlookup' && fn !== 'outputlookup') {
            result.functions.push(fn);
        }
        if (result.mainSearchFunctions.indexOf(fn) === -1) {
            result.mainSearchFunctions.push(fn);
        }
    }

    return result;
}

// =============================================================================
// GITHUB OPERATION FUNCTIONS
// =============================================================================

// Generate metadata filename from detection name or detection filename
function generateMetaFileName(name, detectionFileName) {
    // If we have the detection's file_name, derive metadata filename from it
    if (detectionFileName && detectionFileName.endsWith('.json')) {
        return detectionFileName.replace(/\.json$/, '.meta.json');
    }
    // Fallback: generate from name
    if (!name) return 'unnamed.meta.json';
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') + '.meta.json';
}

// Update sync status indicator
function updateSyncStatus(status, text) {
    var indicator = document.querySelector('.status-indicator');
    var statusText = document.querySelector('.status-text');

    if (indicator) {
        indicator.classList.remove('status-connected', 'status-disconnected', 'status-syncing', 'status-error');
        indicator.classList.add('status-' + status);
    }
    if (statusText) {
        statusText.textContent = text || status;
    }
}

// Save a detection to GitHub
async function saveDetectionToGitHub(detection) {
    if (!github) {
        console.warn('GitHub not configured. Detection saved locally only.');
        throw new Error('GitHub not configured');
    }

    updateSyncStatus('syncing', 'Saving...');

    var detectionsPath = githubConfig.detectionsPath || PATHS.detections;
    var filename = detection.file_name || generateFileName(detection['Detection Name'], detection['Security Domain']);
    var path = detectionsPath + '/' + filename;
    var message = 'Update detection: ' + detection['Detection Name'];

    try {
        // Check if file exists to get SHA
        var sha = await github.getFileSha(path);

        var result = await github.createOrUpdateFile(path, detection, message, sha);

        // Store SHA for future updates
        detection._sha = result.content.sha;
        detection._path = path;
        detection.file_name = filename;

        updateSyncStatus('connected', 'Synced');
        return true;
    } catch (error) {
        updateSyncStatus('error', 'Save Error');
        console.error('Failed to save detection to GitHub:', error);
        throw error; // Re-throw so caller can handle
    }
}

// Save metadata to GitHub
async function saveMetadataToGitHub(name, metadata, detectionFileName) {
    if (!github) {
        throw new Error('GitHub not configured');
    }

    var metadataPath = githubConfig.metadataPath || PATHS.metadata;
    var filename = generateMetaFileName(name, detectionFileName);
    var path = metadataPath + '/' + filename;
    var message = 'Update metadata: ' + name;

    try {
        var existing = detectionMetadata[name];
        var sha = existing ? existing._sha : null;

        // If no SHA cached, check if file exists on GitHub
        if (!sha) {
            sha = await github.getFileSha(path);
        }

        var metaContent = Object.assign({ detectionName: name }, metadata);
        var result = await github.createOrUpdateFile(path, metaContent, message, sha);

        // Store SHA and path for future updates
        if (!detectionMetadata[name]) detectionMetadata[name] = {};
        detectionMetadata[name]._sha = result.content.sha;
        detectionMetadata[name]._path = path;

        return true;
    } catch (error) {
        console.error('Failed to save metadata to GitHub:', error);
        throw error; // Re-throw so caller can handle
    }
}

// Delete a detection from GitHub
async function deleteDetectionFromGitHub(detection) {
    if (!github) {
        throw new Error('GitHub not configured');
    }

    updateSyncStatus('syncing', 'Deleting...');

    try {
        // Delete detection file
        if (detection._sha && detection._path) {
            await github.deleteFile(detection._path, 'Delete detection: ' + detection['Detection Name'], detection._sha);
        } else if (detection.file_name) {
            var detectionsPath = githubConfig.detectionsPath || PATHS.detections;
            var path = detectionsPath + '/' + detection.file_name;
            var sha = await github.getFileSha(path);
            if (sha) {
                await github.deleteFile(path, 'Delete detection: ' + detection['Detection Name'], sha);
            }
        }

        // Delete metadata file
        var meta = detectionMetadata[detection['Detection Name']];
        if (meta && meta._sha && meta._path) {
            await github.deleteFile(meta._path, 'Delete metadata: ' + detection['Detection Name'], meta._sha);
        }

        updateSyncStatus('connected', 'Synced');
        return true;
    } catch (error) {
        updateSyncStatus('error', 'Delete Error');
        console.error('Failed to delete from GitHub:', error);
        throw error; // Re-throw so caller can handle
    }
}

// Save a file to GitHub (helper for compiled files)
async function saveFileToGitHub(path, content, message) {
    if (!github) {
        throw new Error('GitHub not configured');
    }

    try {
        var sha = await github.getFileSha(path);
        await github.createOrUpdateFile(path, content, message, sha);
        return true;
    } catch (error) {
        console.error('Failed to save file:', path, error);
        throw error; // Re-throw so caller can handle
    }
}

// Update compiled files in dist/ folder
async function updateCompiledFiles(detections) {
    if (!github) {
        console.warn('GitHub not configured. Compiled files not updated.');
        return;
    }

    console.log('Updating compiled files...');

    try {
        // Build compiled detections array (remove internal fields)
        var compiledDetections = detections.map(function(d) {
            var clean = Object.assign({}, d);
            clean._sourceFile = clean.file_name || generateFileName(d['Detection Name'], d['Security Domain']);
            delete clean._sha;
            delete clean._path;
            return clean;
        });

        // Build compiled metadata object
        var compiledMetadata = {};
        Object.keys(detectionMetadata).forEach(function(name) {
            var meta = Object.assign({}, detectionMetadata[name]);
            delete meta._sha;
            delete meta._path;
            compiledMetadata[name] = meta;
        });

        // Build manifest
        var manifest = {
            lastCompiled: new Date().toISOString(),
            version: '1.2',
            counts: {
                detections: compiledDetections.length,
                metadata: Object.keys(compiledMetadata).length
            },
            files: {
                detections: compiledDetections.map(function(d) { return d._sourceFile; }),
                metadata: Object.keys(compiledMetadata).map(function(n) { return n.replace(/[^a-zA-Z0-9_-]/g, '_') + '.meta.json'; })
            }
        };

        var distPath = PATHS.dist;

        // Save all-detections.json
        await saveFileToGitHub(distPath + '/all-detections.json', compiledDetections, 'Update compiled detections');

        // Save all-metadata.json
        await saveFileToGitHub(distPath + '/all-metadata.json', compiledMetadata, 'Update compiled metadata');

        // Save manifest.json
        await saveFileToGitHub(distPath + '/manifest.json', manifest, 'Update manifest');

        console.log('Compiled files updated successfully');
    } catch (error) {
        console.error('Failed to update compiled files:', error);
        // Don't throw - individual file was saved, compiled files are secondary
    }
}

// Parse SPL and save metadata for a detection
function parseAndSaveMetadata(detection) {
    var name = detection['Detection Name'];
    if (!detectionMetadata[name]) detectionMetadata[name] = { history: [], parsed: {} };
    detectionMetadata[name].parsed = parseSPL(detection['Search String']);
    detectionMetadata[name].lastParsed = new Date().toISOString();
    detectionMetadata[name].detectionName = name;
    return detectionMetadata[name];
}

// Initialize GitHub API
function initGitHub() {
    // Load saved config from localStorage first
    var savedConfig = localStorage.getItem('dmf_github_config');
    if (savedConfig) {
        try {
            var parsed = JSON.parse(savedConfig);
            // Merge saved config into githubConfig (preserving any new fields from GITHUB_CONFIG)
            if (parsed.baseUrl) githubConfig.baseUrl = parsed.baseUrl;
            if (parsed.repo) githubConfig.repo = parsed.repo;
            if (parsed.branch) githubConfig.branch = parsed.branch;
            if (parsed.token) githubConfig.token = parsed.token;
            if (parsed.detectionsPath) githubConfig.detectionsPath = parsed.detectionsPath;
            if (parsed.metadataPath) githubConfig.metadataPath = parsed.metadataPath;
            console.log('%c GitHub config loaded from localStorage', 'color: #50fa7b');
            console.log('  Config - repo:', githubConfig.repo, 'branch:', githubConfig.branch, 'token present:', !!githubConfig.token && githubConfig.token.length > 10);
        } catch (e) {
            console.warn('Could not parse saved GitHub config:', e);
        }
    }

    // Use dynamic config with fallbacks to GITHUB_CONFIG
    var token = githubConfig.token || GITHUB_CONFIG.token;

    if (token && token !== 'YOUR_GITHUB_PAT' && token.length > 10) {
        github = new GitHubAPI({
            baseUrl: githubConfig.baseUrl || GITHUB_CONFIG.baseUrl,
            repo: githubConfig.repo || GITHUB_CONFIG.repo,
            branch: githubConfig.branch || GITHUB_CONFIG.branch,
            token: token
        });
        githubConfig.connected = true;
        console.log('%c GitHub API initialized', 'color: #50fa7b');
    } else {
        console.warn('%c GitHub token not configured. Running in local mode.', 'color: #f1fa8c');
        githubConfig.connected = false;
    }
}

// =============================================================================
// LOCAL STORAGE FUNCTIONS - Comprehensive caching
// =============================================================================

// Save all application state to localStorage for caching/offline support
function saveToLocalStorage() {
    try {
        // Save detections array
        var AppRef = window.App || window.NewUIApp;
        if (AppRef && AppRef.state && AppRef.state.detections) {
            localStorage.setItem('dmf_detections', JSON.stringify(AppRef.state.detections));
            console.log('Saved ' + AppRef.state.detections.length + ' detections to localStorage');
        }

        // Save detection metadata object
        if (detectionMetadata && Object.keys(detectionMetadata).length > 0) {
            localStorage.setItem('dmf_metadata', JSON.stringify(detectionMetadata));
            console.log('Saved metadata for ' + Object.keys(detectionMetadata).length + ' detections to localStorage');
        }

        // Save macros (both name list and full objects)
        if (typeof macrosState !== 'undefined' && macrosState.macros) {
            var macroNames = macrosState.macros.map(function(m) { return m.name; });
            localStorage.setItem('dmf_macros', JSON.stringify(macroNames));
            localStorage.setItem('dmf_macros_full', JSON.stringify(macrosState.macros));
            console.log('Saved ' + macrosState.macros.length + ' macros to localStorage');
        }

        // Save resources
        if (typeof resourcesState !== 'undefined' && resourcesState.resources) {
            localStorage.setItem('dmf_resources', JSON.stringify(resourcesState.resources));
            console.log('Saved ' + resourcesState.resources.length + ' resources to localStorage');
        }

        // Save parsing rules
        if (typeof settingsState !== 'undefined' && settingsState.parsingRules) {
            localStorage.setItem('dmf_parsing_rules', JSON.stringify(settingsState.parsingRules));
            console.log('Saved ' + settingsState.parsingRules.length + ' parsing rules to localStorage');
        }

        // Save GitHub config (including token for persistence between sessions)
        // Note: Token is stored because this is a client-side app where users manage their own tokens
        var configToSave = {
            baseUrl: githubConfig.baseUrl,
            repo: githubConfig.repo,
            branch: githubConfig.branch,
            token: githubConfig.token, // Include token for GitHub API access
            detectionsPath: githubConfig.detectionsPath,
            metadataPath: githubConfig.metadataPath,
            connected: githubConfig.connected
        };
        localStorage.setItem('dmf_github_config', JSON.stringify(configToSave));

        console.log('%c[localStorage] All application data saved successfully', 'color: #50fa7b');
        return true;
    } catch (e) {
        console.error('Failed to save to localStorage:', e);
        return false;
    }
}

// Load all cached data from localStorage
function loadFromLocalStorage() {
    var loaded = {
        detections: false,
        metadata: false,
        macros: false,
        resources: false,
        parsingRules: false,
        githubConfig: false
    };

    try {
        // Load detections
        var storedDetections = localStorage.getItem('dmf_detections');
        if (storedDetections) {
            var parsedDetections = JSON.parse(storedDetections);
            if (Array.isArray(parsedDetections) && parsedDetections.length > 0) {
                var AppRef = window.App || window.NewUIApp;
                if (AppRef && AppRef.state) {
                    AppRef.state.detections = parsedDetections;
                    AppRef.state.filteredDetections = parsedDetections.slice();
                }
                loaded.detections = true;
                console.log('Loaded ' + parsedDetections.length + ' detections from localStorage');
            }
        }

        // Load metadata
        var storedMetadata = localStorage.getItem('dmf_metadata');
        if (storedMetadata) {
            var parsedMetadata = JSON.parse(storedMetadata);
            if (parsedMetadata && typeof parsedMetadata === 'object') {
                detectionMetadata = parsedMetadata;
                loaded.metadata = true;
                console.log('Loaded metadata for ' + Object.keys(parsedMetadata).length + ' detections from localStorage');
            }
        }

        // Load macros (full objects preferred, fallback to names)
        var storedMacrosFull = localStorage.getItem('dmf_macros_full');
        var storedMacrosNames = localStorage.getItem('dmf_macros');
        if (storedMacrosFull) {
            var parsedMacros = JSON.parse(storedMacrosFull);
            if (Array.isArray(parsedMacros)) {
                if (typeof macrosState !== 'undefined') {
                    macrosState.macros = parsedMacros;
                    macrosState.filteredMacros = parsedMacros.slice();
                }
                if (typeof editorState !== 'undefined') {
                    editorState.loadedMacros = parsedMacros.map(function(m) { return m.name; });
                }
                loaded.macros = true;
                console.log('Loaded ' + parsedMacros.length + ' macros from localStorage (full)');
            }
        } else if (storedMacrosNames) {
            var parsedNames = JSON.parse(storedMacrosNames);
            if (Array.isArray(parsedNames)) {
                if (typeof editorState !== 'undefined') {
                    editorState.loadedMacros = parsedNames;
                }
                loaded.macros = true;
                console.log('Loaded ' + parsedNames.length + ' macro names from localStorage');
            }
        }

        // Load resources
        var storedResources = localStorage.getItem('dmf_resources');
        if (storedResources) {
            var parsedResources = JSON.parse(storedResources);
            if (Array.isArray(parsedResources)) {
                if (typeof resourcesState !== 'undefined') {
                    resourcesState.resources = parsedResources;
                }
                loaded.resources = true;
                console.log('Loaded ' + parsedResources.length + ' resources from localStorage');
            }
        }

        // Load parsing rules
        var storedRules = localStorage.getItem('dmf_parsing_rules');
        if (storedRules) {
            var parsedRules = JSON.parse(storedRules);
            if (Array.isArray(parsedRules)) {
                if (typeof settingsState !== 'undefined') {
                    settingsState.parsingRules = parsedRules;
                }
                loaded.parsingRules = true;
                console.log('Loaded ' + parsedRules.length + ' parsing rules from localStorage');
            }
        }

        // Load GitHub config
        var storedConfig = localStorage.getItem('dmf_github_config');
        if (storedConfig) {
            var parsedConfig = JSON.parse(storedConfig);
            if (parsedConfig && typeof parsedConfig === 'object') {
                // Merge with current config (don't override token if already set)
                if (parsedConfig.baseUrl) githubConfig.baseUrl = parsedConfig.baseUrl;
                if (parsedConfig.repo) githubConfig.repo = parsedConfig.repo;
                if (parsedConfig.branch) githubConfig.branch = parsedConfig.branch;
                if (parsedConfig.detectionsPath) githubConfig.detectionsPath = parsedConfig.detectionsPath;
                if (parsedConfig.metadataPath) githubConfig.metadataPath = parsedConfig.metadataPath;
                loaded.githubConfig = true;
                console.log('Loaded GitHub config from localStorage');
            }
        }

        console.log('%c[localStorage] Cache load complete:', 'color: #8be9fd', loaded);
        return loaded;
    } catch (e) {
        console.error('Failed to load from localStorage:', e);
        return loaded;
    }
}

// =============================================================================
// GITHUB API FILE FETCHING
// =============================================================================

// Build the GitHub API URL for fetching file contents
function buildGitHubApiUrl(filePath) {
    var baseUrl = (githubConfig.baseUrl || GITHUB_CONFIG.baseUrl).replace(/\/+$/, '');
    var repo = githubConfig.repo || GITHUB_CONFIG.repo;
    var branch = githubConfig.branch || GITHUB_CONFIG.branch;

    var apiUrl;
    if (!baseUrl || baseUrl === 'https://github.com' || baseUrl === 'http://github.com') {
        apiUrl = 'https://api.github.com';
    } else {
        // GitHub Enterprise
        apiUrl = baseUrl + '/api/v3';
    }
    return apiUrl + '/repos/' + repo + '/contents/' + filePath + '?ref=' + branch;
}

// Fetch a JSON file from GitHub using the Contents API
function fetchGitHubFile(filePath) {
    var url = buildGitHubApiUrl(filePath);
    console.log('Fetching:', url);

    var token = githubConfig.token || GITHUB_CONFIG.token;

    // Build headers - only include Authorization if we have a valid token
    var headers = {
        'Accept': 'application/vnd.github.v3.raw'  // Get raw content, not base64
    };

    if (token && token !== 'YOUR_GITHUB_PAT' && token.length > 10) {
        headers['Authorization'] = 'token ' + token;
        console.log('  Using token authentication');
    } else {
        console.warn('%c No valid token - attempting unauthenticated access (public repos only)', 'color: #f1fa8c');
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
// AUTO-LOAD FROM STATIC FILES (GitHub or local)
// =============================================================================

// Main data loading function - loads from GitHub with localStorage fallback
function autoLoadFromStaticFiles() {
    var distPath = PATHS.dist;
    var detectionsFile = distPath + '/all-detections.json';
    var metadataFile = distPath + '/all-metadata.json';
    var resourcesFile = distPath + '/resources.json';
    var macrosFile = distPath + '/all-macros.json';

    console.log('Loading from:', detectionsFile, metadataFile, resourcesFile, macrosFile);

    // Check if GitHub is configured with a valid token
    var token = githubConfig.token || GITHUB_CONFIG.token;
    var useGitHub = token && token !== 'YOUR_GITHUB_PAT' && token.length > 10;

    if (useGitHub) {
        console.log('%c Using GitHub API for data loading', 'color: #50fa7b');

        // Fetch all files in parallel using GitHub API
        Promise.all([
            fetchGitHubFile(detectionsFile),
            fetchGitHubFile(metadataFile),
            fetchGitHubFile(resourcesFile).catch(function() { return []; }), // Resources optional
            fetchGitHubFile(macrosFile).catch(function() { return []; }) // Macros optional
        ])
        .then(function(results) {
            processLoadedData(results[0], results[1], results[2], results[3]);
            var AppRef = window.App || window.NewUIApp;
            if (AppRef) AppRef.updateStatus('connected');
            saveToLocalStorage();
            if (typeof showToast === 'function') {
                showToast('Loaded ' + (results[0] ? results[0].length : 0) + ' detections from GitHub', 'success');
            }
        })
        .catch(function(error) {
            console.error('Failed to load from GitHub:', error);
            console.log('%c Falling back to localStorage...', 'color: #f1fa8c');
            loadFromLocalStorage();
            var AppRef = window.App || window.NewUIApp;
            if (AppRef) AppRef.updateStatus('disconnected');
            finalizeDataLoading();
            if (typeof showToast === 'function') {
                showToast('Using cached data (GitHub unavailable)', 'warning');
            }
        });
    } else {
        console.log('%c No GitHub token - using relative fetch', 'color: #f1fa8c');

        // Fetch from relative paths (for local development)
        var AppRef = window.App || window.NewUIApp;
        var distPath = (AppRef && AppRef.config) ? AppRef.config.distPath : 'dist/';
        Promise.all([
            fetch(distPath + 'all-detections.json').then(function(r) { return r.ok ? r.json() : null; }).catch(function() { return null; }),
            fetch(distPath + 'all-metadata.json').then(function(r) { return r.ok ? r.json() : null; }).catch(function() { return null; }),
            fetch(distPath + 'resources.json').then(function(r) { return r.ok ? r.json() : null; }).catch(function() { return []; }),
            fetch(distPath + 'macros.json').then(function(r) { return r.ok ? r.json() : null; }).catch(function() { return []; })
        ])
        .then(function(results) {
            processLoadedData(results[0], results[1], results[2], results[3]);
            var AppRef2 = window.App || window.NewUIApp;
            if (AppRef2) AppRef2.updateStatus('connected');
            saveToLocalStorage();
        })
        .catch(function(error) {
            console.error('Failed to load from files:', error);
            loadFromLocalStorage();
            var AppRef2 = window.App || window.NewUIApp;
            if (AppRef2) AppRef2.updateStatus('disconnected');
            finalizeDataLoading();
        });
    }
}

// Process loaded data from GitHub or local files
function processLoadedData(detectionsData, metadataData, resourcesData, macrosData) {
    // Get App reference (may be exposed as App or NewUIApp depending on timing)
    var AppRef = window.App || window.NewUIApp;
    if (!AppRef || !AppRef.state) {
        console.error('App not initialized yet, storing data for later');
        window._pendingDetections = detectionsData;
        window._pendingMetadata = metadataData;
        window._pendingResources = resourcesData;
        window._pendingMacros = macrosData;
        return;
    }

    // Load detections
    if (Array.isArray(detectionsData) && detectionsData.length > 0) {
        AppRef.state.detections = detectionsData;
        AppRef.state.filteredDetections = detectionsData.slice();
        console.log('%c Loaded ' + detectionsData.length + ' detections', 'color: #50fa7b');
    } else {
        console.warn('No valid detections data, using empty array');
        AppRef.state.detections = [];
        AppRef.state.filteredDetections = [];
    }

    // Load metadata
    if (metadataData && typeof metadataData === 'object' && Object.keys(metadataData).length > 0) {
        detectionMetadata = metadataData;
        console.log('%c Loaded metadata for ' + Object.keys(metadataData).length + ' detections', 'color: #50fa7b');
    } else {
        console.warn('No valid metadata data');
        detectionMetadata = {};
    }

    // Load resources into resourcesState (will be available once IIFE initializes)
    if (Array.isArray(resourcesData) && resourcesData.length > 0) {
        // Store in a temporary global for resourcesState to pick up
        window._loadedResources = resourcesData;
        console.log('%c Loaded ' + resourcesData.length + ' resources', 'color: #50fa7b');
    }

    // Load macros - store in temporary global for macrosState to pick up
    if (Array.isArray(macrosData) && macrosData.length > 0) {
        window._loadedMacros = macrosData;
        console.log('%c Loaded ' + macrosData.length + ' macros', 'color: #50fa7b');
    }

    finalizeDataLoading();
}

// Finalize data loading - update UI
function finalizeDataLoading() {
    var AppRef = window.App || window.NewUIApp;
    if (!AppRef) return;

    AppRef.populateFilters();
    AppRef.renderLibrary();

    // Update other views if initialized
    if (typeof calculateStatusCounts === 'function') {
        calculateStatusCounts();
        if (typeof filterRevalidation === 'function') filterRevalidation();
    }
    if (typeof buildHistoryEntries === 'function') {
        buildHistoryEntries();
    }
    if (typeof renderReports === 'function') {
        renderReports();
    }

    console.log('%c Data loading complete', 'color: #50fa7b');
}

// Build Correlation Search Editor URL (full normalized name)
function buildCorrelationSearchUrl(detectionName) {
    if (!detectionName) return '#';
    var fullName = stripForCorrelationSearch(detectionName);
    var url = SPLUNK_CONFIG.baseUrl + SPLUNK_CONFIG.correlationSearchPath;
    url += '?search=' + encodeURIComponent(fullName);
    return url;
}

(function() {
    'use strict';

    // Application namespace
    const App = {
        // Configuration
        config: {
            distPath: 'dist/',
            version: '1.0.0',
            themeStorageKey: 'dmf_newui_theme',
            authStorageKey: 'dmf_authenticated'
        },

        // DOM elements
        elements: {
            sidebar: null,
            overlay: null,
            statusIndicator: null,
            statusText: null,
            themeToggle: null
        },

        // State
        state: {
            sidebarOpen: false,
            connected: false,
            theme: 'light',
            detections: [],
            filteredDetections: [],
            selectedDetection: null,
            selectedFilteredOut: false,  // Track when selected detection is excluded by filters
            copyableContent: []
        },

        // Check password and initialize
        checkPassword: function() {
            var authenticated = sessionStorage.getItem(this.config.authStorageKey);
            if (authenticated === 'true') {
                this.init();
                return;
            }
            this.showPasswordModal();
        },

        // Show password modal
        showPasswordModal: function() {
            var modal = document.getElementById('modal-password');
            if (modal) {
                modal.classList.remove('hidden');
                var input = document.getElementById('password-input');
                if (input) {
                    input.focus();
                    input.addEventListener('keypress', function(e) {
                        if (e.key === 'Enter') {
                            window.validatePassword();
                        }
                    });
                }
            }
        },

        // Validate entered password
        validatePassword: function() {
            var input = document.getElementById('password-input');
            var error = document.getElementById('password-error');
            var enteredPassword = input ? input.value : '';

            if (enteredPassword === ACCESS_PASSWORD) {
                sessionStorage.setItem(this.config.authStorageKey, 'true');
                var modal = document.getElementById('modal-password');
                if (modal) modal.classList.add('hidden');
                this.init();
            } else {
                if (error) {
                    error.textContent = 'Incorrect password. Please try again.';
                    error.classList.remove('hidden');
                }
                if (input) {
                    input.value = '';
                    input.focus();
                }
            }
        },

        // Initialize the application
        init: function() {
            this.cacheElements();
            this.bindEvents();
            this.loadTheme();
            this.loadFromHash();
            this.updateStatus('disconnected');
            this.loadDetections();
            console.log('DE-MainFrame New UI initialized');
        },

        // Cache DOM elements
        cacheElements: function() {
            this.elements.sidebar = document.getElementById('sidebar');
            this.elements.overlay = document.querySelector('.sidebar-overlay');
            this.elements.statusIndicator = document.querySelector('.status-indicator');
            this.elements.statusText = document.querySelector('.status-text');
            this.elements.themeToggle = document.querySelector('.theme-toggle');
        },

        // Bind events
        bindEvents: function() {
            var self = this;

            // Navigation items
            const navItems = document.querySelectorAll('.nav-item:not(.nav-classic)');
            navItems.forEach(function(item) {
                item.addEventListener('click', function(e) {
                    e.preventDefault();
                    App.handleNavigation(this);
                });
            });

            // Keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                var key = e.key;
                var isCtrlOrCmd = e.ctrlKey || e.metaKey;
                var isInInput = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA';

                // Escape - Close any open modal
                if (key === 'Escape') {
                    var modals = document.querySelectorAll('.modal:not(.hidden)');
                    modals.forEach(function(modal) {
                        // Don't close password modal with Escape
                        if (modal.id !== 'modal-password') {
                            modal.classList.add('hidden');
                        }
                    });
                    return;
                }

                // Ctrl+S - Save detection (when in Editor tab)
                if (isCtrlOrCmd && key === 's') {
                    var editorView = document.getElementById('view-editor');
                    if (editorView && editorView.classList.contains('active')) {
                        e.preventDefault();
                        if (typeof saveDetection === 'function') {
                            saveDetection();
                        }
                    }
                    return;
                }

                // Ctrl+N - Create new detection
                if (isCtrlOrCmd && key === 'n') {
                    e.preventDefault();
                    // Navigate to Editor tab
                    var editorNav = document.querySelector('.nav-item[href="#editor"]');
                    if (editorNav) {
                        App.handleNavigation(editorNav);
                    }
                    // Create new detection
                    if (typeof createNewDetection === 'function') {
                        createNewDetection();
                    }
                    return;
                }

                // Ctrl+F - Focus search bar in Library
                if (isCtrlOrCmd && key === 'f') {
                    var libraryView = document.getElementById('view-library');
                    if (libraryView && libraryView.classList.contains('active')) {
                        e.preventDefault();
                        var searchInput = document.getElementById('library-search-input');
                        if (searchInput) {
                            searchInput.focus();
                            searchInput.select();
                        }
                    }
                    return;
                }

                // Ctrl+I - Open import (trigger file input in Settings)
                if (isCtrlOrCmd && key === 'i') {
                    e.preventDefault();
                    var importInput = document.getElementById('modal-import-file-input');
                    if (importInput) {
                        importInput.click();
                    }
                    return;
                }

                // Ctrl+E - Export current detection (in Editor) or all detections
                if (isCtrlOrCmd && key === 'e') {
                    e.preventDefault();
                    var editorView = document.getElementById('view-editor');
                    if (editorView && editorView.classList.contains('active')) {
                        // Export current detection
                        if (typeof downloadCurrentDetection === 'function') {
                            downloadCurrentDetection();
                        }
                    } else {
                        // Export all detections
                        if (typeof exportAllDetections === 'function') {
                            exportAllDetections();
                        }
                    }
                    return;
                }

                // Number keys 1-8 for tabs (only when not in input)
                if (!isInInput && key >= '1' && key <= '8') {
                    var navItem = document.querySelector('.nav-item[data-key="' + key + '"]');
                    if (navItem) {
                        e.preventDefault();
                        App.handleNavigation(navItem);
                    }
                }
            });

            // Handle hash changes for bookmarking
            window.addEventListener('hashchange', function() {
                App.handleHashChange();
            });

            // Library sidebar collapse toggle (burger menu)
            var librarySidebarToggle = document.getElementById('library-sidebar-toggle');
            if (librarySidebarToggle) {
                librarySidebarToggle.addEventListener('click', function() {
                    var sidebar = document.getElementById('library-sidebar');
                    if (sidebar) {
                        sidebar.classList.toggle('collapsed');
                        // Store preference
                        var isCollapsed = sidebar.classList.contains('collapsed');
                        localStorage.setItem('dmf_library_sidebar_collapsed', isCollapsed ? 'true' : 'false');
                        // Update button title
                        librarySidebarToggle.title = isCollapsed ? 'Show filters panel' : 'Hide filters panel';
                    }
                });
                // Restore collapsed state from preference
                var librarySidebarCollapsed = localStorage.getItem('dmf_library_sidebar_collapsed');
                if (librarySidebarCollapsed === 'true') {
                    var sidebar = document.getElementById('library-sidebar');
                    if (sidebar) {
                        sidebar.classList.add('collapsed');
                        librarySidebarToggle.title = 'Show filters panel';
                    }
                }
            }

            // Legacy sidebar collapse toggle (backward compatibility)
            var collapseBtn = document.getElementById('sidebar-collapse-btn');
            if (collapseBtn) {
                collapseBtn.addEventListener('click', function() {
                    var sidebar = document.getElementById('library-sidebar');
                    if (sidebar) {
                        sidebar.classList.toggle('collapsed');
                        // Store preference
                        var isCollapsed = sidebar.classList.contains('collapsed');
                        localStorage.setItem('dmf_library_sidebar_collapsed', isCollapsed ? 'true' : 'false');
                    }
                });
            }

            // Library main (detail panel) collapse toggle
            var libraryMainToggle = document.getElementById('library-main-toggle');
            if (libraryMainToggle) {
                libraryMainToggle.addEventListener('click', function() {
                    var libraryMain = document.getElementById('library-main');
                    if (libraryMain) {
                        libraryMain.classList.toggle('collapsed');
                        // Store preference
                        var isCollapsed = libraryMain.classList.contains('collapsed');
                        localStorage.setItem('dmf_library_main_collapsed', isCollapsed ? 'true' : 'false');
                        // Update button title
                        libraryMainToggle.title = isCollapsed ? 'Show detail panel' : 'Hide detail panel';
                    }
                });
                // Restore collapsed state from preference
                var libraryMainCollapsed = localStorage.getItem('dmf_library_main_collapsed');
                if (libraryMainCollapsed === 'true') {
                    var libraryMain = document.getElementById('library-main');
                    if (libraryMain) {
                        libraryMain.classList.add('collapsed');
                        libraryMainToggle.title = 'Show detail panel';
                    }
                }
            }

            // Library search - real-time filtering
            var searchInput = document.getElementById('library-search-input');
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    self.applyFilters();
                });
            }

            // Library filter dropdowns
            var filterIds = ['filter-severity', 'filter-status', 'filter-domain', 'filter-datasource', 'filter-mitre', 'filter-origin', 'filter-sort', 'filter-sourcetype', 'filter-main-search-field', 'filter-search-function', 'filter-drilldown-var'];
            filterIds.forEach(function(id) {
                var el = document.getElementById(id);
                if (el) {
                    el.addEventListener('change', function() {
                        self.applyFilters();
                    });
                }
            });

            // Action buttons
            document.getElementById('btn-detail-correlation')?.addEventListener('click', function() {
                var d = self.state.selectedDetection;
                if (d) {
                    var url = buildCorrelationSearchUrl(d['Detection Name']);
                    window.open(url, '_blank');
                }
            });

            document.getElementById('btn-detail-tune')?.addEventListener('click', function() {
                openTuneModal();
            });

            document.getElementById('btn-detail-retrofit')?.addEventListener('click', function() {
                openRetrofitModal();
            });

            document.getElementById('btn-detail-metadata')?.addEventListener('click', function() {
                openMetadataModal();
            });

            document.getElementById('btn-detail-edit')?.addEventListener('click', function() {
                var d = self.state.selectedDetection;
                if (!d) {
                    showToast('Please select a detection first', 'warning');
                    return;
                }
                // Switch to Editor tab and load detection
                switchTab('editor');
                loadDetectionIntoForm(d);
            });

            document.getElementById('btn-detail-delete')?.addEventListener('click', function() {
                var d = self.state.selectedDetection;
                if (!d) return;
                var modal = document.getElementById('modal-confirm');
                var msg = document.getElementById('confirm-message');
                if (msg) msg.textContent = 'Are you sure you want to delete "' + d['Detection Name'] + '"?';
                if (modal) modal.classList.remove('hidden');
            });

            // View toggle buttons (Structured/JSON)
            document.querySelectorAll('#detail-view-toggle .view-toggle-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    // Update active state
                    document.querySelectorAll('#detail-view-toggle .view-toggle-btn').forEach(function(b) {
                        b.classList.remove('active');
                    });
                    btn.classList.add('active');

                    // Toggle visibility
                    var structuredView = document.getElementById('library-detail-body');
                    var jsonView = document.getElementById('detail-json-view');

                    if (btn.dataset.view === 'json') {
                        if (structuredView) structuredView.classList.add('hidden');
                        if (jsonView) jsonView.classList.remove('hidden');
                    } else {
                        if (structuredView) structuredView.classList.remove('hidden');
                        if (jsonView) jsonView.classList.add('hidden');
                    }
                });
            });

            // Modal overlays
            document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
                overlay.addEventListener('click', function() {
                    var modal = this.closest('.modal');
                    if (modal && !modal.classList.contains('password-modal')) {
                        modal.classList.add('hidden');
                    }
                });
            });
        },

        // Toggle sidebar
        toggleSidebar: function() {
            this.state.sidebarOpen = !this.state.sidebarOpen;

            if (this.state.sidebarOpen) {
                this.elements.sidebar.classList.add('open');
                this.elements.overlay.classList.add('visible');
            } else {
                this.elements.sidebar.classList.remove('open');
                this.elements.overlay.classList.remove('visible');
            }
        },

        // Handle navigation
        handleNavigation: function(item) {
            // Remove active from all
            document.querySelectorAll('.nav-item').forEach(function(nav) {
                nav.classList.remove('active');
            });

            // Add active to clicked
            item.classList.add('active');

            // Update content header
            var title = item.textContent.trim();
            var contentHeader = document.querySelector('.content-header h2');
            if (contentHeader) {
                contentHeader.textContent = title;
            }

            // Update URL hash for bookmarking
            var href = item.getAttribute('href');
            if (href && href.startsWith('#')) {
                history.pushState(null, '', href);
            }

            // Close sidebar on mobile
            if (window.innerWidth < 768 && this.state.sidebarOpen) {
                this.toggleSidebar();
            }
        },

        // Handle URL hash changes
        handleHashChange: function() {
            var hash = window.location.hash;
            if (hash) {
                var navItem = document.querySelector('.nav-item[href="' + hash + '"]');
                if (navItem && !navItem.classList.contains('active')) {
                    this.setActiveNav(navItem);
                }
            }
        },

        // Set active nav item without changing hash (used by hashchange)
        setActiveNav: function(item) {
            document.querySelectorAll('.nav-item').forEach(function(nav) {
                nav.classList.remove('active');
            });
            item.classList.add('active');

            var title = item.textContent.trim();
            var contentHeader = document.querySelector('.content-header h2');
            if (contentHeader) {
                contentHeader.textContent = title;
            }

            if (window.innerWidth < 768 && this.state.sidebarOpen) {
                this.toggleSidebar();
            }
        },

        // Load navigation state from URL hash
        loadFromHash: function() {
            var hash = window.location.hash;
            if (hash) {
                var navItem = document.querySelector('.nav-item[href="' + hash + '"]');
                if (navItem) {
                    this.setActiveNav(navItem);
                }
            }
        },

        // Load theme from localStorage
        loadTheme: function() {
            var savedTheme = localStorage.getItem(this.config.themeStorageKey);
            if (savedTheme === 'dark' || savedTheme === 'light') {
                this.state.theme = savedTheme;
            } else {
                this.state.theme = 'light';
            }
            this.applyTheme();
        },

        // Apply current theme to document
        applyTheme: function() {
            if (this.state.theme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
            this.updateThemeToggleIcon();
        },

        // Update theme toggle button icon
        updateThemeToggleIcon: function() {
            if (this.elements.themeToggle) {
                this.elements.themeToggle.textContent = this.state.theme === 'dark' ? '☾' : '☀';
            }
        },

        // Toggle between light and dark theme
        toggleTheme: function() {
            this.state.theme = this.state.theme === 'dark' ? 'light' : 'dark';
            localStorage.setItem(this.config.themeStorageKey, this.state.theme);
            this.applyTheme();
        },

        // Update connection status
        updateStatus: function(status) {
            this.state.connected = (status === 'connected');

            if (this.elements.statusIndicator) {
                this.elements.statusIndicator.classList.remove('status-connected', 'status-disconnected');
                this.elements.statusIndicator.classList.add('status-' + status);
            }

            if (this.elements.statusText) {
                this.elements.statusText.textContent = status === 'connected' ? 'Connected' : 'Disconnected';
            }
        },

        // =====================================================================
        // LIBRARY VIEW FUNCTIONS
        // =====================================================================

        // Load detections from GitHub (with fallback to local files and localStorage)
        loadDetections: function() {
            // Use the global autoLoadFromStaticFiles function which handles:
            // 1. GitHub API fetch when token is configured
            // 2. Relative file fetch for local development
            // 3. localStorage fallback when both fail
            // 4. Loads all-detections.json, all-metadata.json, resources.json, and macros.json
            autoLoadFromStaticFiles();
        },

        // Populate dynamic filter dropdowns
        populateFilters: function() {
            var datasources = {};
            var sourcetypes = {};
            var mitreIds = {};
            var mainSearchFields = {};
            var mainSearchFunctions = {};
            var drilldownVars = {};

            var self = this;
            this.state.detections.forEach(function(d) {
                // Datasources from Required_Data_Sources
                var ds = d['Required_Data_Sources'] || '';
                if (ds) {
                    ds.split(/[,;]/).forEach(function(s) {
                        var trimmed = s.trim();
                        if (trimmed) datasources[trimmed] = (datasources[trimmed] || 0) + 1;
                    });
                }

                // Parse SPL for sourcetypes and other metadata
                var parsed = self.parseSPLForFilters(d['Search String']);

                // Sourcetypes from parsed SPL
                parsed.sourcetypes.forEach(function(st) {
                    sourcetypes[st] = (sourcetypes[st] || 0) + 1;
                });

                // Main search fields from parsed SPL
                parsed.mainSearchFields.forEach(function(f) {
                    mainSearchFields[f] = (mainSearchFields[f] || 0) + 1;
                });

                // Main search functions from parsed SPL
                parsed.mainSearchFunctions.forEach(function(f) {
                    mainSearchFunctions[f] = (mainSearchFunctions[f] || 0) + 1;
                });

                // Drilldown variables
                var ddVars = self.parseDrilldownVarsForFilters(d);
                ddVars.forEach(function(v) {
                    drilldownVars[v] = (drilldownVars[v] || 0) + 1;
                });

                // MITRE IDs
                var mitre = d['Mitre ID'] || [];
                mitre.forEach(function(m) {
                    mitreIds[m] = (mitreIds[m] || 0) + 1;
                });
            });

            // Populate datasource filter
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
                Object.keys(mitreIds).sort().forEach(function(m) {
                    mitreHtml += '<option value="' + escapeAttr(m) + '">' + escapeHtml(m) + ' (' + mitreIds[m] + ')</option>';
                });
                mitreSelect.innerHTML = mitreHtml;
            }

            // Populate main search fields filter
            var fieldSelect = document.getElementById('filter-main-search-field');
            if (fieldSelect) {
                var fieldHtml = '<option value="">Search Fields</option>';
                Object.keys(mainSearchFields).sort().forEach(function(f) {
                    fieldHtml += '<option value="' + escapeAttr(f) + '">' + escapeHtml(f) + ' (' + mainSearchFields[f] + ')</option>';
                });
                fieldSelect.innerHTML = fieldHtml;
            }

            // Populate search functions filter
            var funcSelect = document.getElementById('filter-search-function');
            if (funcSelect) {
                var funcHtml = '<option value="">SPL Commands</option>';
                Object.keys(mainSearchFunctions).sort().forEach(function(f) {
                    funcHtml += '<option value="' + escapeAttr(f) + '">' + escapeHtml(f) + ' (' + mainSearchFunctions[f] + ')</option>';
                });
                funcSelect.innerHTML = funcHtml;
            }

            // Populate drilldown variables filter
            var ddVarSelect = document.getElementById('filter-drilldown-var');
            if (ddVarSelect) {
                var ddVarHtml = '<option value="">Drilldown Vars</option>';
                Object.keys(drilldownVars).sort().forEach(function(v) {
                    ddVarHtml += '<option value="' + escapeAttr(v) + '">$' + escapeHtml(v) + '$ (' + drilldownVars[v] + ')</option>';
                });
                ddVarSelect.innerHTML = ddVarHtml;
            }
        },

        // Parse SPL for filter population (simplified version)
        parseSPLForFilters: function(spl) {
            var result = {
                sourcetypes: [],
                mainSearchFields: [],
                mainSearchFunctions: []
            };

            if (!spl) return result;

            // Parse sourcetypes
            var stRegex = /sourcetype\s*={1,2}\s*["']?([^\s"'|()]+)["']?/gi;
            var match;
            while ((match = stRegex.exec(spl)) !== null) {
                if (result.sourcetypes.indexOf(match[1]) === -1) {
                    result.sourcetypes.push(match[1]);
                }
            }

            // Parse functions/commands (after pipes)
            var phases = spl.split(/(?:^|\n)\s*\|\s*/);
            for (var i = 1; i < phases.length; i++) {
                var funcMatch = phases[i].match(/^([a-zA-Z_][a-zA-Z0-9_]*)/);
                if (funcMatch) {
                    var fn = funcMatch[1].toLowerCase();
                    if (result.mainSearchFunctions.indexOf(fn) === -1) {
                        result.mainSearchFunctions.push(fn);
                    }
                }
            }

            // Parse main search fields (common field patterns)
            var fieldPatterns = [
                /\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=!<>]/g,
                /\bvalues?\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi,
                /\bcount\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi,
                /\bsum\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi,
                /\bavg\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi
            ];

            var excludeFields = ['index', 'sourcetype', 'source', 'host', 'eventtype', 'tag', 'eventcode', 'category', 'earliest', 'latest', 'span'];

            fieldPatterns.forEach(function(pattern) {
                var m;
                while ((m = pattern.exec(spl)) !== null) {
                    var field = m[1];
                    if (field &&
                        result.mainSearchFields.indexOf(field) === -1 &&
                        excludeFields.indexOf(field.toLowerCase()) === -1 &&
                        !/^\d+$/.test(field)) {
                        result.mainSearchFields.push(field);
                    }
                }
            });

            return result;
        },

        // Parse drilldown variables for filter population
        parseDrilldownVarsForFilters: function(d) {
            var allVars = [];

            function parseVars(search) {
                if (!search) return;
                var varMatches = search.match(/\$([a-zA-Z_][a-zA-Z0-9_]*)\$/g);
                if (varMatches) {
                    varMatches.forEach(function(v) {
                        var varName = v.replace(/\$/g, '');
                        if (allVars.indexOf(varName) === -1) {
                            allVars.push(varName);
                        }
                    });
                }
            }

            // Legacy drilldown
            parseVars(d['Drilldown Search (Legacy)']);

            // Numbered drilldowns
            for (var i = 1; i <= 15; i++) {
                parseVars(d['Drilldown Search ' + i]);
            }

            return allVars;
        },

        // Apply filters and search
        applyFilters: function() {
            var searchInput = document.getElementById('library-search-input');
            var searchTerm = searchInput ? searchInput.value.toLowerCase() : '';

            var severityFilter = document.getElementById('filter-severity');
            var statusFilter = document.getElementById('filter-status');
            var domainFilter = document.getElementById('filter-domain');
            var datasourceFilter = document.getElementById('filter-datasource');
            var mitreFilter = document.getElementById('filter-mitre');
            var originFilter = document.getElementById('filter-origin');
            var sortFilter = document.getElementById('filter-sort');
            var sourcetypeFilter = document.getElementById('filter-sourcetype');
            var mainFieldFilter = document.getElementById('filter-main-search-field');
            var searchFuncFilter = document.getElementById('filter-search-function');
            var drilldownVarFilter = document.getElementById('filter-drilldown-var');

            var severity = severityFilter ? severityFilter.value.toLowerCase() : '';
            var status = statusFilter ? statusFilter.value : '';
            var domain = domainFilter ? domainFilter.value.toLowerCase() : '';
            var datasource = datasourceFilter ? datasourceFilter.value : '';
            var mitre = mitreFilter ? mitreFilter.value : '';
            var origin = originFilter ? originFilter.value.toLowerCase() : '';
            var sort = sortFilter ? sortFilter.value : 'name-asc';
            var sourcetype = sourcetypeFilter ? sourcetypeFilter.value : '';
            var mainField = mainFieldFilter ? mainFieldFilter.value : '';
            var searchFunc = searchFuncFilter ? searchFuncFilter.value : '';
            var drilldownVar = drilldownVarFilter ? drilldownVarFilter.value : '';

            var self = this;
            this.state.filteredDetections = this.state.detections.filter(function(d) {
                // Search term - enhanced to search Name, Objective, Search String, and MITRE IDs
                if (searchTerm) {
                    var searchText = [
                        d['Detection Name'] || '',
                        d['Objective'] || '',
                        d['Search String'] || ''
                    ].concat(d['Mitre ID'] || []).join(' ').toLowerCase();
                    if (searchText.indexOf(searchTerm) === -1) return false;
                }

                // Severity
                if (severity) {
                    var dSev = (d['Severity/Priority'] || '').toLowerCase();
                    if (dSev !== severity) return false;
                }

                // Domain
                if (domain) {
                    var dDomain = (d['Security Domain'] || '').toLowerCase();
                    if (dDomain !== domain) return false;
                }

                // Origin
                if (origin) {
                    var dOrigin = (d['origin'] || '').toLowerCase();
                    if (dOrigin !== origin) return false;
                }

                // Datasource
                if (datasource) {
                    var dDs = d['Required_Data_Sources'] || '';
                    if (dDs.indexOf(datasource) === -1) return false;
                }

                // MITRE
                if (mitre) {
                    var dMitre = d['Mitre ID'] || [];
                    if (dMitre.indexOf(mitre) === -1) return false;
                }

                // Sourcetype filter
                if (sourcetype) {
                    var parsed = self.parseSPLForFilters(d['Search String']);
                    if (parsed.sourcetypes.indexOf(sourcetype) === -1) return false;
                }

                // Main search field filter
                if (mainField) {
                    var parsedFields = self.parseSPLForFilters(d['Search String']);
                    if (parsedFields.mainSearchFields.indexOf(mainField) === -1) return false;
                }

                // Search function filter
                if (searchFunc) {
                    var parsedFuncs = self.parseSPLForFilters(d['Search String']);
                    if (parsedFuncs.mainSearchFunctions.indexOf(searchFunc) === -1) return false;
                }

                // Drilldown variable filter
                if (drilldownVar) {
                    var ddVars = self.parseDrilldownVarsForFilters(d);
                    if (ddVars.indexOf(drilldownVar) === -1) return false;
                }

                // Status (check validation)
                if (status) {
                    var detectionStatus = self.getDetectionStatus(d);
                    if (status === 'valid' && detectionStatus !== 'valid') return false;
                    if (status === 'incomplete' && detectionStatus !== 'incomplete') return false;
                    if (status === 'needs-tune' && detectionStatus !== 'needs-tune') return false;
                    if (status === 'needs-retrofit' && detectionStatus !== 'needs-retrofit') return false;
                }

                return true;
            });

            // Apply sorting
            if (sort === 'name-asc') {
                this.state.filteredDetections.sort(function(a, b) {
                    return (a['Detection Name'] || '').localeCompare(b['Detection Name'] || '');
                });
            } else if (sort === 'name-desc') {
                this.state.filteredDetections.sort(function(a, b) {
                    return (b['Detection Name'] || '').localeCompare(a['Detection Name'] || '');
                });
            } else if (sort === 'modified-desc') {
                this.state.filteredDetections.sort(function(a, b) {
                    return new Date(b['Last Modified'] || 0) - new Date(a['Last Modified'] || 0);
                });
            } else if (sort === 'risk-desc') {
                this.state.filteredDetections.sort(function(a, b) {
                    return getRiskScore(b) - getRiskScore(a);
                });
            }

            // Check if selected detection is still in filtered list (US-005)
            // If not, keep showing the content but add visual indicator
            var wasFilteredOut = this.state.selectedFilteredOut;
            if (this.state.selectedDetection) {
                var selectedName = this.state.selectedDetection['Detection Name'];
                var stillInList = this.state.filteredDetections.some(function(d) {
                    return d['Detection Name'] === selectedName;
                });
                this.state.selectedFilteredOut = !stillInList;

                // Re-render detail panel if filtered-out state changed to show/hide indicator
                if (wasFilteredOut !== this.state.selectedFilteredOut) {
                    this.renderDetailPanel(this.state.selectedDetection);
                }
            } else {
                this.state.selectedFilteredOut = false;
            }

            this.renderLibrary();
        },

        // Clear all filters and show all detections
        clearFilters: function() {
            // Reset search input
            var searchInput = document.getElementById('library-search-input');
            if (searchInput) searchInput.value = '';

            // Reset all filter dropdowns
            var filterIds = ['filter-severity', 'filter-status', 'filter-domain', 'filter-datasource', 'filter-mitre', 'filter-origin', 'filter-sourcetype', 'filter-main-search-field', 'filter-search-function', 'filter-drilldown-var'];
            filterIds.forEach(function(id) {
                var el = document.getElementById(id);
                if (el) el.value = '';
            });

            // Reset sort to default
            var sortFilter = document.getElementById('filter-sort');
            if (sortFilter) sortFilter.value = 'name-asc';

            // Clear the filtered-out state
            this.state.selectedFilteredOut = false;

            // Re-apply filters (which will now show all detections)
            this.applyFilters();

            // Re-render detail panel to remove the filtered-out banner
            if (this.state.selectedDetection) {
                this.renderDetailPanel(this.state.selectedDetection);
            }
        },

        // Get detection status
        getDetectionStatus: function(d) {
            var ttl = calculateTTL(d['Last Modified']);
            if (ttl.expired) return 'needs-retrofit';
            if (ttl.days <= 30) return 'needs-tune';

            // Check mandatory fields
            var mandatory = ['Detection Name', 'Objective', 'Severity/Priority', 'Search String'];
            for (var i = 0; i < mandatory.length; i++) {
                if (!d[mandatory[i]]) return 'incomplete';
            }

            return 'valid';
        },

        // Render library list
        renderLibrary: function() {
            var container = document.getElementById('library-list');
            var countEl = document.getElementById('library-count');

            if (countEl) {
                countEl.textContent = this.state.filteredDetections.length + ' detection' + (this.state.filteredDetections.length !== 1 ? 's' : '');
            }

            if (!container) return;

            if (this.state.filteredDetections.length === 0) {
                container.innerHTML = '<div class="empty-state"><span class="empty-icon">📭</span><p>No detections found</p></div>';
                return;
            }

            var html = '';
            var self = this;
            this.state.filteredDetections.forEach(function(d) {
                var sev = (d['Severity/Priority'] || '').toLowerCase();
                var name = d['Detection Name'] || 'Unnamed';
                var domain = d['Security Domain'] || '';
                var modified = d['Last Modified'] ? formatDate(d['Last Modified']) : 'N/A';
                var isSelected = self.state.selectedDetection && self.state.selectedDetection['Detection Name'] === name;

                html += '<div class="library-list-item' + (isSelected ? ' selected' : '') + '" onclick="selectDetection(\'' + escapeAttr(name) + '\')">';
                html += '<div class="library-list-item-header">';
                html += '<span class="library-list-item-name" title="' + escapeAttr(name) + '">' + escapeHtml(name) + '</span>';
                html += '<span class="severity-badge ' + sev + '">' + (sev || 'N/A') + '</span>';
                html += '</div>';
                html += '<div class="library-list-item-meta">';
                html += '<span>' + (domain || 'No domain') + '</span>';
                html += '<span>' + modified + '</span>';
                html += '</div>';
                html += '</div>';
            });
            container.innerHTML = html;
        },

        // Select a detection
        selectDetection: function(name) {
            var detection = this.state.detections.find(function(d) {
                return d['Detection Name'] === name;
            });
            if (!detection) return;

            this.state.selectedDetection = detection;
            // Reset filtered-out state since user is selecting from visible list
            this.state.selectedFilteredOut = false;
            this.renderLibrary();
            this.renderDetailPanel(detection);

            // Scroll content panel to top - both outer container and inner detail body
            // The detail-body has its own overflow-y: auto so we must scroll it too
            var libraryMain = document.querySelector('.library-main');
            if (libraryMain) libraryMain.scrollTop = 0;
            var detailBody = document.getElementById('library-detail-body');
            if (detailBody) detailBody.scrollTop = 0;

            // Scroll the selected item into view in the list after DOM update
            // Use requestAnimationFrame to ensure the DOM has been painted
            requestAnimationFrame(function() {
                var selectedItem = document.querySelector('.library-list-item.selected');
                if (selectedItem) {
                    selectedItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
                }
            });
        },

        // Render detail panel
        renderDetailPanel: function(d) {
            this.state.copyableContent = [];

            document.getElementById('detail-placeholder').classList.add('hidden');
            document.getElementById('library-detail-content').classList.remove('hidden');

            var html = '<div class="doc-container">';

            // TTL Warning Banner
            var ttl = calculateTTL(d['Last Modified']);
            if (ttl.days <= 30) {
                var ttlClass = getTTLClass(ttl.days);
                var ttlMsg = ttl.days <= 0 ? 'TTL EXPIRED - Revalidation required' : 'TTL: ' + ttl.days + ' days remaining';
                html += '<div class="ttl-banner ' + ttlClass + '">' + ttlMsg + '</div>';
            }

            // Filtered-out notice banner (US-005)
            if (this.state.selectedFilteredOut) {
                html += '<div class="filtered-out-banner">This detection is not in the current filtered results. <a href="#" onclick="MainframeApp.clearFilters(); return false;">Clear filters</a> to see it in the list.</div>';
            }

            // Header Section
            html += '<div class="doc-section doc-header-section">';
            html += '<h2 class="doc-detection-name">' + escapeHtml(d['Detection Name'] || 'Unnamed') + '</h2>';

            if (d['Severity/Priority']) {
                var sev = (d['Severity/Priority'] || '').toLowerCase();
                html += '<div class="doc-severity"><span class="severity-badge ' + sev + '">' + d['Severity/Priority'] + '</span></div>';
            }

            html += '<div class="doc-metrics">';
            var riskScore = getRiskScore(d);
            if (riskScore > 0) html += '<div class="doc-metric"><span class="metric-label">Risk Score</span><span class="metric-value">' + riskScore + '</span></div>';
            if (d['Security Domain']) html += '<div class="doc-metric"><span class="metric-label">Domain</span><span class="metric-value">' + escapeHtml(d['Security Domain']) + '</span></div>';
            if (d['origin']) html += '<div class="doc-metric"><span class="metric-label">Origin</span><span class="metric-value">' + escapeHtml(d['origin']) + '</span></div>';
            html += '</div>';
            html += '</div>';

            // Roles Section
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

            // Overview Section
            html += '<div class="doc-section">';
            html += '<h3 class="doc-section-title">Overview</h3>';
            html += this.createCopyableField('Objective', d['Objective'], false);
            if (d['Description'] && d['Description'].trim() && d['Description'] !== d['Objective']) {
                html += this.createCopyableField('Description', d['Description'], false);
            }
            html += this.createCopyableField('Assumptions', d['Assumptions'], false);
            html += this.createCopyableField('Blind Spots / False Positives', d['Blind_Spots_False_Positives'], false);
            html += this.createCopyableField('Required Data Sources', d['Required_Data_Sources'], false);
            html += '</div>';

            // Analyst Guidance
            if (d['Analyst Next Steps']) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Analyst Guidance</h3>';
                var steps = parseAnalystNextSteps(d['Analyst Next Steps']);
                html += this.createCopyableField('Next Steps', steps, true);
                html += '</div>';
            }

            // Search Logic
            if (d['Search String']) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Search Logic</h3>';
                html += this.createCopyableField('SPL Query', d['Search String'], true, true);

                // Parsed metadata
                var parsed = parseSPL(d['Search String']);
                var drilldownVars = parseDrilldownVariables(d);
                var hasParsedData = parsed.indexes.length || parsed.sourcetypes.length || parsed.eventCodes.length ||
                                    parsed.categories.length || parsed.macros.length || parsed.lookups.length ||
                                    (drilldownVars.mainSearchFields && drilldownVars.mainSearchFields.length) ||
                                    (drilldownVars.mainSearchFunctions && drilldownVars.mainSearchFunctions.length) ||
                                    parsed.byFields.length || parsed.evalFields.length ||
                                    (parsed.comments && parsed.comments.length) ||
                                    (parsed.customTags && parsed.customTags.length);

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
                    if (parsed.categories.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Categories</span><div class="tag-group-items">';
                        parsed.categories.forEach(function(c) { html += '<span class="card-tag">' + escapeHtml(c) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (parsed.macros.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Macros</span><div class="tag-group-items">';
                        parsed.macros.forEach(function(m) { html += renderClickableMacroTag(m); });
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
                    if (parsed.evalFields && parsed.evalFields.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Eval Fields</span><div class="tag-group-items">';
                        parsed.evalFields.forEach(function(f) { html += '<span class="card-tag eval-field">' + escapeHtml(f) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (parsed.customTags && parsed.customTags.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Custom Tags</span><div class="tag-group-items">';
                        parsed.customTags.forEach(function(t) { html += '<span class="card-tag custom-tag">' + escapeHtml(t.category + ': ' + t.tag) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (parsed.comments && parsed.comments.length) {
                        html += '<div class="doc-tag-group doc-comments-group"><span class="tag-group-label">Comments</span><div class="tag-group-items">';
                        parsed.comments.forEach(function(c) { html += '<div class="spl-comment">' + escapeHtml(c) + '</div>'; });
                        html += '</div></div>';
                    }

                    html += '</div></div>';
                }
                html += '</div>';
            }

            // MITRE Section
            if (d['Mitre ID'] && d['Mitre ID'].length > 0) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">MITRE ATT&CK</h3>';
                html += '<div class="doc-mitre-tags">';
                d['Mitre ID'].forEach(function(id) { html += '<span class="card-tag mitre">' + escapeHtml(id) + '</span>'; });
                html += '</div></div>';
            }

            // Notable Event Section
            var riskEntries = getRiskEntries(d);
            if (d['Notable Title'] || d['Notable Description'] || riskEntries.length > 0) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Notable Event Configuration</h3>';
                html += this.createCopyableField('Notable Title', d['Notable Title'], false);
                html += this.createCopyableField('Notable Description', d['Notable Description'], false);

                if (riskEntries.length > 0) {
                    html += '<div class="doc-risk-entries">';
                    html += '<div class="doc-risk-header">Risk Configuration</div>';
                    riskEntries.forEach(function(risk) {
                        html += '<div class="doc-risk-entry">';
                        html += '<span>Field: <code>' + escapeHtml(risk.risk_object_field || 'N/A') + '</code></span>';
                        html += '<span>Type: <code>' + escapeHtml(risk.risk_object_type || 'N/A') + '</code></span>';
                        html += '<span>Score: <strong>' + (risk.risk_score || 0) + '</strong></span>';
                        html += '</div>';
                    });
                    html += '</div>';
                }
                html += '</div>';
            }

            // Scheduling Section
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

            // Drilldowns Section (US-007: Filter out empty drilldowns)
            var drilldowns = this.getDrilldowns(d);
            var drilldownVarsData = parseDrilldownVariables(d);
            // Filter out drilldowns that don't have both name AND search populated
            var validDrilldowns = drilldowns.filter(function(dd) {
                return dd.name && dd.name.trim() && dd.search && dd.search.trim();
            });
            var self = this;
            if (validDrilldowns.length > 0) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Drilldowns <span class="section-count">(' + validDrilldowns.length + ')</span></h3>';
                validDrilldowns.forEach(function(dd) {
                    html += '<div class="doc-drilldown">';
                    html += '<div class="drilldown-header">';
                    html += '<span class="drilldown-name">' + escapeHtml(dd.name) + '</span>';
                    if (dd.earliest || dd.latest) {
                        html += '<span class="drilldown-time">' + (dd.earliest || 'earliest') + ' → ' + (dd.latest || 'latest') + '</span>';
                    }
                    html += '</div>';
                    // Show search with copy button if it has content (with SPL syntax highlighting)
                    if (dd.search && dd.search.trim()) {
                        var ddCopyId = self.state.copyableContent.length;
                        self.state.copyableContent.push(dd.search);
                        html += '<div class="drilldown-search-wrap">';
                        html += '<button class="copy-btn" onclick="copyById(' + ddCopyId + ', this)" title="Copy">📋</button>';
                        html += '<pre class="drilldown-search">' + syntaxHighlightSPL(dd.search) + '</pre>';
                        html += '</div>';

                        // Parse drilldown search for SPL metadata
                        var ddParsed = parseSPL(dd.search);
                        var ddHasParsed = ddParsed.indexes.length || ddParsed.sourcetypes.length || ddParsed.eventCodes.length ||
                                          ddParsed.macros.length || ddParsed.mainSearchFunctions.length || ddParsed.byFields.length;
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
                            if (ddParsed.macros.length) {
                                html += '<div class="doc-tag-group"><span class="tag-group-label">Macros</span><div class="tag-group-items">';
                                ddParsed.macros.forEach(function(m) { html += renderClickableMacroTag(m); });
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
                    // Show drilldown variables
                    if (dd.vars && dd.vars.length) {
                        html += '<div class="drilldown-vars">';
                        dd.vars.forEach(function(v) { html += '<span class="card-tag variable">$' + escapeHtml(v) + '$</span>'; });
                        html += '</div>';
                    }
                    html += '</div>';
                });
                html += '</div>';
            }

            // Proposed Test Plan Section
            if (d['Proposed Test Plan'] && d['Proposed Test Plan'].trim()) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Proposed Test Plan</h3>';
                html += this.createCopyableField('Test Plan', d['Proposed Test Plan'], true);
                html += '</div>';
            }

            // File Information Section
            html += '<div class="doc-section doc-footer">';
            html += '<h3 class="doc-section-title">File Information</h3>';
            html += '<div class="doc-file-info">';
            if (d['file_name']) {
                html += '<div class="file-info-item"><span class="file-label">File:</span> <code>' + escapeHtml(d['file_name']) + '</code></div>';
            }
            if (d['First Created']) html += '<div class="file-info-item"><span class="file-label">Created:</span> ' + formatDate(d['First Created']) + '</div>';
            if (d['Last Modified']) html += '<div class="file-info-item"><span class="file-label">Modified:</span> ' + formatDate(d['Last Modified']) + '</div>';
            html += '</div></div>';

            html += '</div>';

            document.getElementById('library-detail-body').innerHTML = html;

            // Populate JSON view with syntax highlighting
            var jsonView = document.getElementById('detail-json-view');
            if (jsonView) {
                jsonView.innerHTML = '<pre class="json-display">' + syntaxHighlightJSON(JSON.stringify(d, null, 2)) + '</pre>';
            }

            // Reset view toggle to structured
            var toggleBtns = document.querySelectorAll('#detail-view-toggle .view-toggle-btn');
            toggleBtns.forEach(function(btn) {
                if (btn.dataset.view === 'structured') {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
            document.getElementById('library-detail-body').classList.remove('hidden');
            if (jsonView) jsonView.classList.add('hidden');
        },

        // Get drilldowns from detection with variables parsed
        getDrilldowns: function(d) {
            var drilldowns = [];

            // Helper to parse $variable$ from search
            function parseVarsFromSearch(search) {
                var found = [];
                if (!search) return found;
                var varMatches = search.match(/\$([a-zA-Z_][a-zA-Z0-9_]*)\$/g);
                if (varMatches) {
                    varMatches.forEach(function(v) {
                        var varName = v.replace(/\$/g, '');
                        if (found.indexOf(varName) === -1) found.push(varName);
                    });
                }
                return found;
            }

            // Legacy drilldown
            if (d['Drilldown Name (Legacy)']) {
                var legacySearch = d['Drilldown Search (Legacy)'] || '';
                drilldowns.push({
                    name: d['Drilldown Name (Legacy)'],
                    search: legacySearch,
                    earliest: d['Drilldown Earliest Offset (Legacy)'],
                    latest: d['Drilldown Latest Offset (Legacy)'],
                    vars: parseVarsFromSearch(legacySearch)
                });
            }

            // Numbered drilldowns
            for (var i = 1; i <= 15; i++) {
                var name = d['Drilldown Name ' + i];
                if (name) {
                    var search = d['Drilldown Search ' + i] || '';
                    drilldowns.push({
                        name: name,
                        search: search,
                        earliest: d['Drilldown Earliest ' + i],
                        latest: d['Drilldown Latest ' + i],
                        vars: parseVarsFromSearch(search)
                    });
                }
            }

            return drilldowns;
        },

        // Create copyable field
        // isSPL parameter enables Splunk SPL syntax highlighting
        createCopyableField: function(label, value, isCode, isSPL) {
            if (!value && value !== 0) return '';
            var copyId = this.state.copyableContent.length;
            this.state.copyableContent.push(String(value));

            // Apply SPL syntax highlighting if isSPL is true, otherwise just escape HTML
            var displayValue;
            if (isSPL) {
                displayValue = syntaxHighlightSPL(String(value));
            } else {
                displayValue = escapeHtml(String(value));
            }

            var html = '<div class="doc-field">';
            html += '<div class="doc-field-header">';
            html += '<span class="doc-field-label">' + label + '</span>';
            html += '<button class="copy-btn" onclick="copyById(' + copyId + ', this)" title="Copy">📋</button>';
            html += '</div>';
            if (isCode) {
                html += '<div class="doc-field-value code-block">' + displayValue + '</div>';
            } else {
                html += '<div class="doc-field-value">' + displayValue + '</div>';
            }
            html += '</div>';
            return html;
        },

        // Handle navigation with view switching
        handleNavigation: function(item) {
            // Remove active from all
            document.querySelectorAll('.nav-item').forEach(function(nav) {
                nav.classList.remove('active');
            });

            // Add active to clicked
            item.classList.add('active');

            // Get the section name from href
            var href = item.getAttribute('href');
            var viewName = href ? href.replace('#', '') : 'library';

            // Hide all views
            document.querySelectorAll('.view').forEach(function(view) {
                view.classList.remove('active');
            });

            // Show the selected view
            var viewEl = document.getElementById('view-' + viewName);
            if (viewEl) {
                viewEl.classList.add('active');
            }

            // Update URL hash for bookmarking
            if (href && href.startsWith('#')) {
                history.pushState(null, '', href);
            }

            // Close sidebar on mobile
            if (window.innerWidth < 768 && this.state.sidebarOpen) {
                this.toggleSidebar();
            }
        }
    };

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function escapeAttr(str) {
        if (!str) return '';
        return String(str)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"');
    }

    function formatDate(dateStr) {
        if (!dateStr) return '';
        try {
            var date = new Date(dateStr);
            return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch (e) {
            return dateStr;
        }
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

    // SPL Syntax Highlighting Function
    function syntaxHighlightSPL(spl) {
        if (!spl) return '';

        // Escape HTML first
        var escaped = spl.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        // SPL commands (common Splunk commands)
        var commands = [
            'search', 'stats', 'eval', 'where', 'table', 'fields', 'rename', 'sort',
            'dedup', 'rex', 'tstats', 'datamodel', 'join', 'append', 'appendcols',
            'chart', 'timechart', 'top', 'rare', 'head', 'tail', 'reverse',
            'transaction', 'bucket', 'bin', 'span', 'eventstats', 'streamstats',
            'lookup', 'inputlookup', 'outputlookup', 'mvexpand', 'mvzip', 'mvcombine',
            'makemv', 'split', 'fillnull', 'replace', 'regex', 'erex',
            'strcat', 'convert', 'xpath', 'xmlkv', 'spath', 'format',
            'collect', 'outputcsv', 'sendemail', 'return', 'makeresults',
            'map', 'foreach', 'accum', 'autoregress', 'diff', 'delta',
            'predict', 'anomalydetection', 'cluster', 'kmeans', 'associate',
            'correlate', 'set', 'abstract', 'reltime', 'localop', 'rest',
            'metadata', 'history', 'eventcount', 'dbquery', 'typelearner',
            'filldown', 'addtotals', 'addcoltotals', 'untable', 'xyseries',
            'geostats', 'geom', 'addinfo', 'analyzefields', 'anomalousvalue'
        ];

        // SPL functions (used in eval, stats, etc.)
        var functions = [
            'count', 'sum', 'avg', 'min', 'max', 'list', 'values', 'dc', 'distinct_count',
            'first', 'last', 'earliest', 'latest', 'range', 'stdev', 'stdevp', 'var', 'varp',
            'perc\\d*', 'percentile', 'median', 'mode', 'rate', 'per_second', 'per_minute', 'per_hour', 'per_day',
            'if', 'case', 'coalesce', 'null', 'nullif', 'validate', 'isnotnull', 'isnull', 'isnum', 'isstr', 'isint',
            'len', 'lower', 'upper', 'trim', 'ltrim', 'rtrim', 'substr', 'replace', 'split', 'mvjoin',
            'mvindex', 'mvcount', 'mvfind', 'mvfilter', 'mvappend', 'mvdedup', 'mvsort', 'mvrange', 'mvzip',
            'tonumber', 'tostring', 'typeof', 'cidrmatch', 'match', 'like', 'searchmatch',
            'now', 'time', 'relative_time', 'strftime', 'strptime', 'mktime',
            'round', 'floor', 'ceiling', 'ceil', 'abs', 'exp', 'ln', 'log', 'pow', 'sqrt', 'random', 'pi', 'e',
            'exact', 'sigfig', 'commands', 'md5', 'sha1', 'sha256', 'sha512',
            'urldecode', 'urlencode', 'isbool', 'printf', 'json_object', 'json_array', 'json_extract', 'json_set', 'json_valid',
            'true', 'false', 'memk', 'rmunit', 'rmcomma', 'ctime', 'iplocation'
        ];

        // Logical and comparison operators
        var operators = ['AND', 'OR', 'NOT', 'AS', 'BY', 'OVER', 'WHERE', 'IN', 'LIKE', 'OUTPUT', 'OUTPUTNEW'];

        // Process the SPL string with syntax highlighting

        // 1. Handle triple-backtick comments first (protect them)
        var commentPlaceholders = [];
        escaped = escaped.replace(/```([^`]*)```/g, function(match, content) {
            var idx = commentPlaceholders.length;
            commentPlaceholders.push('<span class="spl-comment-inline">```' + content + '```</span>');
            return '###COMMENT' + idx + '###';
        });

        // 2. Handle macros (single backticks, but not triple)
        escaped = escaped.replace(/(?<![`])`([^`]+)`(?![`])/g, function(match, macro) {
            return '<span class="spl-macro">`' + macro + '`</span>';
        });

        // 3. Handle strings (double-quoted)
        escaped = escaped.replace(/"([^"\\]*(\\.[^"\\]*)*)"/g, function(match) {
            return '<span class="spl-string">' + match + '</span>';
        });

        // 4. Handle variables ($field$)
        escaped = escaped.replace(/\$([a-zA-Z_][a-zA-Z0-9_]*)\$/g, function(match) {
            return '<span class="spl-variable">' + match + '</span>';
        });

        // 5. Handle pipes (make them bold and highlighted)
        escaped = escaped.replace(/(\s*\|\s*)/g, '<span class="spl-pipe">$1</span>');

        // 6. Handle field=value patterns (field names before operators)
        escaped = escaped.replace(/\b([a-zA-Z_][a-zA-Z0-9_\.]*)\s*(={1,2}|!=|&lt;=?|&gt;=?)/g, function(match, field, op) {
            return '<span class="spl-field">' + field + '</span><span class="spl-operator">' + op + '</span>';
        });

        // 7. Handle SPL commands (after pipes or at start)
        var commandsPattern = new RegExp('(^|\\||\\s)(' + commands.join('|') + ')\\b', 'gi');
        escaped = escaped.replace(commandsPattern, function(match, prefix, cmd) {
            return prefix + '<span class="spl-command">' + cmd + '</span>';
        });

        // 8. Handle SPL functions
        var functionsPattern = new RegExp('\\b(' + functions.join('|') + ')\\s*\\(', 'gi');
        escaped = escaped.replace(functionsPattern, function(match, func) {
            return '<span class="spl-command">' + func + '</span>(';
        });

        // 9. Handle operators (case insensitive for AND, OR, NOT, etc.)
        var operatorsPattern = new RegExp('\\b(' + operators.join('|') + ')\\b', 'gi');
        escaped = escaped.replace(operatorsPattern, function(match) {
            return '<span class="spl-keyword">' + match + '</span>';
        });

        // 10. Handle numbers
        escaped = escaped.replace(/\b(\d+(?:\.\d+)?)\b/g, function(match, num) {
            // Don't highlight if already inside a span
            return '<span class="spl-number">' + num + '</span>';
        });

        // 11. Restore comments
        commentPlaceholders.forEach(function(comment, idx) {
            escaped = escaped.replace('###COMMENT' + idx + '###', comment);
        });

        return escaped;
    }

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

    function getRiskScore(d) {
        if (!d) return 0;
        if (Array.isArray(d['Risk']) && d['Risk'].length > 0) {
            return parseInt(d['Risk'][0].risk_score) || 0;
        }
        if (d['Risk Score'] !== undefined) {
            return parseInt(d['Risk Score']) || 0;
        }
        return 0;
    }

    function getRiskEntries(d) {
        if (!d) return [];
        if (Array.isArray(d['Risk'])) {
            return d['Risk'].filter(function(r) { return r && (r.risk_score || r.risk_object_field); });
        }
        if (d['Risk Score'] || d['Risk Object Field']) {
            return [{
                risk_object_field: d['Risk Object Field'] || '',
                risk_object_type: d['Risk Object Type'] || 'user',
                risk_score: parseInt(d['Risk Score']) || 0
            }];
        }
        return [];
    }

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

    function parseSPL(spl) {
        var result = {
            indexes: [],
            sourcetypes: [],
            eventCodes: [],
            categories: [],
            macros: [],
            lookups: [],
            evalFields: [],
            mainSearchFields: [],
            mainSearchFunctions: [],
            byFields: [],
            functions: [],
            comments: [],
            customTags: []
        };

        if (!spl) return result;

        // Extract comments FIRST (``` comment ```) - NOT macros!
        var commentMatches = spl.match(/```[^`]*```/g);
        if (commentMatches) {
            commentMatches.forEach(function(m) {
                var comment = m.replace(/```/g, '').trim();
                if (comment && result.comments.indexOf(comment) === -1) {
                    result.comments.push(comment);
                }
            });
        }

        // Remove comments from SPL for further parsing to avoid false positives
        var cleanSpl = spl.replace(/```[^`]*```/g, ' ');

        // Parse indexes (handles index=, index==, index IN ())
        var indexRegex = /index\s*={1,2}\s*["']?([^\s"'|()]+)["']?/gi;
        var match;
        while ((match = indexRegex.exec(cleanSpl)) !== null) {
            if (result.indexes.indexOf(match[1]) === -1) {
                result.indexes.push(match[1]);
            }
        }
        // Also handle index IN (...)
        var indexInRegex = /index\s+IN\s*\(([^)]+)\)/gi;
        while ((match = indexInRegex.exec(cleanSpl)) !== null) {
            var inValues = match[1].split(',');
            inValues.forEach(function(v) {
                var val = v.trim().replace(/["']/g, '');
                if (val && result.indexes.indexOf(val) === -1) {
                    result.indexes.push(val);
                }
            });
        }

        // Parse sourcetypes
        var sourcetypeRegex = /sourcetype\s*={1,2}\s*["']?([^\s"'|()]+)["']?/gi;
        while ((match = sourcetypeRegex.exec(cleanSpl)) !== null) {
            if (result.sourcetypes.indexOf(match[1]) === -1) {
                result.sourcetypes.push(match[1]);
            }
        }

        // Parse Event Codes
        var eventCodeRegex = /EventCode\s*[=!<>]+\s*["']?(\d+)["']?/gi;
        while ((match = eventCodeRegex.exec(cleanSpl)) !== null) {
            if (result.eventCodes.indexOf(match[1]) === -1) {
                result.eventCodes.push(match[1]);
            }
        }

        // Parse categories (Azure/Defender) - quoted values
        var categoryRegex = /category\s*={1,2}\s*["']([^"']+)["']/gi;
        while ((match = categoryRegex.exec(cleanSpl)) !== null) {
            if (result.categories.indexOf(match[1]) === -1) {
                result.categories.push(match[1]);
            }
        }
        // Also handle unquoted category values
        var categoryUnquotedRegex = /category\s*={1,2}\s*([^\s"'|()]+)/gi;
        while ((match = categoryUnquotedRegex.exec(cleanSpl)) !== null) {
            var val = match[1].trim();
            // Skip if it starts with a quote (already handled above)
            if (val && !val.startsWith('"') && !val.startsWith("'") && result.categories.indexOf(val) === -1) {
                result.categories.push(val);
            }
        }

        // Parse macros (single backticks, not triple) - use cleanSpl to avoid matching triple backticks
        var macroRegex = /`([^`(]+)(?:\([^)]*\))?`/g;
        while ((match = macroRegex.exec(cleanSpl)) !== null) {
            if (result.macros.indexOf(match[1]) === -1) {
                result.macros.push(match[1]);
            }
        }

        // Parse lookups
        var lookupRegex = /\b(?:lookup|inputlookup|outputlookup)\s+([^\s|,]+)/gi;
        while ((match = lookupRegex.exec(cleanSpl)) !== null) {
            if (result.lookups.indexOf(match[1]) === -1) {
                result.lookups.push(match[1]);
            }
        }

        // Parse eval fields
        var evalRegex = /\beval\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=/gi;
        while ((match = evalRegex.exec(cleanSpl)) !== null) {
            if (result.evalFields.indexOf(match[1]) === -1) {
                result.evalFields.push(match[1]);
            }
        }

        // Parse by fields
        var byRegex = /\bby\s+([a-zA-Z_][a-zA-Z0-9_,\s]*)/gi;
        while ((match = byRegex.exec(cleanSpl)) !== null) {
            var fields = match[1].split(/[,\s]+/);
            fields.forEach(function(f) {
                f = f.trim();
                if (f && result.byFields.indexOf(f) === -1 && f !== 'as' && f !== 'where') {
                    result.byFields.push(f);
                }
            });
        }

        // Parse functions/commands (commands after pipes)
        var phases = cleanSpl.split(/(?:^|\n)\s*\|\s*/);
        for (var i = 1; i < phases.length; i++) {
            var funcMatch = phases[i].match(/^([a-zA-Z_][a-zA-Z0-9_]*)/);
            if (funcMatch) {
                var fn = funcMatch[1].toLowerCase();
                if (result.mainSearchFunctions.indexOf(fn) === -1) {
                    result.mainSearchFunctions.push(fn);
                }
            }
        }

        // Parse main search fields (common field patterns)
        var fieldPatterns = [
            /\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=!<>]/g,  // field=value
            /\bvalues?\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi,  // values(field)
            /\bcount\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi,    // count(field)
            /\bsum\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi,      // sum(field)
            /\bavg\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/gi       // avg(field)
        ];

        var excludeFields = ['index', 'sourcetype', 'source', 'host', 'eventtype', 'tag', 'eventcode', 'category', 'earliest', 'latest', 'span'];

        fieldPatterns.forEach(function(pattern) {
            var m;
            while ((m = pattern.exec(cleanSpl)) !== null) {
                var field = m[1];
                if (field &&
                    result.mainSearchFields.indexOf(field) === -1 &&
                    excludeFields.indexOf(field.toLowerCase()) === -1 &&
                    !/^\d+$/.test(field)) {
                    result.mainSearchFields.push(field);
                }
            }
        });

        // Apply custom tags from parsing rules (if defined in settings)
        if (typeof settingsState !== 'undefined' && settingsState.parsingRules) {
            settingsState.parsingRules.forEach(function(rule) {
                if (!rule.enabled || !rule.pattern || !rule.field) return;
                try {
                    var regex = new RegExp(rule.pattern, 'gi');
                    if (regex.test(cleanSpl)) {
                        // Check if this rule defines a custom tag
                        if (rule.tag && rule.category) {
                            var exists = result.customTags.some(function(t) {
                                return t.category === rule.category && t.tag === rule.tag;
                            });
                            if (!exists) {
                                result.customTags.push({ category: rule.category, tag: rule.tag });
                            }
                        }
                    }
                } catch (e) {
                    // Ignore invalid regex patterns
                }
            });
        }

        // Legacy functions array for backward compatibility
        result.functions = result.mainSearchFunctions;

        return result;
    }

    // =========================================================================
    // GLOBAL FUNCTIONS FOR EVENT HANDLERS
    // =========================================================================

    window.selectDetection = function(name) {
        App.selectDetection(name);
    };

    /**
     * Navigate to Library tab and show a specific detection
     * Used from Revalidation and other tabs to jump to a detection in the Library
     */
    window.goToLibraryDetection = function(detectionName) {
        // Switch to Library tab
        switchTab('library');

        // Find the detection
        var found = App.state.detections.find(function(d) {
            return d['Detection Name'] === detectionName;
        });

        if (found) {
            // Clear any existing filters and set search to the detection name
            var searchInput = document.getElementById('library-search-input');
            if (searchInput) {
                searchInput.value = detectionName;
            }

            // Apply filters to show the detection
            App.applyFilters();

            // Select and show the detection detail after a brief delay for DOM update
            setTimeout(function() {
                App.selectDetection(detectionName);
            }, 100);
        } else {
            showToast('Detection not found: ' + detectionName, 'error');
        }
    };

    window.copyById = function(id, btn) {
        var text = App.state.copyableContent[id] || '';
        if (!text) {
            showToast('Nothing to copy', 'warning');
            return;
        }
        navigator.clipboard.writeText(text).then(function() {
            var original = btn.innerHTML;
            btn.innerHTML = '✓';
            btn.classList.add('copied');
            showToast('Copied to clipboard', 'success');
            setTimeout(function() {
                btn.innerHTML = original;
                btn.classList.remove('copied');
            }, 1500);
        }).catch(function(err) {
            console.error('Failed to copy:', err);
            showToast('Failed to copy to clipboard', 'error');
        });
    };

    // General copy to clipboard function for arbitrary text
    window.copyToClipboard = function(text, btn) {
        if (!text) {
            showToast('Nothing to copy', 'warning');
            return;
        }
        navigator.clipboard.writeText(text).then(function() {
            if (btn) {
                var original = btn.innerHTML;
                btn.innerHTML = '✓';
                btn.classList.add('copied');
                setTimeout(function() {
                    btn.innerHTML = original;
                    btn.classList.remove('copied');
                }, 1500);
            }
            showToast('Copied to clipboard', 'success');
        }).catch(function(err) {
            console.error('Failed to copy:', err);
            showToast('Failed to copy to clipboard', 'error');
        });
    };

    window.openMacroModal = function(macroName) {
        var modal = document.getElementById('modal-macro');
        var titleEl = document.getElementById('macro-modal-title');
        var contentEl = document.getElementById('macro-modal-content');

        if (!modal || !titleEl || !contentEl) return;

        // Use helper functions to look up macro (defined in MACROS VIEW section)
        var macro = null;
        var isMissing = true;
        if (typeof macrosState !== 'undefined' && macrosState.macros && macrosState.macros.length > 0) {
            macro = getMacroByName(macroName);
            isMissing = !isMacroRegistered(macroName);
        }

        if (isMissing || !macro) {
            // Macro is not registered - show warning with option to add
            titleEl.innerHTML = '<span class="macro-missing-indicator">&#9888;</span> <code>`' + escapeHtml(macroName) + '`</code>';
            var usageCount = typeof countMacroUsage === 'function' ? countMacroUsage(macroName) : 0;
            contentEl.innerHTML = '<div class="macro-details-missing">' +
                '<p class="macro-not-found">This macro is not registered in your macros list.</p>' +
                '<p class="macro-hint">This may cause validation errors in detections that use this macro.</p>' +
                (usageCount > 0 ? '<p class="macro-usage-warning">Used in ' + usageCount + ' detection' + (usageCount !== 1 ? 's' : '') + '.</p>' : '') +
                '<button class="btn-primary" onclick="closeMacroModal(); navigateToMacrosWithName(\'' + escapeAttr(macroName) + '\');">Add This Macro</button>' +
                '</div>';
        } else {
            // Macro exists - show details
            var isDeprecated = macro.deprecated;
            titleEl.innerHTML = (isDeprecated ? '<span class="macro-deprecated-indicator">&#9888;</span> ' : '') +
                '<code>`' + escapeHtml(macroName) + '`</code>' +
                (isDeprecated ? ' <span class="macro-deprecated-badge">deprecated</span>' : '');

            var html = '<div class="macro-detail-fields">';
            html += '<div class="macro-detail-field"><label>Definition</label>';
            html += '<pre class="macro-definition">' + escapeHtml(macro.definition || 'No definition provided') + '</pre></div>';
            html += '<div class="macro-detail-field"><label>Description</label>';
            html += '<p>' + escapeHtml(macro.description || 'No description provided') + '</p></div>';
            if (macro.arguments && macro.arguments.length) {
                html += '<div class="macro-detail-field"><label>Arguments</label>';
                var args = Array.isArray(macro.arguments) ? macro.arguments.join(', ') : macro.arguments;
                html += '<code>' + escapeHtml(args) + '</code></div>';
            }
            if (macro.usageCount !== undefined) {
                html += '<div class="macro-detail-field"><label>Usage</label>';
                html += '<span class="macro-usage-count">' + macro.usageCount + ' detection' + (macro.usageCount !== 1 ? 's' : '') + '</span></div>';
            }
            html += '</div>';

            // Add action buttons
            html += '<div class="macro-detail-actions">';
            html += '<button class="btn-secondary" onclick="closeMacroModal(); goToMacrosTab(\'' + escapeAttr(macroName) + '\');">View in Macros Tab</button>';
            html += '</div>';

            contentEl.innerHTML = html;
        }

        modal.classList.remove('hidden');
    };

    window.closeMacroModal = function() {
        var modal = document.getElementById('modal-macro');
        if (modal) {
            modal.classList.add('hidden');
        }
    };

    window.openMetadataModal = function() {
        var d = App.state.selectedDetection;
        if (!d) return;

        var name = d['Detection Name'];
        var meta = detectionMetadata[name] || {};

        // Generate parsed data if not available
        if (!meta.parsed && d) {
            meta.parsed = parseSPL(d['Search String'] || '');
            meta.drilldownVars = parseDrilldownVariables(d);
        }

        var modal = document.getElementById('modal-metadata');
        var titleEl = document.getElementById('metadata-detection-name');
        var formattedEl = document.getElementById('metadata-formatted');
        var jsonEl = document.getElementById('metadata-json-content');

        if (titleEl) titleEl.textContent = name || 'Unnamed';

        // Render JSON view with the metadata
        if (jsonEl) jsonEl.textContent = JSON.stringify(meta, null, 2);

        // Build formatted/structured view
        if (formattedEl) {
            formattedEl.innerHTML = renderFormattedMetadata(name, d, meta);
        }

        // Reset to formatted view (default)
        var formattedDiv = document.getElementById('metadata-formatted');
        var jsonDiv = document.getElementById('metadata-json');
        var toggleBtns = document.querySelectorAll('.metadata-view-toggle .toggle-btn');
        if (formattedDiv) formattedDiv.classList.remove('hidden');
        if (jsonDiv) jsonDiv.classList.add('hidden');
        toggleBtns.forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.getAttribute('data-view') === 'formatted') {
                btn.classList.add('active');
            }
        });

        if (modal) modal.classList.remove('hidden');
    };

    // Helper function to render formatted metadata
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

        // Parsed SPL Data
        var parsed = meta.parsed || {};
        var hasParsedData = (parsed.indexes && parsed.indexes.length) ||
                            (parsed.sourcetypes && parsed.sourcetypes.length) ||
                            (parsed.eventCodes && parsed.eventCodes.length) ||
                            (parsed.categories && parsed.categories.length) ||
                            (parsed.macros && parsed.macros.length) ||
                            (parsed.lookups && parsed.lookups.length) ||
                            (parsed.evalFields && parsed.evalFields.length) ||
                            (parsed.mainSearchFields && parsed.mainSearchFields.length) ||
                            (parsed.mainSearchFunctions && parsed.mainSearchFunctions.length) ||
                            (parsed.byFields && parsed.byFields.length);

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
            if (parsed.categories && parsed.categories.length) {
                html += '<div class="parsed-item"><span class="parsed-label">Categories:</span><span class="parsed-tags">' + parsed.categories.map(function(c) { return '<span class="tag">' + escapeHtml(c) + '</span>'; }).join('') + '</span></div>';
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
            if (parsed.comments && parsed.comments.length) {
                html += '<div class="parsed-item"><span class="parsed-label">Comments:</span><span class="parsed-tags">' + parsed.comments.map(function(c) { return '<span class="tag comment">' + escapeHtml(c) + '</span>'; }).join('') + '</span></div>';
            }
            html += '</div></div>';
        }

        // Drilldown Variables
        var drilldownVars = meta.drilldownVars || {};
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

        // Metadata Status fields
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

        // TTL info if available
        if (meta.ttl) {
            html += '<div class="metadata-section">';
            html += '<h4>TTL Info</h4>';
            html += '<div class="metadata-parsed">';
            html += '<div class="parsed-item"><span class="parsed-label">Days Remaining:</span><span class="parsed-value">' + (meta.ttl.days || 'N/A') + '</span></div>';
            html += '<div class="parsed-item"><span class="parsed-label">Expired:</span><span class="parsed-value">' + (meta.ttl.expired ? 'Yes' : 'No') + '</span></div>';
            html += '</div></div>';
        }

        // History Summary if available
        if (meta.history && meta.history.length > 0) {
            var counts = {
                total: meta.history.length,
                tunes: meta.history.filter(function(h) { return h.type === 'tune'; }).length,
                retrofits: meta.history.filter(function(h) { return h.type === 'retrofit'; }).length,
                revalidations: meta.history.filter(function(h) { return h.type === 'revalidation' || h.subtype === 'revalidation'; }).length
            };
            html += '<div class="metadata-section">';
            html += '<h4>History Summary</h4>';
            html += '<div class="metadata-history-summary">';
            html += '<span class="history-count total">' + counts.total + ' Total</span>';
            html += '<span class="history-count tune">' + counts.tunes + ' Tunes</span>';
            html += '<span class="history-count retrofit">' + counts.retrofits + ' Retrofits</span>';
            html += '<span class="history-count reval">' + counts.revalidations + ' Revalidations</span>';
            html += '</div></div>';

            // Recent History
            html += '<div class="metadata-section">';
            html += '<h4>Recent History (Last 5)</h4>';
            html += '<div class="metadata-history-list">';
            meta.history.slice(0, 5).forEach(function(h) {
                var icon = h.type === 'tune' ? 'T' : h.type === 'retrofit' ? 'R' : 'V';
                html += '<div class="metadata-history-item ' + (h.type || 'version') + '">';
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

        return html;
    }

    window.closeMetadataModal = function() {
        var modal = document.getElementById('modal-metadata');
        if (modal) modal.classList.add('hidden');
    };

    window.switchMetadataView = function(view) {
        var formattedEl = document.getElementById('metadata-formatted');
        var jsonEl = document.getElementById('metadata-json');
        var buttons = document.querySelectorAll('.metadata-view-toggle .toggle-btn');

        buttons.forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.getAttribute('data-view') === view) {
                btn.classList.add('active');
            }
        });

        if (view === 'formatted') {
            formattedEl.classList.remove('hidden');
            jsonEl.classList.add('hidden');
        } else {
            formattedEl.classList.add('hidden');
            jsonEl.classList.remove('hidden');
        }
    };

    window.copyMetadataJson = function() {
        var d = App.state.selectedDetection;
        if (!d) {
            showToast('No detection selected', 'warning');
            return;
        }
        var name = d['Detection Name'];
        var meta = detectionMetadata[name] || {};
        // Generate parsed data if not available
        if (!meta.parsed && d) {
            meta.parsed = parseSPL(d['Search String'] || '');
            meta.drilldownVars = parseDrilldownVariables(d);
        }
        navigator.clipboard.writeText(JSON.stringify(meta, null, 2)).then(function() {
            showToast('Metadata JSON copied to clipboard', 'success');
        }).catch(function(err) {
            console.error('Failed to copy:', err);
            showToast('Failed to copy JSON to clipboard', 'error');
        });
    };

    window.closeConfirmModal = function() {
        var modal = document.getElementById('modal-confirm');
        if (modal) modal.classList.add('hidden');
    };

    // Confirm delete detection
    window.confirmDeleteDetection = async function() {
        var d = App.state.selectedDetection;
        if (!d) {
            closeConfirmModal();
            return;
        }

        closeConfirmModal();
        updateSyncStatus('syncing', 'Deleting...');

        var githubDeleteSuccess = false;

        // Delete from GitHub if connected
        if (github) {
            try {
                await deleteDetectionFromGitHub(d);
                githubDeleteSuccess = true;
            } catch (error) {
                console.error('GitHub delete error:', error);
                showToast('GitHub delete failed: ' + error.message + '. Removed locally only.', 'error');
                updateSyncStatus('error', 'Delete Failed');
            }
        }

        // Remove from local state
        var index = App.state.detections.findIndex(function(det) {
            return det['Detection Name'] === d['Detection Name'];
        });

        if (index >= 0) {
            App.state.detections.splice(index, 1);
        }

        // Remove metadata
        delete detectionMetadata[d['Detection Name']];

        // Update compiled files
        if (github && githubDeleteSuccess) {
            try {
                await updateCompiledFiles(App.state.detections);
            } catch (error) {
                console.error('Failed to update compiled files:', error);
                showToast('Failed to update compiled files: ' + error.message, 'warning');
            }
        }

        // Reset selected detection
        App.state.selectedDetection = null;

        // Update UI
        App.state.filteredDetections = App.state.detections.slice();
        App.renderLibrary();
        document.getElementById('detail-placeholder').classList.remove('hidden');
        document.getElementById('library-detail-content').classList.add('hidden');

        if (github && githubDeleteSuccess) {
            updateSyncStatus('connected', 'Synced');
            showToast('Detection deleted from GitHub successfully', 'success');
        } else if (!github) {
            updateSyncStatus('disconnected', 'Not Connected');
            showToast('Detection deleted locally. Configure GitHub to sync.', 'info');
        }
    };

    // =========================================================================
    // TUNE/RETROFIT MODAL FUNCTIONS
    // =========================================================================

    // Pending tune/retrofit data
    var pendingTune = null;
    var pendingRetrofit = null;

    // Open Tune Modal
    window.openTuneModal = function() {
        var d = App.state.selectedDetection;
        if (!d) {
            showToast('Please select a detection first', 'warning');
            return;
        }

        // Set detection name
        var nameEl = document.getElementById('tune-detection-name');
        if (nameEl) nameEl.textContent = d['Detection Name'];

        // Reset form
        var jiraInput = document.getElementById('tune-jira');
        jiraInput.value = '';
        jiraInput.classList.remove('input-error');
        document.getElementById('tune-analyst').value = '';
        document.getElementById('tune-description').value = '';
        document.getElementById('tune-reason').value = '';

        // Render fields multi-select
        renderFieldsMultiSelect('tune-fields-list', d);

        // Show modal
        document.getElementById('modal-tune').classList.remove('hidden');
    };

    // Close Tune Modal
    window.closeTuneModal = function() {
        document.getElementById('modal-tune').classList.add('hidden');
        pendingTune = null;
    };

    // Submit Tune - stores data and opens editor
    window.submitTune = function() {
        var d = App.state.selectedDetection;
        if (!d) return;

        var jiraInput = document.getElementById('tune-jira');
        var jira = jiraInput.value.trim();
        var analyst = document.getElementById('tune-analyst').value.trim();
        var description = document.getElementById('tune-description').value.trim();
        var reason = document.getElementById('tune-reason').value;
        var fieldsToUpdate = getSelectedFields('tune-fields-list');

        // Validate JIRA - must be exactly 4 digits
        if (!jira || !/^\d{4}$/.test(jira)) {
            jiraInput.classList.add('input-error');
            showToast('JIRA Issue must be exactly 4 digits (e.g., 1234)', 'warning');
            return;
        }
        jiraInput.classList.remove('input-error');

        if (!analyst) {
            showToast('Please enter analyst name', 'warning');
            return;
        }

        if (!reason) {
            showToast('Please select a reason', 'warning');
            return;
        }

        // Store pending tune data with MRDP- prefix
        pendingTune = {
            detectionName: d['Detection Name'],
            jira: 'MRDP-' + jira,
            analyst: analyst,
            description: description,
            reason: reason,
            fieldsToUpdate: fieldsToUpdate,
            oldData: JSON.stringify(d),
            timestamp: new Date().toISOString()
        };

        // Close modal and load into editor
        document.getElementById('modal-tune').classList.add('hidden');

        // Switch to Editor tab and load detection
        switchTab('editor');
        loadDetectionIntoForm(d);

        showToast('Make your changes and save. Tune will be recorded in history.', 'info');
    };

    // Open Retrofit Modal
    window.openRetrofitModal = function() {
        var d = App.state.selectedDetection;
        if (!d) {
            showToast('Please select a detection first', 'warning');
            return;
        }

        // Set detection name
        var nameEl = document.getElementById('retrofit-detection-name');
        if (nameEl) nameEl.textContent = d['Detection Name'];

        // Reset form
        var jiraInput = document.getElementById('retrofit-jira');
        jiraInput.value = '';
        jiraInput.classList.remove('input-error');
        document.getElementById('retrofit-analyst').value = '';
        document.getElementById('retrofit-description').value = '';
        document.getElementById('retrofit-type').value = '';

        // Render fields multi-select
        renderFieldsMultiSelect('retrofit-fields-list', d);

        // Show modal
        document.getElementById('modal-retrofit').classList.remove('hidden');
    };

    // Close Retrofit Modal
    window.closeRetrofitModal = function() {
        document.getElementById('modal-retrofit').classList.add('hidden');
        pendingRetrofit = null;
    };

    // Submit Retrofit - stores data and opens editor
    window.submitRetrofit = function() {
        var d = App.state.selectedDetection;
        if (!d) return;

        var jiraInput = document.getElementById('retrofit-jira');
        var jira = jiraInput.value.trim();
        var analyst = document.getElementById('retrofit-analyst').value.trim();
        var description = document.getElementById('retrofit-description').value.trim();
        var retrofitType = document.getElementById('retrofit-type').value;
        var fieldsToUpdate = getSelectedFields('retrofit-fields-list');

        // Validate JIRA - must be exactly 4 digits
        if (!jira || !/^\d{4}$/.test(jira)) {
            jiraInput.classList.add('input-error');
            showToast('JIRA Issue must be exactly 4 digits (e.g., 1234)', 'warning');
            return;
        }
        jiraInput.classList.remove('input-error');

        if (!analyst) {
            showToast('Please enter analyst name', 'warning');
            return;
        }

        if (!retrofitType) {
            showToast('Please select a retrofit type', 'warning');
            return;
        }

        // Store pending retrofit data with MRDP- prefix
        pendingRetrofit = {
            detectionName: d['Detection Name'],
            jira: 'MRDP-' + jira,
            analyst: analyst,
            description: description,
            type: retrofitType,
            fieldsToUpdate: fieldsToUpdate,
            oldData: JSON.stringify(d),
            timestamp: new Date().toISOString()
        };

        // Close modal and load into editor
        document.getElementById('modal-retrofit').classList.add('hidden');

        // Switch to Editor tab and load detection
        switchTab('editor');
        loadDetectionIntoForm(d);

        showToast('Make your changes and save. Retrofit will be recorded in history.', 'info');
    };

    // Global switchTab function - switches between views
    window.switchTab = function(viewName) {
        // Hide all views
        document.querySelectorAll('.view').forEach(function(view) {
            view.classList.remove('active');
        });

        // Show target view
        var targetView = document.getElementById('view-' + viewName);
        if (targetView) {
            targetView.classList.add('active');
        }

        // Update nav items
        document.querySelectorAll('.nav-item').forEach(function(nav) {
            nav.classList.remove('active');
            if (nav.getAttribute('href') === '#' + viewName) {
                nav.classList.add('active');
            }
        });

        // Update URL hash without triggering hashchange
        history.replaceState(null, '', '#' + viewName);

        // Update content header
        var contentHeader = document.querySelector('.content-header h2');
        if (contentHeader) {
            var titles = {
                'library': 'Library',
                'editor': 'Editor',
                'macros': 'Macros',
                'revalidation': 'Revalidation',
                'history': 'History',
                'resources': 'Resources',
                'reports': 'Reports',
                'settings': 'Settings'
            };
            contentHeader.textContent = titles[viewName] || viewName;
        }
    };

    // Render fields multi-select for tune/retrofit modals
    function renderFieldsMultiSelect(containerId, detection) {
        var container = document.getElementById(containerId);
        if (!container) return;

        var fields = [
            'Detection Name', 'Description', 'Objective', 'Assumptions',
            'Severity/Priority', 'Security Domain', 'Search String',
            'Required_Data_Sources', 'Cron Schedule', 'Trigger Condition',
            'Throttling', 'Risk', 'Notable Title', 'Notable Description',
            'Analyst Next Steps', 'Blind_Spots_False_Positives',
            'Mitre ID', 'Drilldowns', 'Roles', 'Proposed Test Plan'
        ];

        var html = fields.map(function(field) {
            var hasValue = detection && hasFieldValue(detection, field);
            var statusClass = hasValue ? 'has-value' : 'no-value';
            var statusIcon = hasValue ? '✓' : '○';

            return '<label class="field-checkbox ' + statusClass + '">' +
                '<input type="checkbox" value="' + escapeAttr(field) + '" onchange="updateFieldsSelectedCount(\'' + containerId + '\')"> ' +
                '<span class="field-status">' + statusIcon + '</span> ' +
                escapeHtml(field) +
            '</label>';
        }).join('');

        // Add selected count display
        html += '<div class="fields-selected-count" id="' + containerId + '-count">Click to select fields you will update</div>';

        container.innerHTML = html;
    }

    // Update the selected fields count display
    window.updateFieldsSelectedCount = function(containerId) {
        var container = document.getElementById(containerId);
        if (!container) return;

        var count = container.querySelectorAll('input[type="checkbox"]:checked').length;
        var countEl = document.getElementById(containerId + '-count');
        if (countEl) {
            if (count === 0) {
                countEl.textContent = 'Click to select fields you will update';
                countEl.style.color = 'var(--color-text-muted)';
            } else {
                countEl.textContent = count + ' field' + (count === 1 ? '' : 's') + ' selected';
                countEl.style.color = 'var(--color-accent)';
            }
        }
    };

    // Check if a field has a value
    function hasFieldValue(d, field) {
        if (field === 'Drilldowns') {
            return d['Drilldown Name (Legacy)'] || d['Drilldown Name 1'];
        }
        if (field === 'Throttling') {
            var t = d['Throttling'];
            return t && (t.enabled || t.fields);
        }
        if (field === 'Risk') {
            return d['Risk'] && d['Risk'].length > 0 && d['Risk'][0].risk_object_field;
        }
        if (field === 'Mitre ID') {
            return d['Mitre ID'] && d['Mitre ID'].length > 0;
        }
        if (field === 'Roles') {
            return d['Roles'] && d['Roles'].some(function(r) { return r.Name && r.Name.trim(); });
        }
        var val = d[field];
        return val && val !== '';
    }

    // Get selected fields from multi-select
    function getSelectedFields(containerId) {
        var container = document.getElementById(containerId);
        if (!container) return [];

        var checkboxes = container.querySelectorAll('input[type="checkbox"]:checked');
        return Array.from(checkboxes).map(function(cb) { return cb.value; });
    }

    // Add entry to history
    function addToHistory(detectionName, type, description, oldData, analyst, fieldsChanged) {
        // Get existing history from localStorage
        var historyKey = 'de_mainframe_history';
        var history = JSON.parse(localStorage.getItem(historyKey) || '{}');

        if (!history[detectionName]) {
            history[detectionName] = [];
        }

        var entry = {
            id: Date.now(),
            type: type,
            description: description,
            timestamp: new Date().toISOString(),
            oldData: oldData,
            analyst: analyst || 'Unknown',
            fieldsChanged: fieldsChanged || []
        };

        history[detectionName].push(entry);

        // Save back to localStorage
        localStorage.setItem(historyKey, JSON.stringify(history));

        return entry;
    }

    // Get history for a detection
    window.getDetectionHistory = function(detectionName) {
        var historyKey = 'de_mainframe_history';
        var history = JSON.parse(localStorage.getItem(historyKey) || '{}');
        return history[detectionName] || [];
    };

    // Clear pending tune/retrofit after save
    function clearPendingTuneRetrofit() {
        if (pendingTune) {
            addToHistory(
                pendingTune.detectionName,
                'tune',
                pendingTune.description || 'Tuned detection - ' + pendingTune.reason,
                pendingTune.oldData,
                pendingTune.analyst,
                pendingTune.fieldsToUpdate
            );
            showToast('Tune recorded in history', 'success');
            pendingTune = null;
        }

        if (pendingRetrofit) {
            addToHistory(
                pendingRetrofit.detectionName,
                'retrofit',
                pendingRetrofit.description || 'Retrofitted detection - ' + pendingRetrofit.type,
                pendingRetrofit.oldData,
                pendingRetrofit.analyst,
                pendingRetrofit.fieldsToUpdate
            );
            showToast('Retrofit recorded in history', 'success');
            pendingRetrofit = null;
        }
    }

    // Global toggle functions for onclick handlers
    window.toggleSidebar = function() {
        App.toggleSidebar();
    };

    window.toggleTheme = function() {
        App.toggleTheme();
    };

    window.validatePassword = function() {
        App.validatePassword();
    };

    // =========================================================================
    // EDITOR VIEW FUNCTIONS
    // =========================================================================

    // Detection Template
    var DETECTION_TEMPLATE = {
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
        "Mitre ID": [], "Proposed Test Plan": ""
    };

    // Add drilldown fields 1-15
    for (var i = 1; i <= 15; i++) {
        DETECTION_TEMPLATE["Drilldown Name " + i] = "";
        DETECTION_TEMPLATE["Drilldown Search " + i] = "";
        DETECTION_TEMPLATE["Drilldown Earliest " + i] = null;
        DETECTION_TEMPLATE["Drilldown Latest " + i] = null;
    }

    var MANDATORY_FIELDS = [
        'Detection Name', 'Objective', 'Severity/Priority', 'Analyst Next Steps',
        'Blind_Spots_False_Positives', 'Required_Data_Sources', 'Search String',
        'Risk', 'Notable Title'
    ];

    // Editor State
    var editorState = {
        currentDetection: null,
        hasUnsavedChanges: false,
        drilldownCount: 0,
        loadedMacros: [],
        mitreIds: [],
        dataSources: []
    };

    // Initialize Editor
    function initEditor() {
        // Set up form field listeners for validation
        var form = document.getElementById('detection-form');
        if (form) {
            form.addEventListener('input', function() {
                editorState.hasUnsavedChanges = true;
                validateForm();
                updateSplParsedPreview();
            });
            form.addEventListener('change', function() {
                editorState.hasUnsavedChanges = true;
                validateForm();
            });
        }

        // SPL field change triggers parsing
        var splField = document.getElementById('field-search-string');
        if (splField) {
            splField.addEventListener('input', debounce(function() {
                updateSplParsedPreview();
                autoPopulateDataSources();
            }, 300));
        }

        // Detection Name auto-populates Notable Title and Notable Description
        var nameField = document.getElementById('field-detection-name');
        if (nameField) {
            nameField.addEventListener('input', function() {
                autoPopulateNotableFields();
            });
        }

        // Clear autopopulated flag when user manually edits Notable fields
        var notableTitleField = document.getElementById('field-notable-title');
        if (notableTitleField) {
            notableTitleField.addEventListener('input', function() {
                // If user is typing something different than the detection name, mark as manual
                var detName = document.getElementById('field-detection-name').value;
                if (this.value !== detName) {
                    this.dataset.autopopulated = 'false';
                }
            });
        }

        var notableDescField = document.getElementById('field-notable-desc');
        if (notableDescField) {
            notableDescField.addEventListener('input', function() {
                // If user is typing something different than the auto-generated text, mark as manual
                var detName = document.getElementById('field-detection-name').value;
                if (this.value !== detName + ' detected on ') {
                    this.dataset.autopopulated = 'false';
                }
            });
        }

        // MITRE ID input - add tags on Enter key
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

        // Initialize form with blank detection
        createNewDetection();
    }

    // Auto-populate Notable Title and Notable Description from Detection Name
    function autoPopulateNotableFields() {
        var detectionName = document.getElementById('field-detection-name').value;
        var notableTitleEl = document.getElementById('field-notable-title');
        var notableDescEl = document.getElementById('field-notable-desc');

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

    // MITRE TAG MANAGEMENT - Supports sub-techniques (T1003.002)
    function addMitreTag(value) {
        var cleaned = value.trim().toUpperCase();
        if (!cleaned) return;
        // Regex supports sub-techniques like T1003.002
        if (!/^T\d{4}(\.\d{3})?$/.test(cleaned)) {
            showToast('Invalid MITRE format. Use T1234 or T1234.001', 'warning');
            return;
        }
        if (editorState.mitreIds.indexOf(cleaned) === -1) {
            editorState.mitreIds.push(cleaned);
            renderMitreTags();
            editorState.hasUnsavedChanges = true;
            validateForm();
        }
    }

    window.removeMitreTag = function(index) {
        editorState.mitreIds.splice(index, 1);
        renderMitreTags();
        editorState.hasUnsavedChanges = true;
        validateForm();
    };

    function renderMitreTags() {
        var container = document.getElementById('mitre-tags');
        if (!container) return;
        var html = '';
        editorState.mitreIds.forEach(function(id, i) {
            html += '<span class="mitre-tag">' + escapeHtml(id) + '<span class="tag-remove" onclick="removeMitreTag(' + i + ')">×</span></span>';
        });
        container.innerHTML = html;
    }

    // DATA SOURCE TAG MANAGEMENT
    function addDataSourceTag(value) {
        var trimmed = value.trim();
        if (trimmed && editorState.dataSources.indexOf(trimmed) === -1) {
            editorState.dataSources.push(trimmed);
            renderDataSourceTags();
            editorState.hasUnsavedChanges = true;
            validateForm();
        }
    }

    window.removeDataSourceTag = function(index) {
        editorState.dataSources.splice(index, 1);
        renderDataSourceTags();
        editorState.hasUnsavedChanges = true;
        validateForm();
    };

    function renderDataSourceTags() {
        var container = document.getElementById('datasource-tags');
        if (!container) return;
        container.innerHTML = editorState.dataSources.map(function(ds, i) {
            return '<span class="tag">' + escapeHtml(ds) + '<button type="button" onclick="removeDataSourceTag(' + i + ')">x</button></span>';
        }).join('');
    }

    // Debounce helper
    function debounce(fn, wait) {
        var timeout;
        return function() {
            var args = arguments;
            var context = this;
            clearTimeout(timeout);
            timeout = setTimeout(function() {
                fn.apply(context, args);
            }, wait);
        };
    }

    // Format date/time helper
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

    // Create New Detection
    window.createNewDetection = function() {
        editorState.currentDetection = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));
        editorState.currentDetection['First Created'] = new Date().toISOString();
        editorState.hasUnsavedChanges = false;
        editorState.drilldownCount = 0;
        editorState.mitreIds = [];
        editorState.dataSources = [];
        loadDetectionIntoForm(editorState.currentDetection);
        validateForm();
        updateSplParsedPreview();
    };

    // Clear Form - resets all form fields to blank template
    window.clearForm = function() {
        if (editorState.hasUnsavedChanges) {
            // Show confirmation modal
            var modal = document.getElementById('modal-clear-confirm');
            if (modal) modal.classList.remove('hidden');
        } else {
            doClearForm();
        }
    };

    // Actually clear the form (called after confirmation or if no unsaved changes)
    function doClearForm() {
        editorState.currentDetection = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));
        editorState.currentDetection['First Created'] = new Date().toISOString();
        editorState.hasUnsavedChanges = false;
        editorState.drilldownCount = 0;
        editorState.mitreIds = [];
        editorState.dataSources = [];

        // Clear containers
        var drilldownsContainer = document.getElementById('drilldowns-container');
        if (drilldownsContainer) drilldownsContainer.innerHTML = '';

        var riskContainer = document.getElementById('risk-entries-container');
        if (riskContainer) riskContainer.innerHTML = '';

        var mitreTagsContainer = document.getElementById('mitre-tags');
        if (mitreTagsContainer) mitreTagsContainer.innerHTML = '';

        var datasourceTagsContainer = document.getElementById('datasource-tags');
        if (datasourceTagsContainer) datasourceTagsContainer.innerHTML = '';

        loadDetectionIntoForm(editorState.currentDetection);
        validateForm();
        updateSplParsedPreview();
        showToast('Form cleared', 'info');
    }

    // Close Clear Confirm Modal
    window.closeClearConfirmModal = function() {
        var modal = document.getElementById('modal-clear-confirm');
        if (modal) modal.classList.add('hidden');
    };

    // Confirm Clear Form
    window.confirmClearForm = function() {
        closeClearConfirmModal();
        doClearForm();
    };

    // Load Detection into Form
    function loadDetectionIntoForm(d) {
        // Basic fields
        document.getElementById('field-detection-name').value = d['Detection Name'] || '';
        document.getElementById('field-objective').value = d['Objective'] || '';
        document.getElementById('field-description').value = d['Description'] || '';
        document.getElementById('field-severity').value = (d['Severity/Priority'] || '').toLowerCase();
        document.getElementById('field-domain').value = (d['Security Domain'] || '').toLowerCase();
        document.getElementById('field-origin').value = d['origin'] || 'custom';

        // MITRE IDs - populate tag array
        editorState.mitreIds = [];
        if (Array.isArray(d['Mitre ID'])) {
            editorState.mitreIds = d['Mitre ID'].slice(); // Clone the array
        } else if (d['Mitre ID']) {
            // Handle comma-separated string format
            editorState.mitreIds = d['Mitre ID'].split(/[,;]/).map(function(s) { return s.trim(); }).filter(Boolean);
        }
        renderMitreTags();

        // Roles
        if (d['Roles'] && Array.isArray(d['Roles'])) {
            d['Roles'].forEach(function(r) {
                if (r.Role === 'Requestor') {
                    document.getElementById('field-role-requestor-name').value = r.Name || '';
                    document.getElementById('field-role-requestor-title').value = r.Title || '';
                } else if (r.Role === 'Business Owner') {
                    document.getElementById('field-role-business-name').value = r.Name || '';
                    document.getElementById('field-role-business-title').value = r.Title || '';
                } else if (r.Role === 'Technical Owner') {
                    document.getElementById('field-role-technical-name').value = r.Name || '';
                    document.getElementById('field-role-technical-title').value = r.Title || '';
                }
            });
        }

        // Search Configuration
        document.getElementById('field-search-string').value = d['Search String'] || '';

        // Data Sources - populate from comma-separated string into array and render tags
        var dsString = d['Required_Data_Sources'] || '';
        editorState.dataSources = dsString.split(/[,;]/).map(function(s) { return s.trim(); }).filter(Boolean);
        renderDataSourceTags();

        document.getElementById('field-assumptions').value = d['Assumptions'] || '';

        // Risk
        loadRiskEntries(d);

        // Notable Event
        document.getElementById('field-notable-title').value = d['Notable Title'] || '';
        document.getElementById('field-notable-desc').value = d['Notable Description'] || '';
        document.getElementById('field-analyst-steps').value = d['Analyst Next Steps'] || '';
        document.getElementById('field-blind-spots').value = d['Blind_Spots_False_Positives'] || '';

        // Scheduling
        document.getElementById('field-cron').value = d['Cron Schedule'] || '';
        document.getElementById('field-schedule-window').value = d['Schedule Window'] || '';
        document.getElementById('field-schedule-priority').value = d['Schedule Priority'] || '';
        document.getElementById('field-trigger').value = d['Trigger Condition'] || '';

        // Throttling
        var throttle = d['Throttling'] || {};
        document.getElementById('field-throttle-enabled').value = throttle.enabled || '0';
        document.getElementById('field-throttle-fields').value = throttle.fields || '';
        document.getElementById('field-throttle-period').value = throttle.period || '';

        // Drilldowns
        loadDrilldowns(d);

        // Test Plan
        document.getElementById('field-test-plan').value = d['Proposed Test Plan'] || '';

        // Update JSON view
        updateJsonView();

        // Store as current detection for editor
        editorState.currentDetection = JSON.parse(JSON.stringify(d));
    }

    // Make loadDetectionIntoForm globally accessible
    window.loadDetectionIntoForm = loadDetectionIntoForm;

    // Load Risk Entries
    function loadRiskEntries(d) {
        var container = document.getElementById('risk-entries-container');
        container.innerHTML = '';

        var risks = d['Risk'] || [{ risk_object_field: '', risk_object_type: 'user', risk_score: 0 }];
        if (!Array.isArray(risks)) {
            risks = [{
                risk_object_field: d['Risk Object Field'] || '',
                risk_object_type: d['Risk Object Type'] || 'user',
                risk_score: d['Risk Score'] || 0
            }];
        }

        risks.forEach(function(risk, index) {
            addRiskEntryHtml(index, risk);
        });
    }

    // Add Risk Entry HTML
    function addRiskEntryHtml(index, risk) {
        var container = document.getElementById('risk-entries-container');
        var div = document.createElement('div');
        div.className = 'risk-entry';
        div.setAttribute('data-risk-index', index);
        div.innerHTML = '<div class="form-row three-col">' +
            '<div class="form-group">' +
            '<label>Risk Object Field' + (index === 0 ? ' <span class="required">*</span>' : '') + '</label>' +
            '<input type="text" class="form-input risk-field" placeholder="e.g., $user$" value="' + escapeAttr(risk.risk_object_field || '') + '">' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Risk Object Type</label>' +
            '<select class="form-select risk-type">' +
            '<option value="user"' + (risk.risk_object_type === 'user' ? ' selected' : '') + '>User</option>' +
            '<option value="system"' + (risk.risk_object_type === 'system' ? ' selected' : '') + '>System</option>' +
            '<option value="other"' + (risk.risk_object_type === 'other' ? ' selected' : '') + '>Other</option>' +
            '</select>' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Risk Score' + (index === 0 ? ' <span class="required">*</span>' : '') + '</label>' +
            '<input type="number" class="form-input risk-score" min="0" max="100" value="' + (risk.risk_score || 0) + '">' +
            '</div>' +
            '</div>' +
            (index > 0 ? '<button type="button" class="btn-remove" onclick="removeRiskEntry(' + index + ')">×</button>' : '');
        container.appendChild(div);
    }

    // Add Risk Entry
    window.addRiskEntry = function() {
        var container = document.getElementById('risk-entries-container');
        var index = container.children.length;
        addRiskEntryHtml(index, { risk_object_field: '', risk_object_type: 'user', risk_score: 0 });
    };

    // Remove Risk Entry
    window.removeRiskEntry = function(index) {
        var container = document.getElementById('risk-entries-container');
        var entries = container.querySelectorAll('.risk-entry');
        if (entries[index]) {
            container.removeChild(entries[index]);
        }
    };

    // Load Drilldowns
    function loadDrilldowns(d) {
        var container = document.getElementById('drilldowns-container');
        container.innerHTML = '';
        editorState.drilldownCount = 0;

        // Check legacy drilldown
        if (d['Drilldown Name (Legacy)']) {
            addDrilldownHtml({
                name: d['Drilldown Name (Legacy)'],
                search: d['Drilldown Search (Legacy)'] || '',
                earliest: d['Drilldown Earliest Offset (Legacy)'],
                latest: d['Drilldown Latest Offset (Legacy)']
            });
        }

        // Check numbered drilldowns
        for (var i = 1; i <= 15; i++) {
            if (d['Drilldown Name ' + i]) {
                addDrilldownHtml({
                    name: d['Drilldown Name ' + i],
                    search: d['Drilldown Search ' + i] || '',
                    earliest: d['Drilldown Earliest ' + i],
                    latest: d['Drilldown Latest ' + i]
                });
            }
        }
    }

    // Add Drilldown HTML
    function addDrilldownHtml(dd) {
        var container = document.getElementById('drilldowns-container');
        var index = editorState.drilldownCount++;
        var div = document.createElement('div');
        div.className = 'drilldown-entry';
        div.setAttribute('data-drilldown-index', index);
        div.innerHTML = '<div class="drilldown-header">' +
            '<span class="drilldown-title">Drilldown ' + (index + 1) + '</span>' +
            '<button type="button" class="btn-remove" onclick="removeDrilldown(' + index + ')">×</button>' +
            '</div>' +
            '<div class="form-row">' +
            '<div class="form-group full-width">' +
            '<label>Drilldown Name</label>' +
            '<input type="text" class="form-input drilldown-name" value="' + escapeAttr(dd.name || '') + '">' +
            '</div>' +
            '</div>' +
            '<div class="form-row">' +
            '<div class="form-group full-width">' +
            '<label>Drilldown Search</label>' +
            '<textarea class="form-textarea drilldown-search code-input" rows="3">' + escapeHtml(dd.search || '') + '</textarea>' +
            '</div>' +
            '</div>' +
            '<div class="form-row two-col">' +
            '<div class="form-group">' +
            '<label>Earliest Offset</label>' +
            '<input type="text" class="form-input drilldown-earliest" value="' + escapeAttr(dd.earliest || '') + '" placeholder="-24h@h">' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Latest Offset</label>' +
            '<input type="text" class="form-input drilldown-latest" value="' + escapeAttr(dd.latest || '') + '" placeholder="now">' +
            '</div>' +
            '</div>';
        container.appendChild(div);
    }

    // Add Drilldown
    window.addDrilldown = function() {
        addDrilldownHtml({ name: '', search: '', earliest: '', latest: '' });
    };

    // Remove Drilldown
    window.removeDrilldown = function(index) {
        var container = document.getElementById('drilldowns-container');
        var entries = container.querySelectorAll('.drilldown-entry');
        for (var i = 0; i < entries.length; i++) {
            if (parseInt(entries[i].getAttribute('data-drilldown-index')) === index) {
                container.removeChild(entries[i]);
                break;
            }
        }
    };

    // Get Form Data
    function getFormData() {
        var d = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));

        // Basic fields
        d['Detection Name'] = document.getElementById('field-detection-name').value.trim();
        d['Objective'] = document.getElementById('field-objective').value.trim();
        d['Description'] = document.getElementById('field-description').value.trim();
        d['Severity/Priority'] = document.getElementById('field-severity').value;
        d['Security Domain'] = document.getElementById('field-domain').value;
        d['origin'] = document.getElementById('field-origin').value;

        // MITRE IDs - use tag array from editorState
        d['Mitre ID'] = editorState.mitreIds.slice(); // Clone the array

        // Roles
        d['Roles'] = [
            { Role: 'Requestor', Name: document.getElementById('field-role-requestor-name').value.trim(), Title: document.getElementById('field-role-requestor-title').value.trim() },
            { Role: 'Business Owner', Name: document.getElementById('field-role-business-name').value.trim(), Title: document.getElementById('field-role-business-title').value.trim() },
            { Role: 'Technical Owner', Name: document.getElementById('field-role-technical-name').value.trim(), Title: document.getElementById('field-role-technical-title').value.trim() }
        ];

        // Search Configuration
        d['Search String'] = document.getElementById('field-search-string').value;
        // Data Sources - join the tag array into comma-separated string
        d['Required_Data_Sources'] = editorState.dataSources.join(', ');
        d['Assumptions'] = document.getElementById('field-assumptions').value.trim();

        // Risk
        var risks = [];
        var riskEntries = document.querySelectorAll('#risk-entries-container .risk-entry');
        riskEntries.forEach(function(entry) {
            var field = entry.querySelector('.risk-field').value.trim();
            var type = entry.querySelector('.risk-type').value;
            var score = parseInt(entry.querySelector('.risk-score').value) || 0;
            if (field || score > 0) {
                risks.push({ risk_object_field: field, risk_object_type: type, risk_score: score });
            }
        });
        d['Risk'] = risks.length > 0 ? risks : [{ risk_object_field: '', risk_object_type: 'user', risk_score: 0 }];

        // Notable Event
        d['Notable Title'] = document.getElementById('field-notable-title').value.trim();
        d['Notable Description'] = document.getElementById('field-notable-desc').value.trim();
        d['Analyst Next Steps'] = document.getElementById('field-analyst-steps').value.trim();
        d['Blind_Spots_False_Positives'] = document.getElementById('field-blind-spots').value.trim();

        // Scheduling
        d['Cron Schedule'] = document.getElementById('field-cron').value.trim();
        d['Schedule Window'] = document.getElementById('field-schedule-window').value.trim();
        d['Schedule Priority'] = document.getElementById('field-schedule-priority').value;
        d['Trigger Condition'] = document.getElementById('field-trigger').value.trim();

        // Throttling
        d['Throttling'] = {
            enabled: parseInt(document.getElementById('field-throttle-enabled').value) || 0,
            fields: document.getElementById('field-throttle-fields').value.trim(),
            period: document.getElementById('field-throttle-period').value.trim()
        };

        // Drilldowns
        var drilldownEntries = document.querySelectorAll('#drilldowns-container .drilldown-entry');
        var ddIndex = 1;
        drilldownEntries.forEach(function(entry) {
            var name = entry.querySelector('.drilldown-name').value.trim();
            var search = entry.querySelector('.drilldown-search').value;
            var earliest = entry.querySelector('.drilldown-earliest').value.trim();
            var latest = entry.querySelector('.drilldown-latest').value.trim();
            if (name) {
                d['Drilldown Name ' + ddIndex] = name;
                d['Drilldown Search ' + ddIndex] = search;
                d['Drilldown Earliest ' + ddIndex] = earliest || null;
                d['Drilldown Latest ' + ddIndex] = latest || null;
                ddIndex++;
            }
        });

        // Test Plan
        d['Proposed Test Plan'] = document.getElementById('field-test-plan').value.trim();

        // Timestamps
        d['First Created'] = editorState.currentDetection['First Created'] || new Date().toISOString();
        d['Last Modified'] = new Date().toISOString();

        // File name
        d['file_name'] = generateFileName(d['Detection Name'], d['Security Domain']);

        return d;
    }

    // Generate File Name
    function generateFileName(name, domain) {
        if (!name) return '';
        var prefix = '';
        if (domain) {
            var domainMap = {
                'access': 'access', 'endpoint': 'endpoint', 'network': 'network',
                'threat': 'threat', 'identity': 'identity', 'audit': 'audit',
                'application': 'application', 'web': 'web'
            };
            prefix = domainMap[domain.toLowerCase()] || '';
        }
        var cleanName = name.replace(/[<>:"/\\|?*]/g, '').replace(/\s+/g, '_');
        var fileName = (prefix ? prefix + '_' : '') + cleanName;
        return fileName.substring(0, 100) + '.json';
    }

    // Validate Form
    function validateForm() {
        var d = getFormData();
        var errors = [];
        var warnings = [];

        // Check mandatory fields
        if (!d['Detection Name']) errors.push('Detection Name is required');
        if (!d['Objective']) errors.push('Objective is required');
        if (!d['Severity/Priority']) errors.push('Severity/Priority is required');
        if (!d['Analyst Next Steps']) errors.push('Analyst Next Steps is required');
        if (!d['Blind_Spots_False_Positives']) errors.push('Blind Spots/False Positives is required');
        if (editorState.dataSources.length === 0) errors.push('Data Sources is required');
        if (!d['Search String']) errors.push('Search String is required');
        if (!d['Notable Title']) errors.push('Notable Title is required');

        // Check Risk
        var hasRisk = d['Risk'] && d['Risk'].length > 0 &&
                      d['Risk'].some(function(r) { return r.risk_object_field && r.risk_score > 0; });
        if (!hasRisk) errors.push('At least one Risk entry with field and score is required');

        // Warnings
        if (!d['Description']) warnings.push('Description is recommended');
        if (!d['Security Domain']) warnings.push('Security Domain is recommended');
        if (d['Mitre ID'].length === 0) warnings.push('MITRE ATT&CK IDs are recommended');
        if (!d['Cron Schedule']) warnings.push('Cron Schedule is recommended');

        // Update UI
        var errorsEl = document.getElementById('validation-errors');
        var warningsEl = document.getElementById('validation-warnings');
        var statusEl = document.getElementById('validation-status');
        var saveBtn = document.getElementById('btn-editor-save');

        if (errorsEl) {
            if (errors.length > 0) {
                errorsEl.innerHTML = errors.map(function(e) {
                    return '<li class="validation-item error">' + escapeHtml(e) + '</li>';
                }).join('');
            } else {
                errorsEl.innerHTML = '<li class="validation-item success">All required fields complete</li>';
            }
        }

        if (warningsEl) {
            if (warnings.length > 0) {
                warningsEl.innerHTML = warnings.map(function(w) {
                    return '<li class="validation-item warning">' + escapeHtml(w) + '</li>';
                }).join('');
            } else {
                warningsEl.innerHTML = '';
            }
        }

        if (statusEl) {
            if (errors.length === 0) {
                statusEl.textContent = 'Ready';
                statusEl.classList.add('ready');
                statusEl.classList.remove('error');
            } else {
                statusEl.textContent = errors.length + ' Error' + (errors.length > 1 ? 's' : '');
                statusEl.classList.add('error');
                statusEl.classList.remove('ready');
            }
        }

        if (saveBtn) {
            saveBtn.disabled = errors.length > 0;
        }

        // Check for missing macros
        checkMissingMacros(d['Search String']);

        return errors.length === 0;
    }

    // Check Missing Macros
    function checkMissingMacros(spl) {
        var macroHeader = document.getElementById('missing-macros-header');
        var macroList = document.getElementById('missing-macros-list');
        if (!macroHeader || !macroList) return;

        var parsed = parseSPL(spl);
        var missingMacros = [];

        // Check if macros are loaded
        if (parsed.macros.length > 0 && editorState.loadedMacros.length > 0) {
            parsed.macros.forEach(function(macro) {
                if (editorState.loadedMacros.indexOf(macro) === -1) {
                    missingMacros.push(macro);
                }
            });
        } else if (parsed.macros.length > 0) {
            // If no macros loaded, show all as potentially missing (clickable to macros tab)
            missingMacros = parsed.macros;
        }

        if (missingMacros.length > 0) {
            macroHeader.classList.remove('hidden');
            macroList.innerHTML = missingMacros.map(function(m) {
                return '<li class="validation-item warning"><span class="macro-link clickable" onclick="openMacroModal(\'' + escapeAttr(m) + '\')">`' + escapeHtml(m) + '`</span> - click to view details</li>';
            }).join('');
        } else {
            macroHeader.classList.add('hidden');
            macroList.innerHTML = '';
        }
    }

    // Go to Macros Tab
    window.goToMacrosTab = function(macroName) {
        // Navigate to macros view
        var navItem = document.querySelector('.nav-item[href="#macros"]');
        if (navItem) {
            App.handleNavigation(navItem);
        }
        // If macro name provided, select it after navigation
        if (macroName && typeof selectMacro === 'function') {
            setTimeout(function() {
                selectMacro(macroName);
            }, 100);
        }
    };

    // Navigate to Macros tab with pre-filled name for adding a new macro
    window.navigateToMacrosWithName = function(macroName) {
        // Navigate to macros view
        var navItem = document.querySelector('.nav-item[href="#macros"]');
        if (navItem) {
            App.handleNavigation(navItem);
        }
        // Open the "create new macro" form with the name pre-filled
        setTimeout(function() {
            if (typeof createNewMacro === 'function') {
                createNewMacro();
                // Pre-fill the name
                var nameInput = document.getElementById('macro-field-name');
                if (nameInput && macroName) {
                    nameInput.value = macroName;
                }
            }
        }, 150);
    };

    // Update SPL Parsed Preview
    function updateSplParsedPreview() {
        var spl = document.getElementById('field-search-string').value;
        var previewEl = document.getElementById('spl-parsed-preview');
        var contentEl = document.getElementById('spl-parsed-content');

        if (!spl || !previewEl || !contentEl) {
            if (previewEl) previewEl.classList.add('hidden');
            return;
        }

        var parsed = parseSPL(spl);
        var hasContent = parsed.indexes.length || parsed.sourcetypes.length ||
                         parsed.macros.length || parsed.lookups.length || parsed.functions.length;

        if (!hasContent) {
            previewEl.classList.add('hidden');
            return;
        }

        previewEl.classList.remove('hidden');
        var html = '';

        if (parsed.indexes.length) {
            html += '<div class="spl-tag-group"><span class="spl-tag-label">Indexes</span><div class="spl-tag-items">';
            parsed.indexes.forEach(function(i) { html += '<span class="spl-tag">' + escapeHtml(i) + '</span>'; });
            html += '</div></div>';
        }
        if (parsed.sourcetypes.length) {
            html += '<div class="spl-tag-group"><span class="spl-tag-label">Sourcetypes</span><div class="spl-tag-items">';
            parsed.sourcetypes.forEach(function(s) { html += '<span class="spl-tag">' + escapeHtml(s) + '</span>'; });
            html += '</div></div>';
        }
        if (parsed.macros.length) {
            html += '<div class="spl-tag-group"><span class="spl-tag-label">Macros</span><div class="spl-tag-items">';
            parsed.macros.forEach(function(m) {
                var macroMissing = !isMacroRegistered(m);
                var macroObj = getMacroByName(m);
                var macroDeprecated = macroObj && macroObj.deprecated;
                var classes = 'spl-tag macro clickable';
                if (macroMissing) classes += ' macro-missing';
                if (macroDeprecated) classes += ' macro-deprecated';
                html += '<span class="' + classes + '" onclick="openMacroModal(\'' + escapeAttr(m) + '\')" title="Click to view macro details">`' + escapeHtml(m) + '`</span>';
            });
            html += '</div></div>';
        }
        if (parsed.lookups.length) {
            html += '<div class="spl-tag-group"><span class="spl-tag-label">Lookups</span><div class="spl-tag-items">';
            parsed.lookups.forEach(function(l) { html += '<span class="spl-tag">' + escapeHtml(l) + '</span>'; });
            html += '</div></div>';
        }
        if (parsed.functions.length) {
            html += '<div class="spl-tag-group"><span class="spl-tag-label">Functions</span><div class="spl-tag-items">';
            parsed.functions.slice(0, 10).forEach(function(f) { html += '<span class="spl-tag">' + escapeHtml(f) + '</span>'; });
            if (parsed.functions.length > 10) html += '<span class="spl-tag">+' + (parsed.functions.length - 10) + ' more</span>';
            html += '</div></div>';
        }

        contentEl.innerHTML = html;
    }

    // Auto-populate Data Sources from parsed SPL
    // Appends to existing dataSources without duplicates
    function autoPopulateDataSources() {
        var spl = document.getElementById('field-search-string').value;
        var parsed = parseSPL(spl);

        // Keep existing manual entries, append parsed ones (avoid duplicates)
        // Using case-insensitive comparison for duplicates
        var existingLower = editorState.dataSources.map(function(ds) { return ds.toLowerCase(); });

        // Add indexes
        parsed.indexes.forEach(function(idx) {
            if (idx && existingLower.indexOf(idx.toLowerCase()) === -1) {
                editorState.dataSources.push(idx);
                existingLower.push(idx.toLowerCase());
            }
        });

        // Add sourcetypes
        parsed.sourcetypes.forEach(function(st) {
            if (st && existingLower.indexOf(st.toLowerCase()) === -1) {
                editorState.dataSources.push(st);
                existingLower.push(st.toLowerCase());
            }
        });

        // Add categories (e.g., AdvancedHunting-DeviceNetworkEvents)
        if (parsed.categories) {
            parsed.categories.forEach(function(cat) {
                if (cat && existingLower.indexOf(cat.toLowerCase()) === -1) {
                    editorState.dataSources.push(cat);
                    existingLower.push(cat.toLowerCase());
                }
            });
        }

        renderDataSourceTags();
    }

    // Toggle Form Section
    window.toggleFormSection = function(sectionNum) {
        var section = document.querySelector('.form-section[data-section="' + sectionNum + '"]');
        if (!section) return;

        var toggle = section.querySelector('.section-toggle');
        if (section.classList.contains('collapsed')) {
            section.classList.remove('collapsed');
            if (toggle) toggle.textContent = '-';
        } else {
            section.classList.add('collapsed');
            if (toggle) toggle.textContent = '+';
        }
    };

    // Switch Editor Tab
    window.switchEditorTab = function(tab) {
        // Update tab buttons
        document.querySelectorAll('.editor-tab-btn').forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.getAttribute('data-tab') === tab) {
                btn.classList.add('active');
            }
        });

        // Update tab content
        document.querySelectorAll('.editor-tab-content').forEach(function(content) {
            content.classList.remove('active');
        });
        document.getElementById('editor-tab-' + tab).classList.add('active');

        // Sync data between tabs
        if (tab === 'json') {
            updateJsonView();
        } else {
            // If switching to form, JSON changes would need to be applied first
        }
    };

    // Update JSON View
    function updateJsonView() {
        var d = getFormData();
        var jsonEditor = document.getElementById('json-editor');
        if (jsonEditor) {
            jsonEditor.value = JSON.stringify(d, null, 2);
        }
    }

    // Format JSON
    window.formatJson = function() {
        var jsonEditor = document.getElementById('json-editor');
        if (!jsonEditor) return;
        try {
            var parsed = JSON.parse(jsonEditor.value);
            jsonEditor.value = JSON.stringify(parsed, null, 2);
        } catch (e) {
            alert('Invalid JSON: ' + e.message);
        }
    };

    // Apply JSON to Form
    window.applyJsonToForm = function() {
        var jsonEditor = document.getElementById('json-editor');
        if (!jsonEditor) return;
        try {
            var parsed = JSON.parse(jsonEditor.value);
            editorState.currentDetection = parsed;
            loadDetectionIntoForm(parsed);
            validateForm();
            updateSplParsedPreview();
            switchEditorTab('form');
        } catch (e) {
            alert('Invalid JSON: ' + e.message);
        }
    };

    // Open Load Modal
    window.openLoadModal = function() {
        var modal = document.getElementById('modal-load');
        var listEl = document.getElementById('load-list');

        if (!modal || !listEl) return;

        // Populate list
        var html = '';
        App.state.detections.forEach(function(d) {
            var name = d['Detection Name'] || 'Unnamed';
            var sev = (d['Severity/Priority'] || '').toLowerCase();
            var modified = d['Last Modified'] ? formatDate(d['Last Modified']) : 'N/A';
            html += '<div class="load-item" onclick="loadDetectionFromModal(\'' + escapeAttr(name) + '\')">';
            html += '<span class="load-item-name">' + escapeHtml(name) + '</span>';
            html += '<div class="load-item-meta">';
            html += '<span class="severity-badge ' + sev + '">' + (sev || 'N/A') + '</span>';
            html += '<span>' + modified + '</span>';
            html += '</div></div>';
        });
        listEl.innerHTML = html || '<div class="empty-state">No detections found</div>';
        modal.classList.remove('hidden');
        document.getElementById('load-search-input').focus();
    };

    // Close Load Modal
    window.closeLoadModal = function() {
        var modal = document.getElementById('modal-load');
        if (modal) modal.classList.add('hidden');
    };

    // Filter Load List
    window.filterLoadList = function() {
        var searchInput = document.getElementById('load-search-input');
        var searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        var items = document.querySelectorAll('#load-list .load-item');

        items.forEach(function(item) {
            var name = item.querySelector('.load-item-name').textContent.toLowerCase();
            if (name.indexOf(searchTerm) !== -1) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        });
    };

    // Load Detection from Modal
    window.loadDetectionFromModal = function(name) {
        var detection = App.state.detections.find(function(d) {
            return d['Detection Name'] === name;
        });
        if (detection) {
            editorState.currentDetection = JSON.parse(JSON.stringify(detection));
            editorState.hasUnsavedChanges = false;
            loadDetectionIntoForm(editorState.currentDetection);
            validateForm();
            updateSplParsedPreview();
            closeLoadModal();
        }
    };

    // Cancel Editor
    window.cancelEditor = function() {
        if (editorState.hasUnsavedChanges) {
            var modal = document.getElementById('modal-unsaved');
            if (modal) modal.classList.remove('hidden');
        } else {
            createNewDetection();
        }
    };

    // Close Unsaved Modal
    window.closeUnsavedModal = function() {
        var modal = document.getElementById('modal-unsaved');
        if (modal) modal.classList.add('hidden');
    };

    // Discard Changes
    window.discardChanges = function() {
        closeUnsavedModal();
        createNewDetection();
    };

    // Save and Continue
    window.saveAndContinue = function() {
        closeUnsavedModal();
        saveDetection();
    };

    // Save Detection
    window.saveDetection = async function() {
        if (!validateForm()) {
            showToast('Please fix validation errors before saving.', 'error');
            return;
        }

        var d = getFormData();

        // Show saving status
        updateSyncStatus('syncing', 'Saving...');

        // Update local state first
        var existingIndex = App.state.detections.findIndex(function(det) {
            return det['Detection Name'] === d['Detection Name'];
        });

        if (existingIndex >= 0) {
            // Preserve internal fields from existing detection
            var existing = App.state.detections[existingIndex];
            if (existing._sha) d._sha = existing._sha;
            if (existing._path) d._path = existing._path;
            App.state.detections[existingIndex] = d;
        } else {
            App.state.detections.push(d);
        }

        editorState.currentDetection = d;
        editorState.hasUnsavedChanges = false;

        // Parse and generate metadata
        var metadata = parseAndSaveMetadata(d);

        // Save to GitHub if connected
        var githubSaveSuccess = false;
        if (github) {
            try {
                // Save detection file
                await saveDetectionToGitHub(d);

                // Save metadata file
                await saveMetadataToGitHub(d['Detection Name'], metadata, d.file_name);

                // Update compiled files
                await updateCompiledFiles(App.state.detections);

                githubSaveSuccess = true;
                showToast('Detection saved to GitHub successfully!', 'success');
                updateSyncStatus('connected', 'Synced');
                // Record pending tune/retrofit to history
                clearPendingTuneRetrofit();
            } catch (error) {
                console.error('GitHub save error:', error);
                showToast('GitHub save failed: ' + error.message + '. Changes saved locally only.', 'error');
                updateSyncStatus('error', 'Sync Failed');
            }
        } else {
            showToast('Detection saved locally. Configure GitHub in Settings to sync.', 'info');
            updateSyncStatus('disconnected', 'Not Connected');
            // Record pending tune/retrofit to history
            clearPendingTuneRetrofit();
        }

        // Save to localStorage for caching (always, regardless of GitHub success)
        saveToLocalStorage();

        // Update UI
        App.state.filteredDetections = App.state.detections.slice();
        App.renderLibrary();
    };

    // Download current detection as JSON file
    window.downloadCurrentDetection = function() {
        var d = getFormData();
        var filename = d['file_name'] || 'detection.json';
        downloadFile(filename, JSON.stringify(d, null, 2));
        showToast('Downloaded: ' + filename, 'success');
    };

    // Helper function to download a file
    function downloadFile(filename, content) {
        var blob = new Blob([content], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    // =========================================================================
    // MACROS VIEW FUNCTIONS
    // =========================================================================

    // Macros State
    var macrosState = {
        macros: [], // Array of macro objects: { name, definition, description, arguments, deprecated, usageCount }
        filteredMacros: [],
        selectedMacro: null,
        isEditing: false,
        isNewMacro: false
    };

    // Initialize Macros View
    function initMacros() {
        loadMacros();
    }

    // Load macros from dist folder
    function loadMacros() {
        fetch(App.config.distPath + 'macros.json')
            .then(function(response) {
                if (!response.ok) throw new Error('Failed to load macros');
                return response.json();
            })
            .then(function(data) {
                // Convert simple array to macro objects with usage counting
                if (Array.isArray(data)) {
                    macrosState.macros = data.map(function(name) {
                        if (typeof name === 'string') {
                            return {
                                name: name,
                                definition: '',
                                description: '',
                                arguments: '',
                                deprecated: false,
                                usageCount: countMacroUsage(name)
                            };
                        }
                        // Already an object
                        return Object.assign({
                            definition: '',
                            description: '',
                            arguments: '',
                            deprecated: false
                        }, name, {
                            usageCount: countMacroUsage(name.name || name)
                        });
                    });
                } else {
                    macrosState.macros = [];
                }
                macrosState.filteredMacros = macrosState.macros.slice();
                editorState.loadedMacros = macrosState.macros.map(function(m) { return m.name; });
                filterMacros();
            })
            .catch(function(err) {
                console.error('Failed to load macros:', err);
                macrosState.macros = [];
                macrosState.filteredMacros = [];
                renderMacrosList();
            });
    }

    // Count how many detections use a macro
    function countMacroUsage(macroName) {
        if (!App.state.detections || !macroName) return 0;
        var count = 0;
        App.state.detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var regex = new RegExp('`' + escapeRegExp(macroName) + '(?:\\([^)]*\\))?`', 'g');
            if (regex.test(spl)) {
                count++;
            }
        });
        return count;
    }

    // Escape special regex characters
    function escapeRegExp(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // Get macro object by name (returns null if not found)
    function getMacroByName(macroName) {
        if (!macroName) return null;
        for (var i = 0; i < macrosState.macros.length; i++) {
            if (macrosState.macros[i].name === macroName) {
                return macrosState.macros[i];
            }
        }
        return null;
    }

    // Check if a macro exists in the loaded macros
    function isMacroRegistered(macroName) {
        return editorState.loadedMacros.indexOf(macroName) !== -1;
    }

    // Render a clickable macro tag with appropriate styling (for use in Library view)
    function renderClickableMacroTag(macroName) {
        var isMissing = !isMacroRegistered(macroName);
        var macro = getMacroByName(macroName);
        var isDeprecated = macro && macro.deprecated;

        var classes = 'card-tag macro clickable';
        if (isMissing) classes += ' macro-missing';
        if (isDeprecated) classes += ' macro-deprecated';

        return '<span class="' + classes + '" onclick="openMacroModal(\'' + escapeAttr(macroName) + '\')" title="Click to view macro details">`' + escapeHtml(macroName) + '`</span>';
    }

    // Get detections that use a macro
    function getDetectionsUsingMacro(macroName) {
        if (!App.state.detections || !macroName) return [];
        var detections = [];
        App.state.detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var regex = new RegExp('`' + escapeRegExp(macroName) + '(?:\\([^)]*\\))?`', 'g');
            if (regex.test(spl)) {
                detections.push({
                    name: d['Detection Name'],
                    severity: d['Severity/Priority'],
                    domain: d['Security Domain']
                });
            }
        });
        return detections;
    }

    // Filter macros based on search, sort, and deprecated toggle
    window.filterMacros = function() {
        var searchInput = document.getElementById('macros-search-input');
        var sortSelect = document.getElementById('macros-sort');
        var showDeprecated = document.getElementById('macros-show-deprecated');

        var searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        var sortOption = sortSelect ? sortSelect.value : 'name-asc';
        var includeDeprecated = showDeprecated ? showDeprecated.checked : false;

        // Filter
        macrosState.filteredMacros = macrosState.macros.filter(function(m) {
            // Search filter
            if (searchTerm && m.name.toLowerCase().indexOf(searchTerm) === -1) {
                return false;
            }
            // Deprecated filter
            if (!includeDeprecated && m.deprecated) {
                return false;
            }
            return true;
        });

        // Sort
        macrosState.filteredMacros.sort(function(a, b) {
            switch (sortOption) {
                case 'name-desc':
                    return b.name.toLowerCase().localeCompare(a.name.toLowerCase());
                case 'most-used':
                    return (b.usageCount || 0) - (a.usageCount || 0);
                case 'least-used':
                    return (a.usageCount || 0) - (b.usageCount || 0);
                case 'name-asc':
                default:
                    return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
            }
        });

        renderMacrosList();
    };

    // Render macros list
    function renderMacrosList() {
        var container = document.getElementById('macros-list');
        var countEl = document.getElementById('macros-count');

        if (countEl) {
            countEl.textContent = macrosState.filteredMacros.length + ' macro' + (macrosState.filteredMacros.length !== 1 ? 's' : '');
        }

        if (!container) return;

        if (macrosState.filteredMacros.length === 0) {
            container.innerHTML = '<div class="empty-state"><span class="empty-icon">⚙</span><p>No macros found</p></div>';
            return;
        }

        var html = '';
        macrosState.filteredMacros.forEach(function(m) {
            var isSelected = macrosState.selectedMacro && macrosState.selectedMacro.name === m.name;
            var classes = 'macro-list-item';
            if (isSelected) classes += ' selected';
            if (m.deprecated) classes += ' deprecated';

            html += '<div class="' + classes + '" onclick="selectMacro(\'' + escapeAttr(m.name) + '\')">';
            html += '<span class="macro-list-item-name">`' + escapeHtml(m.name) + '`</span>';
            html += '<div class="macro-list-item-meta">';
            if (m.deprecated) {
                html += '<span class="macro-deprecated-badge">deprecated</span>';
            }
            var dotClass = (m.usageCount || 0) > 0 ? 'used' : 'unused';
            html += '<span class="usage-indicator">';
            html += '<span class="usage-dot ' + dotClass + '"></span>';
            html += '(' + (m.usageCount || 0) + ')';
            html += '</span>';
            html += '</div>';
            html += '</div>';
        });
        container.innerHTML = html;
    }

    // Select a macro
    window.selectMacro = function(name) {
        var macro = macrosState.macros.find(function(m) {
            return m.name === name;
        });
        if (!macro) return;

        macrosState.selectedMacro = macro;
        macrosState.isNewMacro = false;
        macrosState.isEditing = false;
        renderMacrosList();
        renderMacroDetail(macro);
    };

    // Render macro detail panel
    function renderMacroDetail(macro) {
        document.getElementById('macro-placeholder').classList.add('hidden');
        document.getElementById('macro-detail-content').classList.remove('hidden');

        var titleEl = document.getElementById('macro-detail-title');
        titleEl.textContent = macrosState.isNewMacro ? 'New Macro' : 'Edit Macro';

        // Populate form
        document.getElementById('macro-field-name').value = macro.name || '';
        document.getElementById('macro-field-definition').value = macro.definition || '';
        document.getElementById('macro-field-description').value = macro.description || '';
        document.getElementById('macro-field-arguments').value = macro.arguments || '';
        document.getElementById('macro-field-deprecated').checked = macro.deprecated || false;

        // Disable name field if editing existing macro
        document.getElementById('macro-field-name').disabled = !macrosState.isNewMacro;

        // Show/hide delete button
        document.getElementById('btn-macro-delete').style.display = macrosState.isNewMacro ? 'none' : '';

        // Show usage section
        renderMacroUsage(macro);
    }

    // Render macro usage section
    function renderMacroUsage(macro) {
        var section = document.getElementById('macro-usage-section');
        var listEl = document.getElementById('macro-usage-list');

        if (macrosState.isNewMacro || !macro.name) {
            section.classList.add('hidden');
            return;
        }

        var detections = getDetectionsUsingMacro(macro.name);
        if (detections.length === 0) {
            section.classList.add('hidden');
            return;
        }

        section.classList.remove('hidden');
        var html = '';
        detections.forEach(function(d) {
            html += '<div class="macro-usage-item" onclick="goToDetection(\'' + escapeAttr(d.name) + '\')">';
            html += '<div class="macro-usage-item-name">' + escapeHtml(d.name) + '</div>';
            html += '<div class="macro-usage-item-meta">';
            if (d.severity) html += '<span>' + escapeHtml(d.severity) + '</span>';
            if (d.domain) html += '<span> | ' + escapeHtml(d.domain) + '</span>';
            html += '</div>';
            html += '</div>';
        });
        listEl.innerHTML = html;
    }

    // Go to detection in library view
    window.goToDetection = function(name) {
        var navItem = document.querySelector('.nav-item[href="#library"]');
        if (navItem) {
            App.handleNavigation(navItem);
            setTimeout(function() {
                App.selectDetection(name);
            }, 100);
        }
    };

    // Create new macro
    window.createNewMacro = function() {
        macrosState.selectedMacro = {
            name: '',
            definition: '',
            description: '',
            arguments: '',
            deprecated: false,
            usageCount: 0
        };
        macrosState.isNewMacro = true;
        macrosState.isEditing = true;
        renderMacrosList();
        renderMacroDetail(macrosState.selectedMacro);
        document.getElementById('macro-field-name').focus();
    };

    // Cancel macro edit
    window.cancelMacroEdit = function() {
        macrosState.selectedMacro = null;
        macrosState.isNewMacro = false;
        macrosState.isEditing = false;

        document.getElementById('macro-placeholder').classList.remove('hidden');
        document.getElementById('macro-detail-content').classList.add('hidden');

        renderMacrosList();
    };

    // Validate macro name (no spaces, underscores only for special chars)
    function validateMacroName(name) {
        if (!name || name.trim() === '') {
            return { valid: false, error: 'Macro name is required' };
        }

        // Remove backticks if present
        name = name.replace(/^`|`$/g, '').trim();

        if (name.indexOf(' ') !== -1) {
            return { valid: false, error: 'Macro name cannot contain spaces. Use underscores instead.' };
        }

        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
            return { valid: false, error: 'Macro name must start with a letter or underscore and contain only letters, numbers, and underscores.' };
        }

        return { valid: true, name: name };
    }

    // Save macro edit
    window.saveMacroEdit = function() {
        var nameInput = document.getElementById('macro-field-name');
        var definitionInput = document.getElementById('macro-field-definition');
        var descriptionInput = document.getElementById('macro-field-description');
        var argumentsInput = document.getElementById('macro-field-arguments');
        var deprecatedInput = document.getElementById('macro-field-deprecated');

        // Validate name
        var validation = validateMacroName(nameInput.value);
        if (!validation.valid) {
            alert(validation.error);
            nameInput.focus();
            return;
        }

        var macroName = validation.name;

        // Validate definition
        var definition = definitionInput.value.trim();
        if (!definition) {
            alert('Macro definition is required');
            definitionInput.focus();
            return;
        }

        // Check for duplicate names when creating new
        if (macrosState.isNewMacro) {
            var exists = macrosState.macros.some(function(m) {
                return m.name.toLowerCase() === macroName.toLowerCase();
            });
            if (exists) {
                alert('A macro with this name already exists');
                nameInput.focus();
                return;
            }
        }

        // Build macro object
        var macro = {
            name: macroName,
            definition: definition,
            description: descriptionInput.value.trim(),
            arguments: argumentsInput.value.trim(),
            deprecated: deprecatedInput.checked,
            usageCount: macrosState.isNewMacro ? 0 : countMacroUsage(macroName)
        };

        if (macrosState.isNewMacro) {
            // Add new macro
            macrosState.macros.push(macro);
        } else {
            // Update existing macro
            var index = macrosState.macros.findIndex(function(m) {
                return m.name === macrosState.selectedMacro.name;
            });
            if (index >= 0) {
                macrosState.macros[index] = macro;
            }
        }

        // Sort macros
        macrosState.macros.sort(function(a, b) {
            return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
        });

        // Update loaded macros for editor validation
        editorState.loadedMacros = macrosState.macros.map(function(m) { return m.name; });

        // Save to GitHub
        updateMacrosFile()
            .then(function(result) {
                macrosState.selectedMacro = macro;
                macrosState.isNewMacro = false;
                macrosState.isEditing = false;
                filterMacros();
                renderMacroDetail(macro);
                if (result && result.localOnly) {
                    App.updateStatus('disconnected');
                    showToast('Macro saved locally. Configure GitHub to sync.', 'info');
                } else {
                    App.updateStatus('connected');
                    showToast('Macro saved to GitHub successfully', 'success');
                }
            })
            .catch(function(error) {
                console.error('Failed to save macro to GitHub:', error);
                // Still update UI since localStorage save succeeded
                macrosState.selectedMacro = macro;
                macrosState.isNewMacro = false;
                macrosState.isEditing = false;
                filterMacros();
                renderMacroDetail(macro);
                App.updateStatus('error');
                showToast('GitHub save failed: ' + error.message + '. Saved locally.', 'error');
            });
    };

    // Confirm delete macro
    window.confirmDeleteMacroUI = function() {
        if (!macrosState.selectedMacro) return;

        var macro = macrosState.selectedMacro;
        var detections = getDetectionsUsingMacro(macro.name);

        var message = 'Are you sure you want to delete the macro "`' + macro.name + '`"?';
        if (detections.length > 0) {
            message += '\n\nWARNING: This macro is used in ' + detections.length + ' detection' + (detections.length > 1 ? 's' : '') + ':\n';
            detections.slice(0, 5).forEach(function(d) {
                message += '- ' + d.name + '\n';
            });
            if (detections.length > 5) {
                message += '... and ' + (detections.length - 5) + ' more';
            }
        }

        if (confirm(message)) {
            deleteMacroUI();
        }
    };

    // Delete macro
    function deleteMacroUI() {
        if (!macrosState.selectedMacro) return;

        var macroName = macrosState.selectedMacro.name;
        macrosState.macros = macrosState.macros.filter(function(m) {
            return m.name !== macroName;
        });

        // Update loaded macros for editor validation
        editorState.loadedMacros = macrosState.macros.map(function(m) { return m.name; });

        // Save to GitHub
        updateMacrosFile()
            .then(function(result) {
                macrosState.selectedMacro = null;
                macrosState.isNewMacro = false;
                document.getElementById('macro-placeholder').classList.remove('hidden');
                document.getElementById('macro-detail-content').classList.add('hidden');
                filterMacros();
                if (result && result.localOnly) {
                    App.updateStatus('disconnected');
                    showToast('Macro deleted locally. Configure GitHub to sync.', 'info');
                } else {
                    App.updateStatus('connected');
                    showToast('Macro deleted from GitHub successfully', 'success');
                }
            })
            .catch(function(error) {
                console.error('Failed to delete macro from GitHub:', error);
                // Still update UI since localStorage delete succeeded
                macrosState.selectedMacro = null;
                macrosState.isNewMacro = false;
                document.getElementById('macro-placeholder').classList.remove('hidden');
                document.getElementById('macro-detail-content').classList.add('hidden');
                filterMacros();
                App.updateStatus('error');
                showToast('GitHub delete failed: ' + error.message + '. Deleted locally.', 'error');
            });
    }

    // Update macros file (GitHub sync)
    function updateMacrosFile() {
        // Always backup to localStorage first
        try {
            var macroNames = macrosState.macros.map(function(m) { return m.name; });
            localStorage.setItem('dmf_macros', JSON.stringify(macroNames));
            localStorage.setItem('dmf_macros_full', JSON.stringify(macrosState.macros));
        } catch (e) {
            console.warn('Failed to save macros to localStorage:', e);
        }

        // If no GitHub connection, just resolve with localStorage save
        if (!github) {
            console.log('No GitHub connection - macros saved to localStorage only');
            return Promise.resolve({ localOnly: true });
        }

        // Save to GitHub
        var macrosPath = PATHS.dist + '/macros.json';
        var content = JSON.stringify(macrosState.macros, null, 2);

        return github.getFileSha(macrosPath)
            .catch(function() {
                // File doesn't exist, will create new
                return null;
            })
            .then(function(sha) {
                return github.createOrUpdateFile(macrosPath, content, 'Update macros.json', sha);
            })
            .then(function(result) {
                console.log('Macros saved to GitHub successfully');
                // Also save comprehensive localStorage cache
                saveToLocalStorage();
                return result;
            })
            .catch(function(error) {
                console.error('Failed to save macros to GitHub:', error);
                // Throw to let caller know GitHub save failed
                throw new Error('GitHub sync failed: ' + error.message);
            });
    }

    // =========================================================================
    // REVALIDATION VIEW FUNCTIONS
    // =========================================================================

    // Revalidation State
    var revalidationState = {
        filteredDetections: [],
        selectedDetection: null,
        selectedItems: [], // Array of detection names for batch operations
        statusCounts: {
            valid: 0,
            incomplete: 0,
            'needs-tune': 0,
            'needs-retrofit': 0
        }
    };

    // Splunk Revalidation Dashboard URL
    var SPLUNK_REVAL_DASHBOARD_URL = SPLUNK_CONFIG.baseUrl + '/en-US/app/SplunkEnterpriseSecuritySuite/detection_revalidation';

    // Initialize Revalidation View
    function initRevalidation() {
        // Wait for detections to load, then initialize
        if (App.state.detections && App.state.detections.length > 0) {
            calculateStatusCounts();
            filterRevalidation();
        }

        // Set up event listeners for revalidation detail buttons
        document.getElementById('btn-reval-correlation')?.addEventListener('click', function() {
            var d = revalidationState.selectedDetection;
            if (d) {
                var url = buildCorrelationSearchUrl(d['Detection Name']);
                window.open(url, '_blank');
            }
        });

        document.getElementById('btn-reval-tune')?.addEventListener('click', function() {
            var d = revalidationState.selectedDetection;
            if (d) {
                markDetectionAsTuned(d);
            }
        });

        document.getElementById('btn-reval-retrofit')?.addEventListener('click', function() {
            var d = revalidationState.selectedDetection;
            if (d) {
                markDetectionAsRetrofitted(d);
            }
        });

        document.getElementById('btn-reval-view-library')?.addEventListener('click', function() {
            var d = revalidationState.selectedDetection;
            if (d) {
                var navItem = document.querySelector('.nav-item[href="#library"]');
                if (navItem) {
                    App.handleNavigation(navItem);
                    setTimeout(function() {
                        App.selectDetection(d['Detection Name']);
                    }, 100);
                }
            }
        });
    }

    // Calculate status counts for all detections
    function calculateStatusCounts() {
        revalidationState.statusCounts = {
            valid: 0,
            incomplete: 0,
            'needs-tune': 0,
            'needs-retrofit': 0
        };

        App.state.detections.forEach(function(d) {
            var status = App.getDetectionStatus(d);
            if (revalidationState.statusCounts[status] !== undefined) {
                revalidationState.statusCounts[status]++;
            }
        });

        // Update count displays
        document.getElementById('reval-count-valid').textContent = revalidationState.statusCounts.valid;
        document.getElementById('reval-count-incomplete').textContent = revalidationState.statusCounts.incomplete;
        document.getElementById('reval-count-needs-tune').textContent = revalidationState.statusCounts['needs-tune'];
        document.getElementById('reval-count-needs-retrofit').textContent = revalidationState.statusCounts['needs-retrofit'];
    }

    // Filter revalidation list based on selected status checkboxes
    window.filterRevalidation = function() {
        // Get selected statuses
        var showValid = document.getElementById('reval-status-valid')?.checked || false;
        var showIncomplete = document.getElementById('reval-status-incomplete')?.checked || false;
        var showNeedsTune = document.getElementById('reval-status-needs-tune')?.checked || false;
        var showNeedsRetrofit = document.getElementById('reval-status-needs-retrofit')?.checked || false;

        // Filter detections
        revalidationState.filteredDetections = App.state.detections.filter(function(d) {
            var status = App.getDetectionStatus(d);
            if (status === 'valid' && showValid) return true;
            if (status === 'incomplete' && showIncomplete) return true;
            if (status === 'needs-tune' && showNeedsTune) return true;
            if (status === 'needs-retrofit' && showNeedsRetrofit) return true;
            return false;
        });

        // Sort by TTL remaining (most urgent first)
        revalidationState.filteredDetections.sort(function(a, b) {
            var ttlA = calculateTTL(a['Last Modified']);
            var ttlB = calculateTTL(b['Last Modified']);
            return ttlA.days - ttlB.days;
        });

        // Clear selection if selected item is no longer visible
        if (revalidationState.selectedDetection) {
            var stillVisible = revalidationState.filteredDetections.some(function(d) {
                return d['Detection Name'] === revalidationState.selectedDetection['Detection Name'];
            });
            if (!stillVisible) {
                revalidationState.selectedDetection = null;
                document.getElementById('reval-detail-placeholder').classList.remove('hidden');
                document.getElementById('reval-detail-content').classList.add('hidden');
            }
        }

        renderRevalidationList();
        updateBatchSelectionInfo();
    };

    // Render revalidation list
    function renderRevalidationList() {
        var container = document.getElementById('revalidation-list');
        var countEl = document.getElementById('revalidation-count');

        if (countEl) {
            countEl.textContent = revalidationState.filteredDetections.length + ' detection' + (revalidationState.filteredDetections.length !== 1 ? 's' : '');
        }

        if (!container) return;

        if (revalidationState.filteredDetections.length === 0) {
            container.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x2714;</span><p>No detections match the selected filters</p></div>';
            return;
        }

        var html = '';
        revalidationState.filteredDetections.forEach(function(d) {
            var name = d['Detection Name'] || 'Unnamed';
            var status = App.getDetectionStatus(d);
            var statusLabel = getStatusLabel(status);
            var ttl = calculateTTL(d['Last Modified']);
            var ttlClass = getTTLColorClass(ttl.days);
            var modified = d['Last Modified'] ? formatDate(d['Last Modified']) : 'N/A';
            var isSelected = revalidationState.selectedDetection && revalidationState.selectedDetection['Detection Name'] === name;
            var isChecked = revalidationState.selectedItems.indexOf(name) !== -1;

            html += '<div class="revalidation-list-item' + (isSelected ? ' selected' : '') + '" onclick="selectRevalidationDetection(\'' + escapeAttr(name) + '\')">';
            html += '<input type="checkbox" class="reval-item-checkbox" ' + (isChecked ? 'checked' : '') + ' onclick="event.stopPropagation(); toggleRevalidationItem(\'' + escapeAttr(name) + '\', this.checked)">';
            html += '<div class="reval-item-content">';
            html += '<div class="reval-item-header">';
            html += '<a href="#" class="reval-item-name reval-item-link" onclick="event.stopPropagation(); goToLibraryDetection(\'' + escapeAttr(name) + '\'); return false;" title="View in Library">' + escapeHtml(name) + '</a>';
            html += '<span class="reval-item-status ' + status + '">' + statusLabel + '</span>';
            html += '</div>';
            html += '<div class="reval-item-meta">';
            html += '<span class="ttl-indicator ' + ttlClass + '"><span class="ttl-dot"></span>' + getTTLText(ttl) + '</span>';
            html += '<span>' + modified + '</span>';
            html += '</div>';
            html += '</div>';
            html += '</div>';
        });
        container.innerHTML = html;
    }

    // Get status label for display
    function getStatusLabel(status) {
        switch (status) {
            case 'valid': return 'Valid';
            case 'incomplete': return 'Incomplete';
            case 'needs-tune': return 'Needs Tune';
            case 'needs-retrofit': return 'Needs Retrofit';
            default: return status;
        }
    }

    // Get TTL color class based on days remaining
    function getTTLColorClass(days) {
        if (days <= 0) return 'ttl-red';
        if (days <= 30) return 'ttl-red';
        if (days <= 90) return 'ttl-yellow';
        return 'ttl-green';
    }

    // Get TTL text for display
    function getTTLText(ttl) {
        if (ttl.expired || ttl.days <= 0) return 'EXPIRED';
        if (ttl.days === 1) return '1 day';
        return ttl.days + ' days';
    }

    // Select a detection in revalidation view
    window.selectRevalidationDetection = function(name) {
        var detection = App.state.detections.find(function(d) {
            return d['Detection Name'] === name;
        });
        if (!detection) return;

        revalidationState.selectedDetection = detection;
        renderRevalidationList();
        renderRevalidationDetail(detection);
    };

    // Toggle selection of a detection for batch operations
    window.toggleRevalidationItem = function(name, checked) {
        if (checked) {
            if (revalidationState.selectedItems.indexOf(name) === -1) {
                revalidationState.selectedItems.push(name);
            }
        } else {
            revalidationState.selectedItems = revalidationState.selectedItems.filter(function(n) {
                return n !== name;
            });
        }
        updateBatchSelectionInfo();
    };

    // Toggle select all
    window.toggleRevalidationSelectAll = function() {
        var selectAllCheckbox = document.getElementById('reval-select-all');
        var isChecked = selectAllCheckbox ? selectAllCheckbox.checked : false;

        if (isChecked) {
            revalidationState.selectedItems = revalidationState.filteredDetections.map(function(d) {
                return d['Detection Name'];
            });
        } else {
            revalidationState.selectedItems = [];
        }

        renderRevalidationList();
        updateBatchSelectionInfo();
    };

    // Update batch selection info
    function updateBatchSelectionInfo() {
        var infoEl = document.getElementById('batch-selection-count');
        var tuneBtn = document.getElementById('btn-batch-tune');
        var retrofitBtn = document.getElementById('btn-batch-retrofit');
        var count = revalidationState.selectedItems.length;

        if (infoEl) {
            if (count === 0) {
                infoEl.textContent = 'Select detections below';
            } else {
                infoEl.textContent = count + ' detection' + (count !== 1 ? 's' : '') + ' selected';
            }
        }

        if (tuneBtn) tuneBtn.disabled = count === 0;
        if (retrofitBtn) retrofitBtn.disabled = count === 0;
    }

    // Render revalidation detail panel
    function renderRevalidationDetail(d) {
        document.getElementById('reval-detail-placeholder').classList.add('hidden');
        document.getElementById('reval-detail-content').classList.remove('hidden');

        var ttl = calculateTTL(d['Last Modified']);
        var ttlClass = getTTLColorClass(ttl.days);
        var status = App.getDetectionStatus(d);
        var progressPercent = Math.max(0, Math.min(100, (ttl.days / TTL_DAYS) * 100));

        var html = '';

        // TTL Section with Banner and Progress Bar
        html += '<div class="reval-ttl-section">';
        html += '<div class="reval-ttl-banner ' + ttlClass + '">';
        html += '<div class="reval-ttl-title">' + (ttl.expired ? 'TTL EXPIRED' : ttl.days + ' Days Remaining') + '</div>';
        html += '<div class="reval-ttl-subtitle">' + (ttl.expired ? 'Revalidation is overdue' : 'Until revalidation required') + '</div>';
        html += '</div>';
        html += '<div class="reval-ttl-progress"><div class="reval-ttl-progress-bar ' + ttlClass + '" style="width: ' + progressPercent + '%"></div></div>';
        html += '</div>';

        // Detection Info Grid
        html += '<div class="reval-info-grid">';
        html += '<div class="reval-info-item"><div class="reval-info-label">Detection Name</div><div class="reval-info-value">' + escapeHtml(d['Detection Name'] || 'Unnamed') + '</div></div>';
        html += '<div class="reval-info-item"><div class="reval-info-label">Status</div><div class="reval-info-value"><span class="reval-item-status ' + status + '">' + getStatusLabel(status) + '</span></div></div>';
        html += '<div class="reval-info-item"><div class="reval-info-label">Severity</div><div class="reval-info-value"><span class="severity-badge ' + (d['Severity/Priority'] || '').toLowerCase() + '">' + (d['Severity/Priority'] || 'N/A') + '</span></div></div>';
        html += '<div class="reval-info-item"><div class="reval-info-label">Domain</div><div class="reval-info-value">' + escapeHtml(d['Security Domain'] || 'N/A') + '</div></div>';
        html += '<div class="reval-info-item"><div class="reval-info-label">Last Modified</div><div class="reval-info-value">' + (d['Last Modified'] ? formatDate(d['Last Modified']) : 'N/A') + '</div></div>';
        html += '<div class="reval-info-item"><div class="reval-info-label">First Created</div><div class="reval-info-value">' + (d['First Created'] ? formatDate(d['First Created']) : 'N/A') + '</div></div>';
        html += '</div>';

        // Objective
        if (d['Objective']) {
            html += '<div class="doc-section">';
            html += '<h3 class="doc-section-title">Objective</h3>';
            html += '<div class="doc-field-value">' + escapeHtml(d['Objective']) + '</div>';
            html += '</div>';
        }

        // Blind Spots (important for revalidation)
        if (d['Blind_Spots_False_Positives']) {
            html += '<div class="doc-section">';
            html += '<h3 class="doc-section-title">Known Blind Spots / False Positives</h3>';
            html += '<div class="doc-field-value">' + escapeHtml(d['Blind_Spots_False_Positives']) + '</div>';
            html += '</div>';
        }

        // Revalidation History (if available)
        if (d['Revalidation_History'] && d['Revalidation_History'].length > 0) {
            html += '<div class="reval-history-section">';
            html += '<div class="reval-history-title">Revalidation History</div>';
            html += '<div class="reval-history-list">';
            d['Revalidation_History'].forEach(function(entry) {
                html += '<div class="reval-history-item">';
                html += '<span class="reval-history-date">' + formatDate(entry.date) + '</span>';
                html += '<span class="reval-history-action">' + escapeHtml(entry.action) + '</span>';
                html += '<span class="reval-history-user">' + escapeHtml(entry.user || 'Unknown') + '</span>';
                html += '</div>';
            });
            html += '</div>';
            html += '</div>';
        }

        document.getElementById('reval-detail-body').innerHTML = html;
    }

    // Batch mark as tuned
    window.batchMarkAsTuned = function() {
        var count = revalidationState.selectedItems.length;
        if (count === 0) return;

        if (confirm('Mark ' + count + ' detection' + (count !== 1 ? 's' : '') + ' as tuned?\n\nThis will update the Last Modified date.')) {
            revalidationState.selectedItems.forEach(function(name) {
                var detection = App.state.detections.find(function(d) {
                    return d['Detection Name'] === name;
                });
                if (detection) {
                    markDetectionAsTuned(detection, true);
                }
            });

            // Clear selection
            revalidationState.selectedItems = [];
            document.getElementById('reval-select-all').checked = false;

            // Refresh
            calculateStatusCounts();
            filterRevalidation();
            showToast(count + ' detection' + (count !== 1 ? 's' : '') + ' marked as tuned', 'success');
        }
    };

    // Batch mark as retrofitted
    window.batchMarkAsRetrofitted = function() {
        var count = revalidationState.selectedItems.length;
        if (count === 0) return;

        if (confirm('Mark ' + count + ' detection' + (count !== 1 ? 's' : '') + ' as retrofitted?\n\nThis will update the Last Modified date.')) {
            revalidationState.selectedItems.forEach(function(name) {
                var detection = App.state.detections.find(function(d) {
                    return d['Detection Name'] === name;
                });
                if (detection) {
                    markDetectionAsRetrofitted(detection, true);
                }
            });

            // Clear selection
            revalidationState.selectedItems = [];
            document.getElementById('reval-select-all').checked = false;

            // Refresh
            calculateStatusCounts();
            filterRevalidation();
            showToast(count + ' detection' + (count !== 1 ? 's' : '') + ' marked as retrofitted', 'success');
        }
    };

    // Mark single detection as tuned
    function markDetectionAsTuned(detection, silent) {
        detection['Last Modified'] = new Date().toISOString();

        // Add to revalidation history
        if (!detection['Revalidation_History']) {
            detection['Revalidation_History'] = [];
        }
        detection['Revalidation_History'].push({
            date: new Date().toISOString(),
            action: 'Marked as Tuned',
            user: 'Current User'
        });

        // Update in main state
        var index = App.state.detections.findIndex(function(d) {
            return d['Detection Name'] === detection['Detection Name'];
        });
        if (index >= 0) {
            App.state.detections[index] = detection;
        }

        if (!silent) {
            calculateStatusCounts();
            filterRevalidation();
            renderRevalidationDetail(detection);
            showToast('Detection marked as tuned', 'success');
        }
    }

    // Mark single detection as retrofitted
    function markDetectionAsRetrofitted(detection, silent) {
        detection['Last Modified'] = new Date().toISOString();

        // Add to revalidation history
        if (!detection['Revalidation_History']) {
            detection['Revalidation_History'] = [];
        }
        detection['Revalidation_History'].push({
            date: new Date().toISOString(),
            action: 'Marked as Retrofitted',
            user: 'Current User'
        });

        // Update in main state
        var index = App.state.detections.findIndex(function(d) {
            return d['Detection Name'] === detection['Detection Name'];
        });
        if (index >= 0) {
            App.state.detections[index] = detection;
        }

        if (!silent) {
            calculateStatusCounts();
            filterRevalidation();
            renderRevalidationDetail(detection);
            showToast('Detection marked as retrofitted', 'success');
        }
    }

    // Open Splunk Revalidation Dashboard in popup
    window.openSplunkRevalidationDashboard = function() {
        var width = 1200;
        var height = 800;
        var left = (screen.width - width) / 2;
        var top = (screen.height - height) / 2;

        window.open(
            SPLUNK_REVAL_DASHBOARD_URL,
            'SplunkRevalidationDashboard',
            'width=' + width + ',height=' + height + ',left=' + left + ',top=' + top + ',scrollbars=yes,resizable=yes'
        );
    };

    // ========================================
    // Revalidation Sub-Tabs
    // ========================================

    // Initialize Revalidation Sub-Tabs
    function initRevalidationTabs() {
        document.querySelectorAll('.reval-tab').forEach(function(tab) {
            tab.addEventListener('click', function() {
                var tabName = tab.dataset.tab;
                if (!tabName) return;

                // Update active tab button
                document.querySelectorAll('.reval-tab').forEach(function(t) {
                    t.classList.remove('active');
                });
                tab.classList.add('active');

                // Update active tab content
                document.querySelectorAll('.reval-tab-content').forEach(function(c) {
                    c.classList.add('hidden');
                    c.classList.remove('active');
                });

                var content = document.getElementById('reval-tab-' + tabName);
                if (content) {
                    content.classList.remove('hidden');
                    content.classList.add('active');
                }

                // Render Splunk Launcher if switching to that tab
                if (tabName === 'splunk-launcher') {
                    renderSplunkLauncher();
                }
            });
        });
    }

    // Splunk Launcher state
    var splunkLauncherState = {
        statusFilter: 'all',
        searchQuery: '',
        filteredDetections: []
    };

    // Filter Splunk Launcher list
    window.filterSplunkLauncher = function() {
        var statusFilter = document.getElementById('launcher-status-filter');
        var searchInput = document.getElementById('launcher-search');

        splunkLauncherState.statusFilter = statusFilter ? statusFilter.value : 'all';
        splunkLauncherState.searchQuery = searchInput ? searchInput.value.toLowerCase().trim() : '';

        renderSplunkLauncher();
    };

    // Render Splunk Launcher content
    function renderSplunkLauncher() {
        var container = document.getElementById('splunk-launcher-list');
        var countEl = document.getElementById('launcher-detection-count');

        if (!container) return;

        var detections = App.state.detections || [];

        // Filter detections based on status
        var filtered = detections.filter(function(d) {
            var status = App.getDetectionStatus(d);
            var ttl = calculateTTL(d['Last Modified']);

            // Status filter
            if (splunkLauncherState.statusFilter === 'all') {
                // Show all that need attention (not valid)
                if (status === 'valid' && !ttl.expired) return false;
            } else if (splunkLauncherState.statusFilter === 'needs-tune') {
                if (status !== 'needs-tune') return false;
            } else if (splunkLauncherState.statusFilter === 'needs-retrofit') {
                if (status !== 'needs-retrofit') return false;
            } else if (splunkLauncherState.statusFilter === 'incomplete') {
                if (status !== 'incomplete') return false;
            } else if (splunkLauncherState.statusFilter === 'expired') {
                if (!ttl.expired) return false;
            }

            // Search filter
            if (splunkLauncherState.searchQuery) {
                var name = (d['Detection Name'] || '').toLowerCase();
                var objective = (d['Objective'] || '').toLowerCase();
                if (name.indexOf(splunkLauncherState.searchQuery) === -1 &&
                    objective.indexOf(splunkLauncherState.searchQuery) === -1) {
                    return false;
                }
            }

            return true;
        });

        // Sort by TTL (most urgent first)
        filtered.sort(function(a, b) {
            var ttlA = calculateTTL(a['Last Modified']);
            var ttlB = calculateTTL(b['Last Modified']);
            return ttlA.days - ttlB.days;
        });

        splunkLauncherState.filteredDetections = filtered;

        // Update count
        if (countEl) {
            countEl.textContent = filtered.length + ' detection' + (filtered.length !== 1 ? 's' : '');
        }

        // Render list
        if (filtered.length === 0) {
            container.innerHTML = '<div class="splunk-launcher-empty">' +
                '<div class="empty-icon">&#x2714;</div>' +
                '<p>No detections match the current filters</p>' +
                '</div>';
            return;
        }

        var html = '';
        filtered.forEach(function(d) {
            var name = d['Detection Name'] || 'Unnamed';
            var status = App.getDetectionStatus(d);
            var ttl = calculateTTL(d['Last Modified']);
            var ttlClass = getTTLColorClass(ttl.days);
            var severity = d['Severity/Priority'] || 'N/A';
            var domain = d['Security Domain'] || 'N/A';

            // Determine display status
            var displayStatus = status;
            var displayStatusLabel = getStatusLabel(status);
            if (ttl.expired && status === 'valid') {
                displayStatus = 'expired';
                displayStatusLabel = 'TTL Expired';
            }

            html += '<div class="launcher-detection-card">';
            html += '<div class="launcher-card-info">';
            html += '<div class="launcher-card-name">' + escapeHtml(name) + '</div>';
            html += '<div class="launcher-card-meta">';
            html += '<span class="launcher-card-status ' + displayStatus + '">' + displayStatusLabel + '</span>';
            html += '<span class="launcher-card-ttl ' + ttlClass + '"><span class="ttl-dot"></span>' + getTTLText(ttl) + '</span>';
            html += '<span>' + escapeHtml(severity) + '</span>';
            html += '<span>' + escapeHtml(domain) + '</span>';
            html += '</div>';
            html += '</div>';
            html += '<div class="launcher-card-actions">';
            html += '<button class="btn-launch-correlation" onclick="launchCorrelationSearch(\'' + escapeAttr(name) + '\')" title="Edit Correlation Search">';
            html += '<span>Correlation</span>';
            html += '</button>';
            html += '<button class="btn-launch-splunk" onclick="launchSplunkDashboard(\'' + escapeAttr(name) + '\')" title="Open Revalidation Dashboard">';
            html += '<span class="splunk-icon">&#x1F4CA;</span>';
            html += '<span>Launch Dashboard</span>';
            html += '</button>';
            html += '</div>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Launch Splunk Dashboard for a specific detection
    window.launchSplunkDashboard = function(detectionName) {
        var dashboardUrl = SPLUNK_CONFIG.baseUrl + SPLUNK_CONFIG.dashboardPath +
            '?form.' + SPLUNK_CONFIG.useCaseFieldName + '=' + encodeURIComponent(detectionName) +
            '&earliest=' + encodeURIComponent(SPLUNK_CONFIG.defaultTimeEarliest) +
            '&latest=' + encodeURIComponent(SPLUNK_CONFIG.defaultTimeLatest);

        var width = SPLUNK_CONFIG.popupWidth || 1400;
        var height = SPLUNK_CONFIG.popupHeight || 900;
        var left = (screen.width - width) / 2;
        var top = (screen.height - height) / 2;

        window.open(
            dashboardUrl,
            'SplunkDashboard_' + Date.now(),
            'width=' + width + ',height=' + height + ',left=' + left + ',top=' + top + ',scrollbars=yes,resizable=yes'
        );
    };

    // Launch Correlation Search editor for a specific detection
    window.launchCorrelationSearch = function(detectionName) {
        var correlationUrl = buildCorrelationSearchUrl(detectionName);

        var width = SPLUNK_CONFIG.popupWidth || 1400;
        var height = SPLUNK_CONFIG.popupHeight || 900;
        var left = (screen.width - width) / 2;
        var top = (screen.height - height) / 2;

        window.open(
            correlationUrl,
            'SplunkCorrelation_' + Date.now(),
            'width=' + width + ',height=' + height + ',left=' + left + ',top=' + top + ',scrollbars=yes,resizable=yes'
        );
    };

    // Simple toast notification (global)
    window.showToast = function showToast(message, type) {
        // Create toast element if it doesn't exist
        var toast = document.getElementById('toast-notification');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'toast-notification';
            toast.style.cssText = 'position: fixed; bottom: 60px; right: 20px; padding: 12px 20px; background: var(--color-text); color: var(--color-bg); font-size: 13px; z-index: 10000; opacity: 0; transition: opacity 0.3s;';
            document.body.appendChild(toast);
        }

        toast.textContent = message;
        if (type === 'error') {
            toast.style.background = '#dc3545';
        } else if (type === 'success') {
            toast.style.background = '#3fb950';
        } else {
            toast.style.background = 'var(--color-text)';
        }

        toast.style.opacity = '1';
        setTimeout(function() {
            toast.style.opacity = '0';
        }, 3000);
    }

    // =========================================================================
    // HISTORY VIEW FUNCTIONS
    // =========================================================================

    // History State
    var historyState = {
        entries: [],
        filteredEntries: [],
        typeCounts: {
            created: 0,
            tuned: 0,
            retrofitted: 0,
            modified: 0
        },
        dateFrom: null,
        dateTo: null,
        analysts: [],
        fieldsChanged: []
    };

    // Initialize History View
    function initHistory() {
        // Set default date range to last 30 days
        setDatePreset('30d');

        // Build history entries from detections
        buildHistoryEntries();
    }

    // Build history entries from all detections
    function buildHistoryEntries() {
        historyState.entries = [];

        if (!App.state.detections || App.state.detections.length === 0) {
            filterHistory();
            return;
        }

        // Create a map of detections for quick lookup
        var detectionMap = {};
        App.state.detections.forEach(function(d) {
            if (d['Detection Name']) {
                detectionMap[d['Detection Name']] = d;
            }
        });

        App.state.detections.forEach(function(d) {
            var detectionName = d['Detection Name'] || 'Unnamed';
            var severity = d['Severity/Priority'] || '';

            // Add creation entry
            if (d['First Created']) {
                historyState.entries.push({
                    detectionName: detectionName,
                    type: 'created',
                    date: new Date(d['First Created']),
                    timestamp: d['First Created'],
                    analyst: getAnalystFromRoles(d),
                    severity: severity,
                    detection: d
                });
            }

            // Add entries from Revalidation_History
            if (d['Revalidation_History'] && Array.isArray(d['Revalidation_History'])) {
                d['Revalidation_History'].forEach(function(entry) {
                    var changeType = getChangeTypeFromAction(entry.action);
                    historyState.entries.push({
                        detectionName: detectionName,
                        type: changeType,
                        date: new Date(entry.date),
                        timestamp: entry.date,
                        analyst: entry.user || 'Unknown',
                        severity: severity,
                        detection: d
                    });
                });
            }

            // Add modification entry if Last Modified is different from First Created
            if (d['Last Modified'] && d['First Created']) {
                var lastMod = new Date(d['Last Modified']);
                var firstCreated = new Date(d['First Created']);
                // Check if they're different (more than 1 minute apart)
                if (Math.abs(lastMod - firstCreated) > 60000) {
                    // Check if this modification is already covered by revalidation history
                    var hasRecentRevalEntry = (d['Revalidation_History'] || []).some(function(entry) {
                        var entryDate = new Date(entry.date);
                        return Math.abs(entryDate - lastMod) < 60000;
                    });

                    if (!hasRecentRevalEntry) {
                        historyState.entries.push({
                            detectionName: detectionName,
                            type: 'modified',
                            date: lastMod,
                            timestamp: d['Last Modified'],
                            analyst: getAnalystFromRoles(d),
                            severity: severity,
                            detection: d
                        });
                    }
                }
            }
        });

        // Add entries from localStorage (tune/retrofit history)
        var localHistory = JSON.parse(localStorage.getItem('de_mainframe_history') || '{}');
        Object.keys(localHistory).forEach(function(detectionName) {
            var entries = localHistory[detectionName] || [];
            var detection = detectionMap[detectionName];
            var severity = detection ? (detection['Severity/Priority'] || '') : '';

            entries.forEach(function(entry) {
                var entryType = entry.type === 'tune' ? 'tuned' : (entry.type === 'retrofit' ? 'retrofitted' : entry.type);
                historyState.entries.push({
                    detectionName: detectionName,
                    type: entryType,
                    date: new Date(entry.timestamp),
                    timestamp: entry.timestamp,
                    analyst: entry.analyst || 'Unknown',
                    severity: severity,
                    detection: detection,
                    description: entry.description,
                    fieldsChanged: entry.fieldsChanged
                });
            });
        });

        // Sort entries by date (newest first)
        historyState.entries.sort(function(a, b) {
            return b.date - a.date;
        });

        // Calculate type counts
        calculateHistoryTypeCounts();

        // Populate advanced filter dropdowns
        populateHistoryFilters();

        // Apply filters
        filterHistory();
    }

    // Get analyst name from detection roles
    function getAnalystFromRoles(d) {
        if (!d['Roles'] || !Array.isArray(d['Roles'])) return 'Unknown';

        // Try Technical Owner first, then Business Owner, then Requestor
        var priorityOrder = ['Technical Owner', 'Business Owner', 'Requestor'];
        for (var i = 0; i < priorityOrder.length; i++) {
            var role = d['Roles'].find(function(r) {
                return r.Role === priorityOrder[i] && r.Name;
            });
            if (role && role.Name) {
                return role.Name;
            }
        }
        return 'Unknown';
    }

    // Get change type from revalidation action string
    function getChangeTypeFromAction(action) {
        if (!action) return 'modified';
        var actionLower = action.toLowerCase();
        if (actionLower.indexOf('tune') !== -1) return 'tuned';
        if (actionLower.indexOf('retrofit') !== -1) return 'retrofitted';
        if (actionLower.indexOf('creat') !== -1) return 'created';
        return 'modified';
    }

    // Calculate type counts for display
    function calculateHistoryTypeCounts() {
        historyState.typeCounts = {
            created: 0,
            tuned: 0,
            retrofitted: 0,
            modified: 0
        };

        historyState.entries.forEach(function(entry) {
            if (historyState.typeCounts[entry.type] !== undefined) {
                historyState.typeCounts[entry.type]++;
            }
        });

        // Update count displays
        var createdEl = document.getElementById('history-count-created');
        var tunedEl = document.getElementById('history-count-tuned');
        var retrofittedEl = document.getElementById('history-count-retrofitted');
        var modifiedEl = document.getElementById('history-count-modified');

        if (createdEl) createdEl.textContent = historyState.typeCounts.created;
        if (tunedEl) tunedEl.textContent = historyState.typeCounts.tuned;
        if (retrofittedEl) retrofittedEl.textContent = historyState.typeCounts.retrofitted;
        if (modifiedEl) modifiedEl.textContent = historyState.typeCounts.modified;
    }

    // Populate history filter dropdowns (Analyst and Field Changed)
    function populateHistoryFilters() {
        var analystSet = new Set();
        var fieldSet = new Set();

        // Extract unique analysts and fields from all history entries
        historyState.entries.forEach(function(entry) {
            if (entry.analyst && entry.analyst !== 'Unknown') {
                analystSet.add(entry.analyst);
            }
            if (entry.fieldsChanged && Array.isArray(entry.fieldsChanged)) {
                entry.fieldsChanged.forEach(function(field) {
                    if (field) fieldSet.add(field);
                });
            }
        });

        // Convert to sorted arrays
        historyState.analysts = Array.from(analystSet).sort(function(a, b) {
            return a.toLowerCase().localeCompare(b.toLowerCase());
        });
        historyState.fieldsChanged = Array.from(fieldSet).sort(function(a, b) {
            return a.toLowerCase().localeCompare(b.toLowerCase());
        });

        // Populate Analyst dropdown
        var analystSelect = document.getElementById('history-analyst-filter');
        if (analystSelect) {
            var currentAnalystValue = analystSelect.value;
            analystSelect.innerHTML = '<option value="">All Analysts</option>';
            historyState.analysts.forEach(function(analyst) {
                var option = document.createElement('option');
                option.value = analyst;
                option.textContent = analyst;
                analystSelect.appendChild(option);
            });
            // Restore previous selection if still valid
            if (currentAnalystValue && historyState.analysts.indexOf(currentAnalystValue) !== -1) {
                analystSelect.value = currentAnalystValue;
            }
        }

        // Populate Field Changed dropdown
        var fieldSelect = document.getElementById('history-field-filter');
        if (fieldSelect) {
            var currentFieldValue = fieldSelect.value;
            fieldSelect.innerHTML = '<option value="">All Fields</option>';
            historyState.fieldsChanged.forEach(function(field) {
                var option = document.createElement('option');
                option.value = field;
                option.textContent = field;
                fieldSelect.appendChild(option);
            });
            // Restore previous selection if still valid
            if (currentFieldValue && historyState.fieldsChanged.indexOf(currentFieldValue) !== -1) {
                fieldSelect.value = currentFieldValue;
            }
        }
    }

    // Set date preset
    window.setDatePreset = function(preset) {
        var now = new Date();
        var fromDate = new Date();
        var toDate = new Date();

        // Reset to end of today
        toDate.setHours(23, 59, 59, 999);

        switch (preset) {
            case '7d':
                fromDate.setDate(now.getDate() - 7);
                break;
            case '30d':
                fromDate.setDate(now.getDate() - 30);
                break;
            case '90d':
                fromDate.setDate(now.getDate() - 90);
                break;
            case 'all':
                fromDate = null;
                toDate = null;
                break;
        }

        if (fromDate) {
            fromDate.setHours(0, 0, 0, 0);
        }

        // Update input fields
        var fromInput = document.getElementById('history-date-from');
        var toInput = document.getElementById('history-date-to');

        if (fromInput) {
            fromInput.value = fromDate ? formatDateForInput(fromDate) : '';
        }
        if (toInput) {
            toInput.value = toDate ? formatDateForInput(toDate) : '';
        }

        // Update preset button states
        var presetBtns = document.querySelectorAll('.preset-btn');
        presetBtns.forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.getAttribute('onclick').indexOf("'" + preset + "'") !== -1) {
                btn.classList.add('active');
            }
        });

        historyState.dateFrom = fromDate;
        historyState.dateTo = toDate;

        filterHistory();
    };

    // Format date for input field (YYYY-MM-DD)
    function formatDateForInput(date) {
        if (!date) return '';
        var year = date.getFullYear();
        var month = String(date.getMonth() + 1).padStart(2, '0');
        var day = String(date.getDate()).padStart(2, '0');
        return year + '-' + month + '-' + day;
    }

    // Filter history entries
    window.filterHistory = function() {
        // Get filter values
        var searchInput = document.getElementById('history-search-input');
        var searchTerm = searchInput ? searchInput.value.toLowerCase() : '';

        var showCreated = document.getElementById('history-type-created')?.checked || false;
        var showTuned = document.getElementById('history-type-tuned')?.checked || false;
        var showRetrofitted = document.getElementById('history-type-retrofitted')?.checked || false;
        var showModified = document.getElementById('history-type-modified')?.checked || false;

        var fromInput = document.getElementById('history-date-from');
        var toInput = document.getElementById('history-date-to');
        var dateFrom = fromInput && fromInput.value ? new Date(fromInput.value) : historyState.dateFrom;
        var dateTo = toInput && toInput.value ? new Date(toInput.value) : historyState.dateTo;

        // Get analyst filter
        var analystSelect = document.getElementById('history-analyst-filter');
        var analystFilter = analystSelect ? analystSelect.value : '';

        // Get field changed filter
        var fieldSelect = document.getElementById('history-field-filter');
        var fieldFilter = fieldSelect ? fieldSelect.value : '';

        if (dateFrom) {
            dateFrom.setHours(0, 0, 0, 0);
        }
        if (dateTo) {
            dateTo.setHours(23, 59, 59, 999);
        }

        // Filter entries
        historyState.filteredEntries = historyState.entries.filter(function(entry) {
            // Type filter
            if (entry.type === 'created' && !showCreated) return false;
            if (entry.type === 'tuned' && !showTuned) return false;
            if (entry.type === 'retrofitted' && !showRetrofitted) return false;
            if (entry.type === 'modified' && !showModified) return false;

            // Search filter
            if (searchTerm && entry.detectionName.toLowerCase().indexOf(searchTerm) === -1) {
                return false;
            }

            // Date filter
            if (dateFrom && entry.date < dateFrom) return false;
            if (dateTo && entry.date > dateTo) return false;

            // Analyst filter
            if (analystFilter && entry.analyst !== analystFilter) return false;

            // Field changed filter
            if (fieldFilter) {
                // Only show entries that have the selected field in their fieldsChanged array
                if (!entry.fieldsChanged || !Array.isArray(entry.fieldsChanged)) return false;
                if (entry.fieldsChanged.indexOf(fieldFilter) === -1) return false;
            }

            return true;
        });

        renderHistoryTimeline();
    };

    // Clear all history filters
    window.clearHistoryFilters = function() {
        // Reset search input
        var searchInput = document.getElementById('history-search-input');
        if (searchInput) searchInput.value = '';

        // Reset all type checkboxes to checked
        var createdCheckbox = document.getElementById('history-type-created');
        var tunedCheckbox = document.getElementById('history-type-tuned');
        var retrofittedCheckbox = document.getElementById('history-type-retrofitted');
        var modifiedCheckbox = document.getElementById('history-type-modified');

        if (createdCheckbox) createdCheckbox.checked = true;
        if (tunedCheckbox) tunedCheckbox.checked = true;
        if (retrofittedCheckbox) retrofittedCheckbox.checked = true;
        if (modifiedCheckbox) modifiedCheckbox.checked = true;

        // Reset analyst filter
        var analystSelect = document.getElementById('history-analyst-filter');
        if (analystSelect) analystSelect.value = '';

        // Reset field filter
        var fieldSelect = document.getElementById('history-field-filter');
        if (fieldSelect) fieldSelect.value = '';

        // Reset date range to "All time"
        setDatePreset('all');
    };

    // Render history timeline
    function renderHistoryTimeline() {
        var container = document.getElementById('history-timeline');
        var countEl = document.getElementById('history-count');

        if (countEl) {
            countEl.textContent = historyState.filteredEntries.length + ' change' + (historyState.filteredEntries.length !== 1 ? 's' : '');
        }

        if (!container) return;

        if (historyState.filteredEntries.length === 0) {
            container.innerHTML = '<div class="history-empty-state"><span class="empty-icon">📜</span><p>No history entries match the selected filters</p></div>';
            return;
        }

        // Group entries by date
        var groupedByDate = {};
        historyState.filteredEntries.forEach(function(entry) {
            var dateKey = formatDateForGrouping(entry.date);
            if (!groupedByDate[dateKey]) {
                groupedByDate[dateKey] = [];
            }
            groupedByDate[dateKey].push(entry);
        });

        // Render grouped entries
        var html = '';
        var dateKeys = Object.keys(groupedByDate);

        dateKeys.forEach(function(dateKey) {
            var entries = groupedByDate[dateKey];

            html += '<div class="timeline-group">';
            html += '<div class="timeline-date-header">' + formatDateForDisplay(entries[0].date) + '</div>';

            entries.forEach(function(entry) {
                var typeLabel = getTypeLabel(entry.type);
                var sevClass = (entry.severity || '').toLowerCase();
                var timeStr = formatTimeForDisplay(entry.date);

                html += '<div class="timeline-entry ' + entry.type + '" onclick="viewDetectionFromHistory(\'' + escapeAttr(entry.detectionName) + '\')">';
                html += '<div class="timeline-entry-header">';
                html += '<span class="timeline-entry-name">' + escapeHtml(entry.detectionName) + '</span>';
                html += '<span class="timeline-entry-type ' + entry.type + '">' + typeLabel + '</span>';
                html += '</div>';
                if (entry.description) {
                    html += '<div class="timeline-entry-desc">' + escapeHtml(entry.description) + '</div>';
                }
                html += '<div class="timeline-entry-meta">';
                html += '<span class="timeline-entry-time">' + timeStr + '</span>';
                html += '<span class="timeline-entry-analyst"><span class="timeline-entry-analyst-icon">👤</span>' + escapeHtml(entry.analyst) + '</span>';
                if (entry.severity) {
                    html += '<span class="timeline-entry-severity"><span class="severity-badge ' + sevClass + '">' + escapeHtml(entry.severity) + '</span></span>';
                }
                if (entry.fieldsChanged && entry.fieldsChanged.length > 0) {
                    html += '<span class="timeline-entry-fields">Fields: ' + escapeHtml(entry.fieldsChanged.join(', ')) + '</span>';
                }
                html += '</div>';
                html += '</div>';
            });

            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Get type label for display
    function getTypeLabel(type) {
        switch (type) {
            case 'created': return 'Created';
            case 'tuned': return 'Tuned';
            case 'retrofitted': return 'Retrofitted';
            case 'modified': return 'Modified';
            default: return type;
        }
    }

    // Format date for grouping key (YYYY-MM-DD)
    function formatDateForGrouping(date) {
        return date.toISOString().split('T')[0];
    }

    // Format date for display in group header
    function formatDateForDisplay(date) {
        var today = new Date();
        var yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);

        var dateOnly = new Date(date.getFullYear(), date.getMonth(), date.getDate());
        var todayOnly = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        var yesterdayOnly = new Date(yesterday.getFullYear(), yesterday.getMonth(), yesterday.getDate());

        if (dateOnly.getTime() === todayOnly.getTime()) {
            return 'Today';
        } else if (dateOnly.getTime() === yesterdayOnly.getTime()) {
            return 'Yesterday';
        } else {
            return date.toLocaleDateString('en-US', {
                weekday: 'long',
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            });
        }
    }

    // Format time for display
    function formatTimeForDisplay(date) {
        return date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    }

    // View detection from history entry
    window.viewDetectionFromHistory = function(detectionName) {
        // Navigate to Library view
        var navItem = document.querySelector('.nav-item[href="#library"]');
        if (navItem) {
            App.handleNavigation(navItem);
            // Select the detection after a brief delay to allow view switch
            setTimeout(function() {
                App.selectDetection(detectionName);
            }, 100);
        }
    };

    // =====================================================================
    // RESOURCES VIEW FUNCTIONS
    // =====================================================================

    // Resources state
    var resourcesState = {
        resources: [],
        editingResourceId: null,
        deleteResourceId: null,
        loaded: false
    };

    // Storage key for resources (fallback cache)
    var RESOURCES_STORAGE_KEY = 'dmf_resources';
    var RESOURCES_JSON_PATH = '../dist/resources.json';

    // Initialize Resources view
    function initResources() {
        loadResources();
    }

    // Load resources from dist/resources.json (primary) or localStorage (fallback)
    function loadResources() {
        // Try to fetch from resources.json first
        fetch(RESOURCES_JSON_PATH)
            .then(function(response) {
                if (!response.ok) throw new Error('Failed to load resources.json');
                return response.json();
            })
            .then(function(data) {
                if (Array.isArray(data) && data.length > 0) {
                    resourcesState.resources = data;
                } else {
                    // resources.json is empty, try localStorage or use defaults
                    loadResourcesFromLocalStorage();
                }
                resourcesState.loaded = true;
                renderResources();
            })
            .catch(function(err) {
                console.warn('Failed to load resources.json, using localStorage:', err);
                loadResourcesFromLocalStorage();
                resourcesState.loaded = true;
                renderResources();
            });
    }

    // Load resources from localStorage (fallback)
    function loadResourcesFromLocalStorage() {
        try {
            var stored = localStorage.getItem(RESOURCES_STORAGE_KEY);
            if (stored) {
                resourcesState.resources = JSON.parse(stored);
            } else {
                // Initialize with some default resources
                resourcesState.resources = [
                    {
                        id: generateResourceId(),
                        name: 'Splunk ES Dashboard',
                        url: 'https://myorg.splunkcloud.com/en-US/app/SplunkEnterpriseSecuritySuite/ess_dashboard',
                        category: 'dashboard',
                        description: 'Enterprise Security Suite main dashboard'
                    },
                    {
                        id: generateResourceId(),
                        name: 'MITRE ATT&CK Navigator',
                        url: 'https://mitre-attack.github.io/attack-navigator/',
                        category: 'external',
                        description: 'ATT&CK technique visualization tool'
                    },
                    {
                        id: generateResourceId(),
                        name: 'Sigma Rules Repository',
                        url: 'https://github.com/SigmaHQ/sigma',
                        category: 'external',
                        description: 'Open signature format for SIEM systems'
                    },
                    {
                        id: generateResourceId(),
                        name: 'Detection Wiki',
                        url: 'https://internal.myorg.com/wiki/detection-engineering',
                        category: 'internal',
                        description: 'Internal documentation for detection engineering'
                    }
                ];
            }
        } catch (e) {
            console.error('Failed to load resources from localStorage:', e);
            resourcesState.resources = [];
        }
    }

    // Save resources to localStorage and trigger GitHub sync
    function saveResources() {
        try {
            // Save to localStorage as cache
            localStorage.setItem(RESOURCES_STORAGE_KEY, JSON.stringify(resourcesState.resources));

            // Trigger GitHub sync notification
            // This follows the same pattern as other views (macros, detections)
            // The actual GitHub commit is handled by external process or manual action
            console.log('Resources updated - ready for GitHub sync via resources.json');

            // Store pending changes indicator
            sessionStorage.setItem('dmf_resources_pending_sync', 'true');

            // Also save comprehensive localStorage cache
            saveToLocalStorage();
        } catch (e) {
            console.error('Failed to save resources:', e);
        }
    }

    // Update resources.json file (for GitHub sync)
    // This function prepares the data for export/sync
    window.exportResourcesForSync = function() {
        return JSON.stringify(resourcesState.resources, null, 2);
    };

    // Generate unique resource ID
    function generateResourceId() {
        return 'res_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    // Render all resources grouped by category
    function renderResources() {
        var categories = ['dashboard', 'external', 'internal'];

        categories.forEach(function(category) {
            var container = document.getElementById('resources-' + category);
            var countEl = document.getElementById('count-' + category);

            if (!container) return;

            var categoryResources = resourcesState.resources.filter(function(r) {
                return r.category === category;
            });

            // Update count
            if (countEl) {
                countEl.textContent = categoryResources.length;
            }

            // Render items
            if (categoryResources.length === 0) {
                container.innerHTML = '<div class="resource-list-empty">No resources in this category</div>';
                return;
            }

            var html = '';
            categoryResources.forEach(function(resource) {
                html += renderResourceItem(resource);
            });

            container.innerHTML = html;
        });
    }

    // Render a single resource item
    function renderResourceItem(resource) {
        var html = '<div class="resource-item" onclick="openResourceUrl(\'' + escapeAttr(resource.id) + '\')">';
        html += '<div class="resource-item-content">';
        html += '<div class="resource-item-name">' + escapeHtml(resource.name) + ' <span class="external-icon">&#x2197;</span></div>';
        html += '<div class="resource-item-url">' + escapeHtml(resource.url) + '</div>';
        if (resource.description) {
            html += '<div class="resource-item-description">' + escapeHtml(resource.description) + '</div>';
        }
        html += '</div>';
        html += '<div class="resource-item-actions">';
        html += '<button class="btn-icon" onclick="event.stopPropagation(); openEditResourceModal(\'' + escapeAttr(resource.id) + '\')" title="Edit">&#x270E;</button>';
        html += '<button class="btn-icon btn-danger" onclick="event.stopPropagation(); openDeleteResourceModal(\'' + escapeAttr(resource.id) + '\')" title="Delete">&#x2715;</button>';
        html += '</div>';
        html += '</div>';
        return html;
    }

    // Open resource URL in new tab
    window.openResourceUrl = function(resourceId) {
        var resource = resourcesState.resources.find(function(r) {
            return r.id === resourceId;
        });
        if (resource && resource.url) {
            window.open(resource.url, '_blank');
        }
    };

    // Open Add Resource Modal
    window.openAddResourceModal = function() {
        resourcesState.editingResourceId = null;

        var modal = document.getElementById('modal-resource');
        var title = document.getElementById('resource-modal-title');
        var nameInput = document.getElementById('resource-name');
        var urlInput = document.getElementById('resource-url');
        var categorySelect = document.getElementById('resource-category');
        var descInput = document.getElementById('resource-description');
        var editIdInput = document.getElementById('resource-edit-id');

        if (title) title.textContent = 'Add Resource';
        if (nameInput) nameInput.value = '';
        if (urlInput) urlInput.value = '';
        if (categorySelect) categorySelect.value = '';
        if (descInput) descInput.value = '';
        if (editIdInput) editIdInput.value = '';

        if (modal) modal.classList.remove('hidden');
        if (nameInput) nameInput.focus();
    };

    // Open Edit Resource Modal
    window.openEditResourceModal = function(resourceId) {
        var resource = resourcesState.resources.find(function(r) {
            return r.id === resourceId;
        });
        if (!resource) return;

        resourcesState.editingResourceId = resourceId;

        var modal = document.getElementById('modal-resource');
        var title = document.getElementById('resource-modal-title');
        var nameInput = document.getElementById('resource-name');
        var urlInput = document.getElementById('resource-url');
        var categorySelect = document.getElementById('resource-category');
        var descInput = document.getElementById('resource-description');
        var editIdInput = document.getElementById('resource-edit-id');

        if (title) title.textContent = 'Edit Resource';
        if (nameInput) nameInput.value = resource.name || '';
        if (urlInput) urlInput.value = resource.url || '';
        if (categorySelect) categorySelect.value = resource.category || '';
        if (descInput) descInput.value = resource.description || '';
        if (editIdInput) editIdInput.value = resourceId;

        if (modal) modal.classList.remove('hidden');
        if (nameInput) nameInput.focus();
    };

    // Close Resource Modal
    window.closeResourceModal = function() {
        var modal = document.getElementById('modal-resource');
        if (modal) modal.classList.add('hidden');
        resourcesState.editingResourceId = null;
    };

    // Save Resource (Add or Edit)
    window.saveResource = function() {
        var nameInput = document.getElementById('resource-name');
        var urlInput = document.getElementById('resource-url');
        var categorySelect = document.getElementById('resource-category');
        var descInput = document.getElementById('resource-description');
        var editIdInput = document.getElementById('resource-edit-id');

        var name = nameInput ? nameInput.value.trim() : '';
        var url = urlInput ? urlInput.value.trim() : '';
        var category = categorySelect ? categorySelect.value : '';
        var description = descInput ? descInput.value.trim() : '';
        var editId = editIdInput ? editIdInput.value : '';

        // Validation
        if (!name) {
            alert('Please enter a resource name');
            if (nameInput) nameInput.focus();
            return;
        }
        if (!url) {
            alert('Please enter a URL');
            if (urlInput) urlInput.focus();
            return;
        }
        if (!category) {
            alert('Please select a category');
            if (categorySelect) categorySelect.focus();
            return;
        }

        // Add https:// if no protocol
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        if (editId) {
            // Update existing resource
            var index = resourcesState.resources.findIndex(function(r) {
                return r.id === editId;
            });
            if (index !== -1) {
                resourcesState.resources[index].name = name;
                resourcesState.resources[index].url = url;
                resourcesState.resources[index].category = category;
                resourcesState.resources[index].description = description;
            }
        } else {
            // Add new resource
            resourcesState.resources.push({
                id: generateResourceId(),
                name: name,
                url: url,
                category: category,
                description: description
            });
        }

        saveResources();
        renderResources();
        closeResourceModal();
    };

    // Open Delete Resource Confirmation Modal
    window.openDeleteResourceModal = function(resourceId) {
        var resource = resourcesState.resources.find(function(r) {
            return r.id === resourceId;
        });
        if (!resource) return;

        resourcesState.deleteResourceId = resourceId;

        var modal = document.getElementById('modal-delete-resource');
        var message = document.getElementById('delete-resource-message');

        if (message) {
            message.textContent = 'Are you sure you want to delete "' + resource.name + '"?';
        }

        if (modal) modal.classList.remove('hidden');
    };

    // Close Delete Resource Modal
    window.closeDeleteResourceModal = function() {
        var modal = document.getElementById('modal-delete-resource');
        if (modal) modal.classList.add('hidden');
        resourcesState.deleteResourceId = null;
    };

    // Confirm Delete Resource
    window.confirmDeleteResource = function() {
        var resourceId = resourcesState.deleteResourceId;
        if (!resourceId) return;

        resourcesState.resources = resourcesState.resources.filter(function(r) {
            return r.id !== resourceId;
        });

        saveResources();
        renderResources();
        closeDeleteResourceModal();
    };

    // =========================================================================
    // REPORTS VIEW FUNCTIONS
    // =========================================================================

    // Reports State
    var reportsState = {
        initialized: false,
        activeTab: 'overview'
    };

    // Initialize Reports View
    function initReports() {
        reportsState.initialized = true;
        initReportsTabs();
        // Reports will be rendered when data is available
        renderReports();
    }

    // Initialize Reports Sub-Tabs
    function initReportsTabs() {
        document.querySelectorAll('.reports-tab').forEach(function(tab) {
            tab.addEventListener('click', function() {
                var tabName = tab.dataset.tab;
                if (!tabName) return;

                // Update active tab button
                document.querySelectorAll('.reports-tab').forEach(function(t) {
                    t.classList.remove('active');
                });
                tab.classList.add('active');

                // Update active tab content
                document.querySelectorAll('.reports-tab-content').forEach(function(c) {
                    c.classList.add('hidden');
                    c.classList.remove('active');
                });

                var content = document.getElementById('reports-' + tabName);
                if (content) {
                    content.classList.remove('hidden');
                    content.classList.add('active');
                }

                // Store active tab
                reportsState.activeTab = tabName;

                // Render specific report based on tab
                var detections = App.state.detections || [];
                if (tabName === 'overview') {
                    renderOverviewTab(detections);
                } else if (tabName === 'coverage') {
                    renderCoverageTab(detections);
                } else if (tabName === 'revalidations') {
                    renderRevalidationReportTab(detections);
                } else if (tabName === 'metadata') {
                    renderMetadataReportTab(detections);
                }
            });
        });
    }

    // Render Reports View (main entry point)
    function renderReports() {
        if (!reportsState.initialized) return;

        var detections = App.state.detections || [];

        // Render all overview report sections (default tab)
        renderOverviewTab(detections);
    }

    // Render Overview Tab
    function renderOverviewTab(detections) {
        renderStatCards(detections);
        renderSeverityChart(detections);
        renderRiskChart(detections);
        renderDomainChart(detections);
        renderDatasourceChart(detections);
        renderMitreChart(detections);
        renderRecentLists(detections);
    }

    // Render Coverage Tab
    function renderCoverageTab(detections) {
        // Summary stats
        var total = detections.length;
        var withMitre = detections.filter(function(d) {
            var mitre = d['Mitre ID'];
            return mitre && (Array.isArray(mitre) ? mitre.length > 0 : String(mitre).trim() !== '');
        }).length;
        var withDrilldowns = detections.filter(function(d) {
            return d['Drilldown Name (Legacy)'] || d['Drilldown Name 1'];
        }).length;

        var totalRisk = 0;
        detections.forEach(function(d) {
            var risk = getRiskScore(d);
            if (risk) totalRisk += risk;
        });
        var avgRisk = total > 0 ? Math.round(totalRisk / total) : 0;

        updateElementText('report-coverage-mitre', total > 0 ? Math.round(withMitre / total * 100) + '%' : '0%');
        updateElementText('report-coverage-drilldowns', total > 0 ? Math.round(withDrilldowns / total * 100) + '%' : '0%');
        updateElementText('report-avg-risk', avgRisk);
        updateElementText('report-total', total);

        // Charts
        renderBarChartFromCounts('report-datasources', getDatasourceCounts(detections), 15);
        renderBarChartFromCounts('report-platforms', getPlatformCounts(detections), 10);
        renderBarChartFromCounts('report-domains', getDomainCounts(detections), 10);
        renderBarChartFromCounts('report-origins', getOriginCounts(detections), 10);
        renderBarChartFromCounts('report-severity', getSeverityCounts(detections), 10);
        renderQualityMetricsChart(detections);
        renderMitreHeatmap(detections);
        renderSearchFieldsChart(detections);
        renderSearchFunctionsChart(detections);
    }

    // Render Revalidation Report Tab
    function renderRevalidationReportTab(detections) {
        var total = detections.length;
        var valid = 0, needTune = 0, needRetrofit = 0;
        var fieldMissing = {};
        var ttlExpired = 0, ttlCritical = 0, ttlWarning = 0, ttlOk = 0;

        // Build field missing counts
        var allFields = (App.MANDATORY_FIELDS || []).concat(App.KEY_FIELDS || []);
        allFields.forEach(function(f) { fieldMissing[f] = 0; });

        detections.forEach(function(d) {
            var status = App.getDetectionStatus(d);
            if (status === 'valid') valid++;
            else if (status === 'needs-tune') needTune++;
            else if (status === 'needs-retrofit') needRetrofit++;

            // Count missing fields
            allFields.forEach(function(f) {
                if (!App.hasValue(d, f)) {
                    fieldMissing[f]++;
                }
            });

            // TTL calculation
            var ttl = calculateTTL(d['Last Modified']);
            if (ttl.days <= 0) ttlExpired++;
            else if (ttl.days <= 30) ttlCritical++;
            else if (ttl.days <= 90) ttlWarning++;
            else ttlOk++;
        });

        // Update summary stats
        updateElementText('reval-report-total', total);
        updateElementText('reval-report-valid', valid);
        updateElementText('reval-report-tune', needTune);
        updateElementText('reval-report-retrofit', needRetrofit);

        // Missing fields chart
        renderMissingFieldsChart(fieldMissing, total);

        // TTL status
        renderTTLStatus(ttlExpired, ttlCritical, ttlWarning, ttlOk);

        // History stats
        var historyStats = getHistoryStats();
        updateElementText('reval-report-history-total', historyStats.totalEntries);
        updateElementText('reval-report-tunes', historyStats.totalTunes);
        updateElementText('reval-report-retrofits', historyStats.totalRetrofits);
        updateElementText('reval-report-analysts', historyStats.uniqueAnalysts);

        // Activity charts
        renderBarChartFromCounts('reval-report-analyst-chart', historyStats.byAnalyst, 10);
        renderBarChartFromCounts('reval-report-reason-chart', historyStats.byReason, 10);

        // Activity timeline
        renderActivityTimeline(historyStats.recentActivity);
    }

    // Render Metadata Report Tab
    function renderMetadataReportTab(detections) {
        var indexes = {};
        var sourcetypes = {};
        var mainSearchFields = {};
        var mainSearchFunctions = {};
        var macros = {};
        var lookups = {};
        var detectionsWithMeta = 0;

        // Parse SPL from each detection to extract metadata
        detections.forEach(function(d) {
            var spl = d['Search String'];
            if (spl) {
                // Use the global parseSPL function to extract metadata
                var parsed = parseSPL(spl);
                detectionsWithMeta++;

                if (parsed.indexes) {
                    parsed.indexes.forEach(function(i) {
                        indexes[i] = (indexes[i] || 0) + 1;
                    });
                }
                if (parsed.sourcetypes) {
                    parsed.sourcetypes.forEach(function(s) {
                        sourcetypes[s] = (sourcetypes[s] || 0) + 1;
                    });
                }
                if (parsed.mainSearchFields) {
                    parsed.mainSearchFields.forEach(function(f) {
                        mainSearchFields[f] = (mainSearchFields[f] || 0) + 1;
                    });
                }
                if (parsed.mainSearchFunctions) {
                    parsed.mainSearchFunctions.forEach(function(f) {
                        mainSearchFunctions[f] = (mainSearchFunctions[f] || 0) + 1;
                    });
                }
                if (parsed.macros) {
                    parsed.macros.forEach(function(m) {
                        macros[m] = (macros[m] || 0) + 1;
                    });
                }
                if (parsed.lookups) {
                    parsed.lookups.forEach(function(l) {
                        lookups[l] = (lookups[l] || 0) + 1;
                    });
                }
            }
        });

        // Update summary stats
        updateElementText('meta-report-detections', detectionsWithMeta);
        updateElementText('meta-report-indexes', Object.keys(indexes).length);
        updateElementText('meta-report-sourcetypes', Object.keys(sourcetypes).length);
        updateElementText('meta-report-functions', Object.keys(mainSearchFunctions).length);

        // Render charts
        renderBarChartFromCounts('meta-report-index-chart', indexes, 15);
        renderBarChartFromCounts('meta-report-sourcetype-chart', sourcetypes, 15);
        renderBarChartFromCounts('meta-report-fields-chart', mainSearchFields, 15);
        renderBarChartFromCounts('meta-report-func-chart', mainSearchFunctions, 15);
        renderBarChartFromCounts('meta-report-macros-chart', macros, 15);
        renderBarChartFromCounts('meta-report-lookups-chart', lookups, 15);
    }

    // Helper: Render bar chart from counts object
    function renderBarChartFromCounts(containerId, counts, limit) {
        var container = document.getElementById(containerId);
        if (!container) return;

        var sorted = Object.keys(counts).sort(function(a, b) {
            return counts[b] - counts[a];
        }).slice(0, limit || 15);

        if (sorted.length === 0) {
            container.innerHTML = '<div class="chart-empty">No data available</div>';
            return;
        }

        var maxCount = Math.max.apply(null, sorted.map(function(k) { return counts[k]; }));
        var html = '';

        sorted.forEach(function(key) {
            var count = counts[key];
            var percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label" title="' + escapeAttr(key) + '">' + escapeHtml(key) + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar" style="width: ' + percentage + '%"></div>';
            html += '<span class="bar-chart-value">' + count + '</span>';
            html += '</div></div>';
        });

        container.innerHTML = html;
    }

    // Helper: Get domain counts
    function getDomainCounts(detections) {
        var counts = {};
        detections.forEach(function(d) {
            var domain = d['Security Domain'] || 'Unknown';
            counts[domain] = (counts[domain] || 0) + 1;
        });
        return counts;
    }

    // Helper: Get datasource counts
    function getDatasourceCounts(detections) {
        var counts = {};
        detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var parsed = parseSPL(spl);
            parsed.indexes.forEach(function(idx) {
                counts[idx] = (counts[idx] || 0) + 1;
            });
            parsed.sourcetypes.forEach(function(st) {
                counts[st] = (counts[st] || 0) + 1;
            });
        });
        return counts;
    }

    // Helper: Get platform counts (based on index patterns)
    function getPlatformCounts(detections) {
        var counts = {};
        detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var parsed = parseSPL(spl);
            // Simple platform detection
            parsed.indexes.forEach(function(idx) {
                var lower = idx.toLowerCase();
                if (lower.indexOf('win') !== -1 || lower.indexOf('sysmon') !== -1 || lower.indexOf('winevent') !== -1) {
                    counts['Windows'] = (counts['Windows'] || 0) + 1;
                } else if (lower.indexOf('linux') !== -1 || lower.indexOf('syslog') !== -1) {
                    counts['Linux'] = (counts['Linux'] || 0) + 1;
                } else if (lower.indexOf('azure') !== -1 || lower.indexOf('o365') !== -1 || lower.indexOf('ms_') !== -1) {
                    counts['Cloud/Azure'] = (counts['Cloud/Azure'] || 0) + 1;
                } else if (lower.indexOf('aws') !== -1) {
                    counts['AWS'] = (counts['AWS'] || 0) + 1;
                } else if (lower.indexOf('gcp') !== -1) {
                    counts['GCP'] = (counts['GCP'] || 0) + 1;
                } else if (lower.indexOf('network') !== -1 || lower.indexOf('firewall') !== -1) {
                    counts['Network'] = (counts['Network'] || 0) + 1;
                } else {
                    counts['Other'] = (counts['Other'] || 0) + 1;
                }
            });
        });
        return counts;
    }

    // Helper: Get origin counts
    function getOriginCounts(detections) {
        var counts = {};
        detections.forEach(function(d) {
            var origin = d.origin || 'custom';
            counts[origin] = (counts[origin] || 0) + 1;
        });
        return counts;
    }

    // Helper: Get severity counts
    function getSeverityCounts(detections) {
        var counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
        detections.forEach(function(d) {
            var sev = (d['Severity/Priority'] || '').toLowerCase();
            if (sev === 'critical') counts.critical++;
            else if (sev === 'high') counts.high++;
            else if (sev === 'medium') counts.medium++;
            else if (sev === 'low') counts.low++;
            else if (sev === 'informational' || sev === 'info') counts.informational++;
        });
        return counts;
    }

    // Helper: Render missing fields chart
    function renderMissingFieldsChart(fieldMissing, total) {
        var container = document.getElementById('reval-report-fields');
        if (!container) return;

        var sorted = Object.keys(fieldMissing).filter(function(f) {
            return fieldMissing[f] > 0;
        }).sort(function(a, b) {
            return fieldMissing[b] - fieldMissing[a];
        });

        if (sorted.length === 0) {
            container.innerHTML = '<div class="chart-empty">All fields complete</div>';
            return;
        }

        var html = '<div class="field-missing-chart">';
        sorted.forEach(function(f) {
            var count = fieldMissing[f];
            var pct = total > 0 ? (count / total * 100).toFixed(1) : 0;
            var label = App.FIELD_LABELS && App.FIELD_LABELS[f] ? App.FIELD_LABELS[f] : f;
            html += '<div class="field-bar-row">';
            html += '<span class="field-name">' + escapeHtml(label) + '</span>';
            html += '<div class="field-bar"><div class="field-bar-fill" style="width:' + pct + '%"></div></div>';
            html += '<span class="field-count">' + count + '</span>';
            html += '</div>';
        });
        html += '</div>';
        container.innerHTML = html;
    }

    // Helper: Render TTL status
    function renderTTLStatus(expired, critical, warning, ok) {
        var container = document.getElementById('reval-report-ttl');
        if (!container) return;

        var html = '<div class="ttl-summary-chart">';
        html += '<div class="ttl-bar-item"><span class="ttl-label ttl-expired">Expired</span><span class="ttl-count">' + expired + '</span></div>';
        html += '<div class="ttl-bar-item"><span class="ttl-label ttl-critical">Critical (&le;30d)</span><span class="ttl-count">' + critical + '</span></div>';
        html += '<div class="ttl-bar-item"><span class="ttl-label ttl-warning">Warning (&le;90d)</span><span class="ttl-count">' + warning + '</span></div>';
        html += '<div class="ttl-bar-item"><span class="ttl-label ttl-ok">OK</span><span class="ttl-count">' + ok + '</span></div>';
        html += '</div>';
        container.innerHTML = html;
    }

    // Helper: Get history stats
    function getHistoryStats() {
        var metadata = App.state.metadata || {};
        var stats = {
            totalEntries: 0,
            totalTunes: 0,
            totalRetrofits: 0,
            uniqueAnalysts: 0,
            byAnalyst: {},
            byReason: {},
            recentActivity: []
        };

        var reasonLabels = {
            false_positives: 'False Positives',
            performance: 'Performance',
            coverage: 'Coverage',
            threshold: 'Threshold',
            data_source: 'Data Source',
            other: 'Other'
        };

        Object.keys(metadata).forEach(function(name) {
            var meta = metadata[name];
            if (meta && meta.history) {
                meta.history.forEach(function(h) {
                    stats.totalEntries++;
                    if (h.type === 'tune') stats.totalTunes++;
                    if (h.type === 'retrofit') stats.totalRetrofits++;
                    if (h.analyst) {
                        stats.byAnalyst[h.analyst] = (stats.byAnalyst[h.analyst] || 0) + 1;
                    }
                    if (h.reason) {
                        var label = reasonLabels[h.reason] || h.reason;
                        stats.byReason[label] = (stats.byReason[label] || 0) + 1;
                    }
                    stats.recentActivity.push({ name: name, entry: h });
                });
            }
        });

        stats.uniqueAnalysts = Object.keys(stats.byAnalyst).length;
        stats.recentActivity.sort(function(a, b) {
            return new Date(b.entry.timestamp) - new Date(a.entry.timestamp);
        });

        return stats;
    }

    // Helper: Render activity timeline
    function renderActivityTimeline(activities) {
        var container = document.getElementById('reval-report-timeline');
        if (!container) return;

        if (!activities || activities.length === 0) {
            container.innerHTML = '<div class="chart-empty">No activity</div>';
            return;
        }

        var html = '<div class="activity-timeline">';
        activities.slice(0, 20).forEach(function(item) {
            var h = item.entry;
            var icon = h.type === 'tune' ? '&#x1F527;' : h.type === 'retrofit' ? '&#x26A1;' : '&#x1F4DD;';
            html += '<div class="activity-item ' + (h.type || '') + '">';
            html += '<span class="activity-icon">' + icon + '</span>';
            html += '<div class="activity-content">';
            html += '<span class="activity-detection">' + escapeHtml(item.name) + '</span>';
            html += '<span class="activity-desc">' + escapeHtml(h.description || 'No description') + '</span>';
            html += '</div>';
            html += '<span class="activity-date">' + (h.timestamp ? new Date(h.timestamp).toLocaleDateString() : '') + '</span>';
            html += '</div>';
        });
        html += '</div>';
        container.innerHTML = html;
    }

    // Helper: Render quality metrics chart
    function renderQualityMetricsChart(detections) {
        var container = document.getElementById('report-quality');
        if (!container) return;

        var total = detections.length;
        if (total === 0) {
            container.innerHTML = '<div class="chart-empty">No data available</div>';
            return;
        }

        var metrics = {
            'Has Description': 0,
            'Has Objective': 0,
            'Has MITRE': 0,
            'Has Drilldowns': 0,
            'Has Risk Score': 0,
            'Has Next Steps': 0
        };

        detections.forEach(function(d) {
            if (d['Description'] && d['Description'].trim()) metrics['Has Description']++;
            if (d['Objective'] && d['Objective'].trim()) metrics['Has Objective']++;
            var mitre = d['Mitre ID'];
            if (mitre && (Array.isArray(mitre) ? mitre.length > 0 : String(mitre).trim() !== '')) metrics['Has MITRE']++;
            if (d['Drilldown Name (Legacy)'] || d['Drilldown Name 1']) metrics['Has Drilldowns']++;
            if (getRiskScore(d) > 0) metrics['Has Risk Score']++;
            if (d['Analyst Next Steps'] && d['Analyst Next Steps'].trim()) metrics['Has Next Steps']++;
        });

        var counts = {};
        Object.keys(metrics).forEach(function(k) {
            counts[k] = Math.round(metrics[k] / total * 100);
        });

        renderBarChartFromCounts('report-quality', counts, 10);
    }

    // Render Severity Chart (for Overview tab)
    function renderSeverityChart(detections) {
        var counts = getSeverityCounts(detections);
        renderBarChartFromCounts('chart-severity', counts, 5);
    }

    // Render MITRE Chart (for Overview tab)
    function renderMitreChart(detections) {
        var container = document.getElementById('chart-mitre');
        if (!container) return;

        var mitreCounts = {};
        detections.forEach(function(d) {
            var mitreIds = d['Mitre ID'] || [];
            if (!Array.isArray(mitreIds)) {
                mitreIds = String(mitreIds).split(/[,;]/).map(function(s) { return s.trim(); }).filter(Boolean);
            }
            mitreIds.forEach(function(id) {
                // Get just the technique (not sub-technique) for grouping
                var technique = id.split('.')[0];
                mitreCounts[technique] = (mitreCounts[technique] || 0) + 1;
            });
        });

        renderBarChartFromCounts('chart-mitre', mitreCounts, 15);
    }

    // Calculate TTL helper
    function calculateTTL(lastModified) {
        if (!lastModified) return { days: 999, expired: false };
        var modified = new Date(lastModified);
        var now = new Date();
        var diffDays = Math.floor((now - modified) / (1000 * 60 * 60 * 24));
        var ttlDays = 365 - diffDays;
        return {
            days: ttlDays,
            expired: ttlDays <= 0
        };
    }

    // Render Stats Cards
    function renderStatCards(detections) {
        var counts = {
            total: detections.length,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0
        };

        detections.forEach(function(d) {
            var sev = (d['Severity/Priority'] || '').toLowerCase();
            if (sev === 'critical') counts.critical++;
            else if (sev === 'high') counts.high++;
            else if (sev === 'medium') counts.medium++;
            else if (sev === 'low') counts.low++;
            else if (sev === 'informational' || sev === 'info') counts.informational++;
        });

        updateElementText('stat-total-detections', counts.total);
        updateElementText('stat-critical', counts.critical);
        updateElementText('stat-high', counts.high);
        updateElementText('stat-medium', counts.medium);
        updateElementText('stat-low', counts.low);
        updateElementText('stat-info', counts.informational);
    }

    // Render Revalidation Status Summary
    function renderRevalidationStatus(detections) {
        var counts = {
            valid: 0,
            incomplete: 0,
            needsTune: 0,
            needsRetrofit: 0
        };

        detections.forEach(function(d) {
            var status = App.getDetectionStatus(d);
            if (status === 'valid') counts.valid++;
            else if (status === 'incomplete') counts.incomplete++;
            else if (status === 'needs-tune') counts.needsTune++;
            else if (status === 'needs-retrofit') counts.needsRetrofit++;
        });

        updateElementText('reval-stat-valid', counts.valid);
        updateElementText('reval-stat-incomplete', counts.incomplete);
        updateElementText('reval-stat-needs-tune', counts.needsTune);
        updateElementText('reval-stat-needs-retrofit', counts.needsRetrofit);
    }

    // Render Domain Bar Chart
    function renderDomainChart(detections) {
        var container = document.getElementById('chart-by-domain');
        if (!container) return;

        var domainCounts = {};
        detections.forEach(function(d) {
            var domain = d['Security Domain'] || 'Unknown';
            domainCounts[domain] = (domainCounts[domain] || 0) + 1;
        });

        var sortedDomains = Object.keys(domainCounts).sort(function(a, b) {
            return domainCounts[b] - domainCounts[a];
        });

        if (sortedDomains.length === 0) {
            container.innerHTML = '<div class="chart-empty">No data available</div>';
            return;
        }

        var maxCount = Math.max.apply(null, Object.values(domainCounts));
        var html = '';

        sortedDomains.forEach(function(domain) {
            var count = domainCounts[domain];
            var percentage = (count / maxCount) * 100;
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label" title="' + escapeAttr(domain) + '">' + escapeHtml(domain) + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar" style="width: ' + percentage + '%"></div>';
            html += '<span class="bar-chart-value">' + count + '</span>';
            html += '</div></div>';
        });

        container.innerHTML = html;
    }

    // Render Data Source Bar Chart
    function renderDatasourceChart(detections) {
        var container = document.getElementById('chart-by-datasource');
        if (!container) return;

        var dsCounts = {};
        detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var parsed = parseSPL(spl);

            // Count indexes
            parsed.indexes.forEach(function(idx) {
                dsCounts[idx] = (dsCounts[idx] || 0) + 1;
            });

            // Count sourcetypes
            parsed.sourcetypes.forEach(function(st) {
                dsCounts[st] = (dsCounts[st] || 0) + 1;
            });
        });

        var sortedDs = Object.keys(dsCounts).sort(function(a, b) {
            return dsCounts[b] - dsCounts[a];
        }).slice(0, 15); // Top 15

        if (sortedDs.length === 0) {
            container.innerHTML = '<div class="chart-empty">No data available</div>';
            return;
        }

        var maxCount = Math.max.apply(null, sortedDs.map(function(ds) { return dsCounts[ds]; }));
        var html = '';

        sortedDs.forEach(function(ds) {
            var count = dsCounts[ds];
            var percentage = (count / maxCount) * 100;
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label" title="' + escapeAttr(ds) + '">' + escapeHtml(ds) + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar" style="width: ' + percentage + '%"></div>';
            html += '<span class="bar-chart-value">' + count + '</span>';
            html += '</div></div>';
        });

        container.innerHTML = html;
    }

    // Render MITRE ATT&CK Heatmap
    function renderMitreHeatmap(detections) {
        var container = document.getElementById('report-mitre-heatmap');
        var countEl = document.getElementById('mitre-technique-count');
        if (!container) return;

        var mitreCounts = {};
        detections.forEach(function(d) {
            var mitreIds = d['Mitre ID'] || [];
            if (!Array.isArray(mitreIds)) {
                mitreIds = String(mitreIds).split(/[,;]/).map(function(s) { return s.trim(); }).filter(Boolean);
            }
            mitreIds.forEach(function(id) {
                mitreCounts[id] = (mitreCounts[id] || 0) + 1;
            });
        });

        // Sort by count descending for the heatmap view
        var sortedMitre = Object.keys(mitreCounts).map(function(id) {
            return [id, mitreCounts[id]];
        }).sort(function(a, b) {
            return b[1] - a[1];
        });

        if (countEl) {
            countEl.textContent = sortedMitre.length + ' technique' + (sortedMitre.length !== 1 ? 's' : '') + ' covered';
        }

        if (sortedMitre.length === 0) {
            container.innerHTML = '<div class="chart-empty">No MITRE techniques mapped</div>';
            return;
        }

        var maxCount = sortedMitre[0][1];
        var html = '';

        // Show top 30 techniques with opacity-scaled heatmap
        sortedMitre.slice(0, 30).forEach(function(item) {
            var id = item[0];
            var count = item[1];
            var opacity = 0.25 + (count / maxCount) * 0.75;
            html += '<div class="mitre-heatmap-cell" style="background: rgba(168, 85, 247, ' + opacity + ');" title="' + escapeAttr(id) + ': ' + count + ' detection(s)">';
            html += escapeHtml(id);
            html += '<span class="count">' + count + '</span>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Render Quality Metrics Chart
    function renderQualityMetrics(detections) {
        var container = document.getElementById('report-quality');
        if (!container) return;

        var total = detections.length;
        if (total === 0) {
            container.innerHTML = '<div class="chart-empty">No detections</div>';
            return;
        }

        var withMitre = 0;
        var withDrilldowns = 0;
        var withRoles = 0;
        var withAnalystSteps = 0;
        var withDescription = 0;
        var allMandatory = 0;

        detections.forEach(function(d) {
            // Has MITRE Tags
            var mitreIds = d['Mitre ID'] || [];
            if (Array.isArray(mitreIds) && mitreIds.length > 0) withMitre++;

            // Has Drilldowns
            if (d['Drilldown Name (Legacy)'] || d['Drilldown Name 1']) withDrilldowns++;

            // Has Roles
            if (d['Roles'] && d['Roles'].some(function(r) { return r.Name && r.Name.trim(); })) withRoles++;

            // Has Analyst Steps
            if (d['Analyst Next Steps'] && d['Analyst Next Steps'].trim()) withAnalystSteps++;

            // Has Description (different from Objective)
            if (d['Description'] && d['Description'].trim() && d['Description'] !== d['Objective']) withDescription++;

            // All Mandatory Fields
            var status = App.getDetectionStatus(d);
            if (status === 'valid') allMandatory++;
        });

        var metrics = [
            { label: 'Has MITRE Tags', count: withMitre },
            { label: 'Has Drilldowns', count: withDrilldowns },
            { label: 'Has Roles/Owners', count: withRoles },
            { label: 'Has Analyst Steps', count: withAnalystSteps },
            { label: 'Has Description', count: withDescription },
            { label: 'All Mandatory Fields', count: allMandatory }
        ];

        var html = '';
        metrics.forEach(function(m) {
            var pct = Math.round((m.count / total) * 100);
            var colorClass = pct >= 80 ? 'quality-success' : pct >= 50 ? 'quality-warning' : 'quality-error';
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label">' + m.label + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar ' + colorClass + '" style="width: ' + pct + '%"></div>';
            html += '<span class="bar-chart-value">' + pct + '% (' + m.count + ')</span>';
            html += '</div></div>';
        });

        container.innerHTML = html;
    }

    // Render Top Search Fields Chart
    function renderSearchFieldsChart(detections) {
        var container = document.getElementById('chart-search-fields');
        if (!container) return;

        var fieldCounts = {};
        detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var parsed = parseSPL(spl);

            // Count main search fields
            (parsed.mainSearchFields || []).forEach(function(f) {
                fieldCounts[f] = (fieldCounts[f] || 0) + 1;
            });

            // Also count by fields
            (parsed.byFields || []).forEach(function(f) {
                fieldCounts[f] = (fieldCounts[f] || 0) + 1;
            });
        });

        var sorted = Object.keys(fieldCounts).map(function(k) {
            return [k, fieldCounts[k]];
        }).sort(function(a, b) {
            return b[1] - a[1];
        }).slice(0, 15);

        if (sorted.length === 0) {
            container.innerHTML = '<div class="chart-empty">No field data</div>';
            return;
        }

        var maxCount = sorted[0][1];
        var html = '';
        sorted.forEach(function(item) {
            var field = item[0];
            var count = item[1];
            var pct = (count / maxCount) * 100;
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label" title="' + escapeAttr(field) + '">' + escapeHtml(field) + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar fields-bar" style="width: ' + pct + '%"></div>';
            html += '<span class="bar-chart-value">' + count + '</span>';
            html += '</div></div>';
        });

        container.innerHTML = html;
    }

    // Render Top SPL Functions Chart
    function renderSearchFunctionsChart(detections) {
        var container = document.getElementById('chart-search-functions');
        if (!container) return;

        var funcCounts = {};
        detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var parsed = parseSPL(spl);

            // Count SPL functions/commands
            (parsed.mainSearchFunctions || []).forEach(function(f) {
                funcCounts[f] = (funcCounts[f] || 0) + 1;
            });
        });

        var sorted = Object.keys(funcCounts).map(function(k) {
            return [k, funcCounts[k]];
        }).sort(function(a, b) {
            return b[1] - a[1];
        }).slice(0, 15);

        if (sorted.length === 0) {
            container.innerHTML = '<div class="chart-empty">No function data</div>';
            return;
        }

        var maxCount = sorted[0][1];
        var html = '';
        sorted.forEach(function(item) {
            var func = item[0];
            var count = item[1];
            var pct = (count / maxCount) * 100;
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label" title="' + escapeAttr(func) + '">' + escapeHtml(func) + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar functions-bar" style="width: ' + pct + '%"></div>';
            html += '<span class="bar-chart-value">' + count + '</span>';
            html += '</div></div>';
        });

        container.innerHTML = html;
    }

    // Render Metadata Statistics (Top 15 each)
    function renderMetadataStats(detections) {
        var macroCounts = {};
        var lookupCounts = {};
        var indexCounts = {};

        detections.forEach(function(d) {
            var spl = d['Search String'] || '';
            var parsed = parseSPL(spl);

            parsed.macros.forEach(function(m) {
                macroCounts[m] = (macroCounts[m] || 0) + 1;
            });

            parsed.lookups.forEach(function(l) {
                lookupCounts[l] = (lookupCounts[l] || 0) + 1;
            });

            parsed.indexes.forEach(function(i) {
                indexCounts[i] = (indexCounts[i] || 0) + 1;
            });
        });

        renderMetadataList('top-macros-list', macroCounts, 15);
        renderMetadataList('top-lookups-list', lookupCounts, 15);
        renderMetadataList('top-indexes-list', indexCounts, 15);
    }

    // Helper: Render Metadata List
    function renderMetadataList(containerId, counts, limit) {
        var container = document.getElementById(containerId);
        if (!container) return;

        var sorted = Object.keys(counts).sort(function(a, b) {
            return counts[b] - counts[a];
        }).slice(0, limit);

        if (sorted.length === 0) {
            container.innerHTML = '<div class="metadata-empty">No data available</div>';
            return;
        }

        var html = '';
        sorted.forEach(function(name) {
            var count = counts[name];
            html += '<div class="metadata-item">';
            html += '<span class="metadata-item-name" title="' + escapeAttr(name) + '">' + escapeHtml(name) + '</span>';
            html += '<span class="metadata-item-count">' + count + '</span>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Helper: Update element text
    function updateElementText(id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    // Render Risk Score Distribution Chart
    function renderRiskChart(detections) {
        var container = document.getElementById('chart-risk-distribution');
        if (!container) return;

        // Create buckets for risk scores (0-9, 10-19, ..., 90-100)
        var buckets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        var labels = ['0-9', '10-19', '20-29', '30-39', '40-49', '50-59', '60-69', '70-79', '80-89', '90-100'];

        detections.forEach(function(d) {
            var risk = getRiskScore(d);
            var bucket = Math.min(Math.floor(risk / 10), 9);
            buckets[bucket]++;
        });

        var maxCount = Math.max.apply(null, buckets.concat([1]));
        var html = '';

        labels.forEach(function(label, i) {
            var count = buckets[i];
            var percentage = (count / maxCount) * 100;
            html += '<div class="bar-chart-row">';
            html += '<div class="bar-chart-label">' + label + '</div>';
            html += '<div class="bar-chart-bar-container">';
            html += '<div class="bar-chart-bar risk-bar" style="width: ' + percentage + '%"></div>';
            html += '<span class="bar-chart-value">' + count + '</span>';
            html += '</div></div>';
        });

        container.innerHTML = html || '<div class="chart-empty">No risk data</div>';

        // Update risk statistics
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

        updateElementText('risk-stat-avg', avgRisk);
        updateElementText('risk-stat-max', maxRisk);
        updateElementText('risk-stat-min', minRisk < 100 ? minRisk : 0);
    }

    // Render Recent Activity Lists
    function renderRecentLists(detections) {
        renderRecentModifications(detections);
        renderRecentTunes();
        renderRecentRetrofits();
    }

    // Render Recent Modifications
    function renderRecentModifications(detections) {
        var container = document.getElementById('list-recent-modifications');
        if (!container) return;

        var sorted = detections.filter(function(d) {
            return d['Last Modified'];
        }).sort(function(a, b) {
            return new Date(b['Last Modified']) - new Date(a['Last Modified']);
        }).slice(0, 5);

        if (sorted.length === 0) {
            container.innerHTML = '<div class="recent-list-empty">No recent modifications</div>';
            return;
        }

        var html = '';
        sorted.forEach(function(d) {
            var detectionName = d['Detection Name'] || 'Unnamed';
            html += '<div class="recent-list-item" onclick="viewDetectionFromHistory(\'' + escapeAttr(detectionName) + '\')">';
            html += '<span class="recent-list-name">' + escapeHtml(detectionName) + '</span>';
            html += '<span class="recent-list-date">' + formatDateTime(d['Last Modified']) + '</span>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Render Recent Tunes
    function renderRecentTunes() {
        var container = document.getElementById('list-recent-tunes');
        if (!container) return;

        var localHistory = JSON.parse(localStorage.getItem('de_mainframe_history') || '{}');
        var tunes = [];

        Object.keys(localHistory).forEach(function(name) {
            (localHistory[name] || []).filter(function(h) {
                return h.type === 'tune';
            }).forEach(function(h) {
                tunes.push({ name: name, timestamp: h.timestamp, analyst: h.analyst });
            });
        });

        tunes.sort(function(a, b) {
            return new Date(b.timestamp) - new Date(a.timestamp);
        });

        if (tunes.length === 0) {
            container.innerHTML = '<div class="recent-list-empty">No recent tunes</div>';
            return;
        }

        var html = '';
        tunes.slice(0, 5).forEach(function(t) {
            html += '<div class="recent-list-item tuned" onclick="viewDetectionFromHistory(\'' + escapeAttr(t.name) + '\')">';
            html += '<span class="recent-list-name">' + escapeHtml(t.name) + '</span>';
            html += '<span class="recent-list-date">' + formatDateTime(t.timestamp) + '</span>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Render Recent Retrofits
    function renderRecentRetrofits() {
        var container = document.getElementById('list-recent-retrofits');
        if (!container) return;

        var localHistory = JSON.parse(localStorage.getItem('de_mainframe_history') || '{}');
        var retrofits = [];

        Object.keys(localHistory).forEach(function(name) {
            (localHistory[name] || []).filter(function(h) {
                return h.type === 'retrofit';
            }).forEach(function(h) {
                retrofits.push({ name: name, timestamp: h.timestamp, analyst: h.analyst });
            });
        });

        retrofits.sort(function(a, b) {
            return new Date(b.timestamp) - new Date(a.timestamp);
        });

        if (retrofits.length === 0) {
            container.innerHTML = '<div class="recent-list-empty">No recent retrofits</div>';
            return;
        }

        var html = '';
        retrofits.slice(0, 5).forEach(function(r) {
            html += '<div class="recent-list-item retrofitted" onclick="viewDetectionFromHistory(\'' + escapeAttr(r.name) + '\')">';
            html += '<span class="recent-list-name">' + escapeHtml(r.name) + '</span>';
            html += '<span class="recent-list-date">' + formatDateTime(r.timestamp) + '</span>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // =========================================================================
    // SETTINGS VIEW FUNCTIONS
    // =========================================================================

    // Settings Storage Keys
    var SETTINGS_STORAGE_KEY = 'dmf_settings';
    var PARSING_RULES_STORAGE_KEY = 'dmf_parsing_rules';

    // Settings State
    var settingsState = {
        initialized: false,
        settings: {
            github: {
                baseUrl: 'https://api.github.com',
                repo: '',
                branch: 'main',
                token: ''
            },
            splunk: {
                baseUrl: 'https://myorg.splunkcloud.com',
                correlationPath: '/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit'
            }
        },
        parsingRules: [],
        editingRuleId: null
    };

    // Initialize Settings
    function initSettings() {
        loadSettings();
        loadParsingRules();
        renderSettings();
        renderParsingRules();
        settingsState.initialized = true;
    }

    // Load settings from localStorage
    function loadSettings() {
        try {
            var stored = localStorage.getItem(SETTINGS_STORAGE_KEY);
            if (stored) {
                var parsed = JSON.parse(stored);
                settingsState.settings = Object.assign({}, settingsState.settings, parsed);
            }
        } catch (e) {
            console.error('Failed to load settings:', e);
        }
    }

    // Save settings to localStorage
    function saveSettingsToStorage() {
        try {
            localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settingsState.settings));
            return true;
        } catch (e) {
            console.error('Failed to save settings:', e);
            return false;
        }
    }

    // Load parsing rules from localStorage
    function loadParsingRules() {
        try {
            var stored = localStorage.getItem(PARSING_RULES_STORAGE_KEY);
            if (stored) {
                settingsState.parsingRules = JSON.parse(stored);
            } else {
                // Default parsing rules
                settingsState.parsingRules = [
                    {
                        id: 'rule_1',
                        name: 'Extract Index',
                        pattern: 'index\\s*=\\s*["\']?([\\w\\-\\*]+)["\']?',
                        field: 'indexes',
                        enabled: true
                    },
                    {
                        id: 'rule_2',
                        name: 'Extract Sourcetype',
                        pattern: 'sourcetype\\s*=\\s*["\']?([\\w\\-\\:\\.\\*]+)["\']?',
                        field: 'sourcetypes',
                        enabled: true
                    },
                    {
                        id: 'rule_3',
                        name: 'Extract Macro',
                        pattern: '`([\\w_]+(?:\\([^)]*\\))?)`',
                        field: 'macros',
                        enabled: true
                    },
                    {
                        id: 'rule_4',
                        name: 'Extract Lookup',
                        pattern: '\\|\\s*(?:lookup|inputlookup|outputlookup)\\s+([\\w_]+)',
                        field: 'lookups',
                        enabled: true
                    }
                ];
            }
        } catch (e) {
            console.error('Failed to load parsing rules:', e);
            settingsState.parsingRules = [];
        }
    }

    // Save parsing rules to localStorage
    function saveParsingRulesToStorage() {
        try {
            localStorage.setItem(PARSING_RULES_STORAGE_KEY, JSON.stringify(settingsState.parsingRules));
            return true;
        } catch (e) {
            console.error('Failed to save parsing rules:', e);
            return false;
        }
    }

    // Render settings into both view and modal
    function renderSettings() {
        var s = settingsState.settings;

        // View inputs
        setInputValue('setting-github-base-url', s.github.baseUrl);
        setInputValue('setting-github-repo', s.github.repo);
        setInputValue('setting-github-branch', s.github.branch);
        setInputValue('setting-github-token', s.github.token);
        setInputValue('setting-splunk-base-url', s.splunk.baseUrl);
        setInputValue('setting-splunk-correlation-path', s.splunk.correlationPath);

        // Modal inputs
        setInputValue('modal-github-base-url', s.github.baseUrl);
        setInputValue('modal-github-repo', s.github.repo);
        setInputValue('modal-github-branch', s.github.branch);
        setInputValue('modal-github-token', s.github.token);
        setInputValue('modal-splunk-base-url', s.splunk.baseUrl);
        setInputValue('modal-splunk-correlation-path', s.splunk.correlationPath);
    }

    // Helper: Set input value
    function setInputValue(id, value) {
        var el = document.getElementById(id);
        if (el) el.value = value || '';
    }

    // Helper: Get input value
    function getInputValue(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : '';
    }

    // Render parsing rules into both view and modal tables
    function renderParsingRules() {
        var rules = settingsState.parsingRules;

        // View table
        renderParsingRulesTable('parsing-rules-tbody', rules);
        // Modal table
        renderParsingRulesTable('modal-parsing-rules-tbody', rules);
    }

    // Render parsing rules table
    function renderParsingRulesTable(tbodyId, rules) {
        var tbody = document.getElementById(tbodyId);
        if (!tbody) return;

        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="parsing-rules-empty">No parsing rules configured. Add one to customize SPL parsing.</td></tr>';
            return;
        }

        var html = '';
        rules.forEach(function(rule) {
            if (!rule) return; // Skip invalid rules
            var ruleName = rule.name || 'Unnamed';
            var rulePattern = rule.pattern || rule.value || '';
            var ruleField = rule.field || '';
            var displayPattern = rulePattern.length > 30 ? rulePattern.substring(0, 30) + '...' : rulePattern;
            html += '<tr>';
            html += '<td>' + escapeHtml(ruleName) + '</td>';
            html += '<td><code>' + escapeHtml(displayPattern) + '</code></td>';
            html += '<td>' + escapeHtml(ruleField) + '</td>';
            html += '<td><input type="checkbox" ' + (rule.enabled ? 'checked' : '') + ' onchange="toggleParsingRule(\'' + (rule.id || '') + '\', this.checked)"></td>';
            html += '<td class="rule-actions">';
            html += '<button class="btn-icon" onclick="editParsingRule(\'' + (rule.id || '') + '\')" title="Edit">&#x270E;</button>';
            html += '<button class="btn-icon delete" onclick="deleteParsingRule(\'' + (rule.id || '') + '\')" title="Delete">&#x2715;</button>';
            html += '</td>';
            html += '</tr>';
        });

        tbody.innerHTML = html;
    }

    // Open Settings Modal
    window.openSettingsModal = function() {
        renderSettings();
        renderParsingRules();
        var modal = document.getElementById('modal-settings');
        if (modal) modal.classList.remove('hidden');
    };

    // Close Settings Modal
    window.closeSettingsModal = function() {
        var modal = document.getElementById('modal-settings');
        if (modal) modal.classList.add('hidden');
    };

    // Switch Settings Tab
    window.switchSettingsTab = function(tabName) {
        // Update tab buttons
        document.querySelectorAll('.settings-tab').forEach(function(tab) {
            tab.classList.remove('active');
            if (tab.getAttribute('data-settings-tab') === tabName) {
                tab.classList.add('active');
            }
        });

        // Update tab content
        document.querySelectorAll('.settings-tab-content').forEach(function(content) {
            content.classList.remove('active');
        });
        var activeContent = document.getElementById('settings-tab-' + tabName);
        if (activeContent) activeContent.classList.add('active');
    };

    // Collect settings from inputs
    function collectSettingsFromInputs(isModal) {
        var prefix = isModal ? 'modal-' : 'setting-';

        return {
            github: {
                baseUrl: getInputValue(prefix + 'github-base-url') || 'https://api.github.com',
                repo: getInputValue(prefix + 'github-repo'),
                branch: getInputValue(prefix + 'github-branch') || 'main',
                token: getInputValue(prefix + 'github-token')
            },
            splunk: {
                baseUrl: getInputValue(prefix + 'splunk-base-url'),
                correlationPath: getInputValue(prefix + 'splunk-correlation-path')
            }
        };
    }

    // Save All Settings
    window.saveAllSettings = function() {
        // Determine which source to use (view or modal)
        var modal = document.getElementById('modal-settings');
        var isModal = modal && !modal.classList.contains('hidden');

        settingsState.settings = collectSettingsFromInputs(isModal);

        var settingsSaved = saveSettingsToStorage();
        var rulesSaved = saveParsingRulesToStorage();

        // Update Splunk config globally
        if (settingsState.settings.splunk.baseUrl) {
            SPLUNK_CONFIG.baseUrl = settingsState.settings.splunk.baseUrl;
        }
        if (settingsState.settings.splunk.correlationPath) {
            SPLUNK_CONFIG.correlationSearchPath = settingsState.settings.splunk.correlationPath;
        }

        // Re-render to sync both view and modal
        renderSettings();
        renderParsingRules();

        if (settingsSaved && rulesSaved) {
            showToast('Settings saved successfully', 'success');
        } else {
            showToast('Failed to save some settings', 'error');
        }
    };

    // Reset Settings to Defaults
    window.resetSettings = function() {
        if (!confirm('Are you sure you want to reset all settings to defaults?')) return;

        settingsState.settings = {
            github: {
                baseUrl: 'https://api.github.com',
                repo: '',
                branch: 'main',
                token: ''
            },
            splunk: {
                baseUrl: 'https://myorg.splunkcloud.com',
                correlationPath: '/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit'
            }
        };

        settingsState.parsingRules = [
            { id: 'rule_1', name: 'Extract Index', pattern: 'index\\s*=\\s*["\']?([\\w\\-\\*]+)["\']?', field: 'indexes', enabled: true },
            { id: 'rule_2', name: 'Extract Sourcetype', pattern: 'sourcetype\\s*=\\s*["\']?([\\w\\-\\:\\.\\*]+)["\']?', field: 'sourcetypes', enabled: true },
            { id: 'rule_3', name: 'Extract Macro', pattern: '`([\\w_]+(?:\\([^)]*\\))?)`', field: 'macros', enabled: true },
            { id: 'rule_4', name: 'Extract Lookup', pattern: '\\|\\s*(?:lookup|inputlookup|outputlookup)\\s+([\\w_]+)', field: 'lookups', enabled: true }
        ];

        saveSettingsToStorage();
        saveParsingRulesToStorage();
        renderSettings();
        renderParsingRules();
        showToast('Settings reset to defaults', 'success');
    };

    // Test GitHub Connection
    window.testGitHubConnection = function() {
        var modal = document.getElementById('modal-settings');
        var isModal = modal && !modal.classList.contains('hidden');
        var prefix = isModal ? 'modal-' : 'setting-';

        var baseUrl = getInputValue(prefix + 'github-base-url') || 'https://api.github.com';
        var repo = getInputValue(prefix + 'github-repo');
        var token = getInputValue(prefix + 'github-token');

        var statusEl = document.getElementById(prefix + 'github-connection-status');
        if (!statusEl) statusEl = document.getElementById('github-connection-status');

        if (!repo) {
            if (statusEl) {
                statusEl.textContent = 'Repository required';
                statusEl.className = 'connection-status error';
            }
            showToast('Please enter a repository (owner/repo)', 'error');
            return;
        }

        if (statusEl) {
            statusEl.textContent = 'Testing...';
            statusEl.className = 'connection-status testing';
        }

        // Build API URL
        var apiUrl = baseUrl + '/repos/' + repo;

        var headers = {
            'Accept': 'application/vnd.github.v3+json'
        };
        if (token) {
            headers['Authorization'] = 'token ' + token;
        }

        fetch(apiUrl, { headers: headers })
            .then(function(response) {
                if (response.ok) {
                    return response.json();
                } else if (response.status === 401) {
                    throw new Error('Invalid token');
                } else if (response.status === 404) {
                    throw new Error('Repository not found');
                } else {
                    throw new Error('HTTP ' + response.status);
                }
            })
            .then(function(data) {
                if (statusEl) {
                    statusEl.textContent = 'Connected to ' + data.full_name;
                    statusEl.className = 'connection-status success';
                }
                showToast('GitHub connection successful', 'success');
            })
            .catch(function(err) {
                if (statusEl) {
                    statusEl.textContent = err.message;
                    statusEl.className = 'connection-status error';
                }
                showToast('GitHub connection failed: ' + err.message, 'error');
            });
    };

    // Re-parse All Detections
    window.reparseAllDetections = function() {
        var detections = App.state.detections || [];
        if (detections.length === 0) {
            showToast('No detections to re-parse', 'error');
            return;
        }

        // Show progress indicators
        var progressEls = ['reparse-progress', 'modal-reparse-progress'];
        progressEls.forEach(function(id) {
            var el = document.getElementById(id);
            if (el) el.classList.remove('hidden');
        });

        var total = detections.length;
        var processed = 0;

        function updateProgress(count) {
            var percent = Math.round((count / total) * 100);
            ['reparse-progress-fill', 'modal-reparse-progress-fill'].forEach(function(id) {
                var el = document.getElementById(id);
                if (el) el.style.width = percent + '%';
            });
            ['reparse-progress-text', 'modal-reparse-progress-text'].forEach(function(id) {
                var el = document.getElementById(id);
                if (el) el.textContent = percent + '%';
            });
        }

        function processNext() {
            if (processed >= total) {
                // Done
                progressEls.forEach(function(id) {
                    var el = document.getElementById(id);
                    if (el) {
                        setTimeout(function() { el.classList.add('hidden'); }, 1500);
                    }
                });
                showToast('Re-parsed ' + total + ' detections', 'success');
                App.renderLibrary();
                return;
            }

            var d = detections[processed];
            var spl = d['Search String'] || '';
            if (spl) {
                var parsed = parseSPL(spl);
                d['_parsed'] = parsed;

                // Update Required_Data_Sources if not set
                if (!d['Required_Data_Sources'] || d['Required_Data_Sources'] === '') {
                    var sources = parsed.indexes.concat(parsed.sourcetypes);
                    d['Required_Data_Sources'] = sources.join(', ');
                }
            }

            processed++;
            updateProgress(processed);

            // Process in batches to avoid UI freeze
            setTimeout(processNext, 10);
        }

        processNext();
    };

    // Import Detections from JSON File with GitHub sync
    window.handleImportFile = async function(event) {
        var files = event.target.files;
        if (!files || files.length === 0) return;

        // Collect all detections from all files
        var allImportedDetections = [];
        var parseErrors = [];

        // Read all files first
        var filePromises = [];
        for (var i = 0; i < files.length; i++) {
            filePromises.push(new Promise(function(resolve, reject) {
                var file = files[i];
                var reader = new FileReader();
                reader.onload = function(e) {
                    try {
                        var data = JSON.parse(e.target.result);
                        // Handle array or single detection
                        var detections = Array.isArray(data) ? data : [data];
                        resolve({ file: file.name, detections: detections });
                    } catch (err) {
                        resolve({ file: file.name, error: err.message });
                    }
                };
                reader.onerror = function() {
                    resolve({ file: file.name, error: 'Failed to read file' });
                };
                reader.readAsText(file);
            }));
        }

        // Wait for all files to be read
        var results = await Promise.all(filePromises);

        // Process results
        results.forEach(function(result) {
            if (result.error) {
                parseErrors.push(result.file + ': ' + result.error);
            } else if (result.detections) {
                allImportedDetections = allImportedDetections.concat(result.detections);
            }
        });

        if (allImportedDetections.length === 0) {
            var errorMsg = parseErrors.length > 0
                ? 'Failed to parse files: ' + parseErrors.join(', ')
                : 'No detections found in file(s)';
            showToast(errorMsg, 'error');
            event.target.value = '';
            return;
        }

        // Show importing toast
        showToast('Importing ' + allImportedDetections.length + ' detection(s)...', 'info');

        var added = 0;
        var updated = 0;
        var failed = 0;
        var processedDetections = [];

        // Process each detection
        for (var j = 0; j < allImportedDetections.length; j++) {
            var d = allImportedDetections[j];

            if (!d['Detection Name']) {
                failed++;
                continue;
            }

            try {
                // Generate file_name if not present
                if (!d.file_name) {
                    d.file_name = generateFileName(d['Detection Name'], d['Security Domain']);
                }

                // Set timestamps if not present
                var now = new Date().toISOString();
                if (!d['First Created']) {
                    d['First Created'] = now;
                }
                d['Last Modified'] = now;

                // Parse SPL and generate metadata
                var parsed = parseSPL(d['Search String'] || '');
                var metadata = {
                    parsed: parsed,
                    lastParsed: now,
                    detectionName: d['Detection Name']
                };

                // Auto-populate Required_Data_Sources if empty
                if (!d['Required_Data_Sources'] || d['Required_Data_Sources'] === '') {
                    var sources = [];
                    if (parsed.indexes) sources = sources.concat(parsed.indexes);
                    if (parsed.sourcetypes) sources = sources.concat(parsed.sourcetypes);
                    if (parsed.categories) sources = sources.concat(parsed.categories);
                    if (sources.length > 0) {
                        d['Required_Data_Sources'] = sources.join(', ');
                    }
                }

                // Check if detection already exists
                var existingIndex = App.state.detections.findIndex(function(existing) {
                    return existing['Detection Name'] === d['Detection Name'];
                });

                // Save to GitHub if connected
                if (github) {
                    await saveDetectionToGitHub(d);
                    await saveMetadataToGitHub(d['Detection Name'], metadata, d.file_name);
                }

                // Update local state
                if (existingIndex >= 0) {
                    App.state.detections[existingIndex] = d;
                    updated++;
                } else {
                    App.state.detections.push(d);
                    added++;
                }

                // Update metadata cache
                detectionMetadata[d['Detection Name']] = metadata;
                processedDetections.push(d);

            } catch (err) {
                console.error('Failed to import detection:', d['Detection Name'], err);
                failed++;
            }
        }

        // Update compiled files if we have GitHub and processed any detections
        if (github && processedDetections.length > 0) {
            try {
                await updateCompiledFiles(App.state.detections);
            } catch (err) {
                console.error('Failed to update compiled files:', err);
            }
        }

        // Save to localStorage
        saveToLocalStorage();

        // Update UI
        App.state.filteredDetections = App.state.detections.slice();
        App.renderLibrary();
        App.populateFilters();

        // Show result message
        var messages = [];
        if (added > 0) messages.push(added + ' added');
        if (updated > 0) messages.push(updated + ' updated');
        if (failed > 0) messages.push(failed + ' failed');
        if (parseErrors.length > 0) messages.push(parseErrors.length + ' file(s) had parse errors');

        var toastType = failed > 0 || parseErrors.length > 0 ? 'warning' : 'success';
        var syncNote = github ? ' (synced to GitHub)' : ' (local only - GitHub not connected)';
        showToast('Import complete: ' + messages.join(', ') + syncNote, toastType);

        event.target.value = ''; // Reset file input
    };

    // Export All Detections to JSON File
    window.exportAllDetections = function() {
        var detections = App.state.detections || [];
        if (detections.length === 0) {
            showToast('No detections to export', 'error');
            return;
        }

        var json = JSON.stringify(detections, null, 2);
        var blob = new Blob([json], { type: 'application/json' });
        var url = URL.createObjectURL(blob);

        var a = document.createElement('a');
        a.href = url;
        a.download = 'detections_export_' + new Date().toISOString().slice(0, 10) + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast('Exported ' + detections.length + ' detections', 'success');
    };

    // Add Parsing Rule
    window.addParsingRule = function() {
        settingsState.editingRuleId = null;

        var modal = document.getElementById('modal-parsing-rule');
        var title = document.getElementById('parsing-rule-modal-title');
        var nameInput = document.getElementById('parsing-rule-name');
        var patternInput = document.getElementById('parsing-rule-pattern');
        var fieldInput = document.getElementById('parsing-rule-field');
        var enabledInput = document.getElementById('parsing-rule-enabled');
        var editIdInput = document.getElementById('parsing-rule-edit-id');

        if (title) title.textContent = 'Add Parsing Rule';
        if (nameInput) nameInput.value = '';
        if (patternInput) patternInput.value = '';
        if (fieldInput) fieldInput.value = '';
        if (enabledInput) enabledInput.checked = true;
        if (editIdInput) editIdInput.value = '';

        if (modal) modal.classList.remove('hidden');
        if (nameInput) nameInput.focus();
    };

    // Edit Parsing Rule
    window.editParsingRule = function(ruleId) {
        var rule = settingsState.parsingRules.find(function(r) {
            return r.id === ruleId;
        });
        if (!rule) return;

        settingsState.editingRuleId = ruleId;

        var modal = document.getElementById('modal-parsing-rule');
        var title = document.getElementById('parsing-rule-modal-title');
        var nameInput = document.getElementById('parsing-rule-name');
        var patternInput = document.getElementById('parsing-rule-pattern');
        var fieldInput = document.getElementById('parsing-rule-field');
        var enabledInput = document.getElementById('parsing-rule-enabled');
        var editIdInput = document.getElementById('parsing-rule-edit-id');

        if (title) title.textContent = 'Edit Parsing Rule';
        if (nameInput) nameInput.value = rule.name || '';
        if (patternInput) patternInput.value = rule.pattern || '';
        if (fieldInput) fieldInput.value = rule.field || '';
        if (enabledInput) enabledInput.checked = rule.enabled !== false;
        if (editIdInput) editIdInput.value = ruleId;

        if (modal) modal.classList.remove('hidden');
        if (nameInput) nameInput.focus();
    };

    // Close Parsing Rule Modal
    window.closeParsingRuleModal = function() {
        var modal = document.getElementById('modal-parsing-rule');
        if (modal) modal.classList.add('hidden');
        settingsState.editingRuleId = null;
    };

    // Save Parsing Rule
    window.saveParsingRule = function() {
        var nameInput = document.getElementById('parsing-rule-name');
        var patternInput = document.getElementById('parsing-rule-pattern');
        var fieldInput = document.getElementById('parsing-rule-field');
        var enabledInput = document.getElementById('parsing-rule-enabled');
        var editIdInput = document.getElementById('parsing-rule-edit-id');

        var name = nameInput ? nameInput.value.trim() : '';
        var pattern = patternInput ? patternInput.value.trim() : '';
        var field = fieldInput ? fieldInput.value.trim() : '';
        var enabled = enabledInput ? enabledInput.checked : true;
        var editId = editIdInput ? editIdInput.value : '';

        // Validation
        if (!name) {
            alert('Please enter a rule name');
            if (nameInput) nameInput.focus();
            return;
        }
        if (!pattern) {
            alert('Please enter a regex pattern');
            if (patternInput) patternInput.focus();
            return;
        }
        if (!field) {
            alert('Please enter a field name');
            if (fieldInput) fieldInput.focus();
            return;
        }

        // Validate regex
        try {
            new RegExp(pattern, 'gi');
        } catch (e) {
            alert('Invalid regex pattern: ' + e.message);
            if (patternInput) patternInput.focus();
            return;
        }

        if (editId) {
            // Update existing rule
            var index = settingsState.parsingRules.findIndex(function(r) {
                return r.id === editId;
            });
            if (index !== -1) {
                settingsState.parsingRules[index].name = name;
                settingsState.parsingRules[index].pattern = pattern;
                settingsState.parsingRules[index].field = field;
                settingsState.parsingRules[index].enabled = enabled;
            }
        } else {
            // Add new rule
            settingsState.parsingRules.push({
                id: 'rule_' + Date.now(),
                name: name,
                pattern: pattern,
                field: field,
                enabled: enabled
            });
        }

        saveParsingRulesToStorage();
        renderParsingRules();
        closeParsingRuleModal();
        showToast('Parsing rule saved', 'success');
    };

    // Toggle Parsing Rule
    window.toggleParsingRule = function(ruleId, enabled) {
        var rule = settingsState.parsingRules.find(function(r) {
            return r.id === ruleId;
        });
        if (rule) {
            rule.enabled = enabled;
            saveParsingRulesToStorage();
        }
    };

    // Delete Parsing Rule
    window.deleteParsingRule = function(ruleId) {
        if (!confirm('Are you sure you want to delete this parsing rule?')) return;

        settingsState.parsingRules = settingsState.parsingRules.filter(function(r) {
            return r.id !== ruleId;
        });

        saveParsingRulesToStorage();
        renderParsingRules();
        showToast('Parsing rule deleted', 'success');
    };

    // Initialize when DOM is ready - check password first
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            App.checkPassword();
        });
    } else {
        App.checkPassword();
    }

    // Add editor init to App init
    var originalInit = App.init;
    App.init = function() {
        // Initialize GitHub API first (global function)
        initGitHub();

        originalInit.call(this);
        initEditor();
        initMacros();
        initRevalidation();
        initRevalidationTabs();
        initHistory();
        initResources();
        initReports();
        initSettings();
    };

    // Expose App to global scope for debugging and external access
    window.NewUIApp = App;
    window.App = App;  // Also expose as App for functions outside IIFE
})();
