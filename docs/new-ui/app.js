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
    correlationSearchPath: '/en-US/app/SplunkEnterpriseSecuritySuite/correlation_search_edit'
};

// Build Correlation Search Editor URL
function buildCorrelationSearchUrl(detectionName) {
    if (!detectionName) return '#';
    var url = SPLUNK_CONFIG.baseUrl + SPLUNK_CONFIG.correlationSearchPath;
    url += '?search=' + encodeURIComponent(detectionName);
    return url;
}

(function() {
    'use strict';

    // Application namespace
    const App = {
        // Configuration
        config: {
            distPath: '../dist/',
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

            // Keyboard shortcuts (1-8 for tabs)
            document.addEventListener('keydown', function(e) {
                // Ignore if user is typing in an input/textarea
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                    return;
                }
                // Check for number keys 1-8
                var key = e.key;
                if (key >= '1' && key <= '8') {
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

            // Library search - real-time filtering
            var searchInput = document.getElementById('library-search-input');
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    self.applyFilters();
                });
            }

            // Library filter dropdowns
            var filterIds = ['filter-severity', 'filter-status', 'filter-domain', 'filter-datasource', 'filter-mitre', 'filter-origin'];
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
                alert('Tune functionality - redirecting to Classic UI');
                window.location.href = '../';
            });

            document.getElementById('btn-detail-retrofit')?.addEventListener('click', function() {
                alert('Retrofit functionality - redirecting to Classic UI');
                window.location.href = '../';
            });

            document.getElementById('btn-detail-metadata')?.addEventListener('click', function() {
                openMetadataModal();
            });

            document.getElementById('btn-detail-edit')?.addEventListener('click', function() {
                alert('Edit functionality - redirecting to Classic UI');
                window.location.href = '../';
            });

            document.getElementById('btn-detail-delete')?.addEventListener('click', function() {
                var d = self.state.selectedDetection;
                if (!d) return;
                var modal = document.getElementById('modal-confirm');
                var msg = document.getElementById('confirm-message');
                if (msg) msg.textContent = 'Are you sure you want to delete "' + d['Detection Name'] + '"?';
                if (modal) modal.classList.remove('hidden');
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

        // Load detections from dist folder
        loadDetections: function() {
            var self = this;
            fetch(this.config.distPath + 'detections.json')
                .then(function(response) {
                    if (!response.ok) throw new Error('Failed to load detections');
                    return response.json();
                })
                .then(function(data) {
                    self.state.detections = data || [];
                    self.state.filteredDetections = self.state.detections.slice();
                    self.updateStatus('connected');
                    self.populateFilters();
                    self.renderLibrary();
                })
                .catch(function(err) {
                    console.error('Failed to load detections:', err);
                    self.updateStatus('disconnected');
                    self.state.detections = [];
                    self.state.filteredDetections = [];
                    self.renderLibrary();
                });
        },

        // Populate dynamic filter dropdowns
        populateFilters: function() {
            var datasources = {};
            var mitreIds = {};

            this.state.detections.forEach(function(d) {
                // Datasources from Required_Data_Sources
                var ds = d['Required_Data_Sources'] || '';
                if (ds) {
                    ds.split(/[,;]/).forEach(function(s) {
                        var trimmed = s.trim();
                        if (trimmed) datasources[trimmed] = true;
                    });
                }
                // MITRE IDs
                var mitre = d['Mitre ID'] || [];
                mitre.forEach(function(m) {
                    mitreIds[m] = true;
                });
            });

            // Populate datasource filter
            var dsSelect = document.getElementById('filter-datasource');
            if (dsSelect) {
                var dsHtml = '<option value="">All Datasources</option>';
                Object.keys(datasources).sort().forEach(function(ds) {
                    dsHtml += '<option value="' + escapeAttr(ds) + '">' + escapeHtml(ds) + '</option>';
                });
                dsSelect.innerHTML = dsHtml;
            }

            // Populate MITRE filter
            var mitreSelect = document.getElementById('filter-mitre');
            if (mitreSelect) {
                var mitreHtml = '<option value="">All MITRE</option>';
                Object.keys(mitreIds).sort().forEach(function(m) {
                    mitreHtml += '<option value="' + escapeAttr(m) + '">' + escapeHtml(m) + '</option>';
                });
                mitreSelect.innerHTML = mitreHtml;
            }
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

            var severity = severityFilter ? severityFilter.value.toLowerCase() : '';
            var status = statusFilter ? statusFilter.value : '';
            var domain = domainFilter ? domainFilter.value.toLowerCase() : '';
            var datasource = datasourceFilter ? datasourceFilter.value : '';
            var mitre = mitreFilter ? mitreFilter.value : '';
            var origin = originFilter ? originFilter.value.toLowerCase() : '';

            var self = this;
            this.state.filteredDetections = this.state.detections.filter(function(d) {
                // Search term
                if (searchTerm) {
                    var name = (d['Detection Name'] || '').toLowerCase();
                    if (name.indexOf(searchTerm) === -1) return false;
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

            this.renderLibrary();
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
                html += '<span class="library-list-item-name">' + escapeHtml(name) + '</span>';
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
            this.renderLibrary();
            this.renderDetailPanel(detection);
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
                var ttlMsg = ttl.days <= 0 ? '⚠️ TTL EXPIRED - Revalidation required' : '⏰ TTL: ' + ttl.days + ' days remaining';
                html += '<div class="ttl-banner ' + ttlClass + '">' + ttlMsg + '</div>';
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
                html += this.createCopyableField('Next Steps', d['Analyst Next Steps'], true);
                html += '</div>';
            }

            // Search Logic
            if (d['Search String']) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Search Logic</h3>';
                html += this.createCopyableField('SPL Query', d['Search String'], true);

                // Parsed metadata
                var parsed = parseSPL(d['Search String']);
                if (parsed.indexes.length || parsed.sourcetypes.length || parsed.macros.length || parsed.lookups.length) {
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
                    if (parsed.macros.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Macros</span><div class="tag-group-items">';
                        parsed.macros.forEach(function(m) { html += '<span class="card-tag macro" onclick="openMacroModal(\'' + escapeAttr(m) + '\')">`' + escapeHtml(m) + '`</span>'; });
                        html += '</div></div>';
                    }
                    if (parsed.lookups.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Lookups</span><div class="tag-group-items">';
                        parsed.lookups.forEach(function(l) { html += '<span class="card-tag">' + escapeHtml(l) + '</span>'; });
                        html += '</div></div>';
                    }
                    if (parsed.functions.length) {
                        html += '<div class="doc-tag-group"><span class="tag-group-label">Functions</span><div class="tag-group-items">';
                        parsed.functions.forEach(function(f) { html += '<span class="card-tag">' + escapeHtml(f) + '</span>'; });
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
            if (d['Cron Schedule'] || d['Trigger Condition']) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Scheduling</h3>';
                html += '<div class="doc-schedule-grid">';
                if (d['Cron Schedule']) html += '<div class="doc-schedule-item"><span class="schedule-label">Cron</span><code>' + escapeHtml(d['Cron Schedule']) + '</code></div>';
                if (d['Schedule Window']) html += '<div class="doc-schedule-item"><span class="schedule-label">Window</span><span>' + escapeHtml(d['Schedule Window']) + '</span></div>';
                if (d['Schedule Priority']) html += '<div class="doc-schedule-item"><span class="schedule-label">Priority</span><span>' + escapeHtml(d['Schedule Priority']) + '</span></div>';
                if (d['Trigger Condition']) html += '<div class="doc-schedule-item full-width"><span class="schedule-label">Trigger</span><code>' + escapeHtml(d['Trigger Condition']) + '</code></div>';
                html += '</div></div>';
            }

            // Drilldowns Section
            var drilldowns = this.getDrilldowns(d);
            if (drilldowns.length > 0) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Drilldowns</h3>';
                html += '<div class="doc-drilldowns">';
                drilldowns.forEach(function(dd) {
                    html += '<div class="doc-drilldown">';
                    html += '<div class="drilldown-header">';
                    html += '<span class="drilldown-name">' + escapeHtml(dd.name) + '</span>';
                    if (dd.earliest || dd.latest) {
                        html += '<span class="drilldown-time">' + escapeHtml(dd.earliest || '') + ' to ' + escapeHtml(dd.latest || '') + '</span>';
                    }
                    html += '</div>';
                    html += '<div class="drilldown-search">' + escapeHtml(dd.search) + '</div>';
                    html += '</div>';
                });
                html += '</div></div>';
            }

            // Timestamps Section
            if (d['First Created'] || d['Last Modified']) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Timestamps</h3>';
                html += '<div class="doc-timestamps">';
                if (d['First Created']) {
                    html += '<div class="doc-timestamp"><span class="timestamp-label">Created</span><span class="timestamp-value">' + formatDate(d['First Created']) + '</span></div>';
                }
                if (d['Last Modified']) {
                    html += '<div class="doc-timestamp"><span class="timestamp-label">Modified</span><span class="timestamp-value">' + formatDate(d['Last Modified']) + '</span></div>';
                }
                html += '</div></div>';
            }

            html += '</div>';

            document.getElementById('library-detail-body').innerHTML = html;
        },

        // Get drilldowns from detection
        getDrilldowns: function(d) {
            var drilldowns = [];

            // Legacy drilldown
            if (d['Drilldown Name (Legacy)']) {
                drilldowns.push({
                    name: d['Drilldown Name (Legacy)'],
                    search: d['Drilldown Search (Legacy)'] || '',
                    earliest: d['Drilldown Earliest Offset (Legacy)'],
                    latest: d['Drilldown Latest Offset (Legacy)']
                });
            }

            // Numbered drilldowns
            for (var i = 1; i <= 15; i++) {
                var name = d['Drilldown Name ' + i];
                if (name) {
                    drilldowns.push({
                        name: name,
                        search: d['Drilldown Search ' + i] || '',
                        earliest: d['Drilldown Earliest ' + i],
                        latest: d['Drilldown Latest ' + i]
                    });
                }
            }

            return drilldowns;
        },

        // Create copyable field
        createCopyableField: function(label, value, isCode) {
            if (!value && value !== 0) return '';
            var escapedValue = escapeHtml(String(value));
            var copyId = this.state.copyableContent.length;
            this.state.copyableContent.push(String(value));

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

    function parseSPL(spl) {
        var result = {
            indexes: [],
            sourcetypes: [],
            eventCodes: [],
            macros: [],
            lookups: [],
            functions: []
        };

        if (!spl) return result;

        // Parse indexes
        var indexRegex = /index\s*=\s*["']?([^\s"'|]+)/gi;
        var match;
        while ((match = indexRegex.exec(spl)) !== null) {
            if (result.indexes.indexOf(match[1]) === -1) {
                result.indexes.push(match[1]);
            }
        }

        // Parse sourcetypes
        var sourcetypeRegex = /sourcetype\s*=\s*["']?([^\s"'|]+)/gi;
        while ((match = sourcetypeRegex.exec(spl)) !== null) {
            if (result.sourcetypes.indexOf(match[1]) === -1) {
                result.sourcetypes.push(match[1]);
            }
        }

        // Parse macros
        var macroRegex = /`([^`(]+)(?:\([^)]*\))?`/g;
        while ((match = macroRegex.exec(spl)) !== null) {
            if (result.macros.indexOf(match[1]) === -1) {
                result.macros.push(match[1]);
            }
        }

        // Parse lookups
        var lookupRegex = /\|\s*(?:lookup|inputlookup|outputlookup)\s+([^\s|]+)/gi;
        while ((match = lookupRegex.exec(spl)) !== null) {
            if (result.lookups.indexOf(match[1]) === -1) {
                result.lookups.push(match[1]);
            }
        }

        // Parse functions (commands after pipes)
        var funcRegex = /\|\s*([a-z_][a-z0-9_]*)/gi;
        while ((match = funcRegex.exec(spl)) !== null) {
            var fn = match[1].toLowerCase();
            if (result.functions.indexOf(fn) === -1 && fn !== 'lookup' && fn !== 'inputlookup' && fn !== 'outputlookup') {
                result.functions.push(fn);
            }
        }

        return result;
    }

    // =========================================================================
    // GLOBAL FUNCTIONS FOR EVENT HANDLERS
    // =========================================================================

    window.selectDetection = function(name) {
        App.selectDetection(name);
    };

    window.copyById = function(id, btn) {
        var text = App.state.copyableContent[id] || '';
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
    };

    window.openMacroModal = function(macroName) {
        var modal = document.getElementById('modal-macro');
        var nameDisplay = document.getElementById('macro-name-display');
        if (modal && nameDisplay) {
            nameDisplay.textContent = '`' + macroName + '`';
            modal.classList.remove('hidden');
        }
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

        var modal = document.getElementById('modal-metadata');
        var titleEl = document.getElementById('metadata-detection-name');
        var formattedEl = document.getElementById('metadata-formatted');
        var jsonEl = document.getElementById('metadata-json-content');

        if (titleEl) titleEl.textContent = d['Detection Name'] || 'Unnamed';
        if (jsonEl) jsonEl.textContent = JSON.stringify(d, null, 2);

        // Build formatted view
        if (formattedEl) {
            var html = '';
            Object.keys(d).forEach(function(key) {
                var val = d[key];
                if (val !== null && val !== undefined && val !== '') {
                    html += '<div style="margin-bottom:8px;"><strong>' + escapeHtml(key) + ':</strong> ';
                    if (typeof val === 'object') {
                        html += '<pre style="margin:4px 0;font-size:11px;">' + escapeHtml(JSON.stringify(val, null, 2)) + '</pre>';
                    } else {
                        html += escapeHtml(String(val));
                    }
                    html += '</div>';
                }
            });
            formattedEl.innerHTML = html;
        }

        if (modal) modal.classList.remove('hidden');
    };

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
        if (!d) return;
        navigator.clipboard.writeText(JSON.stringify(d, null, 2)).then(function() {
            alert('JSON copied to clipboard');
        }).catch(function(err) {
            console.error('Failed to copy:', err);
        });
    };

    window.closeConfirmModal = function() {
        var modal = document.getElementById('modal-confirm');
        if (modal) modal.classList.add('hidden');
    };

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

    // Initialize when DOM is ready - check password first
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            App.checkPassword();
        });
    } else {
        App.checkPassword();
    }

    // Expose App to global scope for debugging
    window.NewUIApp = App;
})();
