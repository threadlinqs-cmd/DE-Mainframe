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

            // Sidebar collapse toggle
            var collapseBtn = document.getElementById('sidebar-collapse-btn');
            if (collapseBtn) {
                collapseBtn.addEventListener('click', function() {
                    var sidebar = document.getElementById('library-sidebar');
                    if (sidebar) {
                        sidebar.classList.toggle('collapsed');
                        // Store preference
                        var isCollapsed = sidebar.classList.contains('collapsed');
                        localStorage.setItem('dmf_sidebar_collapsed', isCollapsed ? 'true' : 'false');
                    }
                });
                // Restore collapsed state from preference
                var sidebarCollapsed = localStorage.getItem('dmf_sidebar_collapsed');
                if (sidebarCollapsed === 'true') {
                    var sidebar = document.getElementById('library-sidebar');
                    if (sidebar) sidebar.classList.add('collapsed');
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

        // Load detections from dist folder
        loadDetections: function() {
            var self = this;
            fetch(this.config.distPath + 'all-detections.json')
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
                    // Update revalidation view if initialized
                    if (typeof calculateStatusCounts === 'function') {
                        calculateStatusCounts();
                        filterRevalidation();
                    }
                    // Update history view if initialized
                    if (typeof buildHistoryEntries === 'function') {
                        buildHistoryEntries();
                    }
                    // Update reports view if initialized
                    if (typeof renderReports === 'function') {
                        renderReports();
                    }
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

            // Check if selected detection is still in filtered list (US-005)
            // If not, keep showing the content but remove highlight from list
            // This matches old UI behavior - selected content remains visible
            if (this.state.selectedDetection) {
                var selectedName = this.state.selectedDetection['Detection Name'];
                var stillInList = this.state.filteredDetections.some(function(d) {
                    return d['Detection Name'] === selectedName;
                });
                // Selection is maintained even if filtered out - content stays visible
                // The renderLibrary will not show highlight since detection is not in filteredDetections
            }

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
            this.renderLibrary();
            this.renderDetailPanel(detection);

            // Scroll detail body to top
            var detailBody = document.querySelector('.library-main');
            if (detailBody) detailBody.scrollTop = 0;

            // Scroll the selected item into view in the list (US-004)
            var selectedItem = document.querySelector('.library-list-item.selected');
            if (selectedItem) {
                selectedItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            }
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

            // Drilldowns Section (US-007: Filter out empty drilldowns)
            var drilldowns = this.getDrilldowns(d);
            // Filter out drilldowns with no search content
            var validDrilldowns = drilldowns.filter(function(dd) {
                return dd.name && dd.name.trim();
            });
            if (validDrilldowns.length > 0) {
                html += '<div class="doc-section">';
                html += '<h3 class="doc-section-title">Drilldowns</h3>';
                html += '<div class="doc-drilldowns">';
                validDrilldowns.forEach(function(dd) {
                    html += '<div class="doc-drilldown">';
                    html += '<div class="drilldown-header">';
                    html += '<span class="drilldown-name">' + escapeHtml(dd.name) + '</span>';
                    if (dd.earliest || dd.latest) {
                        html += '<span class="drilldown-time">' + escapeHtml(dd.earliest || '') + ' to ' + escapeHtml(dd.latest || '') + '</span>';
                    }
                    html += '</div>';
                    // Only show search if it has content
                    if (dd.search && dd.search.trim()) {
                        html += '<div class="drilldown-search">' + escapeHtml(dd.search) + '</div>';
                    }
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

            // Populate JSON view
            var jsonView = document.getElementById('detail-json-view');
            if (jsonView) {
                jsonView.innerHTML = '<pre class="json-display">' + escapeHtml(JSON.stringify(d, null, 2)) + '</pre>';
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
        var titleEl = document.getElementById('macro-modal-title');
        var contentEl = document.getElementById('macro-modal-content');

        if (!modal || !titleEl || !contentEl) return;

        // Look up the macro from macrosState
        var macro = null;
        if (typeof macrosState !== 'undefined' && macrosState.macros) {
            macro = macrosState.macros.find(function(m) {
                return m.name === macroName;
            });
        }

        if (!macro) {
            titleEl.innerHTML = '<code>`' + escapeHtml(macroName) + '`</code>';
            contentEl.innerHTML = '<p class="macro-not-found">Macro not found in macros list.</p><p class="macro-hint">This macro is used in the detection\'s search logic but is not defined in the macros configuration.</p>';
        } else {
            titleEl.innerHTML = '<code>`' + escapeHtml(macroName) + '`</code>';

            var html = '<div class="macro-detail-fields">';
            html += '<div class="macro-detail-field"><label>Definition</label>';
            html += '<pre class="macro-definition">' + escapeHtml(macro.definition || 'No definition') + '</pre></div>';
            html += '<div class="macro-detail-field"><label>Description</label>';
            html += '<p>' + escapeHtml(macro.description || 'No description') + '</p></div>';
            if (macro.arguments && macro.arguments.length) {
                html += '<div class="macro-detail-field"><label>Arguments</label>';
                var args = Array.isArray(macro.arguments) ? macro.arguments.join(', ') : macro.arguments;
                html += '<code>' + escapeHtml(args) + '</code></div>';
            }
            if (macro.usageCount !== undefined) {
                html += '<div class="macro-detail-field"><label>Usage</label>';
                html += '<span class="macro-usage-count">' + macro.usageCount + ' detection' + (macro.usageCount !== 1 ? 's' : '') + '</span></div>';
            }
            if (macro.deprecated) {
                html += '<div class="macro-detail-field"><span class="macro-deprecated-badge">Deprecated</span></div>';
            }
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
        loadedMacros: []
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

        // Detection Name auto-populates Notable Title
        var nameField = document.getElementById('field-detection-name');
        if (nameField) {
            nameField.addEventListener('input', function() {
                var notableField = document.getElementById('field-notable-title');
                if (notableField && !notableField.value) {
                    notableField.value = nameField.value;
                }
            });
        }

        // Initialize form with blank detection
        createNewDetection();
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

    // Create New Detection
    window.createNewDetection = function() {
        editorState.currentDetection = JSON.parse(JSON.stringify(DETECTION_TEMPLATE));
        editorState.currentDetection['First Created'] = new Date().toISOString();
        editorState.hasUnsavedChanges = false;
        editorState.drilldownCount = 0;
        loadDetectionIntoForm(editorState.currentDetection);
        validateForm();
        updateSplParsedPreview();
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

        // MITRE IDs
        var mitreVal = '';
        if (Array.isArray(d['Mitre ID'])) {
            mitreVal = d['Mitre ID'].join(', ');
        } else if (d['Mitre ID']) {
            mitreVal = d['Mitre ID'];
        }
        document.getElementById('field-mitre').value = mitreVal;

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
        document.getElementById('field-datasources').value = d['Required_Data_Sources'] || '';
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
    }

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

        // MITRE IDs
        var mitreInput = document.getElementById('field-mitre').value;
        if (mitreInput) {
            d['Mitre ID'] = mitreInput.split(/[,;]/).map(function(s) { return s.trim(); }).filter(Boolean);
        } else {
            d['Mitre ID'] = [];
        }

        // Roles
        d['Roles'] = [
            { Role: 'Requestor', Name: document.getElementById('field-role-requestor-name').value.trim(), Title: document.getElementById('field-role-requestor-title').value.trim() },
            { Role: 'Business Owner', Name: document.getElementById('field-role-business-name').value.trim(), Title: document.getElementById('field-role-business-title').value.trim() },
            { Role: 'Technical Owner', Name: document.getElementById('field-role-technical-name').value.trim(), Title: document.getElementById('field-role-technical-title').value.trim() }
        ];

        // Search Configuration
        d['Search String'] = document.getElementById('field-search-string').value;
        d['Required_Data_Sources'] = document.getElementById('field-datasources').value.trim();
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
        if (!d['Required_Data_Sources']) errors.push('Data Sources is required');
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
                return '<li class="validation-item warning"><span class="macro-link" onclick="goToMacrosTab(\'' + escapeAttr(m) + '\')">`' + escapeHtml(m) + '`</span> - click to check in Macros tab</li>';
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
            parsed.macros.forEach(function(m) { html += '<span class="spl-tag macro">`' + escapeHtml(m) + '`</span>'; });
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

    // Auto-populate Data Sources
    function autoPopulateDataSources() {
        var spl = document.getElementById('field-search-string').value;
        var dsField = document.getElementById('field-datasources');
        if (!dsField) return;

        var parsed = parseSPL(spl);
        var sources = [];

        parsed.indexes.forEach(function(i) {
            if (sources.indexOf(i) === -1) sources.push(i);
        });
        parsed.sourcetypes.forEach(function(s) {
            if (sources.indexOf(s) === -1) sources.push(s);
        });

        // Merge with existing manual entries
        var existing = dsField.value.split(/[,;]/).map(function(s) { return s.trim(); }).filter(Boolean);
        sources.forEach(function(s) {
            if (existing.indexOf(s) === -1) existing.push(s);
        });

        dsField.value = existing.join(', ');
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
    window.saveDetection = function() {
        if (!validateForm()) {
            alert('Please fix validation errors before saving.');
            return;
        }

        var d = getFormData();

        // Show saving status
        App.updateStatus('saving');

        // In a real implementation, this would save to GitHub
        // For now, we'll update the local state
        var existingIndex = App.state.detections.findIndex(function(det) {
            return det['Detection Name'] === d['Detection Name'];
        });

        if (existingIndex >= 0) {
            App.state.detections[existingIndex] = d;
        } else {
            App.state.detections.push(d);
        }

        editorState.currentDetection = d;
        editorState.hasUnsavedChanges = false;

        // Update UI
        App.state.filteredDetections = App.state.detections.slice();
        App.renderLibrary();
        App.updateStatus('connected');

        alert('Detection saved successfully!\n\nNote: In production, this would sync to GitHub.');
    };

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
            .then(function() {
                macrosState.selectedMacro = macro;
                macrosState.isNewMacro = false;
                macrosState.isEditing = false;
                filterMacros();
                renderMacroDetail(macro);
                App.updateStatus('connected');
                showToast('Macro saved successfully', 'success');
            })
            .catch(function(error) {
                console.error('Failed to save macro:', error);
                showToast('Failed to save macro: ' + error.message, 'error');
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
            .then(function() {
                macrosState.selectedMacro = null;
                macrosState.isNewMacro = false;
                document.getElementById('macro-placeholder').classList.remove('hidden');
                document.getElementById('macro-detail-content').classList.add('hidden');
                filterMacros();
                App.updateStatus('connected');
                showToast('Macro deleted', 'success');
            })
            .catch(function(error) {
                console.error('Failed to delete macro:', error);
                showToast('Failed to delete macro: ' + error.message, 'error');
            });
    }

    // Update macros file (GitHub sync)
    function updateMacrosFile() {
        // For now, we'll store locally since GitHub integration would require auth
        // In production, this would use the GitHub API

        return new Promise(function(resolve, reject) {
            try {
                // Store in localStorage as backup
                var macroNames = macrosState.macros.map(function(m) { return m.name; });
                localStorage.setItem('dmf_macros', JSON.stringify(macroNames));

                // Store full macro data
                localStorage.setItem('dmf_macros_full', JSON.stringify(macrosState.macros));

                // Simulate async operation
                setTimeout(function() {
                    resolve();
                }, 100);
            } catch (e) {
                reject(e);
            }
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
            html += '<span class="reval-item-name">' + escapeHtml(name) + '</span>';
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

    // Simple toast notification
    function showToast(message, type) {
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
        dateTo: null
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

        // Sort entries by date (newest first)
        historyState.entries.sort(function(a, b) {
            return b.date - a.date;
        });

        // Calculate type counts
        calculateHistoryTypeCounts();

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

            return true;
        });

        renderHistoryTimeline();
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
                html += '<div class="timeline-entry-meta">';
                html += '<span class="timeline-entry-time">' + timeStr + '</span>';
                html += '<span class="timeline-entry-analyst"><span class="timeline-entry-analyst-icon">👤</span>' + escapeHtml(entry.analyst) + '</span>';
                if (entry.severity) {
                    html += '<span class="timeline-entry-severity"><span class="severity-badge ' + sevClass + '">' + escapeHtml(entry.severity) + '</span></span>';
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
        initialized: false
    };

    // Initialize Reports View
    function initReports() {
        reportsState.initialized = true;
        // Reports will be rendered when data is available
        renderReports();
    }

    // Render Reports View
    function renderReports() {
        if (!reportsState.initialized) return;

        var detections = App.state.detections || [];

        // Render all report sections
        renderStatCards(detections);
        renderRevalidationStatus(detections);
        renderDomainChart(detections);
        renderDatasourceChart(detections);
        renderMitreCoverage(detections);
        renderMetadataStats(detections);
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

    // Render MITRE ATT&CK Coverage
    function renderMitreCoverage(detections) {
        var container = document.getElementById('mitre-coverage-list');
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

        var sortedMitre = Object.keys(mitreCounts).sort(function(a, b) {
            // Sort by technique ID
            return a.localeCompare(b);
        });

        if (countEl) {
            countEl.textContent = sortedMitre.length + ' technique' + (sortedMitre.length !== 1 ? 's' : '') + ' covered';
        }

        if (sortedMitre.length === 0) {
            container.innerHTML = '<div class="chart-empty">No MITRE techniques mapped</div>';
            return;
        }

        var html = '';
        sortedMitre.forEach(function(id) {
            var count = mitreCounts[id];
            html += '<div class="mitre-technique-tag">';
            html += '<span class="mitre-technique-id">' + escapeHtml(id) + '</span>';
            html += '<span class="mitre-technique-count">' + count + '</span>';
            html += '</div>';
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
            html += '<tr>';
            html += '<td>' + escapeHtml(rule.name) + '</td>';
            html += '<td><code>' + escapeHtml(rule.pattern.substring(0, 30) + (rule.pattern.length > 30 ? '...' : '')) + '</code></td>';
            html += '<td>' + escapeHtml(rule.field) + '</td>';
            html += '<td><input type="checkbox" ' + (rule.enabled ? 'checked' : '') + ' onchange="toggleParsingRule(\'' + rule.id + '\', this.checked)"></td>';
            html += '<td class="rule-actions">';
            html += '<button class="btn-icon" onclick="editParsingRule(\'' + rule.id + '\')" title="Edit">&#x270E;</button>';
            html += '<button class="btn-icon delete" onclick="deleteParsingRule(\'' + rule.id + '\')" title="Delete">&#x2715;</button>';
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
        var prefix = isModal ? 'modal-' : '';

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

    // Import Detections from JSON File
    window.handleImportFile = function(event) {
        var file = event.target.files[0];
        if (!file) return;

        var reader = new FileReader();
        reader.onload = function(e) {
            try {
                var data = JSON.parse(e.target.result);

                // Handle array or single detection
                var importedDetections = Array.isArray(data) ? data : [data];

                if (importedDetections.length === 0) {
                    showToast('No detections found in file', 'error');
                    return;
                }

                // Merge with existing detections
                var existingNames = {};
                App.state.detections.forEach(function(d) {
                    existingNames[d['Detection Name']] = true;
                });

                var added = 0;
                var updated = 0;

                importedDetections.forEach(function(d) {
                    if (!d['Detection Name']) return;

                    var existingIndex = App.state.detections.findIndex(function(existing) {
                        return existing['Detection Name'] === d['Detection Name'];
                    });

                    if (existingIndex >= 0) {
                        App.state.detections[existingIndex] = d;
                        updated++;
                    } else {
                        App.state.detections.push(d);
                        added++;
                    }
                });

                App.state.filteredDetections = App.state.detections.slice();
                App.renderLibrary();
                App.populateFilters();

                var message = '';
                if (added > 0) message += added + ' added';
                if (updated > 0) message += (message ? ', ' : '') + updated + ' updated';
                showToast('Import complete: ' + message, 'success');

            } catch (err) {
                showToast('Failed to parse JSON: ' + err.message, 'error');
            }
        };

        reader.readAsText(file);
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
        originalInit.call(this);
        initEditor();
        initMacros();
        initRevalidation();
        initHistory();
        initResources();
        initReports();
        initSettings();
    };

    // Expose App to global scope for debugging
    window.NewUIApp = App;
})();
