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
            theme: 'light'
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
        }
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
