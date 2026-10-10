/*
 * luci-app-guardian-onyx - Modern OpenWrt Unified Security & Threat Management
 * Manages AdGuard Home, Firewall rules, and Connected Client Monitoring.
 * Crafted with Onyx Theme Design System.
 */
'use strict';
'require view';
'require fs';
'require poll';
'require ui';
'require uci';

var ACTION_SCRIPT = '/usr/libexec/guardian-action.sh';

// Helper: Safely parse JSON strings
function safeJson(str, fallback) {
    if (!str || typeof str !== 'string') return fallback;
    try {
        var trimmed = str.trim();
        if (trimmed.indexOf('{') === 0 || trimmed.indexOf('[') === 0) {
            return JSON.parse(trimmed);
        }
    } catch (e) {}
    return fallback;
}

// Helper: Format numbers with comma separation
function fmtNum(n) {
    if (n === null || n === undefined || isNaN(n)) return '0';
    return Number(n).toLocaleString();
}

// Helper: Format percentage
function fmtPct(num, total) {
    if (!total || total <= 0) return '0.0%';
    return ((num / total) * 100).toFixed(1) + '%';
}

// Helper: Format ISO timestamp or epoch seconds
function fmtTime(val) {
    if (!val) return '--:--:--';
    try {
        var d = null;
        if (typeof val === 'number') {
            d = new Date(val * 1000);
        } else if (typeof val === 'string') {
            d = new Date(val);
        }
        if (d && !isNaN(d.getTime())) {
            return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
    } catch (e) {}
    return String(val);
}

// Helper: Relative time formatter
function fmtRelative(val) {
    if (!val) return _('Unknown');
    try {
        var d = (typeof val === 'number') ? new Date(val * 1000) : new Date(val);
        if (d && !isNaN(d.getTime())) {
            var diff = Math.floor((Date.now() - d.getTime()) / 1000);
            if (diff < 60) return diff + 's ' + _('ago');
            if (diff < 3600) return Math.floor(diff / 60) + 'm ' + _('ago');
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ' + _('ago');
            return Math.floor(diff / 86400) + 'd ' + _('ago');
        }
    } catch (e) {}
    return String(val);
}

// Helper: SVG Icon Creator
function svgIcon(name, size, color) {
    var s = size || 16;
    var c = color || 'currentColor';
    var paths = {
        shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        fire: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><circle cx="9" cy="7" r="4" fill="none" stroke="' + c + '" stroke-width="2"/><path d="M23 21v-2a4 4 0 0 0-3-3.87" fill="none" stroke="' + c + '" stroke-width="2"/><path d="M16 3.13a4 4 0 0 1 0 7.75" fill="none" stroke="' + c + '" stroke-width="2"/>',
        threat: '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" fill="none" stroke="' + c + '" stroke-width="2"/><line x1="12" y1="8" x2="12" y2="12" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><line x1="12" y1="16" x2="12.01" y2="16" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/>',
        refresh: '<polyline points="23 4 23 10 17 10" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="1 20 1 14 7 14" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><line x1="12" y1="2" x2="12" y2="12" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/>',
        external: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><polyline points="15 3 21 3 21 9" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="10" y1="14" x2="21" y2="3" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/>',
        search: '<circle cx="11" cy="11" r="8" fill="none" stroke="' + c + '" stroke-width="2"/><line x1="21" y1="21" x2="16.65" y2="16.65" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/>',
        check: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><polyline points="22 4 12 14.01 9 11.01" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        cross: '<circle cx="12" cy="12" r="10" fill="none" stroke="' + c + '" stroke-width="2"/><line x1="15" y1="9" x2="9" y2="15" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><line x1="9" y1="9" x2="15" y2="15" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/>',
        filter: '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        network: '<rect x="2" y="2" width="20" height="8" rx="2" ry="2" fill="none" stroke="' + c + '" stroke-width="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2" fill="none" stroke="' + c + '" stroke-width="2"/><line x1="6" y1="6" x2="6.01" y2="6" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/><line x1="6" y1="18" x2="6.01" y2="18" stroke="' + c + '" stroke-width="2" stroke-linecap="round"/>',
        settings: '<circle cx="12" cy="12" r="3" fill="none" stroke="' + c + '" stroke-width="2"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        pulse: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12" fill="none" stroke="' + c + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
    };
    var inner = paths[name] || paths['shield'];
    var span = document.createElement('span');
    span.style.display = 'inline-flex';
    span.style.alignItems = 'center';
    span.style.justifyContent = 'center';
    span.style.lineHeight = '1';
    span.style.verticalAlign = 'middle';
    span.innerHTML = '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24">' + inner + '</svg>';
    return span;
}

// Client risk assessment
function assessClientRisk(client) {
    var hostname = (client.hostname || '').trim();
    var mac = (client.mac || '').toLowerCase().trim();
    var isUnknown = (!hostname || hostname === '*' || hostname === 'Unknown' || hostname === 'unknown');

    var isMulticastOrBroad = (mac.indexOf('ff:') === 0 || mac.indexOf('01:00:5e') === 0 || mac.indexOf('33:33') === 0);
    var isZeroMac = (mac === '00:00:00:00:00:00');

    if (isZeroMac || isMulticastOrBroad) {
        return {
            level: 'danger',
            color: '#ef4444',
            badgeClass: 'gn-pill-danger',
            label: _('Suspicious'),
            reason: _('Invalid or broadcast MAC')
        };
    }

    if (isUnknown) {
        return {
            level: 'warning',
            color: '#f59e0b',
            badgeClass: 'gn-pill-warning',
            label: _('Unregistered'),
            reason: _('No DHCP hostname record')
        };
    }

    return {
        level: 'success',
        color: '#10b981',
        badgeClass: 'gn-pill-success',
        label: _('Verified'),
        reason: _('Known DHCP lease')
    };
}

return view.extend({
    activeTab: 'adguard',
    pollTimer: null,
    statusData: {},
    firewallZones: [],
    firewallRules: null,
    connectedClients: [],
    conntrackCount: 0,
    uciGuardian: {},
    uciFirewall: {},
    clientSearchTerm: '',
    isTogglingProtection: false,
    isReloadingFirewall: false,
    isScanningClients: false,
    isTestingConnection: false,
    isSavingSettings: false,

    load: function() {
        return Promise.all([
            L.resolveDefault(fs.exec(ACTION_SCRIPT, ['status']), null),
            L.resolveDefault(fs.exec(ACTION_SCRIPT, ['adguard_stats']), null),
            L.resolveDefault(fs.exec(ACTION_SCRIPT, ['firewall_zones']), null),
            L.resolveDefault(fs.exec(ACTION_SCRIPT, ['clients']), null),
            L.resolveDefault(fs.read('/proc/sys/net/netfilter/nf_conntrack_count'), null),
            uci.load('guardian').catch(function() { return {}; }),
            uci.load('firewall').catch(function() { return {}; })
        ]);
    },

    detectThemeIsDark: function() {
        try {
            var dt = document.documentElement.getAttribute('data-theme');
            if (dt === 'dark') return true;
            if (dt === 'light') return false;

            var body = document.body || {};
            var html = document.documentElement || {};
            var classList = ((body.className || '') + ' ' + (html.className || '')).toLowerCase();
            if (classList.indexOf('theme-light') !== -1 || classList.indexOf('light-mode') !== -1 || (body.classList && body.classList.contains('light'))) return false;
            if (classList.indexOf('theme-dark') !== -1 || classList.indexOf('dark-mode') !== -1 || (body.classList && body.classList.contains('dark'))) return true;

            var links = document.querySelectorAll('link[rel="stylesheet"]');
            for (var i = 0; i < links.length; i++) {
                var href = (links[i].getAttribute('href') || '').toLowerCase();
                if (href.indexOf('bootstrap-dark') !== -1 || href.indexOf('dark.css') !== -1) return true;
                if (href.indexOf('bootstrap-light') !== -1) return false;
            }

            var candidates = [body, html, document.getElementById('maincontent'), document.querySelector('main')];
            for (var j = 0; j < candidates.length; j++) {
                if (!candidates[j]) continue;
                var bg = window.getComputedStyle(candidates[j]).backgroundColor;
                var m = bg.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d\.]+))?\)/);
                if (m) {
                    var a = (m[4] !== undefined) ? parseFloat(m[4]) : 1;
                    if (a > 0.15) {
                        var lum = (0.299 * (+m[1]) + 0.587 * (+m[2]) + 0.114 * (+m[3]));
                        return (lum < 140);
                    }
                }
            }
            return false;
        } catch(e) {
            return false;
        }
    },

    // Refresh Data in Background (Every 10s)
    refreshData: function() {
        var self = this;
        return Promise.all([
            L.resolveDefault(fs.exec(ACTION_SCRIPT, ['status']), null),
            L.resolveDefault(fs.exec(ACTION_SCRIPT, ['adguard_stats']), null)
        ]).then(function(results) {
            if (results[0] && results[0].stdout) {
                self.statusData = safeJson(results[0].stdout, self.statusData);
            }
            if (results[1] && results[1].stdout) {
                self.adguardStatsDirect = safeJson(results[1].stdout, {});
                if (self.statusData && self.statusData.adguard) {
                    if (!self.statusData.adguard.stats || !self.statusData.adguard.stats.num_dns_queries) {
                        self.statusData.adguard.stats = self.adguardStatsDirect;
                    }
                }
            }
            if (self.activeTab === 'adguard') {
                var agPane = document.getElementById('gn-pane-adguard');
                if (agPane) {
                    self.renderAdGuardPane(agPane);
                }
            }
        }).catch(function() {});
    },

    // Action: Toggle AdGuard Protection
    handleToggleProtection: function(btnEl) {
        var self = this;
        if (self.isTogglingProtection) return;
        self.isTogglingProtection = true;
        if (btnEl) {
            btnEl.disabled = true;
            btnEl.innerHTML = '<span>⏳</span> ' + _('Updating...');
        }

        fs.exec(ACTION_SCRIPT, ['adguard_toggle']).then(function(res) {
            var raw = res && res.stdout ? res.stdout.trim() : '';
            var json = safeJson(raw, {});
            if (json.protection_enabled !== undefined && self.statusData && self.statusData.adguard) {
                self.statusData.adguard.protection_enabled = json.protection_enabled;
            }
            var isProt = (json.protection_enabled === true);
            var notice = isProt ? _('AdGuard Protection STARTED. Filtering is now active.') :
                                  _('AdGuard Protection PAUSED. All filtering is now stopped.');
            ui.addNotification(null, E('p', {}, notice), 3500);
            var agPane = document.getElementById('gn-pane-adguard');
            if (agPane) {
                self.renderAdGuardPane(agPane);
            }
            return self.refreshData();
        }).catch(function(err) {
            ui.addNotification(null, E('p', {}, _('Failed to toggle AdGuard protection: ') + (err.message || err)), 4000);
        }).finally(function() {
            self.isTogglingProtection = false;
            if (btnEl) btnEl.disabled = false;
        });
    },

    // Action: Reload Firewall
    handleReloadFirewall: function(btnEl) {
        var self = this;
        if (self.isReloadingFirewall) return;
        self.isReloadingFirewall = true;
        if (btnEl) {
            btnEl.disabled = true;
            btnEl.innerHTML = '<span>?</span> ' + _('Reloading...');
        }

        var reloadPromise = fs.exec(ACTION_SCRIPT, ['firewall_reload']).catch(function() {
            return fs.exec('/sbin/fw4', ['reload']);
        }).catch(function() {
            return fs.exec('/sbin/fw3', ['reload']);
        }).catch(function() {
            return fs.exec('/etc/init.d/firewall', ['reload']);
        });

        reloadPromise.then(function() {
            ui.addNotification(null, E('p', {}, _('Firewall rules reloaded successfully.')), 3500);
            return Promise.all([
                L.resolveDefault(fs.exec(ACTION_SCRIPT, ['firewall_zones']), null),
                L.resolveDefault(fs.read('/proc/sys/net/netfilter/nf_conntrack_count'), null)
            ]);
        }).then(function(results) {
            if (results[0] && results[0].stdout) {
                self.firewallZones = safeJson(results[0].stdout, self.firewallZones);
            }
            if (results[1]) {
                self.conntrackCount = parseInt(results[1].trim(), 10) || 0;
            }
            var fwPane = document.getElementById('gn-pane-firewall');
            if (fwPane) self.renderFirewallPane(fwPane);
        }).catch(function(err) {
            ui.addNotification(null, E('p', {}, _('Failed to reload firewall: ') + (err.message || err)), 4000);
        }).finally(function() {
            self.isReloadingFirewall = false;
            if (btnEl) {
                btnEl.disabled = false;
                btnEl.innerHTML = '';
                btnEl.appendChild(svgIcon('refresh', 14));
                btnEl.appendChild(document.createTextNode(' ' + _('Reload Firewall')));
            }
        });
    },

    // Action: Scan ARP / Clients
    handleScanClients: function(btnEl, container) {
        var self = this;
        if (self.isScanningClients) return;
        self.isScanningClients = true;
        if (btnEl) {
            btnEl.disabled = true;
            btnEl.innerHTML = '<span>?</span> ' + _('Scanning...');
        }

        fs.exec(ACTION_SCRIPT, ['clients']).then(function(res) {
            if (res && res.stdout) {
                self.connectedClients = safeJson(res.stdout, []);
            }
            ui.addNotification(null, E('p', {}, _('Client network scan complete.')), 3000);
            if (container) {
                self.renderClientsPane(container);
            }
        }).catch(function(err) {
            ui.addNotification(null, E('p', {}, _('Client scan failed: ') + (err.message || err)), 4000);
        }).finally(function() {
            self.isScanningClients = false;
            if (btnEl) {
                btnEl.disabled = false;
                btnEl.innerHTML = '';
                btnEl.appendChild(svgIcon('search', 14));
                btnEl.appendChild(document.createTextNode(' ' + _('Scan Now')));
            }
        });
    },

    // =========================================================================
    // TAB 1: ADGUARD HOME RENDERER
    // =========================================================================
    renderAdGuardPane: function(container) {
        var self = this;
        container.innerHTML = '';

        var ag = (self.statusData && self.statusData.adguard) || {};
        var agStats = (ag.stats && Object.keys(ag.stats).length > 0) ? ag.stats : (self.adguardStatsDirect || {});
        var isOnline = (ag.status === 'online') ||
                       (agStats && agStats.num_dns_queries !== undefined && agStats.num_dns_queries > 0);
        var isProtEnabled = (ag.protection_enabled !== false && ag.protection_enabled !== 'false' && ag.protection_enabled !== 0);

        // Dynamically compute AdGuard endpoint from Settings (UCI)
        var uciHost = (uci.get('guardian', 'main', 'adguard_host') || '').trim();
        var uciPort = (uci.get('guardian', 'main', 'adguard_port') || '').trim();
        var host = uciHost || ag.host || window.location.hostname || '192.168.1.1';
        var port = uciPort || ag.port || 8080;
        var version = (ag.version && ag.version !== 'N/A') ? ag.version : ((isOnline && ag.version) ? ag.version : 'Running');
        var agDisplayHost = (host === '127.0.0.1' || host === 'localhost') ? (window.location.hostname || '192.168.1.1') : host;
        var agUrl = 'http://' + agDisplayHost + ':' + port;

        var dnsTotal = agStats.num_dns_queries || 0;
        var dnsBlocked = agStats.num_blocked_filtering || 0;
        var safeBrowsingBlocked = agStats.num_replaced_safebrowsing || 0;
        var parentalBlocked = agStats.num_replaced_parental || 0;
        var avgLatencyMs = agStats.avg_processing_time ? (agStats.avg_processing_time * 1000).toFixed(1) : '--';

        // Toggle Protection Button (Start / Pause)
        var toggleProtBtn = E('button', {
            'class': 'gn-btn ' + (!isOnline ? 'gn-btn-sec' : (isProtEnabled ? 'gn-btn-warning' : 'gn-btn-success')),
            'style': 'display:inline-flex;align-items:center;gap:6px;',
            'disabled': !isOnline ? true : null
        }, [
            svgIcon('power', 14),
            E('span', {}, (!isOnline ? _('Service Offline') : (isProtEnabled ? _('Pause Protection') : _('Start Protection'))))
        ]);
        toggleProtBtn.addEventListener('click', function() { self.handleToggleProtection(toggleProtBtn); });

        // Connection Banner Card
        var banner = E('div', { 'class': 'gn-card gn-banner-card', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'style': 'display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;' }, [
                E('div', { 'style': 'display:flex;align-items:center;gap:14px;' }, [
                    E('div', { 'class': 'gn-icon-box' }, svgIcon('shield', 26, !isOnline ? '#ef4444' : (isProtEnabled ? '#10b981' : '#f59e0b'))),
                    E('div', {}, [
                        E('div', { 'style': 'display:flex;align-items:center;gap:10px;' }, [
                            E('h3', { 'style': 'margin:0;font-size:17px;font-weight:700;color:var(--gn-text-main);' }, _('AdGuard Home Core Engine')),
                            E('span', { 'class': 'gn-pill ' + (!isOnline ? 'gn-pill-danger' : (isProtEnabled ? 'gn-pill-success' : 'gn-pill-warning')) }, [
                                E('span', { 'class': 'gn-pulse-dot ' + (!isOnline ? 'gn-dot-red' : (isProtEnabled ? 'gn-dot-green' : 'gn-dot-amber')) }),
                                !isOnline ? _('Disconnected') : (isProtEnabled ? _('Connected & Active') : _('Protection Paused'))
                            ])
                        ]),
                        E('div', { 'style': 'font-size:12px;color:var(--gn-text-muted);margin-top:4px;display:flex;gap:14px;flex-wrap:wrap;' }, [
                            E('span', {}, _('Host: ') + agDisplayHost + ':' + port),
                            E('span', {}, _('Version: ') + version),
                            E('span', {}, _('Status: ') + (!isOnline ? _('Service Unreachable') : (isProtEnabled ? _('Active DNS Filter') : _('Filtering Paused (Bypass Mode)'))))
                        ])
                    ])
                ]),
                E('div', { 'style': 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;' }, [
                    E('a', {
                        'href': agUrl,
                        'target': '_blank',
                        'class': 'gn-btn gn-btn-sec',
                        'style': 'text-decoration:none;display:inline-flex;align-items:center;gap:6px;'
                    }, [
                        svgIcon('external', 14),
                        E('span', {}, _('Open AdGuard UI ↗'))
                    ]),
                    toggleProtBtn,
                    E('button', {
                        'class': 'gn-btn gn-btn-sec',
                        'click': function() { self.switchTab('settings'); }
                    }, [
                        svgIcon('settings', 14),
                        document.createTextNode(' ' + _('Settings'))
                    ])
                ])
            ])
        ]);

        // Key Metric Cards (5 Cards)
        var metricGrid = E('div', { 'class': 'gn-kpi-grid', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('DNS Queries (24h)')),
                E('div', { 'class': 'gn-stat-num' }, fmtNum(dnsTotal)),
                E('div', { 'class': 'gn-stat-sub' }, _('Total requests handled'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Blocked by Filters')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#ef4444;' }, fmtNum(dnsBlocked)),
                E('div', { 'class': 'gn-stat-sub' }, fmtPct(dnsBlocked, dnsTotal) + _(' filter rate'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Malware / Phishing')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#f59e0b;' }, fmtNum(safeBrowsingBlocked)),
                E('div', { 'class': 'gn-stat-sub' }, _('Safe Browsing hits'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Parental Blocks')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#a855f7;' }, fmtNum(parentalBlocked)),
                E('div', { 'class': 'gn-stat-sub' }, _('Adult content stopped'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Average Latency')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#10b981;' }, avgLatencyMs + ' ms'),
                E('div', { 'class': 'gn-stat-sub' }, _('Upstream query speed'))
            ])
        ]);

        // Live DNS Query Log Direct Link Card
        var queryLogAllUrl = agUrl + '/#logs?response_status=all';
        var queryLogBlockedUrl = agUrl + '/#logs?response_status=filtered';
        var queryLogAllowedUrl = agUrl + '/#logs?response_status=not_filtered';

        var queryLogCard = E('div', { 'class': 'gn-card' }, [
            E('div', { 'class': 'gn-card-header', 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;' }, [
                E('div', { 'class': 'gn-card-title' }, [
                    svgIcon('search', 16, '#6366f1'),
                    E('span', {}, _('Live DNS Query Inspector & Logs'))
                ]),
                E('a', {
                    'href': queryLogAllUrl,
                    'target': '_blank',
                    'class': 'gn-btn gn-btn-primary gn-btn-sm',
                    'style': 'text-decoration:none;display:inline-flex;align-items:center;gap:6px;'
                }, [
                    svgIcon('external', 13),
                    E('span', {}, _('Open Live Logs ↗'))
                ])
            ]),
            E('div', { 'style': 'padding:22px;display:flex;flex-direction:column;gap:18px;' }, [
                E('div', { 'style': 'display:flex;align-items:flex-start;gap:14px;' }, [
                    E('div', { 'class': 'gn-icon-box', 'style': 'background:rgba(99,102,241,0.1);color:#6366f1;flex-shrink:0;' }, svgIcon('search', 22, '#6366f1')),
                    E('div', {}, [
                        E('div', { 'style': 'font-size:14px;font-weight:700;color:var(--gn-text-main);margin-bottom:5px;' },
                            _('Native AdGuard Home Live Query Inspector')
                        ),
                        E('div', { 'style': 'font-size:12px;color:var(--gn-text-muted);line-height:1.6;' },
                            _('Inspect real-time DNS queries, DNSSEC validations, protocol types, client devices, and individual rule triggers with instant unblock and block controls directly in AdGuard Home.')
                        )
                    ])
                ]),
                E('div', { 'style': 'display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding-top:4px;' }, [
                    E('a', {
                        'href': queryLogAllUrl,
                        'target': '_blank',
                        'class': 'gn-btn gn-btn-primary',
                        'style': 'text-decoration:none;display:inline-flex;align-items:center;gap:8px;'
                    }, [
                        svgIcon('search', 14),
                        E('span', {}, _('Check All Live Queries ↗'))
                    ]),
                    E('a', {
                        'href': queryLogBlockedUrl,
                        'target': '_blank',
                        'class': 'gn-btn gn-btn-danger',
                        'style': 'text-decoration:none;display:inline-flex;align-items:center;gap:8px;'
                    }, [
                        svgIcon('cross', 14, '#ffffff'),
                        E('span', {}, _('Check Blocked Queries Only ↗'))
                    ]),
                    E('a', {
                        'href': queryLogAllowedUrl,
                        'target': '_blank',
                        'class': 'gn-btn gn-btn-sec',
                        'style': 'text-decoration:none;display:inline-flex;align-items:center;gap:8px;'
                    }, [
                        svgIcon('check', 14, '#10b981'),
                        E('span', {}, _('Check Allowed Queries ↗'))
                    ])
                ]),
                E('div', { 'style': 'display:flex;align-items:center;gap:10px;font-size:12px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);border-radius:8px;padding:10px 14px;' }, [
                    E('span', { 'style': 'font-weight:600;color:var(--gn-text-muted);' }, _('Direct URL:')),
                    E('a', {
                        'href': queryLogAllUrl,
                        'target': '_blank',
                        'style': 'color:#6366f1;text-decoration:none;font-family:monospace;word-break:break-all;'
                    }, queryLogAllUrl)
                ])
            ])
        ]);

        container.appendChild(banner);
        container.appendChild(metricGrid);
        container.appendChild(queryLogCard);
    },

    renderFirewallPane: function(container) {
        var self = this;
        container.innerHTML = '';

        var fw = (self.statusData && self.statusData.firewall) || {};
        var isRunning = (fw.running === 1 || fw.running === true);
        var zones = self.firewallZones || [];
        var redirects = (uci.sections('firewall', 'redirect') || []);
        var conntrackSessions = self.conntrackCount || 0;

        // Top Control Header
        var btnReloadFw = E('button', {
            'class': 'gn-btn gn-btn-danger',
            'style': 'display:inline-flex;align-items:center;gap:8px;'
        }, [
            svgIcon('refresh', 14),
            E('span', {}, _('Reload Firewall'))
        ]);
        btnReloadFw.addEventListener('click', function() { self.handleReloadFirewall(btnReloadFw); });

        var topCard = E('div', { 'class': 'gn-card gn-card-glow-amber', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;' }, [
                E('div', { 'style': 'display:flex;align-items:center;gap:14px;' }, [
                    E('div', { 'class': 'gn-icon-box' }, svgIcon('fire', 26, '#f59e0b')),
                    E('div', {}, [
                        E('div', { 'style': 'display:flex;align-items:center;gap:10px;' }, [
                            E('h3', { 'style': 'margin:0;font-size:17px;font-weight:700;color:var(--gn-text-main);' }, _('OpenWrt Firewall Engine')),
                            E('span', { 'class': 'gn-pill ' + (isRunning ? 'gn-pill-success' : 'gn-pill-danger') }, [
                                E('span', { 'class': 'gn-pulse-dot ' + (isRunning ? 'gn-dot-green' : 'gn-dot-red') }),
                                isRunning ? _('Active & Filtering') : _('Stopped')
                            ])
                        ]),
                        E('div', { 'style': 'font-size:12px;color:var(--gn-text-muted);margin-top:4px;display:flex;gap:16px;' }, [
                            E('span', {}, _('Engine: ') + 'nftables (fw4) / iptables'),
                            E('span', {}, _('Conntrack Sessions: ') + fmtNum(conntrackSessions))
                        ])
                    ])
                ]),
                E('div', { 'style': 'display:flex;gap:10px;align-items:center;' }, [
                    E('div', { 'class': 'gn-badge gn-badge-accent' }, [
                        svgIcon('pulse', 13, '#6366f1'),
                        E('span', {}, fmtNum(conntrackSessions) + ' ' + _('Active Conntracks'))
                    ]),
                    btnReloadFw
                ])
            ])
        ]);

        // Firewall Zones Table Card
        var zonesTable = E('table', { 'class': 'gn-table' }, [
            E('thead', {}, [
                E('tr', {}, [
                    E('th', {}, _('Zone Name')),
                    E('th', {}, _('Input Policy')),
                    E('th', {}, _('Output Policy')),
                    E('th', {}, _('Forward Policy')),
                    E('th', {}, _('Protection Level'))
                ])
            ]),
            E('tbody', {}, (zones.length > 0 ? zones : [
                { name: 'lan', input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT' },
                { name: 'wan', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' }
            ]).map(function(z) {
                var getPolicyBadge = function(policy) {
                    var p = (policy || 'DROP').toUpperCase();
                    if (p === 'ACCEPT') return E('span', { 'class': 'gn-pill gn-pill-success' }, 'ACCEPT');
                    if (p === 'DROP') return E('span', { 'class': 'gn-pill gn-pill-danger' }, 'DROP');
                    if (p === 'REJECT') return E('span', { 'class': 'gn-pill gn-pill-warning' }, 'REJECT');
                    return E('span', { 'class': 'gn-pill' }, p);
                };

                return E('tr', {}, [
                    E('td', { 'style': 'font-weight:700;color:var(--gn-text-main);' }, [
                        E('span', { 'style': 'display:inline-flex;align-items:center;gap:6px;' }, [
                            svgIcon('network', 14, '#6366f1'),
                            z.name
                        ])
                    ]),
                    E('td', {}, getPolicyBadge(z.input)),
                    E('td', {}, getPolicyBadge(z.output)),
                    E('td', {}, getPolicyBadge(z.forward)),
                    E('td', {}, [
                        E('span', { 'class': 'gn-pill ' + (z.name === 'wan' ? 'gn-pill-warning' : 'gn-pill-info') },
                            z.name === 'wan' ? _('Hardened Gateway') : _('Internal Trusted')
                        )
                    ])
                ]);
            }))
        ]);

        var zonesCard = E('div', { 'class': 'gn-card', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'class': 'gn-card-header' }, [
                E('div', { 'class': 'gn-card-title' }, [
                    svgIcon('fire', 16, '#f59e0b'),
                    E('span', {}, _('Firewall Security Zones & Traffic Policies'))
                ])
            ]),
            E('div', { 'class': 'gn-table-container' }, [zonesTable])
        ]);

        // Port Forwards / NAT Redirection Rules Table Card
        var portForwardsTable = E('table', { 'class': 'gn-table' }, [
            E('thead', {}, [
                E('tr', {}, [
                    E('th', {}, _('Rule Name')),
                    E('th', {}, _('Protocol')),
                    E('th', {}, _('External Source')),
                    E('th', {}, _('Internal Destination')),
                    E('th', {}, _('Status'))
                ])
            ]),
            E('tbody', {}, (redirects.length > 0 ? redirects.map(function(r, idx) {
                var isEnabled = (r.enabled !== '0');
                var srcPort = r.src_dport || r.src_port || '*';
                var destIp = r.dest_ip || '127.0.0.1';
                var destPort = r.dest_port || srcPort;
                var proto = (r.proto || 'tcp udp').toUpperCase();

                return E('tr', {}, [
                    E('td', { 'style': 'font-weight:600;color:var(--gn-text-main);' }, r.name || (_('Port Forward #') + (idx + 1))),
                    E('td', {}, [
                        E('span', { 'class': 'gn-badge gn-badge-muted' }, proto)
                    ]),
                    E('td', {}, [
                        E('code', { 'class': 'gn-code' }, (r.src || 'wan') + ':' + srcPort)
                    ]),
                    E('td', {}, [
                        E('code', { 'class': 'gn-code' }, destIp + ':' + destPort)
                    ]),
                    E('td', {}, [
                        E('span', { 'class': 'gn-pill ' + (isEnabled ? 'gn-pill-success' : 'gn-pill-muted') },
                            isEnabled ? _('Active') : _('Disabled')
                        )
                    ])
                ]);
            }) : [
                E('tr', {}, [
                    E('td', { 'colspan': '5', 'style': 'text-align:center;padding:24px;color:var(--gn-text-muted);' },
                        _('No active port forwarding (DNAT) rules defined.')
                    )
                ])
            ]))
        ]);

        var redirectsCard = E('div', { 'class': 'gn-card' }, [
            E('div', { 'class': 'gn-card-header' }, [
                E('div', { 'class': 'gn-card-title' }, [
                    svgIcon('network', 16, '#6366f1'),
                    E('span', {}, _('Active Port Redirections (DNAT Rules)'))
                ])
            ]),
            E('div', { 'class': 'gn-table-container' }, [portForwardsTable])
        ]);

        container.appendChild(topCard);
        container.appendChild(zonesCard);
        container.appendChild(redirectsCard);
    },

    // =========================================================================
    // TAB 4: CONNECTED CLIENTS RENDERER
    // =========================================================================
    renderClientsPane: function(container) {
        var self = this;
        container.innerHTML = '';

        var clients = self.connectedClients || [];
        var total = clients.length;
        var verifiedCount = 0;
        var unknownCount = 0;
        var suspiciousCount = 0;

        clients.forEach(function(c) {
            var risk = assessClientRisk(c);
            if (risk.level === 'success') verifiedCount++;
            else if (risk.level === 'warning') unknownCount++;
            else if (risk.level === 'danger') suspiciousCount++;
        });

        // Top Summary Metric Cards
        var metricGrid = E('div', { 'class': 'gn-kpi-grid', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Total ARP Clients')),
                E('div', { 'class': 'gn-stat-num' }, String(total)),
                E('div', { 'class': 'gn-stat-sub' }, _('Discovered on network'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Verified Leases')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#10b981;' }, String(verifiedCount)),
                E('div', { 'class': 'gn-stat-sub' }, _('Known hostnames in DHCP'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Unregistered Devices')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#f59e0b;' }, String(unknownCount)),
                E('div', { 'class': 'gn-stat-sub' }, _('No DHCP hostname record'))
            ]),
            E('div', { 'class': 'gn-card' }, [
                E('div', { 'class': 'gn-stat-lbl' }, _('Suspicious / High-Risk')),
                E('div', { 'class': 'gn-stat-num', 'style': 'color:#ef4444;' }, String(suspiciousCount)),
                E('div', { 'class': 'gn-stat-sub' }, _('Anomalous or broadcast MAC'))
            ])
        ]);

        // Interactive Controls & Search Box
        var searchInput = E('input', {
            'type': 'text',
            'class': 'cbi-input-text gn-input',
            'placeholder': _('Filter by IP, MAC, hostname, interface...'),
            'value': self.clientSearchTerm || '',
            'style': 'min-width:260px;'
        });

        var btnScanNow = E('button', {
            'class': 'gn-btn gn-btn-primary',
            'style': 'display:inline-flex;align-items:center;gap:6px;'
        }, [
            svgIcon('search', 14),
            E('span', {}, _('Scan Now'))
        ]);
        btnScanNow.addEventListener('click', function() {
            self.handleScanClients(btnScanNow, container);
        });

        var clientTableWrapper = E('div', { 'class': 'gn-table-container' });

        function updateClientList() {
            var filtered = (self.connectedClients || []).filter(function(c) {
                if (!self.clientSearchTerm) return true;
                var term = self.clientSearchTerm.toLowerCase();
                var ip = (c.ip || '').toLowerCase();
                var mac = (c.mac || '').toLowerCase();
                var host = (c.hostname || '').toLowerCase();
                var iface = (c.iface || '').toLowerCase();
                return (ip.indexOf(term) !== -1 || mac.indexOf(term) !== -1 ||
                        host.indexOf(term) !== -1 || iface.indexOf(term) !== -1);
            });
            clientTableWrapper.innerHTML = '';
            clientTableWrapper.appendChild(self.buildClientTable(filtered));
        }

        searchInput.addEventListener('input', function(e) {
            self.clientSearchTerm = e.target.value.trim();
            updateClientList();
        });

        updateClientList();

        var clientCard = E('div', { 'class': 'gn-card', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'class': 'gn-card-header', 'style': 'display:flex;justify-content:space-between;align-items:center;flex-wrap:gap:12px;' }, [
                E('div', { 'class': 'gn-card-title' }, [
                    svgIcon('users', 16, '#10b981'),
                    E('span', {}, _('Connected Clients & ARP Security Table'))
                ]),
                E('div', { 'style': 'display:flex;gap:10px;align-items:center;' }, [
                    searchInput,
                    btnScanNow
                ])
            ]),
            clientTableWrapper
        ]);

        // Security Guidance Card
        var adviceCard = E('div', { 'class': 'gn-card gn-banner-card' }, [
            E('div', { 'style': 'display:flex;align-items:flex-start;gap:14px;' }, [
                E('div', { 'class': 'gn-icon-box', 'style': 'margin-top:2px;' }, svgIcon('shield', 22, '#6366f1')),
                E('div', {}, [
                    E('h4', { 'style': 'margin:0 0 6px 0;font-size:15px;color:var(--gn-text-main);font-weight:700;' },
                        _('Security Recommendation: Hostname Identification & Network Isolation')
                    ),
                    E('p', { 'style': 'margin:0;font-size:13px;color:var(--gn-text-muted);line-height:1.5;' },
                        _('Assign static DHCP leases with descriptive hostnames for all home and office hardware. Isolate IoT gadgets and guest visitors into dedicated VLAN zones to restrict lateral access to critical network resources.')
                    )
                ])
            ])
        ]);

        container.appendChild(metricGrid);
        container.appendChild(clientCard);
        container.appendChild(adviceCard);
    },

    // =========================================================================
    // TAB 5: SETTINGS RENDERER
    // =========================================================================
    renderSettingsPane: function(container) {
        var self = this;
        container.innerHTML = '';

        var enabledVal = uci.get('guardian', 'main', 'adguard_enabled');
        if (enabledVal === undefined || enabledVal === null) enabledVal = '1';
        var isEnabled = (enabledVal === '1');

        var hostVal = uci.get('guardian', 'main', 'adguard_host') || '127.0.0.1';
        var portVal = uci.get('guardian', 'main', 'adguard_port') || '8080';
        var userVal = uci.get('guardian', 'main', 'adguard_user') || '';
        var passVal = uci.get('guardian', 'main', 'adguard_password') || '';
        var intervalVal = uci.get('guardian', 'main', 'threat_scan_interval') || '60';

        // Result Banner Container for Test Connection
        var testResultBox = E('div', { 'id': 'gn-test-result-box', 'style': 'margin-bottom:18px;display:none;' });

        // Input elements
        var inputEnabled = E('input', {
            'type': 'checkbox',
            'id': 'gn-cfg-enabled',
            'checked': isEnabled ? '' : null,
            'style': 'width:18px;height:18px;cursor:pointer;'
        });

        var inputHost = E('input', {
            'type': 'text',
            'id': 'gn-cfg-host',
            'class': 'cbi-input-text gn-input',
            'value': hostVal,
            'placeholder': '127.0.0.1 or 192.168.1.1',
            'style': 'width:100%;max-width:340px;'
        });

        var inputPort = E('input', {
            'type': 'number',
            'id': 'gn-cfg-port',
            'class': 'cbi-input-text gn-input',
            'value': String(portVal),
            'placeholder': '8080 or 8081',
            'style': 'width:100%;max-width:160px;'
        });

        var inputUser = E('input', {
            'type': 'text',
            'id': 'gn-cfg-user',
            'class': 'cbi-input-text gn-input',
            'value': userVal,
            'placeholder': _('Enter username or click Retrieve from File'),
            'style': 'width:100%;max-width:280px;'
        });

        var inputPass = E('input', {
            'type': 'password',
            'id': 'gn-cfg-pass',
            'class': 'cbi-input-text gn-input',
            'value': passVal,
            'placeholder': _('Enter password or click Retrieve from File'),
            'style': 'width:100%;max-width:280px;'
        });

        // Retrieve from File Button
        var btnRetrieve = E('button', {
            'class': 'gn-btn gn-btn-sec gn-btn-sm',
            'type': 'button',
            'style': 'display:inline-flex;align-items:center;gap:6px;'
        }, [
            svgIcon('refresh', 13),
            E('span', {}, _('Retrieve from File'))
        ]);

        btnRetrieve.addEventListener('click', function() {
            btnRetrieve.disabled = true;
            btnRetrieve.innerHTML = '<span>⏳</span> ' + _('Retrieving...');

            fs.exec(ACTION_SCRIPT, ['retrieve_credentials']).then(function(res) {
                var raw = res && res.stdout ? res.stdout.trim() : '';
                var json = safeJson(raw, null);

                if (json && json.found) {
                    if (json.user) inputUser.value = json.user;
                    if (json.password) inputPass.value = json.password;

                    var infoMsg = _('Credentials retrieved from ') + (json.source || _('system file')) + ': ' +
                                  (json.user ? (_('User="') + json.user + '" ') : '') +
                                  (json.password ? _('(Password populated)') : _('(No plaintext password stored in file)'));
                    ui.addNotification(null, E('p', {}, infoMsg), 5000);
                } else {
                    ui.addNotification(null, E('p', {}, _('No stored credentials found in /etc/guardian_credentials.json or system configs.')), 4000);
                }
            }).catch(function(err) {
                ui.addNotification(null, E('p', {}, _('Failed to retrieve credentials: ') + (err.message || err)), 4000);
            }).finally(function() {
                btnRetrieve.disabled = false;
                btnRetrieve.innerHTML = '';
                btnRetrieve.appendChild(svgIcon('refresh', 13));
                btnRetrieve.appendChild(document.createTextNode(' ' + _('Retrieve from File')));
            });
        });

        var btnTogglePass = E('button', {
            'class': 'gn-btn gn-btn-sec gn-btn-sm',
            'type': 'button',
            'style': 'margin-left:8px;'
        }, _('Show'));
        btnTogglePass.addEventListener('click', function() {
            if (inputPass.type === 'password') {
                inputPass.type = 'text';
                btnTogglePass.textContent = _('Hide');
            } else {
                inputPass.type = 'password';
                btnTogglePass.textContent = _('Show');
            }
        });

        var inputInterval = E('input', {
            'type': 'number',
            'id': 'gn-cfg-interval',
            'class': 'cbi-input-text gn-input',
            'value': String(intervalVal),
            'placeholder': '60',
            'style': 'width:100%;max-width:140px;'
        });

        // Test Connection Button
        var btnTest = E('button', {
            'class': 'gn-btn gn-btn-sec',
            'style': 'display:inline-flex;align-items:center;gap:8px;'
        }, [
            svgIcon('search', 14),
            E('span', {}, _('Test AdGuard Connection'))
        ]);

        btnTest.addEventListener('click', function() {
            if (self.isTestingConnection) return;
            self.isTestingConnection = true;
            btnTest.disabled = true;
            btnTest.innerHTML = '<span>?</span> ' + _('Testing Connection...');

            testResultBox.style.display = 'none';

            var h = inputHost.value.trim() || '127.0.0.1';
            var p = inputPort.value.trim() || '8080';
            var u = inputUser.value.trim() || 'admin';
            var pwd = inputPass.value;

            fs.exec(ACTION_SCRIPT, ['test_connection', h, p, u, pwd]).then(function(res) {
                var raw = res && res.stdout ? res.stdout.trim() : '';
                var json = safeJson(raw, null);

                testResultBox.innerHTML = '';
                testResultBox.style.display = 'block';

                if (json && (json.version || json.running !== undefined)) {
                    testResultBox.className = 'gn-card';
                    testResultBox.style.borderLeft = '4px solid #10b981';
                    testResultBox.appendChild(E('div', { 'style': 'display:flex;align-items:center;gap:12px;' }, [
                        svgIcon('check', 20, '#10b981'),
                        E('div', {}, [
                            E('strong', { 'style': 'color:#10b981;font-size:14px;' }, _('Connection Successful!')),
                            E('div', { 'style': 'font-size:13px;color:var(--gn-text-main);margin-top:3px;' },
                                _('AdGuard Home ') + (json.version || '') + _(' is online and reachable at http://') + h + ':' + p + '.'
                            )
                        ])
                    ]));
                } else {
                    var errMsg = (json && json.error) ? json.error : (raw || _('Unable to connect. Check IP, Port, Username, or Password.'));
                    testResultBox.className = 'gn-card';
                    testResultBox.style.borderLeft = '4px solid #ef4444';
                    testResultBox.appendChild(E('div', { 'style': 'display:flex;align-items:center;gap:12px;' }, [
                        svgIcon('cross', 20, '#ef4444'),
                        E('div', {}, [
                            E('strong', { 'style': 'color:#ef4444;font-size:14px;' }, _('Connection Failed')),
                            E('div', { 'style': 'font-size:13px;color:var(--gn-text-muted);margin-top:3px;' }, errMsg)
                        ])
                    ]));
                }
            }).catch(function(err) {
                testResultBox.innerHTML = '';
                testResultBox.style.display = 'block';
                testResultBox.className = 'gn-card';
                testResultBox.style.borderLeft = '4px solid #ef4444';
                testResultBox.appendChild(E('div', {}, [
                    E('strong', { 'style': 'color:#ef4444;' }, _('Error: ')),
                    document.createTextNode(err.message || String(err))
                ]));
            }).finally(function() {
                self.isTestingConnection = false;
                btnTest.disabled = false;
                btnTest.innerHTML = '';
                btnTest.appendChild(svgIcon('search', 14));
                btnTest.appendChild(document.createTextNode(' ' + _('Test AdGuard Connection')));
            });
        });

        // Save & Apply Button
        var btnSave = E('button', {
            'class': 'gn-btn gn-btn-primary',
            'style': 'display:inline-flex;align-items:center;gap:8px;'
        }, [
            svgIcon('check', 15),
            E('span', {}, _('Save & Apply Settings'))
        ]);

        btnSave.addEventListener('click', function() {
            if (self.isSavingSettings) return;
            self.isSavingSettings = true;
            btnSave.disabled = true;
            btnSave.innerHTML = '<span>⏳</span> ' + _('Saving...');

            var isEn = inputEnabled.checked ? '1' : '0';
            var h = inputHost.value.trim() || '127.0.0.1';
            var p = inputPort.value.trim() || '8080';
            var u = inputUser.value.trim();
            var pwd = inputPass.value;
            var intv = inputInterval.value.trim() || '60';

            uci.set('guardian', 'main', 'adguard_enabled', isEn);
            uci.set('guardian', 'main', 'adguard_host', h);
            uci.set('guardian', 'main', 'adguard_port', p);
            uci.set('guardian', 'main', 'adguard_user', u);
            uci.set('guardian', 'main', 'adguard_password', pwd);
            uci.set('guardian', 'main', 'threat_scan_interval', intv);

            uci.save().then(function() {
                return uci.apply();
            }).then(function() {
                if (u || pwd) {
                    return fs.exec(ACTION_SCRIPT, ['save_credentials', u, pwd]);
                }
            }).then(function() {
                ui.addNotification(null, E('p', {}, _('Guardian Onyx settings saved and applied successfully.')), 3500);
                return self.refreshData();
            }).catch(function(err) {
                ui.addNotification(null, E('p', {}, _('Failed to save settings: ') + (err.message || err)), 4000);
            }).finally(function() {
                self.isSavingSettings = false;
                btnSave.disabled = false;
                btnSave.innerHTML = '';
                btnSave.appendChild(svgIcon('check', 15));
                btnSave.appendChild(document.createTextNode(' ' + _('Save & Apply Settings')));
            });
        });

        // Settings View Cards
        var headerCard = E('div', { 'class': 'gn-card gn-banner-card', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'style': 'display:flex;align-items:center;gap:14px;' }, [
                E('div', { 'class': 'gn-icon-box' }, svgIcon('settings', 24, '#6366f1')),
                E('div', {}, [
                    E('h3', { 'style': 'margin:0;font-size:17px;font-weight:700;color:var(--gn-text-main);' }, _('Guardian Configuration & Parameters')),
                    E('p', { 'style': 'margin:4px 0 0 0;font-size:13px;color:var(--gn-text-muted);' },
                        _('Customize AdGuard Home connection endpoints, authentication credentials, and daemon scan behavior.')
                    )
                ])
            ])
        ]);

        var settingsFormCard = E('div', { 'class': 'gn-card', 'style': 'margin-bottom:20px;' }, [
            E('div', { 'class': 'gn-card-header', 'style': 'margin-bottom:16px;' }, [
                E('div', { 'class': 'gn-card-title' }, [
                    svgIcon('shield', 16, '#6366f1'),
                    E('span', {}, _('AdGuard Home Connection Parameters'))
                ])
            ]),

            // Form Fields
            E('div', { 'style': 'display:flex;flex-direction:column;gap:16px;' }, [
                // Enabled checkbox
                E('div', { 'style': 'display:flex;align-items:center;gap:12px;' }, [
                    inputEnabled,
                    E('label', { 'for': 'gn-cfg-enabled', 'style': 'font-weight:600;cursor:pointer;color:var(--gn-text-main);' },
                        _('Enable AdGuard Home Integration (Poll API for stats, query logs & filters)')
                    )
                ]),

                // Host & Port Row
                E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit, minmax(260px, 1fr));gap:16px;' }, [
                    E('div', {}, [
                        E('label', { 'style': 'display:block;font-size:12px;font-weight:600;color:var(--gn-text-muted);margin-bottom:6px;' }, _('AdGuard Host / IP:')),
                        inputHost,
                        E('div', { 'style': 'font-size:11px;color:var(--gn-text-dim);margin-top:4px;' },
                            _('Default: 127.0.0.1 (use router IP e.g. 192.168.1.1 if running on specific interface)')
                        )
                    ]),
                    E('div', {}, [
                        E('label', { 'style': 'display:block;font-size:12px;font-weight:600;color:var(--gn-text-muted);margin-bottom:6px;' }, _('AdGuard HTTP Port:')),
                        inputPort,
                        E('div', { 'style': 'font-size:11px;color:var(--gn-text-dim);margin-top:4px;' },
                            _('Configurable AdGuard Web UI port (e.g. 8080, 8081, or 3000)')
                        )
                    ])
                ]),

                // Username & Password Row
                E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit, minmax(260px, 1fr));gap:16px;' }, [
                    E('div', {}, [
                        E('label', { 'style': 'display:block;font-size:12px;font-weight:600;color:var(--gn-text-muted);margin-bottom:6px;' }, _('AdGuard Username:')),
                        inputUser,
                        E('div', { 'style': 'font-size:11px;color:var(--gn-text-dim);margin-top:4px;' }, _('Leave blank if no authentication is configured'))
                    ]),
                    E('div', {}, [
                        E('label', { 'style': 'display:block;font-size:12px;font-weight:600;color:var(--gn-text-muted);margin-bottom:6px;' }, _('AdGuard Password:')),
                        E('div', { 'style': 'display:flex;align-items:center;' }, [
                            inputPass,
                            btnTogglePass
                        ]),
                        E('div', { 'style': 'font-size:11px;color:var(--gn-text-dim);margin-top:4px;' }, _('Leave blank if no authentication is configured'))
                    ])
                ]),

                // Retrieve from File Helper Box
                E('div', { 'style': 'display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;padding:10px 14px;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.2);border-radius:8px;' }, [
                    E('div', { 'style': 'display:flex;align-items:center;gap:8px;' }, [
                        svgIcon('shield', 15, '#6366f1'),
                        E('span', { 'style': 'font-size:12px;color:var(--gn-text-muted);' },
                            _('Forgot username or password? Restore from router files:')
                        )
                    ]),
                    btnRetrieve
                ]),

                // Threat Scan Interval Row
                E('div', { 'style': 'border-top:1px solid var(--gn-card-border);padding-top:16px;' }, [
                    E('label', { 'style': 'display:block;font-size:12px;font-weight:600;color:var(--gn-text-muted);margin-bottom:6px;' }, _('Threat & ARP Scan Interval (Seconds):')),
                    inputInterval,
                    E('div', { 'style': 'font-size:11px;color:var(--gn-text-dim);margin-top:4px;' }, _('Interval for background state queries (default: 60s)'))
                ]),

                // Action Buttons Row
                E('div', { 'style': 'display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:8px;' }, [
                    btnSave,
                    btnTest
                ])
            ])
        ]);

        container.appendChild(headerCard);
        container.appendChild(testResultBox);
        container.appendChild(settingsFormCard);
    },

    // =========================================================================
    // SUB-COMPONENT BUILDERS
    // =========================================================================

    // Client Table (used in Tab 4)
    buildClientTable: function(clients) {
        if (!clients || clients.length === 0) {
            return E('div', { 'style': 'padding:32px;text-align:center;color:var(--gn-text-muted);' }, [
                E('div', { 'style': 'font-size:28px;margin-bottom:8px;' }, '??'),
                E('div', { 'style': 'font-weight:600;font-size:14px;' }, _('No Active ARP Clients Found')),
                E('div', { 'style': 'font-size:12px;margin-top:4px;' }, _('Click "Scan Now" to query the network.'))
            ]);
        }

        return E('table', { 'class': 'gn-table' }, [
            E('thead', {}, [
                E('tr', {}, [
                    E('th', {}, _('Risk')),
                    E('th', {}, _('IP Address')),
                    E('th', {}, _('MAC Address')),
                    E('th', {}, _('Hostname')),
                    E('th', {}, _('Interface')),
                    E('th', {}, _('Status')),
                    E('th', {}, _('Assessment'))
                ])
            ]),
            E('tbody', {}, clients.map(function(c) {
                var risk = assessClientRisk(c);
                var hostname = (c.hostname && c.hostname !== '*' && c.hostname !== 'Unknown') ? c.hostname : _('Unknown Device');

                return E('tr', {}, [
                    E('td', { 'style': 'text-align:center;' }, [
                        E('span', {
                            'class': 'gn-risk-dot',
                            'style': 'background:' + risk.color + ';',
                            'title': risk.label + ' - ' + risk.reason
                        })
                    ]),
                    E('td', { 'style': 'font-weight:600;' }, [
                        E('code', { 'class': 'gn-code' }, c.ip)
                    ]),
                    E('td', {}, [
                        E('code', { 'class': 'gn-code gn-code-mac' }, (c.mac || '').toUpperCase())
                    ]),
                    E('td', { 'style': 'color:var(--gn-text-main);font-weight:500;' }, hostname),
                    E('td', {}, [
                        E('span', { 'class': 'gn-badge gn-badge-muted' }, c.iface || 'br-lan')
                    ]),
                    E('td', {}, [
                        E('span', { 'class': 'gn-pill gn-pill-success' }, [
                            E('span', { 'class': 'gn-pulse-dot gn-dot-green' }),
                            _('Online')
                        ])
                    ]),
                    E('td', {}, [
                        E('span', { 'class': 'gn-pill ' + risk.badgeClass }, risk.label)
                    ])
                ]);
            }))
        ]);
    },

    // =========================================================================
    // TAB SWITCHING LOGIC
    // =========================================================================
    switchTab: function(targetTab) {
        var self = this;
        self.activeTab = targetTab;

        var tabs = ['adguard', 'firewall', 'clients', 'settings'];
        tabs.forEach(function(t) {
            var btn = document.getElementById('gn-tab-btn-' + t);
            var pane = document.getElementById('gn-pane-' + t);
            if (btn) btn.classList.toggle('active', t === targetTab);
            if (pane) pane.style.display = (t === targetTab) ? 'block' : 'none';
        });

        // Tab-specific rendering on activation
        if (targetTab === 'adguard') {
            var pa = document.getElementById('gn-pane-adguard');
            if (pa) self.renderAdGuardPane(pa);
        } else if (targetTab === 'firewall') {
            var pf = document.getElementById('gn-pane-firewall');
            if (pf) self.renderFirewallPane(pf);
        } else if (targetTab === 'clients') {
            var pc = document.getElementById('gn-pane-clients');
            if (pc) self.renderClientsPane(pc);
        } else if (targetTab === 'settings') {
            var ps = document.getElementById('gn-pane-settings');
            if (ps) self.renderSettingsPane(ps);
        }
    },

    // =========================================================================
    // MAIN RENDER FUNCTION
    // =========================================================================
    render: function(data) {
        var self = this;

        // Parse initial loaded data
        if (data[0] && data[0].stdout) self.statusData = safeJson(data[0].stdout, {});
        if (data[1] && data[1].stdout) {
            self.adguardStatsDirect = safeJson(data[1].stdout, {});
        } else {
            self.adguardStatsDirect = {};
        }
        if (data[2] && data[2].stdout) self.firewallZones = safeJson(data[2].stdout, []);
        if (data[3] && data[3].stdout) self.connectedClients = safeJson(data[3].stdout, []);
        if (data[4]) self.conntrackCount = parseInt(data[4].trim(), 10) || 0;
        self.uciGuardian = data[5] || {};
        self.uciFirewall = data[6] || {};

        // Merge direct stats into statusData if statusData.adguard is empty or missing stats
        if (!self.statusData || !self.statusData.adguard) {
            self.statusData = self.statusData || {};
            self.statusData.adguard = self.statusData.adguard || {
                status: (self.adguardFilters.length > 0 || self.adguardLog.length > 0) ? 'online' : 'offline',
                stats: self.adguardStatsDirect
            };
        } else if (!self.statusData.adguard.stats || !self.statusData.adguard.stats.num_dns_queries) {
            if (self.adguardStatsDirect && self.adguardStatsDirect.num_dns_queries) {
                self.statusData.adguard.stats = self.adguardStatsDirect;
            }
        }

        // Native High-Craft Theme Stylesheet (Inline Injection)
        var styleNode = E('style', {}, [
            /* Container & Theme Tokens */
            '.gn-wrapper { max-width:1180px; margin:16px auto; padding:0 14px; font-family:"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color:var(--gn-text-main); box-sizing:border-box;',
            '  --gn-bg: #0a0e1a;',
            '  --gn-card-bg: #111827;',
            '  --gn-card-border: #1f2937;',
            '  --gn-card-radius: 12px;',
            '  --gn-card-shadow: 0 8px 30px rgba(0, 0, 0, 0.45);',
            '  --gn-accent: #6366f1;',
            '  --gn-accent-hover: #4f46e5;',
            '  --gn-accent-bg: rgba(99, 102, 241, 0.12);',
            '  --gn-accent-border: rgba(99, 102, 241, 0.3);',
            '  --gn-success: #10b981;',
            '  --gn-success-bg: rgba(16, 185, 129, 0.12);',
            '  --gn-success-border: rgba(16, 185, 129, 0.3);',
            '  --gn-danger: #ef4444;',
            '  --gn-danger-bg: rgba(239, 68, 68, 0.12);',
            '  --gn-danger-border: rgba(239, 68, 68, 0.3);',
            '  --gn-warning: #f59e0b;',
            '  --gn-warning-bg: rgba(245, 158, 11, 0.12);',
            '  --gn-warning-border: rgba(245, 158, 11, 0.3);',
            '  --gn-text-main: #f9fafb;',
            '  --gn-text-muted: #9ca3af;',
            '  --gn-text-dim: #6b7280;',
            '  --gn-table-header-bg: rgba(255, 255, 255, 0.03);',
            '  --gn-table-row-hover: rgba(99, 102, 241, 0.07);',
            '  --gn-table-row-alt: rgba(255, 255, 255, 0.015);',
            '  --gn-code-bg: #0f172a;',
            '}',

            /* Adaptive Light Mode Override */
            ':root[data-theme="light"] .gn-wrapper, body.light .gn-wrapper, body.theme-light .gn-wrapper, .gn-wrapper.gn-theme-light {',
            '  --gn-bg: #f8fafc !important;',
            '  --gn-card-bg: #ffffff !important;',
            '  --gn-card-border: #e2e8f0 !important;',
            '  --gn-card-shadow: 0 4px 16px -1px rgba(15, 23, 42, 0.08) !important;',
            '  --gn-text-main: #0f172a !important;',
            '  --gn-text-muted: #475569 !important;',
            '  --gn-text-dim: #64748b !important;',
            '  --gn-table-header-bg: #f1f5f9 !important;',
            '  --gn-table-row-hover: #f8fafc !important;',
            '  --gn-table-row-alt: #fcfcfd !important;',
            '  --gn-code-bg: #f1f5f9 !important;',
            '}',

            /* Header Section */
            '.gn-header { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:16px; margin-bottom:20px; padding:18px 24px; background:var(--gn-card-bg); border:1px solid var(--gn-card-border); border-radius:var(--gn-card-radius); box-shadow:var(--gn-card-shadow); }',
            '.gn-brand { display:flex; align-items:center; gap:14px; }',
            '.gn-brand-icon { width:44px; height:44px; border-radius:12px; background:linear-gradient(135deg, #6366f1, #8b5cf6); display:flex; align-items:center; justify-content:center; color:#ffffff; box-shadow:0 4px 14px rgba(99,102,241,0.35); }',
            '.gn-title { font-size:20px; font-weight:800; color:var(--gn-text-main); margin:0; line-height:1.2; letter-spacing:-0.02em; }',
            '.gn-subtitle { font-size:12px; color:var(--gn-text-muted); margin:4px 0 0 0; }',

            /* Tab Navigation Bar */
            '.gn-nav-tabs { display:flex; gap:8px; border-bottom:1px solid var(--gn-card-border); margin-bottom:22px; overflow-x:auto; }',
            '.gn-tab-btn { display:inline-flex; align-items:center; gap:8px; padding:10px 18px; font-size:13px; font-weight:600; color:var(--gn-text-muted); background:transparent; border:none; border-bottom:3px solid transparent; cursor:pointer; transition:all 0.2s ease; border-radius:6px 6px 0 0; }',
            '.gn-tab-btn:hover { color:var(--gn-text-main); background:rgba(255,255,255,0.03); }',
            '.gn-tab-btn.active { color:#ffffff; border-bottom-color:var(--gn-accent); background:var(--gn-accent-bg); }',

            /* Action Bars */
            '.gn-action-bar { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:14px; margin-bottom:18px; }',

            /* Cards & KPI Grid */
            '.gn-kpi-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:16px; }',
            '.gn-card { background:var(--gn-card-bg); border:1px solid var(--gn-card-border); border-radius:var(--gn-card-radius); box-shadow:var(--gn-card-shadow); padding:20px; box-sizing:border-box; transition:transform 0.15s ease, border-color 0.15s ease; }',
            '.gn-card:hover { border-color:rgba(99, 102, 241, 0.35); }',
            '.gn-card-glow-indigo { border-top:3px solid #6366f1; }',
            '.gn-card-glow-amber { border-top:3px solid #f59e0b; }',
            '.gn-card-glow-emerald { border-top:3px solid #10b981; }',
            '.gn-card-glow-rose { border-top:3px solid #ef4444; }',
            '.gn-card-top { display:flex; justify-content:space-between; align-items:center; }',
            '.gn-card-title { font-size:13px; font-weight:600; color:var(--gn-text-muted); display:flex; align-items:center; gap:8px; }',
            '.gn-card-header { padding:14px 20px; border-bottom:1px solid var(--gn-card-border); }',
            '.gn-kpi-val { font-size:26px; font-weight:800; color:var(--gn-text-main); line-height:1.2; letter-spacing:-0.03em; }',
            '.gn-kpi-sub { font-size:12px; color:var(--gn-text-dim); margin-top:6px; }',

            /* Progress Bar */
            '.gn-progress-track { width:100%; height:8px; border-radius:999px; background:rgba(255,255,255,0.06); overflow:hidden; }',
            '.gn-progress-fill { height:100%; border-radius:999px; background:linear-gradient(90deg, #6366f1, #10b981); transition:width 0.4s ease; }',

            /* Badges & Pills */
            '.gn-pill { display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:999px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; }',
            '.gn-pill-success { background:var(--gn-success-bg); color:#10b981; border:1px solid var(--gn-success-border); }',
            '.gn-pill-danger { background:var(--gn-danger-bg); color:#ef4444; border:1px solid var(--gn-danger-border); }',
            '.gn-pill-warning { background:var(--gn-warning-bg); color:#f59e0b; border:1px solid var(--gn-warning-border); }',
            '.gn-pill-info { background:rgba(6,182,212,0.12); color:#06b6d4; border:1px solid rgba(6,182,212,0.3); }',
            '.gn-pill-muted { background:rgba(255,255,255,0.05); color:var(--gn-text-muted); border:1px solid var(--gn-card-border); }',
            '.gn-badge { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:6px; font-size:12px; font-weight:600; }',
            '.gn-badge-muted { background:rgba(255,255,255,0.04); color:var(--gn-text-muted); border:1px solid var(--gn-card-border); }',
            '.gn-badge-accent { background:var(--gn-accent-bg); color:#818cf8; border:1px solid var(--gn-accent-border); }',

            /* Buttons */
            '.gn-btn { padding:8px 16px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; transition:all 0.15s ease; border:1px solid transparent; }',
            '.gn-btn-primary { background:#6366f1; color:#ffffff; }',
            '.gn-btn-primary:hover { background:#4f46e5; }',
            '.gn-btn-sec { background:rgba(255,255,255,0.05); color:var(--gn-text-main); border:1px solid var(--gn-card-border); }',
            '.gn-btn-sec:hover { background:rgba(255,255,255,0.08); border-color:var(--gn-accent); }',
            '.gn-btn-danger { background:#ef4444; color:#ffffff; }',
            '.gn-btn-danger:hover { background:#dc2626; }',
            '.gn-btn-warning { background:#f59e0b; color:#ffffff; }',
            '.gn-btn-warning:hover { background:#d97706; }',
            '.gn-btn-sm { padding:5px 12px; font-size:12px; border-radius:6px; }',

            /* Inputs & Forms */
            '.gn-input { background:var(--gn-card-bg); border:1px solid var(--gn-card-border); border-radius:6px; color:var(--gn-text-main); padding:6px 12px; font-size:12px; outline:none; }',
            '.gn-input:focus { border-color:var(--gn-accent); }',
            '.gn-select { background:var(--gn-card-bg); border:1px solid var(--gn-card-border); border-radius:6px; color:var(--gn-text-main); padding:6px 12px; font-size:12px; outline:none; }',

            /* Table Styles */
            '.gn-table-container { width:100%; overflow-x:auto; }',
            '.gn-table { width:100%; border-collapse:collapse; text-align:left; font-size:13px; }',
            '.gn-table th { background:var(--gn-table-header-bg); color:var(--gn-text-muted); font-weight:600; padding:12px 16px; border-bottom:1px solid var(--gn-card-border); font-size:11px; text-transform:uppercase; letter-spacing:0.04em; }',
            '.gn-table td { padding:12px 16px; border-bottom:1px solid rgba(255,255,255,0.04); vertical-align:middle; }',
            '.gn-table tr:hover td { background:var(--gn-table-row-hover); }',

            /* Monospace & Code */
            '.gn-code { background:var(--gn-code-bg); padding:2px 6px; border-radius:4px; font-family:"SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size:12px; color:#38bdf8; }',
            '.gn-code-mac { color:#a78bfa; }',

            /* Pulsing Status Dots */
            '.gn-pulse-dot { width:8px; height:8px; border-radius:50%; display:inline-block; }',
            '.gn-dot-green { background:#10b981; box-shadow:0 0 8px rgba(16,185,129,0.8); animation:gnPulse 2s infinite; }',
            '.gn-dot-red { background:#ef4444; }',
            '.gn-risk-dot { width:10px; height:10px; border-radius:50%; display:inline-block; }',

            /* Animations */
            '@keyframes gnPulse { 0% { transform:scale(0.95); box-shadow:0 0 0 0 rgba(16,185,129,0.7); } 70% { transform:scale(1); box-shadow:0 0 0 6px rgba(16,185,129,0); } 100% { transform:scale(0.95); box-shadow:0 0 0 0 rgba(16,185,129,0); } }',
            '@keyframes gnSpin { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }',
            '.gn-spin { animation:gnSpin 1s linear infinite; }',

            /* Misc Components */
            '.gn-icon-box { width:46px; height:46px; border-radius:10px; background:rgba(99,102,241,0.12); border:1px solid rgba(99,102,241,0.25); display:flex; align-items:center; justify-content:center; }',
            '.gn-banner-card { border-left:4px solid #6366f1; }',
            '.gn-stat-box { padding:10px 14px; background:rgba(255,255,255,0.02); border-radius:8px; border:1px solid rgba(255,255,255,0.03); }',
            '.gn-stat-lbl { font-size:11px; font-weight:600; color:var(--gn-text-muted); text-transform:uppercase; letter-spacing:0.03em; }',
            '.gn-stat-num { font-size:20px; font-weight:800; color:var(--gn-text-main); margin-top:4px; }',
            '.gn-stat-sub { font-size:11px; color:var(--gn-text-dim); margin-top:3px; }'
        ]);

        // Main Wrapper & Theme Application
        var wrapper = E('div', { 'class': 'gn-wrapper' });
        if (!self.detectThemeIsDark()) {
            wrapper.classList.add('gn-theme-light');
        }

        // Top Header
        var header = E('div', { 'class': 'gn-header' }, [
            E('div', { 'class': 'gn-brand' }, [
                E('div', { 'class': 'gn-brand-icon' }, svgIcon('shield', 24, '#ffffff')),
                E('div', {}, [
                    E('div', { 'style': 'display:flex;align-items:center;gap:8px;' }, [
                        E('h1', { 'class': 'gn-title' }, 'Guardian Onyx'),
                        E('span', { 'class': 'gn-badge gn-badge-accent', 'style': 'font-size:11px;padding:2px 8px;' }, 'v1.0.2')
                    ]),
                    E('p', { 'class': 'gn-subtitle' }, _('OpenWrt Unified Security, AdGuard Home & Firewall Monitoring'))
                ])
            ]),
            E('div', { 'style': 'display:flex;align-items:center;gap:12px;' }, [
                E('span', { 'class': 'gn-pill gn-pill-info' }, _('Onyx Suite')),
                E('span', { 'class': 'gn-pill gn-pill-success' }, [
                    E('span', { 'class': 'gn-pulse-dot gn-dot-green' }),
                    _('System Protected')
                ])
            ])
        ]);

        // Tab Navigation Buttons (4 Tabs)
        var tabBtnAdguard = E('button', {
            'id': 'gn-tab-btn-adguard',
            'class': 'gn-tab-btn active'
        }, [
            svgIcon('shield', 15),
            E('span', {}, _('AdGuard Home'))
        ]);

        var tabBtnFirewall = E('button', {
            'id': 'gn-tab-btn-firewall',
            'class': 'gn-tab-btn'
        }, [
            svgIcon('fire', 15),
            E('span', {}, _('Firewall'))
        ]);

        var tabBtnClients = E('button', {
            'id': 'gn-tab-btn-clients',
            'class': 'gn-tab-btn'
        }, [
            svgIcon('users', 15),
            E('span', {}, _('Connected Clients'))
        ]);

        var tabBtnSettings = E('button', {
            'id': 'gn-tab-btn-settings',
            'class': 'gn-tab-btn'
        }, [
            svgIcon('settings', 15),
            E('span', {}, _('Settings'))
        ]);

        tabBtnAdguard.addEventListener('click', function() { self.switchTab('adguard'); });
        tabBtnFirewall.addEventListener('click', function() { self.switchTab('firewall'); });
        tabBtnClients.addEventListener('click', function() { self.switchTab('clients'); });
        tabBtnSettings.addEventListener('click', function() { self.switchTab('settings'); });

        var navTabs = E('div', { 'class': 'gn-nav-tabs' }, [
            tabBtnAdguard,
            tabBtnFirewall,
            tabBtnClients,
            tabBtnSettings
        ]);

        // Content Panes
        var paneAdguard = E('div', { 'id': 'gn-pane-adguard', 'style': 'display:block;' });
        var paneFirewall = E('div', { 'id': 'gn-pane-firewall', 'style': 'display:none;' });
        var paneClients = E('div', { 'id': 'gn-pane-clients', 'style': 'display:none;' });
        var paneSettings = E('div', { 'id': 'gn-pane-settings', 'style': 'display:none;' });

        // Initial Pane Render
        self.renderAdGuardPane(paneAdguard);

        // Assembly
        wrapper.appendChild(styleNode);
        wrapper.appendChild(header);
        wrapper.appendChild(navTabs);
        wrapper.appendChild(paneAdguard);
        wrapper.appendChild(paneFirewall);
        wrapper.appendChild(paneClients);
        wrapper.appendChild(paneSettings);

        // Setup Polling every 10 seconds
        poll.add(function() {
            return self.refreshData();
        }, 10);

        return wrapper;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
