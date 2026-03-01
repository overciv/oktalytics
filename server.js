// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { ExpressOIDC } = require('@okta/oidc-middleware');
const okta = require('@okta/okta-sdk-nodejs');
const path = require('path');
const fs = require('fs').promises;

const PORT = process.env.PORT || 3000;

// Cache configuration
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

function getCacheFile(appId) {
  if (!appId || appId === 'all') return './cache/metrics-all.json';
  return `./cache/metrics-app-${appId}.json`;
}

// Configured applications for scoped metrics
const OKTA_APPS = process.env.OKTA_APPS ? JSON.parse(process.env.OKTA_APPS) : [];

// Initialize Okta Client
const oktaClient = new okta.Client({
  orgUrl: process.env.OKTA_ORG_URL,
  token: process.env.OKTA_API_TOKEN
});

// Progress tracking for real-time updates
let progressData = {
  isProcessing: false,
  totalLogs: 0,
  processedLogs: 0,
  currentPage: 0,
  estimatedTime: 0,
  startTime: null
};

// Helper function to sleep
async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Ensure cache directory exists
async function ensureCacheDir() {
  try {
    await fs.mkdir('./cache', { recursive: true });
  } catch (error) {
    console.error('Error creating cache directory:', error);
  }
}

// Load cached metrics
async function loadCache(appId) {
  try {
    const data = await fs.readFile(getCacheFile(appId), 'utf8');
    const cache = JSON.parse(data);

    // Check if cache is still valid
    if (Date.now() - cache.timestamp < CACHE_DURATION) {
      return cache;
    }
  } catch (error) {
    // Cache doesn't exist or is invalid
  }
  return null;
}

// Save metrics to cache
async function saveCache(metrics, logsProcessed, appId) {
  try {
    await ensureCacheDir();
    const cacheData = {
      metrics,
      logsProcessed,
      timestamp: Date.now()
    };
    await fs.writeFile(getCacheFile(appId), JSON.stringify(cacheData, null, 2));
  } catch (error) {
    console.error('Error saving cache:', error);
  }
}

// Incremental fetch with streaming processing
async function fetchLogsIncremental(sinceDate, untilDate, appId, onProgress) {
  const metrics = {
    dailyMetrics: {},
    uniqueUsers: new Set(),
    mfaAbandonments: new Set(),
    authenticationTransactions: {},
    userLastActivity: {}
  };

  // Initialize daily metrics
  for (let i = 0; i < 31; i++) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateKey = date.toISOString().split('T')[0];
    metrics.dailyMetrics[dateKey] = {
      uniqueUsers: new Set(),
      mfaAbandonments: 0,
      authenticationTimes: [],
      failedPasswords: 0,
      failedMFA: 0,
      successfulLogins: 0,
      fastPassEnrollments: 0,
      fastPassAuthUsers: new Set(),
      fastPassDevices: new Set(),
      fastPassAuths: 0,
      biometricUsers: new Set(),
      emailDeliverySuccess: 0,
      emailDeliveryFailure: 0,
      emailDropped: 0,
      emailBounced: 0,
      emailSpam: 0,
      emailUnsubscribed: 0
    };
  }

  // Add FastPass and biometric tracking sets
  metrics.fastPassEnrolledUsers = new Set();
  metrics.fastPassAuthUsers = new Set();
  metrics.fastPassDevices = new Set();
  metrics.biometricUsers = new Set();

  let totalProcessed = 0;
  let retryCount = 0;
  const maxRetries = 5;
  let pageCount = 0;
  
  try {
    let url = `${process.env.OKTA_ORG_URL}/api/v1/logs?since=${sinceDate}&until=${untilDate}&limit=1000`;
    
    while (url) {
      try {
        const response = await fetch(url, {
          headers: {
            'Authorization': `SSWS ${process.env.OKTA_API_TOKEN}`,
            'Accept': 'application/json'
          }
        });

        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = parseInt(response.headers.get('x-rate-limit-reset')) || 60;
          const waitTime = Math.min(retryAfter * 1000, 60000);
          
          console.log(`Rate limited. Waiting ${waitTime/1000} seconds...`);
          await sleep(waitTime);
          retryCount++;
          
          if (retryCount >= maxRetries) {
            throw new Error('Max retries exceeded for rate limiting');
          }
          continue;
        }

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const logs = await response.json();
        pageCount++;
        
        // Process logs immediately (streaming processing)
        processLogsBatch(logs, metrics, appId);
        
        totalProcessed += logs.length;
        
        // Update progress
        if (onProgress) {
          onProgress({
            processedLogs: totalProcessed,
            currentPage: pageCount
          });
        }

        // Check for next page
        const linkHeader = response.headers.get('link');
        url = null;
        
        if (linkHeader) {
          const nextLink = linkHeader.split(',').find(link => link.includes('rel="next"'));
          if (nextLink) {
            const match = nextLink.match(/<([^>]+)>/);
            if (match) {
              url = match[1];
            }
          }
        }

        // Small delay between requests
        await sleep(100);
        
      } catch (error) {
        console.error('Error fetching logs:', error);
        throw error;
      }
    }
  } catch (error) {
    console.error('Error in fetchLogsIncremental:', error);
    throw error;
  }

  return { metrics, totalProcessed };
}

// Process a batch of logs immediately
function processLogsBatch(logs, metrics, appId) {
  logs.forEach(log => {
    // When scoped to a specific app, only process events where that app appears as a target
    if (appId && appId !== 'all') {
      const targets = log.target || [];
      if (!targets.some(t => t.id === appId)) return;
    }

    const dateKey = log.published.split('T')[0];
    const userId = log.actor?.id;
    const eventType = log.eventType;
    const outcome = log.outcome?.result;
    const outcomeReason = log.outcome?.reason;

    if (!metrics.dailyMetrics[dateKey]) return;

    // Track user last activity
    const logTimestamp = new Date(log.published).getTime();
    if (userId) {
      if (!metrics.userLastActivity[userId] || logTimestamp > metrics.userLastActivity[userId]) {
        metrics.userLastActivity[userId] = logTimestamp;
      }
    }

    // Track unique users and successful logins.
    // - All Apps scope: use user.session.start (counts new Okta sessions)
    // - App-scoped: use user.authentication.sso which fires for both SP and IDP-initiated
    //   SSO flows and always lists the target app, whereas user.session.start only lists
    //   the app as a target for SP-initiated flows.
    if (appId && appId !== 'all') {
      if (eventType === 'user.authentication.sso' && outcome === 'SUCCESS' && userId) {
        metrics.uniqueUsers.add(userId);
        metrics.dailyMetrics[dateKey].uniqueUsers.add(userId);
        metrics.dailyMetrics[dateKey].successfulLogins++;
      }
    } else {
      if (eventType === 'user.session.start' && userId) {
        metrics.uniqueUsers.add(userId);
        metrics.dailyMetrics[dateKey].uniqueUsers.add(userId);
        if (outcome === 'SUCCESS') {
          metrics.dailyMetrics[dateKey].successfulLogins++;
        }
      }
    }

    // Track failed password authentication
    if ((eventType === 'user.authentication.authenticate' || 
         eventType === 'user.session.start') && 
        outcome === 'FAILURE') {
      const reason = log.outcome?.reason;
      if (reason === 'INVALID_CREDENTIALS' || reason === 'VERIFICATION_ERROR') {
        metrics.dailyMetrics[dateKey].failedPasswords++;
      }
    }

    // Track failed MFA
    if ((eventType === 'user.authentication.auth_via_mfa' ||
         eventType === 'user.mfa.factor.verify' ||
         eventType === 'user.mfa.okta_verify.deny_push') && 
        outcome === 'FAILURE') {
      metrics.dailyMetrics[dateKey].failedMFA++;
    }

    // Track FastPass enrollments - Correct filter
    // outcome.reason eq "User set up SIGNED_NONCE factor" and eventType eq "user.mfa.factor.activate"
    if (eventType === 'user.mfa.factor.activate' && 
        outcome === 'SUCCESS' &&
        outcomeReason === 'User set up SIGNED_NONCE factor') {
      metrics.dailyMetrics[dateKey].fastPassEnrollments++;
      if (userId) {
        metrics.fastPassEnrolledUsers.add(userId);
      }
    }

    // Track FastPass authentications
    // Based on Okta article: look for debugContext.debugData.behaviors containing "New Device=NEGATIVE"
    // and authentication success
    if ((eventType === 'user.authentication.authenticate' || 
         eventType === 'policy.evaluate_sign_on') && 
        outcome === 'SUCCESS') {
      
      const behaviors = log.debugContext?.debugData?.behaviors;
      const deviceId = log.client?.device;
      const keyTypeUsed = log.debugContext?.debugData?.keyTypeUsedForAuthentication;
      
      // Check if FastPass was used (behaviors contains "New Device=NEGATIVE" or similar indicators)
      const isFastPass = behaviors && 
                        (behaviors.includes('New Device=NEGATIVE') || 
                         behaviors.includes('SIGNED_NONCE'));
      
      if (isFastPass) {
        // Track unique users using FastPass
        if (userId) {
          metrics.fastPassAuthUsers.add(userId);
          metrics.dailyMetrics[dateKey].fastPassAuthUsers.add(userId);
        }
        
        // Track unique devices using FastPass
        if (deviceId) {
          metrics.fastPassDevices.add(deviceId);
          metrics.dailyMetrics[dateKey].fastPassDevices.add(deviceId);
        }
        
        metrics.dailyMetrics[dateKey].fastPassAuths++;
      }
      
      // Track biometric usage
      // debugContext.debugData.keyTypeUsedForAuthentication eq "USER_VERIFYING_BIO_OR_PIN"
      if (keyTypeUsed === 'USER_VERIFYING_BIO_OR_PIN') {
        if (userId) {
          metrics.biometricUsers.add(userId);
          metrics.dailyMetrics[dateKey].biometricUsers.add(userId);
        }
      }
    }

    // Also check user.authentication.auth_via_mfa for FastPass
    if (eventType === 'user.authentication.auth_via_mfa' && outcome === 'SUCCESS') {
      const behaviors = log.debugContext?.debugData?.behaviors;
      const deviceId = log.client?.device;
      const keyTypeUsed = log.debugContext?.debugData?.keyTypeUsedForAuthentication;
      
      const isFastPass = behaviors && 
                        (behaviors.includes('New Device=NEGATIVE') || 
                         behaviors.includes('SIGNED_NONCE'));
      
      if (isFastPass) {
        if (userId) {
          metrics.fastPassAuthUsers.add(userId);
          metrics.dailyMetrics[dateKey].fastPassAuthUsers.add(userId);
        }
        
        if (deviceId) {
          metrics.fastPassDevices.add(deviceId);
          metrics.dailyMetrics[dateKey].fastPassDevices.add(deviceId);
        }
        
        metrics.dailyMetrics[dateKey].fastPassAuths++;
      }
      
      // Track biometric usage
      if (keyTypeUsed === 'USER_VERIFYING_BIO_OR_PIN') {
        if (userId) {
          metrics.biometricUsers.add(userId);
          metrics.dailyMetrics[dateKey].biometricUsers.add(userId);
        }
      }
    }

    // Track authentication transactions (only store essential data)
    const transactionId = log.debugContext?.debugData?.authnRequestId;
    if (transactionId && (eventType === 'user.session.start' || eventType.includes('mfa'))) {
      if (!metrics.authenticationTransactions[transactionId]) {
        metrics.authenticationTransactions[transactionId] = {
          dateKey: dateKey,
          timestamps: []
        };
      }
      metrics.authenticationTransactions[transactionId].timestamps.push(logTimestamp);
    }

    // Track MFA abandonment
    if (eventType === 'user.mfa.factor.suspend' || 
        eventType === 'user.authentication.auth_via_mfa' && outcome === 'FAILURE') {
      metrics.mfaAbandonments.add(userId);
      metrics.dailyMetrics[dateKey].mfaAbandonments++;
    }

    // Track Email Delivery
    if (eventType === 'system.email.delivery') {
      const providerMessage = log.debugContext?.debugData?.providerMessage;
      
      if (outcome === 'SUCCESS') {
        // Email delivered successfully
        metrics.dailyMetrics[dateKey].emailDeliverySuccess++;
      } else if (outcome === 'FAILURE') {
        // Email delivery failed
        metrics.dailyMetrics[dateKey].emailDeliveryFailure++;
        
        // Check specific failure reasons
        if (outcomeReason === 'dropped') {
          metrics.dailyMetrics[dateKey].emailDropped++;
          
          // Check provider message for specific drop reasons
          if (providerMessage === 'Spam Reporting Address') {
            metrics.dailyMetrics[dateKey].emailSpam++;
          } else if (providerMessage === 'Bounced Address') {
            metrics.dailyMetrics[dateKey].emailBounced++;
          } else if (providerMessage === 'Unsubscribed Address') {
            metrics.dailyMetrics[dateKey].emailUnsubscribed++;
          }
        } else if (outcomeReason === 'bounce') {
          // Also count general bounces
          metrics.dailyMetrics[dateKey].emailBounced++;
        }
      }
    }
  });
}

// Calculate final metrics from processed data
function calculateFinalMetrics(metricsData) {
  // Calculate authentication times
  Object.values(metricsData.authenticationTransactions).forEach(transaction => {
    if (transaction.timestamps.length > 1) {
      const authTime = (Math.max(...transaction.timestamps) - Math.min(...transaction.timestamps)) / 1000;
      
      if (transaction.dateKey && metricsData.dailyMetrics[transaction.dateKey]) {
        metricsData.dailyMetrics[transaction.dateKey].authenticationTimes.push(authTime);
      }
    }
  });

  // Calculate inactive users
  const threeMonthsAgo = Date.now() - (90 * 24 * 60 * 60 * 1000);
  const inactiveUsers = Object.values(metricsData.userLastActivity).filter(
    lastActivity => lastActivity < threeMonthsAgo
  ).length;

  // Build chart data
  const chartData = Object.keys(metricsData.dailyMetrics)
    .sort()
    .map(date => ({
      date,
      uniqueUsers: metricsData.dailyMetrics[date].uniqueUsers.size,
      mfaAbandonments: metricsData.dailyMetrics[date].mfaAbandonments,
      avgAuthTime: metricsData.dailyMetrics[date].authenticationTimes.length > 0
        ? metricsData.dailyMetrics[date].authenticationTimes.reduce((a, b) => a + b, 0) / 
          metricsData.dailyMetrics[date].authenticationTimes.length
        : 0,
      failedPasswords: metricsData.dailyMetrics[date].failedPasswords,
      failedMFA: metricsData.dailyMetrics[date].failedMFA,
      successfulLogins: metricsData.dailyMetrics[date].successfulLogins,
      fastPassEnrollments: metricsData.dailyMetrics[date].fastPassEnrollments,
      fastPassAuthUsers: metricsData.dailyMetrics[date].fastPassAuthUsers.size,
      fastPassDevices: metricsData.dailyMetrics[date].fastPassDevices.size,
      fastPassAuths: metricsData.dailyMetrics[date].fastPassAuths,
      biometricUsers: metricsData.dailyMetrics[date].biometricUsers.size,
      emailDeliverySuccess: metricsData.dailyMetrics[date].emailDeliverySuccess,
      emailDeliveryFailure: metricsData.dailyMetrics[date].emailDeliveryFailure,
      emailDropped: metricsData.dailyMetrics[date].emailDropped,
      emailBounced: metricsData.dailyMetrics[date].emailBounced,
      emailSpam: metricsData.dailyMetrics[date].emailSpam,
      emailUnsubscribed: metricsData.dailyMetrics[date].emailUnsubscribed
    }));

  const totalFailedPasswords = chartData.reduce((sum, day) => sum + day.failedPasswords, 0);
  const totalFailedMFA = chartData.reduce((sum, day) => sum + day.failedMFA, 0);
  const totalSuccessfulLogins = chartData.reduce((sum, day) => sum + day.successfulLogins, 0);
  const totalFastPassEnrollments = chartData.reduce((sum, day) => sum + day.fastPassEnrollments, 0);
  const totalFastPassAuths = chartData.reduce((sum, day) => sum + day.fastPassAuths, 0);
  const totalEmailSuccess = chartData.reduce((sum, day) => sum + day.emailDeliverySuccess, 0);
  const totalEmailFailure = chartData.reduce((sum, day) => sum + day.emailDeliveryFailure, 0);
  const totalEmailDropped = chartData.reduce((sum, day) => sum + day.emailDropped, 0);
  const totalEmailBounced = chartData.reduce((sum, day) => sum + day.emailBounced, 0);
  const totalEmailSpam = chartData.reduce((sum, day) => sum + day.emailSpam, 0);
  const totalEmailUnsubscribed = chartData.reduce((sum, day) => sum + day.emailUnsubscribed, 0);

  return {
    totalUniqueUsers: metricsData.uniqueUsers.size,
    totalMfaAbandonments: metricsData.mfaAbandonments.size,
    overallAvgAuthTime: chartData.reduce((sum, day) => sum + day.avgAuthTime, 0) / 
                        chartData.filter(day => day.avgAuthTime > 0).length || 0,
    totalFailedPasswords,
    totalFailedMFA,
    totalSuccessfulLogins,
    inactiveUsers,
    totalFastPassEnrollments,
    totalFastPassAuthUsers: metricsData.fastPassAuthUsers.size,
    totalFastPassDevices: metricsData.fastPassDevices.size,
    totalFastPassAuths,
    totalBiometricUsers: metricsData.biometricUsers.size,
    totalEmailSuccess,
    totalEmailFailure,
    totalEmailDropped,
    totalEmailBounced,
    totalEmailSpam,
    totalEmailUnsubscribed,
    dailyData: chartData
  };
}

// NOW CREATE EXPRESS APP AND CONFIGURE MIDDLEWARE
const app = express();

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-random-secret-key-change-this',
  resave: true,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// OIDC configuration
const oidc = new ExpressOIDC({
  issuer: `${process.env.OKTA_ORG_URL}/oauth2/default`,
  client_id: process.env.OKTA_CLIENT_ID,
  client_secret: process.env.OKTA_CLIENT_SECRET,
  appBaseUrl: process.env.APP_BASE_URL || `http://localhost:${PORT}`,
  redirect_uri: process.env.REDIRECT_URI || `http://localhost:${PORT}/authorization-code/callback`,
  scope: 'openid profile email',
  routes: {
    login: {
      path: '/login'
    },
    loginCallback: {
      path: '/authorization-code/callback',
      afterCallback: '/dashboard'
    }
  },
  postLogoutRedirectUri: process.env.POST_LOGOUT_REDIRECT_URI || `http://localhost:${PORT}`
});

app.use(oidc.router);
app.use(express.json());

// Middleware to check authentication
const requireAuth = (req, res, next) => {
  if (!req.userContext || !req.userContext.userinfo) {
    return res.redirect('/login');
  }
  next();
};

// Authentication check before serving static files
app.use((req, res, next) => {
  if (req.path.startsWith('/login') || 
      req.path.startsWith('/authorization-code/callback') ||
      req.path.startsWith('/logout')) {
    return next();
  }
  
  if (!req.userContext || !req.userContext.userinfo) {
    return res.redirect('/login');
  }
  
  next();
});

app.use(express.static('public'));

// API endpoint to get current progress
app.get('/api/progress', requireAuth, (req, res) => {
  res.json(progressData);
});

// API endpoint to get user info
app.get('/api/userinfo', requireAuth, (req, res) => {
  res.json({
    name: req.userContext.userinfo.name,
    email: req.userContext.userinfo.email,
    sub: req.userContext.userinfo.sub
  });
});

// API endpoint to list configured applications
app.get('/api/apps', requireAuth, (req, res) => {
  res.json({ apps: OKTA_APPS });
});

// Diagnostic endpoint: scan recent logs and return all unique app targets found
app.get('/api/debug/app-targets', requireAuth, async (req, res) => {
  try {
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const url = `${process.env.OKTA_ORG_URL}/api/v1/logs?since=${since}&limit=1000`;
    const response = await fetch(url, {
      headers: {
        'Authorization': `SSWS ${process.env.OKTA_API_TOKEN}`,
        'Accept': 'application/json'
      }
    });
    if (!response.ok) throw new Error(`Okta API error: ${response.status}`);
    const logs = await response.json();

    const appsById = {};
    logs.forEach(log => {
      (log.target || []).forEach(t => {
        if (t.type === 'AppInstance' && t.id && !appsById[t.id]) {
          appsById[t.id] = { id: t.id, displayName: t.displayName, alternateId: t.alternateId };
        }
      });
    });

    const configuredIds = new Set(OKTA_APPS.map(a => a.id));
    const appTargets = Object.values(appsById).map(a => ({
      ...a,
      configuredInEnv: configuredIds.has(a.id)
    }));

    res.json({ logsScanned: logs.length, appTargets });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API endpoint to fetch cached metrics
app.get('/api/cached-metrics', requireAuth, async (req, res) => {
  const appId = req.query.appId || 'all';
  try {
    const cache = await loadCache(appId);
    if (cache) {
      res.json({
        success: true,
        cached: true,
        metrics: cache.metrics,
        logsProcessed: cache.logsProcessed,
        timestamp: new Date(cache.timestamp).toISOString(),
        cacheAge: Math.floor((Date.now() - cache.timestamp) / 1000 / 60) // minutes
      });
    } else {
      res.json({
        success: false,
        cached: false,
        message: 'No cache available'
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API endpoint to fetch and calculate metrics with progress
app.post('/api/fetch-metrics', requireAuth, async (req, res) => {
  const appId = req.body.appId || 'all';

  // Prevent concurrent processing
  if (progressData.isProcessing) {
    return res.status(429).json({
      success: false,
      error: 'Processing already in progress'
    });
  }

  progressData = {
    isProcessing: true,
    appId,
    totalLogs: 0,
    processedLogs: 0,
    currentPage: 0,
    estimatedTime: 0,
    startTime: Date.now()
  };

  // Send immediate response
  res.json({
    success: true,
    message: 'Processing started. Use /api/progress to track progress.',
    processing: true
  });

  // Process in background
  try {
    const now = new Date();
    const thirtyOneDaysAgo = new Date(now.getTime() - 31 * 24 * 60 * 60 * 1000);

    const sinceDate = thirtyOneDaysAgo.toISOString();
    const untilDate = now.toISOString();

    console.log(`Starting incremental fetch from ${sinceDate} to ${untilDate} (appId: ${appId})`);

    const { metrics: metricsData, totalProcessed } = await fetchLogsIncremental(
      sinceDate,
      untilDate,
      appId,
      (progress) => {
        progressData.processedLogs = progress.processedLogs;
        progressData.currentPage = progress.currentPage;
        progressData.totalLogs = progress.processedLogs;

        const elapsed = Date.now() - progressData.startTime;
        progressData.estimatedTime = elapsed;
      }
    );

    console.log(`Processed ${totalProcessed} log entries`);

    const finalMetrics = calculateFinalMetrics(metricsData);

    // Save to cache
    await saveCache(finalMetrics, totalProcessed, appId);

    progressData.isProcessing = false;
    progressData.totalLogs = totalProcessed;

  } catch (error) {
    console.error('Error in background processing:', error);
    progressData.isProcessing = false;
    progressData.error = error.message;
  }
});

// API endpoint to clear cache
app.post('/api/clear-cache', requireAuth, async (req, res) => {
  const appId = req.body.appId || 'all';
  try {
    await fs.unlink(getCacheFile(appId));
    res.json({ success: true, message: 'Cache cleared' });
  } catch (error) {
    res.json({ success: true, message: 'No cache to clear' });
  }
});

// Root automatically redirects to dashboard (which will trigger login if needed)
app.get('/', (req, res) => {
  if (!req.userContext || !req.userContext.userinfo) {
    return res.redirect('/login');
  }
  res.redirect('/dashboard');
});

// Dashboard route (protected)
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Logout route - Okta Single Logout (SLO)
app.get('/logout', (req, res) => {
  const idToken = req.userContext ? req.userContext.tokens.id_token : null;
  
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
      
      // Redirect to Okta logout endpoint for Single Logout
      if (idToken) {
        const logoutUrl = `${process.env.OKTA_ORG_URL}/oauth2/default/v1/logout?` +
          `id_token_hint=${idToken}&` +
          `post_logout_redirect_uri=${encodeURIComponent(process.env.POST_LOGOUT_REDIRECT_URI || `http://localhost:${PORT}`)}`;
        res.redirect(logoutUrl);
      } else {
        res.redirect('/');
      }
    });
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

oidc.on('ready', () => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('OIDC Authentication enabled');
    console.log('Optimizations enabled:');
    console.log('- Streaming processing (memory efficient)');
    console.log('- Caching (1 hour duration)');
    console.log('- Real-time progress tracking');
    console.log('- Background processing');
  });
});

oidc.on('error', (err) => {
  console.error('OIDC Error:', err);
});

// package.json
/*
{
  "name": "okta-analytics-dashboard",
  "version": "2.0.0",
  "description": "Okta Authentication Analytics Dashboard - Optimized",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "@okta/okta-sdk-nodejs": "^7.0.0",
    "@okta/oidc-middleware": "^4.5.0",
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
*/

// .env.example
/*
# Okta Organization Settings
OKTA_ORG_URL=https://your-domain.okta.com
OKTA_API_TOKEN=your-api-token-here

# OIDC Settings
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
APP_BASE_URL=http://localhost:3000
REDIRECT_URI=http://localhost:3000/authorization-code/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3000

# Session Secret
SESSION_SECRET=your-random-secret-key-change-this-in-production

# Application Settings
PORT=3000
NODE_ENV=development
*/