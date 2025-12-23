# Okta Authentication Analytics Dashboard - Optimized for Large Datasets

A high-performance Node.js web application that displays comprehensive authentication analytics from Okta System Logs, optimized for organizations with millions of users.

## 🚀 Performance Optimizations

### 1. **Streaming Processing**
- Logs are processed incrementally as they're fetched (no need to store all logs in memory)
- Reduces memory footprint from GB to MB
- Processes batches of 1000 logs at a time

### 2. **Caching System**
- Results are cached for 1 hour to avoid repeated API calls
- Cache stored in local file system (`./cache/metrics-cache.json`)
- Load cached data instantly without waiting

### 3. **Background Processing**
- Initial request returns immediately
- Processing happens in the background
- Real-time progress updates via polling

### 4. **Real-time Progress Tracking**
- Live updates on logs processed
- Page counter
- Elapsed time display
- No need to wait blindly

### 5. **Optimized Data Structures**
- Only essential transaction data stored
- Sets used for unique counting (memory efficient)
- Minimal object creation during processing

## Features

- **7 Key Metrics**: Unique users, successful logins, failed passwords, failed MFA, MFA abandonments, inactive users, avg auth time
- **6 Interactive Charts**: Daily trends for all metrics
- **Smart Caching**: 1-hour cache with manual refresh option
- **Progress Tracking**: Real-time updates during data processing
- **Rate Limiting**: Automatic handling with exponential backoff
- **Pagination**: Efficient handling of large log datasets

## Performance Benchmarks

For a typical Okta tenant:
- **Small org** (1K-10K users): ~30 seconds
- **Medium org** (10K-100K users): ~2-5 minutes
- **Large org** (100K-1M users): ~5-15 minutes
- **Enterprise** (1M+ users): ~15-30 minutes

*Times vary based on API rate limits and log volume*

## Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create `.env` file:
   ```
   OKTA_ORG_URL=https://your-domain.okta.com
   OKTA_API_TOKEN=your-api-token-here
   PORT=3000
   ```

3. Start the server:
   ```bash
   npm start
   ```

## Usage

### First Time Use
1. Navigate to `http://localhost:3000`
2. Click "Refresh Data" to start processing
3. Monitor real-time progress
4. Data will display automatically when complete

### Subsequent Uses
1. Click "Load Cached Data" for instant results
2. Cache is valid for 1 hour
3. Click "Refresh Data" to update with latest logs

### API Endpoints

- `GET /api/cached-metrics` - Retrieve cached metrics
- `POST /api/fetch-metrics` - Start background processing
- `GET /api/progress` - Get real-time progress updates
- `POST /api/clear-cache` - Clear cached data

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Frontend (Auto-polling for progress)          │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│  Express Server                                  │
│  - Background processing                         │
│  - Progress tracking                             │
│  - Cache management                              │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│  Okta System Logs API                           │
│  - Paginated fetching (1000/page)               │
│  - Rate limit handling                           │
│  - Streaming processing                          │
└──────────────────────────────────────────────────┘
```

## Optimization Tips

### For Very Large Datasets

1. **Run during off-peak hours**: Lower API contention
2. **Increase cache duration**: Modify `CACHE_DURATION` in server.js
3. **Reduce date range**: Change from 31 days to 7 or 14 days
4. **Schedule automated runs**: Use cron to refresh cache periodically

### Memory Management

The application uses streaming processing, so memory usage should remain constant regardless of log volume:
- **Base memory**: ~50-100 MB
- **Per-request overhead**: ~10-20 MB
- **Cache storage**: ~1-5 MB per cached result

### API Rate Limits

Okta API rate limits:
- **System Logs API**: 120 requests per minute
- **Rate limit handling**: Automatic retry with backoff
- **Optimization**: 100ms delay between requests (prevents hitting limits)

## Monitoring

Server logs provide real-time information:
```bash
npm start
# Watch console for:
# - Pages fetched
# - Logs processed
# - Rate limit notices
# - Processing completion
```

## Troubleshooting

### Processing Takes Too Long
- Check API rate limits in Okta admin
- Verify network connectivity
- Consider reducing date range

### Out of Memory Errors
- Shouldn't happen with streaming processing
- If it does, check Node.js version (requires v14+)
- Increase Node memory: `node --max-old-space-size=4096 server.js`

### Cache Not Working
- Check `./cache` directory exists and is writable
- Verify disk space available
- Check server logs for cache errors

## Security

- Never commit `.env` file
- Rotate API tokens regularly
- Consider adding authentication to the dashboard
- Use HTTPS in production
- Implement IP whitelisting if needed

## Future Enhancements

- [ ] PostgreSQL/Redis for caching (multi-instance support)
- [ ] Incremental updates (only fetch new logs since last run)
- [ ] WebSocket for progress updates (instead of polling)
- [ ] Export to CSV/PDF
- [ ] Alerting system for anomalies
- [ ] Multi-tenant support
- [ ] Historical comparison

## License

MIT
