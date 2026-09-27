# exchange-walletst
# TikTok profile statistics

TikTok blocks unauthenticated server-side scraping on many networks. To show reliable follower and following counts for searched public accounts, start the server with a TikAPI key:

```sh
TIKAPI_KEY=your_key npm start
```

The application still attempts its public TikTok fallbacks when no key is set, but those sources can be blocked and then cannot return live counts.
