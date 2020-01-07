Gamo
====

An image proxy and optimization server. Like Camo, and compatible with Camo, but
running proxied images through optimization, and with added functionality to resize
them to specified dimensions using the URL path.

It expects to run behind a reverse proxy like Nginx or Varnish which would perform
caching. By itself, it makes no attempt to do so.

URL structure:

    /[HMAC]/[Hex-encoded URL]

Optionally:

    /[HMAC]/[Hex-encoded URL]/[Dimensions]

The dimensions are to be given as a single integer as one side of a square. The
image will be resized proportionally to fit within the total number of pixels.

Arbitrary dimensions cannot be used. Pre-determined values are configured through
the command-line invocation.

Usage:

    gamo --key=SHARED_HMAC_SECRET --bind=127.0.0.1:8081 --dimensions=256,512,1024
