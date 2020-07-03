Long: v4-signature
Arg: <provider1[:provider2]>
Help: provides AWS V4 signature authentication
Added: 7.74.0
---
provides AWS V4 signature authentication on HTTPS header:

The provider argument is a string that is used by the algorithm when creating
outgoing authentication headers.

Example with "Test:Try":
When curl will do the algorithm, it will Generate:
"TEST-HMAC-SHA256" for "Algorithm"
"x-try-date" for "date"
"test4_request" for "request type"
"SignedHeaders=content-type;host;x-try-date" for "signed headers"

If you use just "test", instead of "test:try",
test will be use for every generated string.
