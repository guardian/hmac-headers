[![hmac-headers Scala version support](https://index.scala-lang.org/guardian/hmac-headers/hmac-headers/latest-by-scala-version.svg?platform=jvm)](https://index.scala-lang.org/guardian/hmac-headers/hmac-headers)
[![Release](https://github.com/guardian/hmac-headers/actions/workflows/release.yml/badge.svg)](https://github.com/guardian/hmac-headers/actions/workflows/release.yml)

# Introduction

hmac-headers is a Scala utility for signing and verifying HMAC signatures passed in a header in a HTTP request.
Given a secret key shared between the client and the server, hmac-headers can do the following:

- on the client side, create two strings which can be put in appropriate headers (generally the `Date` and `Authorization` headers) as part of the request:
  - a date in the following format: Sun, 06 Nov 1994 08:49:37 GMT (see https://tools.ietf.org/html/rfc7231#section-7.1.1.1)
  - a Base64 encoded HMAC, signed using the URI, the date and the secret

- on the server side, verify that the received headers are valid. Given a date string and a HMAC hash, it will check that:
  - the hash was computed using the same secret
  - the date is within the allowed time range (to avoid replay attacks)

# Usage

In your build.sbt:

```
libraryDependencies += "com.gu" %% "hmac-headers" % "<version>" // find the latest version by checking this repo's tags
```

## Releasing

### Testing locally

You can publish locally by running:

```shell
# Test your signing setup works (you may need to follow the guide below first)
sbt +publishLocalSigned

# Publish locally so that other projects can use your local ivy repository
sbt +publishLocal
```

# Publishing a new release

This repo uses [`gha-scala-library-release-workflow`](https://github.com/guardian/gha-scala-library-release-workflow)
to automate publishing releases (both full & preview releases) - see
[**Making a Release**](https://github.com/guardian/gha-scala-library-release-workflow/blob/main/docs/making-a-release.md).

## Verifying requests

```
import com.gu.hmac.HMACHeaders

val authorization = // extract HMAC from header
val date = // extract date from header
val uri = new URI(request.uri) // extract the URI from the request

hmacService.validateHMACHeaders(date, authorization, uri)) // returns a Boolean
```

## Signing requests


```
import com.gu.hmac.HMACHeaders

val hmacHeaders = hmac.createHMACHeaderValues(new URI("example.com"))
// Add headers to your request as appropriate, e.g. in Play
ws.url("example.com")
  .withHeaders(HeaderNames.DATE -> hmacHeaders.date, HeaderNames.AUTHORIZATION -> hmacHeaders.token)
```
