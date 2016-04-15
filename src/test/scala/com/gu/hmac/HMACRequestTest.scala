package com.gu.hmac

import java.net.URI

import org.joda.time.DateTime
import org.scalatest.{Matchers, FlatSpec}

class HMACRequestTest extends FlatSpec with Matchers {

  val uri = new URI("/signin?query=someData")
  val date = new DateTime(1994, 11, 15, 8, 12)

  "toString" should "include empty string for content MD5 if there is no content" in{
    val request = HMACRequest(
      httpVerb = HTTP.GET,
      date = HMACDate(date),
      uri = uri,
      contentMd5 = HMACContentMD5(None)
    )
    request.toSeq.length should be(6)
    request.toString should be("GET\n\n\nTue, 15 Nov 1994 08:12:00 GMT\n/signin\n")
  }

  "toString" should "include empty string for content type if there is no content type" in{
    val request = HMACRequest(
      httpVerb = HTTP.GET,
      date = HMACDate(date),
      uri = uri,
      contentType = None,
      contentMd5 = HMACContentMD5(Some("content"))
    )
    request.toSeq.length should be(6)
    request.toString should be("GET\nmgNkuembtIDdJeHwKEyFVQ==\n\nTue, 15 Nov 1994 08:12:00 GMT\n/signin\n")
  }

  "toString" should "include empty string for additional headers if there are no additional headers" in{
    val request = HMACRequest(
      httpVerb = HTTP.GET,
      date = HMACDate(date),
      uri = uri,
      contentType = HMACContentType("application/json"),
      contentMd5 = HMACContentMD5(Some("content")),
      additionalHeaders = None
    )
    request.toSeq.length should be(6)
    request.toString should be("GET\nmgNkuembtIDdJeHwKEyFVQ==\napplication/json\nTue, 15 Nov 1994 08:12:00 GMT\n/signin\n")
  }

}
