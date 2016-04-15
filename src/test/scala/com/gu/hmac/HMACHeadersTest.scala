package com.gu.hmac

import java.net.URI

import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.digest.DigestUtils
import org.joda.time.DateTime
import org.scalatest.{FlatSpec, Matchers}

class HMACHeadersTest extends FlatSpec with Matchers {
  import HMACDate.DateTimeOps
  val hmacHeader = new HMACHeaders {
    override def secret = "secret"
  }

  val wrongHmacHeader = new HMACHeaders {
    override def secret = "wrong"
  }

  val uri = new URI("http:///www.theguardian.com/signin?query=someData")
  val date = new DateTime(1994, 11, 15, 8, 12)
  val body = Some("{\"some\": \"json\"}")

  val hmacRequest = HMACRequest(
    httpVerb = HTTP.POST,
    date = HMACDate(date),
    uri = uri,
    additionalHeaders = None,
    contentType = None,
    contentMd5 = HMACContentMD5(body)
  )


  val expectedHMAC = hmacHeader.sign(hmacRequest)
  val dateHeaderValue = "Tue, 15 Nov 1994 08:12:00 GMT"

  "createHMACHeaderValues" should "create a Date and Authorization token base on a URI and a secret" in {
    val headers = hmacHeader.createHMACHeaderValues(hmacRequest)
    headers.date should be(dateHeaderValue)
    headers.token should be(expectedHMAC)
  }

  "validateHMACHeaders" should "return true if the HMAC and the date are valid" in {
    val now = DateTime.now()
    val validHmacRequest = HMACRequest(
      httpVerb = hmacRequest.httpVerb,
      date = HMACDate(now),
      uri = hmacRequest.uri,
      additionalHeaders = hmacRequest.additionalHeaders,
      contentType = hmacRequest.contentType,
      contentMd5 = hmacRequest.contentMd5
    )
    val hmac = hmacHeader.sign(validHmacRequest)
    val isHmacValid = hmacHeader.validateHMACHeaders(
      httpVerb = validHmacRequest.httpVerb,
      date = validHmacRequest.date,
      uri = validHmacRequest.uri,
      contentMd5 = validHmacRequest.contentMd5
    )(HMACToken(hmac))
    isHmacValid should be(true)
  }

  it should "raise an exception if the Date header is in the wrong format" in {
    val wrongDateHeaderFormat = "Tu, 15 Nov 1994 08:12:00 GMT"
    intercept[HMACInvalidDateError] {
      hmacHeader.validateHMACHeaders(
        httpVerb = HTTP.GET,
        date = HMACDate(wrongDateHeaderFormat),
        uri = uri)(HMACToken(expectedHMAC))
    }
  }

  "isHMACValid" should "return true if the two hmac signatures match" in {
    hmacHeader.isHMACValid(hmacRequest, HMACToken(expectedHMAC)) should be(true)
  }

  it should "return false if the two dates do not match" in {
    val wrongDate = new DateTime(1993, 11, 15, 8, 12)
    val hmacRequestWithWrongDate = HMACRequest(
      httpVerb = hmacRequest.httpVerb,
      date = HMACDate(wrongDate),
      uri = hmacRequest.uri,
      additionalHeaders = hmacRequest.additionalHeaders,
      contentType = hmacRequest.contentType,
      contentMd5 = hmacRequest.contentMd5
    )
    hmacHeader.isHMACValid(hmacRequestWithWrongDate, HMACToken(expectedHMAC)) should be(false)
  }

  it should "return false if the two URIs do not match" in {
    val wrongUri = new URI("http:///www.theguardian.com/other")
    val hmacRequestWithWrongUri = HMACRequest(
      httpVerb = hmacRequest.httpVerb,
      date = hmacRequest.date,
      uri = wrongUri,
      additionalHeaders = hmacRequest.additionalHeaders,
      contentType = hmacRequest.contentType,
      contentMd5 = hmacRequest.contentMd5
    )
    hmacHeader.isHMACValid(hmacRequestWithWrongUri, HMACToken(expectedHMAC)) should be(false)
  }

  it should "return false if the two secrets do not match" in {
    val wrongHMAC = wrongHmacHeader.sign(hmacRequest)
    hmacHeader.isHMACValid(hmacRequest, HMACToken(wrongHMAC)) should be(false)
  }

  "isDateValid" should "return true if the date is within the expected time frame" in {
    val threeMinutesAgo = DateTime.now.minusMinutes(3)
    hmacHeader.isDateValid(HMACDate(threeMinutesAgo)) should be(true)
  }

  it should "return false if the date is outside the expected time frame" in {
    val sixMinutesAgo = DateTime.now.minusMinutes(6)
    hmacHeader.isDateValid(HMACDate(sixMinutesAgo)) should be(false)
  }

  it should "return false if the date is in the future" in {
    val inThreeMinutes = DateTime.now.plusMinutes(6)
    hmacHeader.isDateValid(HMACDate(inThreeMinutes)) should be(false)
  }

  "HMACContentMD5" should "return a base64 encoded md5 hash" in {
    val expectedMD5 = DigestUtils.md5("example content")
    val base64MD5 = HMACContentMD5(Some("example content")).get

    Base64.decodeBase64(base64MD5.toString) should be(expectedMD5)
  }
}
