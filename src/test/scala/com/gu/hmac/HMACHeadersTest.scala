package com.gu.hmac

import java.net.URI

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
  val expectedHMAC = hmacHeader.sign(date, uri)
  val dateHeaderValue = "Tue, 15 Nov 1994 08:12:00 GMT"

  "createHMACHeaderValues" should "create a Date and Authorization token base on a URI and a secret" in {
    val headers = hmacHeader.createHMACHeaderValues(uri, date)
    headers.date should be(dateHeaderValue)
    headers.token should be(s"HMAC $expectedHMAC")
  }

  "validateHMACHeaders" should "return true if the HMAC and the date are valid" in {
    val now = DateTime.now()
    val hmac = hmacHeader.sign(now, uri)
    hmacHeader.validateHMACHeaders(now.toRfc7231String, s"HMAC $hmac", uri) should be(true)
  }

  it should "raise an exception if the Date header is in the wrong format" in {
    val wrongDateHeaderFormat = "Tu, 15 Nov 1994 08:12:00 GMT"
    intercept[HMACInvalidDateError] {
      hmacHeader.validateHMACHeaders(wrongDateHeaderFormat, expectedHMAC, uri)
    }
  }

  it should "raise an exception if the HMAC header is in the wrong format" in {
    val wrongTokenHeaderFormat = "abcdef"
    intercept[HMACInvalidTokenError] {
      hmacHeader.validateHMACHeaders(dateHeaderValue, wrongTokenHeaderFormat, uri) should be(true)
    }
  }

  "isHMACValid" should "return true if the two hmac signatures match" in {
    hmacHeader.isHMACValid(HMACDate(date), uri, HMACToken(expectedHMAC)) should be(true)
  }

  it should "return false if the two dates do not match" in {
    val wrongDate = new DateTime(1993, 11, 15, 8, 12)
    hmacHeader.isHMACValid(HMACDate(wrongDate), uri, HMACToken(expectedHMAC)) should be(false)
  }

  it should "return false if the two URIs do not match" in {
    val wrongUri = new URI("http:///www.theguardian.com/other")
    hmacHeader.isHMACValid(HMACDate(date), wrongUri, HMACToken(expectedHMAC)) should be(false)
  }

  it should "return false if the two secrets do not match" in {
    val wrongHMAC = wrongHmacHeader.sign(date, uri)
    hmacHeader.isHMACValid(HMACDate(date), uri, HMACToken(wrongHMAC)) should be(false)
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
}
