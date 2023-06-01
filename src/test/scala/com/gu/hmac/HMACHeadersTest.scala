package com.gu.hmac

import java.net.URI
import org.joda.time.DateTime
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import java.time.{Clock, Instant, ZoneId}

class HMACHeadersTest extends AnyWordSpec with Matchers {
  import HMACDate.DateTimeOps
  val validSecret = "secret"
  val invalidSecret = "wrong"

  val uri = new URI("http:///www.theguardian.com/signin?query=someData")
  val date = new DateTime(1994, 11, 15, 8, 12)

  val expectedHMAC = "3AQ08uT4ToOISOXWMr68UvzrgrqIx3KK/pKEenwVES8="
  val dateHeaderValue = "Tue, 15 Nov 1994 08:12:00 GMT"

  val javaInstant = Instant.ofEpochMilli(date.toInstant.getMillis)

  val fixedClock =
    Clock.fixed(javaInstant, ZoneId.systemDefault)

  val hmacHeader = new HMACHeaders {
    override val clock: Clock = fixedClock
    override def secret = validSecret
  }

  val wrongHmacHeader = new HMACHeaders {
    override val clock: Clock = fixedClock
    override def secret = invalidSecret
  }

  val hmacValidator = new ValidateHMACHeader {
    override val clock: Clock = fixedClock
  }

  val hmacCreator = new CreateHMACHeader {
    override val clock: Clock = fixedClock
  }

  "HMACHeaders" when {
    "createHMACHeaderValues" should {
      "create a Date and Authorization token based on a URI and a secret" in {
        val headers = hmacHeader.createHMACHeaderValues(uri)
        headers.date should be(dateHeaderValue)
        headers.token should be(s"HMAC $expectedHMAC")
      }
    }

    "createHMACHeaderValues" should {
      "return true if the HMAC and the date are valid" in {
        val now = new DateTime(fixedClock.instant().toEpochMilli())
        hmacHeader.validateHMACHeaders(now.toRfc7231String, s"HMAC $expectedHMAC", uri) should be(true)
      }
    }
  }

  "CreateHMACHeader" when {
    "createHMACHeaderValuesWithSecret" should {
      "create a Date and Authorization token based on a URI and a secret" in {
        val headers = hmacCreator.createHMACHeaderValuesWithSecret(validSecret, uri)
        headers.date should be(dateHeaderValue)
        headers.token should be(s"HMAC $expectedHMAC")
      }
    }
  }

  "ValidateHMACHeader" when {
    "validateHMACHeadersWithSecret" should {
      "return true if the HMAC and the date are valid" in {
        val now = new DateTime(fixedClock.instant().toEpochMilli())
        hmacValidator.validateHMACHeadersWithSecret(hmacHeader.secret, now.toRfc7231String, s"HMAC $expectedHMAC", uri) should be(true)
      }
      "return false if the HMAC is invalid" in {
        val now = new DateTime(fixedClock.instant().toEpochMilli())
        hmacValidator.validateHMACHeadersWithSecret(hmacHeader.secret, now.toRfc7231String, s"HMAC nope", uri) should be(false)
      }
      "return false if the date is invalid" in {
        val now = new DateTime(fixedClock.instant().toEpochMilli())
        val tenMinutesAgo = now.minusMinutes(hmacValidator.HmacValidDurationInMinutes + 1)
        hmacValidator.validateHMACHeadersWithSecret(hmacHeader.secret, tenMinutesAgo.toRfc7231String, s"HMAC $expectedHMAC", uri) should be(false)
      }
      "raise an exception if the Date header is in the wrong format" in {
        val wrongDateHeaderFormat = "Tu, 15 Nov 1994 08:12:00 GMT"
        intercept[HMACInvalidDateError] {
          hmacValidator.validateHMACHeadersWithSecret(hmacHeader.secret, wrongDateHeaderFormat, expectedHMAC, uri)
        }
      }
      "raise an exception if the HMAC header is in the wrong format" in {
        val wrongTokenHeaderFormat = "abcdef"
        intercept[HMACInvalidTokenError] {
          hmacValidator.validateHMACHeadersWithSecret(hmacHeader.secret, dateHeaderValue, wrongTokenHeaderFormat, uri) should be(true)
        }
      }
    }
    "isHMACValid" should {
      "return true if the two hmac signatures match" in {
        hmacValidator.isHMACValid(hmacHeader.secret, HMACDate(date), uri, HMACToken(expectedHMAC)) should be(true)
      }
      "return false if the two dates do not match" in {
        val wrongDate = new DateTime(1993, 11, 15, 8, 12)
        hmacValidator.isHMACValid(hmacHeader.secret, HMACDate(wrongDate), uri, HMACToken(expectedHMAC)) should be(false)
      }
      "return false if the two URIs do not match" in {
        val wrongUri = new URI("http:///www.theguardian.com/other")
        hmacValidator.isHMACValid(hmacHeader.secret, HMACDate(date), wrongUri, HMACToken(expectedHMAC)) should be(false)
      }
      "return false if the two secrets do not match" in {
        val wrongHMAC = HMACSignatory.sign(wrongHmacHeader.secret, date, uri)
        hmacValidator.isHMACValid(hmacHeader.secret, HMACDate(date), uri, HMACToken(wrongHMAC)) should be(false)
      }
    }
    "isDateValid" should {
      "return true if the date is within the expected time frame" in {
        val threeMinutesAgo = date.minusMinutes(3)
        hmacValidator.isDateValid(HMACDate(threeMinutesAgo)) should be(true)
      }
      "return false if the date is outside the expected time frame" in {
        val sixMinutesAgo = date.minusMinutes(6)
        hmacValidator.isDateValid(HMACDate(sixMinutesAgo)) should be(false)
      }
      "return false if the date is in the future" in {
        val inSixMinutes = date.plusMinutes(6)
        hmacValidator.isDateValid(HMACDate(inSixMinutes)) should be(false)
      }
    }
  }
}
